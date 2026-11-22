use super::types::{ArchiveFormat, ArchiveRequest, ArchiveTicketResponse};
use super::{
    ARCHIVE_CHANNEL_CAPACITY, ARCHIVE_CHUNK_BYTES, ARCHIVE_PLANNING_TIMEOUT, ARCHIVE_SEMAPHORE,
    ARCHIVE_TICKET_STORE, IO_BUF_BYTES, MAX_SEARCH_ENTRIES,
};
use crate::auth::AuthUser;
use crate::mcbrowser::{
    build_attachment_content_disposition, map_fs_io_error, normalize_relative_path,
    open_configured_user_browser_fs_with_conn, validate_mcbrowser_user, McBrowserError,
};
use af_files::BrowserFs;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path as AxumPath};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
#[cfg(test)]
use flate2::read::GzDecoder;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use rand::RngCore;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveTicketEntry {
    pub user_id: i64,
    pub jti: String,
    pub effective_scope: String,
    pub paths: Vec<String>,
    pub format: ArchiveFormat,
    pub filename: String,
    pub expires_at: Instant,
}

pub struct ArchiveTicketStore {
    max_tickets: usize,
    ttl: Duration,
    entries: StdMutex<HashMap<[u8; 32], ArchiveTicketEntry>>,
}

impl ArchiveTicketStore {
    pub fn new(max_tickets: usize, ttl: Duration) -> Self {
        Self {
            max_tickets,
            ttl,
            entries: StdMutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn prune_expired_at(&self, now: Instant) -> usize {
        let mut guard = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|_, v| v.expires_at > now);
        guard.len()
    }

    #[cfg(test)]
    pub fn active_len_at(&self, now: Instant) -> usize {
        self.prune_expired_at(now)
    }

    pub fn issue_at(
        &self,
        user: &AuthUser,
        effective_scope: String,
        normalized_paths: Vec<String>,
        format: ArchiveFormat,
        now: Instant,
    ) -> Result<(String, ArchiveTicketResponse), McBrowserError> {
        let user_id = validate_mcbrowser_user(user)?;
        let jti = user.jti.trim();
        if jti.is_empty() {
            return Err(McBrowserError::Unauthorized(
                "Missing session token identifier".to_string(),
            ));
        }
        let normalized_paths = normalize_archive_selection(&normalized_paths)?;
        let filename = compute_archive_download_filename(&normalized_paths, format);

        let mut random_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let ticket = hex::encode(random_bytes);
        let digest_key: [u8; 32] = Sha256::digest(ticket.as_bytes()).into();

        let mut guard = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|_, v| v.expires_at > now);
        if guard.len() >= self.max_tickets {
            return Err(McBrowserError::Conflict(format!(
                "Archive ticket capacity exceeded (maximum {} active tickets)",
                self.max_tickets
            )));
        }

        guard.insert(
            digest_key,
            ArchiveTicketEntry {
                user_id,
                jti: jti.to_string(),
                effective_scope,
                paths: normalized_paths,
                format,
                filename: filename.clone(),
                expires_at: now + self.ttl,
            },
        );

        let url = format!("/api/v1/auth/mcbrowser/archive/{ticket}");
        Ok((ticket, ArchiveTicketResponse { url, filename }))
    }

    pub fn redeem_at(
        &self,
        raw_ticket: &str,
        user: &AuthUser,
        current_effective_scope: &str,
        now: Instant,
    ) -> Result<ArchiveTicketEntry, McBrowserError> {
        let user_id = validate_mcbrowser_user(user)?;
        let jti = user.jti.trim();
        if jti.is_empty() {
            return Err(McBrowserError::Unauthorized(
                "Missing session token identifier".to_string(),
            ));
        }

        let clean_ticket = raw_ticket.trim();
        if clean_ticket.len() != 64 || !clean_ticket.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(McBrowserError::NotFound(
                "Invalid or expired archive ticket".to_string(),
            ));
        }

        let digest_key: [u8; 32] = Sha256::digest(clean_ticket.as_bytes()).into();
        let entry = {
            let mut guard = match self.entries.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.retain(|_, v| v.expires_at > now);
            guard.remove(&digest_key)
        };

        let Some(entry) = entry else {
            return Err(McBrowserError::NotFound(
                "Invalid or expired archive ticket".to_string(),
            ));
        };

        if entry.user_id != user_id || entry.jti != jti {
            return Err(McBrowserError::Forbidden(
                "Archive ticket does not belong to the active user session".to_string(),
            ));
        }

        if entry.effective_scope != current_effective_scope {
            return Err(McBrowserError::Forbidden(
                "User storage scope changed since archive ticket was issued".to_string(),
            ));
        }

        Ok(entry)
    }
}

pub fn compute_archive_download_filename(
    normalized_selection: &[String],
    format: ArchiveFormat,
) -> String {
    let base_name = if normalized_selection.len() == 1 {
        normalized_selection[0]
            .rsplit('/')
            .next()
            .unwrap_or("archive")
            .to_string()
    } else {
        "archive".to_string()
    };
    format!("{base_name}.{}", format.extension())
}

#[derive(Debug, Clone)]
pub struct ArchivePlanItem {
    pub fs_path: String,
    pub archive_path: String,
    pub is_dir: bool,
    pub resolved_path: String,
    pub authorization_paths: Vec<String>,
    pub source_size: u64,
    source_file: Option<Arc<File>>,
}

pub(super) struct ArchiveSourceReader {
    file: Arc<File>,
    offset: u64,
    length: u64,
}

impl Read for ArchiveSourceReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.offset);
        let maximum = remaining.min(buffer.len() as u64) as usize;
        if maximum == 0 {
            return Ok(0);
        }
        let count =
            std::os::unix::fs::FileExt::read_at(&*self.file, &mut buffer[..maximum], self.offset)?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "Pinned archive source was truncated",
            ));
        }
        self.offset = self.offset.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "Archive source offset overflow")
        })?;
        Ok(count)
    }
}

pub(super) enum ArchiveWalkStep {
    Visit(String),
    Leave(String),
}

#[derive(Clone)]
pub(super) struct ArchivePlanningControl {
    cancelled: Arc<AtomicBool>,
    pub(super) deadline: Instant,
}

impl ArchivePlanningControl {
    pub(super) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + ARCHIVE_PLANNING_TIMEOUT,
        }
    }

    fn check(&self) -> Result<(), McBrowserError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(McBrowserError::RequestTimeout(
                "Archive request cancelled".to_string(),
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(McBrowserError::RequestTimeout(
                "Archive planning deadline exceeded".to_string(),
            ));
        }
        Ok(())
    }
}

pub(super) struct ArchivePlanningGuard(pub(super) ArchivePlanningControl);

impl Drop for ArchivePlanningGuard {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

pub fn validate_archive_entry_name(raw: &str) -> Result<String, McBrowserError> {
    let normalized = normalize_relative_path(raw, false)?;
    if normalized.starts_with('/')
        || normalized.contains('\\')
        || normalized.contains(':')
        || normalized.chars().any(|c| c.is_control())
    {
        return Err(McBrowserError::BadRequest(
            "Unsafe archive entry path".to_string(),
        ));
    }
    for segment in normalized.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with(".af-upload-tmp.")
        {
            return Err(McBrowserError::BadRequest(
                "Unsafe archive entry segment".to_string(),
            ));
        }
    }
    Ok(normalized)
}

pub fn normalize_archive_selection(raw_paths: &[String]) -> Result<Vec<String>, McBrowserError> {
    if raw_paths.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive request must include at least one path".to_string(),
        ));
    }
    if raw_paths.len() > MAX_SEARCH_ENTRIES {
        return Err(McBrowserError::BadRequest(
            "Archive request exceeds maximum path count".to_string(),
        ));
    }

    let mut normalized = Vec::with_capacity(raw_paths.len());
    let mut seen = HashSet::with_capacity(raw_paths.len());
    for raw in raw_paths {
        let clean = validate_archive_entry_name(raw)?;
        if !seen.insert(clean.clone()) {
            return Err(McBrowserError::BadRequest(format!(
                "Duplicate path in archive selection: '{clean}'"
            )));
        }
        normalized.push(clean);
    }

    for (i, a) in normalized.iter().enumerate() {
        let prefix = format!("{a}/");
        for (j, b) in normalized.iter().enumerate() {
            if i != j && b.starts_with(&prefix) {
                return Err(McBrowserError::BadRequest(format!(
                    "Overlapping archive paths '{a}' and '{b}' would produce duplicate entries"
                )));
            }
        }
    }

    Ok(normalized)
}

pub fn collect_archive_plan_with_auth<F>(
    bfs: &BrowserFs,
    selected_paths: &[String],
    authorize_download: F,
) -> Result<Vec<ArchivePlanItem>, McBrowserError>
where
    F: FnMut(&str) -> Result<(), McBrowserError>,
{
    collect_archive_plan_with_control(
        bfs,
        selected_paths,
        &ArchivePlanningControl::new(),
        authorize_download,
    )
}

pub(super) fn collect_archive_plan_with_control<F>(
    bfs: &BrowserFs,
    selected_paths: &[String],
    control: &ArchivePlanningControl,
    mut authorize_download: F,
) -> Result<Vec<ArchivePlanItem>, McBrowserError>
where
    F: FnMut(&str) -> Result<(), McBrowserError>,
{
    control.check()?;
    let normalized_selection = normalize_archive_selection(selected_paths)?;
    let mut plan = Vec::new();
    let mut seen_archive_names = HashSet::new();
    let mut active_directories = HashSet::new();
    let mut scheduled_entries = normalized_selection.len();
    let mut pending: Vec<_> = normalized_selection
        .into_iter()
        .rev()
        .map(ArchiveWalkStep::Visit)
        .collect();

    while let Some(step) = pending.pop() {
        control.check()?;
        let path = match step {
            ArchiveWalkStep::Visit(path) => path,
            ArchiveWalkStep::Leave(resolved_path) => {
                active_directories.remove(&resolved_path);
                continue;
            }
        };
        if plan.len() >= MAX_SEARCH_ENTRIES {
            return Err(McBrowserError::BadRequest(format!(
                "Archive exceeds maximum entry limit of {MAX_SEARCH_ENTRIES}"
            )));
        }
        authorize_download(&path)?;
        let resolved = bfs
            .metadata_resolving_internal_links(&path)
            .map_err(|error| map_fs_io_error(error, "Failed to inspect archive source"))?;
        for authorized_path in
            archive_authorization_paths(&path, &resolved.resolution_paths, &resolved.resolved_path)
        {
            authorize_download(&authorized_path)?;
        }
        let archive_path = validate_archive_entry_name(&path)?;
        if !seen_archive_names.insert(archive_path.clone()) {
            return Err(McBrowserError::BadRequest(format!(
                "Duplicate archive entry path '{archive_path}'"
            )));
        }
        match resolved.entry.kind.as_str() {
            "file" => {
                let opened = bfs
                    .open_file_resolving_internal_links(&path)
                    .map_err(|error| map_fs_io_error(error, "Failed to open archive source"))?;
                let authorization_paths = archive_authorization_paths(
                    &path,
                    &opened.resolution_paths,
                    &opened.resolved_path,
                );
                for authorized_path in &authorization_paths {
                    authorize_download(authorized_path)?;
                }
                let metadata = opened.file.metadata().map_err(|error| {
                    map_fs_io_error(error, "Failed to inspect pinned archive source")
                })?;
                plan.push(ArchivePlanItem {
                    fs_path: path,
                    archive_path,
                    is_dir: false,
                    resolved_path: opened.resolved_path,
                    authorization_paths,
                    source_size: metadata.len(),
                    source_file: Some(Arc::new(opened.file)),
                });
            }
            "directory" => {
                let listing = bfs
                    .list_with_trace_resolving_internal_links(&path)
                    .map_err(|error| map_fs_io_error(error, "Failed to list archive source"))?;
                let authorization_paths = archive_authorization_paths(
                    &path,
                    &listing.resolution_paths,
                    &listing.resolved_path,
                );
                for authorized_path in &authorization_paths {
                    authorize_download(authorized_path)?;
                }
                if !active_directories.insert(listing.resolved_path.clone()) {
                    return Err(McBrowserError::Forbidden(
                        "Archive source contains a directory alias cycle".to_string(),
                    ));
                }
                scheduled_entries = scheduled_entries.saturating_add(listing.entries.len());
                if scheduled_entries > MAX_SEARCH_ENTRIES {
                    return Err(McBrowserError::BadRequest(format!(
                        "Archive exceeds maximum entry limit of {MAX_SEARCH_ENTRIES}"
                    )));
                }
                pending.push(ArchiveWalkStep::Leave(listing.resolved_path.clone()));
                for child in listing.entries.into_iter().rev() {
                    pending.push(ArchiveWalkStep::Visit(format!("{path}/{}", child.name)));
                }
                plan.push(ArchivePlanItem {
                    fs_path: path,
                    archive_path,
                    is_dir: true,
                    resolved_path: listing.resolved_path,
                    authorization_paths,
                    source_size: 0,
                    source_file: None,
                });
            }
            _ => {
                return Err(McBrowserError::Forbidden(
                    "Special files cannot be archived".to_string(),
                ));
            }
        }
    }

    control.check()?;
    Ok(plan)
}

pub(super) fn archive_authorization_paths(
    path: &str,
    trace: &[String],
    resolved_path: &str,
) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for candidate in std::iter::once(path)
        .chain(trace.iter().map(String::as_str))
        .chain(std::iter::once(resolved_path))
    {
        if seen.insert(candidate.to_string()) {
            paths.push(candidate.to_string());
        }
    }
    paths
}

pub(super) fn open_planned_archive_file(item: &ArchivePlanItem) -> io::Result<ArchiveSourceReader> {
    let file = item.source_file.as_ref().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidInput, "Pinned archive source is missing")
    })?;
    if std::os::unix::fs::MetadataExt::nlink(&file.metadata()?) > 1 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Hardlinked archive sources are not permitted",
        ));
    }
    Ok(ArchiveSourceReader {
        file: Arc::clone(file),
        offset: 0,
        length: item.source_size,
    })
}

pub fn collect_archive_plan_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    selected_paths: &[String],
) -> Result<Vec<ArchivePlanItem>, McBrowserError> {
    collect_archive_plan_for_user_with_control_conn(
        conn,
        bfs,
        auth_user,
        selected_paths,
        &ArchivePlanningControl::new(),
    )
}

pub(super) fn collect_archive_plan_for_user_with_control_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    selected_paths: &[String],
    control: &ArchivePlanningControl,
) -> Result<Vec<ArchivePlanItem>, McBrowserError> {
    collect_archive_plan_with_control(bfs, selected_paths, control, |path| {
        control.check()?;
        crate::mcbrowser::policy::authorize_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Read,
            path,
        )?;
        crate::mcbrowser::policy::authorize_with_conn(
            conn,
            auth_user,
            crate::mcbrowser::policy::Permission::Download,
            path,
        )
    })
}

pub fn write_archive_to_writer<W: Write>(
    bfs: &BrowserFs,
    plan: &[ArchivePlanItem],
    format: ArchiveFormat,
    writer: W,
) -> io::Result<()> {
    match format {
        ArchiveFormat::Zip => write_zip_archive(bfs, plan, writer),
        ArchiveFormat::Tar => write_tar_archive(bfs, plan, writer),
        ArchiveFormat::TarGz => {
            let gz = GzEncoder::new(writer, Compression::default());
            let mut builder = tar::Builder::new(gz);
            append_tar_items(bfs, plan, &mut builder)?;
            let gz = builder.into_inner()?;
            let mut inner = gz.finish()?;
            inner.flush()
        }
        ArchiveFormat::TarBz2 => {
            let bz = bzip2::write::BzEncoder::new(writer, bzip2::Compression::default());
            let mut builder = tar::Builder::new(bz);
            append_tar_items(bfs, plan, &mut builder)?;
            let bz = builder.into_inner()?;
            let mut inner = bz.finish()?;
            inner.flush()
        }
        ArchiveFormat::TarXz => {
            let xz = xz2::write::XzEncoder::new(writer, 6);
            let mut builder = tar::Builder::new(xz);
            append_tar_items(bfs, plan, &mut builder)?;
            let xz = builder.into_inner()?;
            let mut inner = xz.finish()?;
            inner.flush()
        }
        ArchiveFormat::TarLz4 => {
            let lz4 = lz4_flex::frame::FrameEncoder::new(writer);
            let mut builder = tar::Builder::new(lz4);
            append_tar_items(bfs, plan, &mut builder)?;
            let lz4 = builder.into_inner()?;
            let mut inner = lz4
                .finish()
                .map_err(|e| io::Error::other(format!("lz4 frame finish failed: {e}")))?;
            inner.flush()
        }
        ArchiveFormat::TarSz => {
            let sz = snap::write::FrameEncoder::new(writer);
            let mut builder = tar::Builder::new(sz);
            append_tar_items(bfs, plan, &mut builder)?;
            let mut sz = builder.into_inner()?;
            sz.flush()?;
            let mut inner = sz
                .into_inner()
                .map_err(|e| io::Error::other(format!("snappy frame finish failed: {e}")))?;
            inner.flush()
        }
        ArchiveFormat::TarBr => {
            let mut br = brotli::CompressorWriter::new(writer, IO_BUF_BYTES, 6, 22);
            {
                let mut builder = tar::Builder::new(&mut br);
                append_tar_items(bfs, plan, &mut builder)?;
                let _ = builder.into_inner()?;
            }
            br.flush()?;
            let mut inner = br.into_inner();
            inner.flush()
        }
        ArchiveFormat::TarZst => {
            let zst = zstd::stream::write::Encoder::new(writer, 3)?;
            let mut builder = tar::Builder::new(zst);
            append_tar_items(bfs, plan, &mut builder)?;
            let zst = builder.into_inner()?;
            let mut inner = zst.finish()?;
            inner.flush()
        }
    }
}

#[cfg(test)]
pub fn decode_tar_archive_entries<R: Read>(
    format: ArchiveFormat,
    reader: R,
) -> io::Result<BTreeMap<String, Vec<u8>>> {
    fn collect_from_tar<T: Read>(
        mut archive: tar::Archive<T>,
    ) -> io::Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        for entry_res in archive.entries()? {
            let mut entry = entry_res?;
            let path = entry.path()?.to_string_lossy().to_string();
            if entry.header().entry_type().is_file() {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                out.insert(path, buf);
            }
        }
        Ok(out)
    }

    match format {
        ArchiveFormat::Zip => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "use zip::ZipArchive for zip format",
        )),
        ArchiveFormat::Tar => collect_from_tar(tar::Archive::new(reader)),
        ArchiveFormat::TarGz => collect_from_tar(tar::Archive::new(GzDecoder::new(reader))),
        ArchiveFormat::TarBz2 => {
            collect_from_tar(tar::Archive::new(bzip2::read::BzDecoder::new(reader)))
        }
        ArchiveFormat::TarXz => {
            collect_from_tar(tar::Archive::new(xz2::read::XzDecoder::new(reader)))
        }
        ArchiveFormat::TarLz4 => collect_from_tar(tar::Archive::new(
            lz4_flex::frame::FrameDecoder::new(reader),
        )),
        ArchiveFormat::TarSz => {
            collect_from_tar(tar::Archive::new(snap::read::FrameDecoder::new(reader)))
        }
        ArchiveFormat::TarBr => collect_from_tar(tar::Archive::new(brotli::Decompressor::new(
            reader,
            IO_BUF_BYTES,
        ))),
        ArchiveFormat::TarZst => {
            let dec = zstd::stream::read::Decoder::new(reader)?;
            collect_from_tar(tar::Archive::new(dec))
        }
    }
}

pub(super) fn write_tar_archive<W: Write>(
    bfs: &BrowserFs,
    plan: &[ArchivePlanItem],
    writer: W,
) -> io::Result<()> {
    let mut builder = tar::Builder::new(writer);
    append_tar_items(bfs, plan, &mut builder)?;
    let mut inner = builder.into_inner()?;
    inner.flush()
}

pub(super) fn append_tar_items<W: Write>(
    _bfs: &BrowserFs,
    plan: &[ArchivePlanItem],
    builder: &mut tar::Builder<W>,
) -> io::Result<()> {
    for item in plan {
        let clean_name = validate_archive_entry_name(&item.archive_path)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("{e:?}")))?;
        if item.is_dir {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
            header.set_mtime(0);
            header.set_cksum();
            let dir_name = format!("{clean_name}/");
            builder.append_data(&mut header, &dir_name, io::empty())?;
        } else {
            let file = open_planned_archive_file(item)?;
            let size = item.source_size;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(size);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, &clean_name, file.take(size))?;
        }
    }
    builder.finish()
}

#[derive(Debug, Clone)]
pub(crate) struct ZipEntryRecord {
    pub(crate) name_bytes: Vec<u8>,
    pub(crate) version_needed: u16,
    pub(crate) method: u16,
    pub(crate) flags: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) local_header_offset: u64,
    pub(crate) external_attr: u32,
}

pub(crate) struct CountingWriter<W> {
    pub(crate) inner: W,
    pub(crate) written: u64,
}

impl<W: Write> CountingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written = self
            .written
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "archive size overflow"))?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn write_zip_central_directory_and_eocd<W: Write>(
    out: &mut CountingWriter<W>,
    records: &[ZipEntryRecord],
) -> io::Result<()> {
    let cd_start = out.written;
    let mut any_entry_zip64 = false;

    for rec in records {
        let need_uncomp_64 = rec.uncompressed_size >= u32::MAX as u64;
        let need_comp_64 = rec.compressed_size >= u32::MAX as u64;
        let need_offset_64 = rec.local_header_offset >= u32::MAX as u64;
        let need_zip64 = need_uncomp_64 || need_comp_64 || need_offset_64;
        if need_zip64 {
            any_entry_zip64 = true;
        }

        let mut extra = Vec::with_capacity(32);
        if need_zip64 {
            let mut field_data = Vec::with_capacity(24);
            if need_uncomp_64 {
                field_data.extend_from_slice(&rec.uncompressed_size.to_le_bytes());
            }
            if need_comp_64 {
                field_data.extend_from_slice(&rec.compressed_size.to_le_bytes());
            }
            if need_offset_64 {
                field_data.extend_from_slice(&rec.local_header_offset.to_le_bytes());
            }
            extra.extend_from_slice(&0x0001u16.to_le_bytes());
            extra.extend_from_slice(&(field_data.len() as u16).to_le_bytes());
            extra.extend_from_slice(&field_data);
        }

        let version_needed = if need_zip64 {
            rec.version_needed.max(45)
        } else {
            rec.version_needed
        };
        let comp_32 = if need_comp_64 {
            u32::MAX
        } else {
            rec.compressed_size as u32
        };
        let uncomp_32 = if need_uncomp_64 {
            u32::MAX
        } else {
            rec.uncompressed_size as u32
        };
        let offset_32 = if need_offset_64 {
            u32::MAX
        } else {
            rec.local_header_offset as u32
        };

        out.write_all(&0x02014b50u32.to_le_bytes())?;
        out.write_all(&((3u16 << 8) | version_needed).to_le_bytes())?;
        out.write_all(&version_needed.to_le_bytes())?;
        out.write_all(&rec.flags.to_le_bytes())?;
        out.write_all(&rec.method.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&0x0021u16.to_le_bytes())?;
        out.write_all(&rec.crc32.to_le_bytes())?;
        out.write_all(&comp_32.to_le_bytes())?;
        out.write_all(&uncomp_32.to_le_bytes())?;
        out.write_all(&(rec.name_bytes.len() as u16).to_le_bytes())?;
        out.write_all(&(extra.len() as u16).to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&rec.external_attr.to_le_bytes())?;
        out.write_all(&offset_32.to_le_bytes())?;
        out.write_all(&rec.name_bytes)?;
        if !extra.is_empty() {
            out.write_all(&extra)?;
        }
    }

    let cd_end = out.written;
    let cd_size = cd_end.saturating_sub(cd_start);
    let total_entries = records.len() as u64;
    let need_zip64_eocd = any_entry_zip64
        || total_entries >= u16::MAX as u64
        || cd_size >= u32::MAX as u64
        || cd_start >= u32::MAX as u64;

    if need_zip64_eocd {
        let zip64_eocd_offset = out.written;
        out.write_all(&0x06064b50u32.to_le_bytes())?;
        out.write_all(&44u64.to_le_bytes())?;
        out.write_all(&((3u16 << 8) | 45u16).to_le_bytes())?;
        out.write_all(&45u16.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&total_entries.to_le_bytes())?;
        out.write_all(&total_entries.to_le_bytes())?;
        out.write_all(&cd_size.to_le_bytes())?;
        out.write_all(&cd_start.to_le_bytes())?;

        out.write_all(&0x07064b50u32.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&zip64_eocd_offset.to_le_bytes())?;
        out.write_all(&1u32.to_le_bytes())?;
    }

    let entries_16 = if total_entries >= u16::MAX as u64 {
        u16::MAX
    } else {
        total_entries as u16
    };
    let cd_size_32 = if cd_size >= u32::MAX as u64 {
        u32::MAX
    } else {
        cd_size as u32
    };
    let cd_start_32 = if cd_start >= u32::MAX as u64 {
        u32::MAX
    } else {
        cd_start as u32
    };

    out.write_all(&0x06054b50u32.to_le_bytes())?;
    out.write_all(&0u16.to_le_bytes())?;
    out.write_all(&0u16.to_le_bytes())?;
    out.write_all(&entries_16.to_le_bytes())?;
    out.write_all(&entries_16.to_le_bytes())?;
    out.write_all(&cd_size_32.to_le_bytes())?;
    out.write_all(&cd_start_32.to_le_bytes())?;
    out.write_all(&0u16.to_le_bytes())?;
    out.flush()
}

pub(super) fn write_zip_archive<W: Write>(
    _bfs: &BrowserFs,
    plan: &[ArchivePlanItem],
    writer: W,
) -> io::Result<()> {
    let mut out = CountingWriter::new(writer);
    let mut records = Vec::with_capacity(plan.len());
    let mut copy_buf = vec![0u8; IO_BUF_BYTES];

    for item in plan {
        let clean_name = validate_archive_entry_name(&item.archive_path)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("{e:?}")))?;
        let name_str = if item.is_dir {
            format!("{clean_name}/")
        } else {
            clean_name
        };
        let name_bytes = name_str.into_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "zip entry name exceeds maximum length",
            ));
        }

        let local_header_offset = out.written;

        if item.is_dir {
            let flags: u16 = 0x0800; // UTF-8 filename flag
            let method: u16 = 0; // Store
            let version_needed: u16 = if local_header_offset >= u32::MAX as u64 {
                45
            } else {
                20
            };
            out.write_all(&0x04034b50u32.to_le_bytes())?;
            out.write_all(&version_needed.to_le_bytes())?;
            out.write_all(&flags.to_le_bytes())?;
            out.write_all(&method.to_le_bytes())?;
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&0x0021u16.to_le_bytes())?;
            out.write_all(&0u32.to_le_bytes())?;
            out.write_all(&0u32.to_le_bytes())?;
            out.write_all(&0u32.to_le_bytes())?;
            out.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&name_bytes)?;

            records.push(ZipEntryRecord {
                name_bytes,
                version_needed,
                method,
                flags,
                crc32: 0,
                compressed_size: 0,
                uncompressed_size: 0,
                local_header_offset,
                external_attr: (0o40755u32 << 16) | 0x10,
            });
        } else {
            let mut file = open_planned_archive_file(item)?;
            let flags: u16 = 0x0008 | 0x0800; // Data descriptor + UTF-8
            let method: u16 = 8; // Deflate
                                 // Use ZIP64 version 4.5 + 20-byte empty ZIP64 extra field (0x0001, len 16, 0u64, 0u64)
                                 // so streaming decoders (Info-ZIP, Go archive/zip, Python zipfile, Rust zip crate)
                                 // unambiguously parse the 24-byte 64-bit Data Descriptor even for >= 4 GiB files.
            let version_needed: u16 = 45;
            let mut local_extra = [0u8; 20];
            local_extra[0..2].copy_from_slice(&0x0001u16.to_le_bytes());
            local_extra[2..4].copy_from_slice(&16u16.to_le_bytes());

            out.write_all(&0x04034b50u32.to_le_bytes())?;
            out.write_all(&version_needed.to_le_bytes())?;
            out.write_all(&flags.to_le_bytes())?;
            out.write_all(&method.to_le_bytes())?;
            out.write_all(&0u16.to_le_bytes())?;
            out.write_all(&0x0021u16.to_le_bytes())?;
            out.write_all(&0u32.to_le_bytes())?;
            out.write_all(&u32::MAX.to_le_bytes())?;
            out.write_all(&u32::MAX.to_le_bytes())?;
            out.write_all(&(name_bytes.len() as u16).to_le_bytes())?;
            out.write_all(&(local_extra.len() as u16).to_le_bytes())?;
            out.write_all(&name_bytes)?;
            out.write_all(&local_extra)?;

            let data_start = out.written;
            let mut hasher = Crc32Hasher::new();
            let mut uncompressed_size: u64 = 0;
            {
                let mut encoder = DeflateEncoder::new(&mut out, Compression::default());
                loop {
                    match file.read(&mut copy_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let slice = &copy_buf[..n];
                            hasher.update(slice);
                            uncompressed_size =
                                uncompressed_size.checked_add(n as u64).ok_or_else(|| {
                                    io::Error::new(
                                        ErrorKind::InvalidInput,
                                        "zip entry size overflow",
                                    )
                                })?;
                            encoder.write_all(slice)?;
                        }
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
                encoder.finish()?;
            }
            let data_end = out.written;
            let compressed_size = data_end.saturating_sub(data_start);
            let crc32 = hasher.finalize();

            // 64-bit Data Descriptor (signature + crc32 + 8-byte compressed + 8-byte uncompressed)
            out.write_all(&0x08074b50u32.to_le_bytes())?;
            out.write_all(&crc32.to_le_bytes())?;
            out.write_all(&compressed_size.to_le_bytes())?;
            out.write_all(&uncompressed_size.to_le_bytes())?;

            records.push(ZipEntryRecord {
                name_bytes,
                version_needed,
                method,
                flags,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset,
                external_attr: 0o100644u32 << 16,
            });
        }
    }

    write_zip_central_directory_and_eocd(&mut out, &records)
}

pub(crate) struct ChannelChunkWriter {
    tx: mpsc::Sender<Result<Bytes, io::Error>>,
    buf: Vec<u8>,
}

impl ChannelChunkWriter {
    pub(crate) fn new(tx: mpsc::Sender<Result<Bytes, io::Error>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(ARCHIVE_CHUNK_BYTES),
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let payload = Bytes::copy_from_slice(&self.buf);
        self.buf.clear();
        self.tx
            .blocking_send(Ok(payload))
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "archive stream receiver closed"))
    }
}

impl Write for ChannelChunkWriter {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        while !data.is_empty() {
            let space = ARCHIVE_CHUNK_BYTES.saturating_sub(self.buf.len());
            if space == 0 {
                self.flush_buffer()?;
                continue;
            }
            let take = space.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() >= ARCHIVE_CHUNK_BYTES {
                self.flush_buffer()?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()
    }
}

pub fn redeem_and_plan_archive_ticket_with<S, F, A>(
    store: &ArchiveTicketStore,
    raw_ticket: &str,
    auth_user: &AuthUser,
    now: Instant,
    resolve_scope: S,
    open_fs: F,
    authorize_download: A,
) -> Result<(ArchiveTicketEntry, BrowserFs, Vec<ArchivePlanItem>), McBrowserError>
where
    S: FnOnce(i64) -> Result<String, McBrowserError>,
    F: FnOnce(i64) -> Result<BrowserFs, McBrowserError>,
    A: FnMut(&str) -> Result<(), McBrowserError>,
{
    let user_id = validate_mcbrowser_user(auth_user)?;
    let live_scope = resolve_scope(user_id)?;
    let entry = store.redeem_at(raw_ticket, auth_user, &live_scope, now)?;
    let bfs = open_fs(user_id)?;
    let plan = collect_archive_plan_with_auth(&bfs, &entry.paths, authorize_download)?;
    Ok((entry, bfs, plan))
}

pub(super) async fn create_archive_ticket(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<ArchiveRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let format = match ArchiveFormat::parse(&req.format) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let normalized_selection = match normalize_archive_selection(&req.paths) {
        Ok(paths) => paths,
        Err(e) => return e.into_response(),
    };

    let Ok(permit) = Arc::clone(&ARCHIVE_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Archive concurrency limiter closed".to_string())
            .into_response();
    };
    let control = ArchivePlanningControl::new();
    let _guard = ArchivePlanningGuard(control.clone());
    let user_for_plan = auth_user;
    let res =
        tokio::task::spawn_blocking(move || -> Result<ArchiveTicketResponse, McBrowserError> {
            let _permit = permit;
            control.check()?;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal(
                    "Database unavailable for archive ticket creation".to_string(),
                )
            })?;
            let effective_scope =
                crate::mcbrowser::policy::effective_scope_with_conn(&conn, user_id)?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let _plan = collect_archive_plan_for_user_with_control_conn(
                &conn,
                &bfs,
                &user_for_plan,
                &normalized_selection,
                &control,
            )?;
            drop(conn);

            control.check()?;
            let (_ticket, resp) = ARCHIVE_TICKET_STORE.issue_at(
                &user_for_plan,
                effective_scope,
                normalized_selection,
                format,
                Instant::now(),
            )?;
            Ok(resp)
        })
        .await;

    match res {
        Ok(Ok(ticket_resp)) => {
            let mut resp = Json(ticket_resp).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Archive ticket creation task failed".to_string())
            .into_response(),
    }
}

pub(super) fn build_archive_stream_response(
    bfs: BrowserFs,
    plan: Vec<ArchivePlanItem>,
    format: ArchiveFormat,
    download_filename: String,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(ARCHIVE_CHANNEL_CAPACITY);

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let writer = ChannelChunkWriter::new(tx.clone());
        if let Err(err) = write_archive_to_writer(&bfs, &plan, format, writer) {
            let _ = tx.blocking_send(Err(err));
        }
    });

    let stream = ReceiverStream::new(rx);
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = StatusCode::OK;

    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(format.content_type()),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        build_attachment_content_disposition(&download_filename),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub(super) async fn download_archive_by_ticket(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(ticket): AxumPath<String>,
) -> Response {
    if let Err(e) = validate_mcbrowser_user(&auth_user) {
        return e.into_response();
    }

    let Ok(permit) = Arc::clone(&ARCHIVE_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Archive concurrency limiter closed".to_string())
            .into_response();
    };

    let control = ArchivePlanningControl::new();
    let _guard = ArchivePlanningGuard(control.clone());
    let user_for_redeem = auth_user;
    let prep_res = tokio::task::spawn_blocking(move || {
        control.check()?;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal(
                "Database unavailable for archive ticket redemption".to_string(),
            )
        })?;
        let prepared = redeem_and_plan_archive_ticket_with(
            &ARCHIVE_TICKET_STORE,
            &ticket,
            &user_for_redeem,
            Instant::now(),
            |uid| crate::mcbrowser::policy::effective_scope_with_conn(&conn, uid),
            |uid| open_configured_user_browser_fs_with_conn(&conn, uid),
            |path| {
                control.check()?;
                crate::mcbrowser::policy::authorize_with_conn(
                    &conn,
                    &user_for_redeem,
                    crate::mcbrowser::policy::Permission::Download,
                    path,
                )
            },
        )?;
        control.check()?;
        Ok::<_, McBrowserError>((prepared, permit))
    })
    .await;

    let ((entry, bfs, plan), permit) = match prep_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return e.into_response(),
        Err(_) => {
            return McBrowserError::Internal("Archive ticket preparation task failed".to_string())
                .into_response()
        }
    };

    build_archive_stream_response(bfs, plan, entry.format, entry.filename, permit)
}

pub(super) async fn download_archive(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<ArchiveRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let format = match ArchiveFormat::parse(&req.format) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let normalized_selection = match normalize_archive_selection(&req.paths) {
        Ok(paths) => paths,
        Err(e) => return e.into_response(),
    };

    let Ok(permit) = Arc::clone(&ARCHIVE_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Archive concurrency limiter closed".to_string())
            .into_response();
    };

    let control = ArchivePlanningControl::new();
    let _guard = ArchivePlanningGuard(control.clone());
    let user_for_plan = auth_user;
    let selection_for_plan = normalized_selection.clone();
    let prep_res = tokio::task::spawn_blocking(move || {
        control.check()?;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for archive preparation".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let plan = collect_archive_plan_for_user_with_control_conn(
            &conn,
            &bfs,
            &user_for_plan,
            &selection_for_plan,
            &control,
        )?;
        Ok::<_, McBrowserError>((bfs, plan, permit))
    })
    .await;

    let (bfs, plan, permit) = match prep_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return e.into_response(),
        Err(_) => {
            return McBrowserError::Internal("Archive preparation task failed".to_string())
                .into_response()
        }
    };

    let download_filename = compute_archive_download_filename(&normalized_selection, format);
    build_archive_stream_response(bfs, plan, format, download_filename, permit)
}

/// Safe IEEE 802.3 CRC-32 hasher backed by `flate2::Crc`.
pub(super) struct Crc32Hasher {
    crc: flate2::Crc,
}

impl Crc32Hasher {
    pub(super) fn new() -> Self {
        Self {
            crc: flate2::Crc::new(),
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.crc.update(bytes);
        }
    }

    pub(super) fn finalize(self) -> u32 {
        self.crc.sum()
    }
}
