use super::{
    build_attachment_content_disposition, check_fd_free_space, load_active_quota_conn,
    map_fs_io_error, normalize_relative_path, open_authorized_file_with_conn,
    open_configured_user_browser_fs_with_conn, release_user_quota_conn, reserve_user_quota_atomic,
    user_mutation_stripe, validate_mcbrowser_user, McBrowserError, MutationSuccessResponse,
    PathQuery,
};
use crate::auth::AuthUser;
use af_files::{BrowserFs, Entry};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Extension, Path as AxumPath, Query, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use flate2::read::GzDecoder;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

pub const MAX_SEARCH_ENTRIES: usize = 10_000;
pub const MAX_EDITOR_CONTENT_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_ARCHIVE_TICKETS: usize = 256;
pub const ARCHIVE_TICKET_TTL_SECS: u64 = 60;
pub const ARCHIVE_TICKET_TTL: Duration = Duration::from_secs(ARCHIVE_TICKET_TTL_SECS);
const CONTENT_BODY_LIMIT_BYTES: usize = (MAX_EDITOR_CONTENT_BYTES * 6) + 65_536;
const EDITOR_CONCURRENCY_LIMIT: usize = 4;
const CHECKSUM_CONCURRENCY_LIMIT: usize = 4;
const ARCHIVE_CONCURRENCY_LIMIT: usize = 4;
const ARCHIVE_CHANNEL_CAPACITY: usize = 8;
const ARCHIVE_CHUNK_BYTES: usize = 64 * 1024;
const ARCHIVE_PLANNING_TIMEOUT: Duration = Duration::from_secs(30);
const IO_BUF_BYTES: usize = 64 * 1024;

static CHECKSUM_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(CHECKSUM_CONCURRENCY_LIMIT)));

static EDITOR_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(EDITOR_CONCURRENCY_LIMIT));

static ARCHIVE_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(ARCHIVE_CONCURRENCY_LIMIT)));

static ARCHIVE_TICKET_STORE: Lazy<ArchiveTicketStore> =
    Lazy::new(|| ArchiveTicketStore::new(MAX_ARCHIVE_TICKETS, ARCHIVE_TICKET_TTL));

#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub q: String,
    #[serde(default, rename = "type")]
    pub entry_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperationConflictPolicy {
    #[default]
    Error,
    Overwrite,
    KeepBoth,
}

impl OperationConflictPolicy {
    pub fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" | "fail" | "none" => Ok(Self::Error),
            "overwrite" | "override" | "replace" => Ok(Self::Overwrite),
            "keep-both" | "keep_both" | "keepboth" | "rename" => Ok(Self::KeepBoth),
            _ => Err(McBrowserError::BadRequest(
                "Invalid conflict resolution policy: expected 'error', 'overwrite' ('override'), or 'keep-both' ('rename')".to_string(),
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Overwrite => "overwrite",
            Self::KeepBoth => "keep-both",
        }
    }
}

impl Serialize for OperationConflictPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OperationConflictPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|error| {
            serde::de::Error::custom(match error {
                McBrowserError::BadRequest(message) => message,
                other => format!("{other:?}"),
            })
        })
    }
}

pub fn resolve_operation_conflict_policy(
    conflict: Option<OperationConflictPolicy>,
    overwrite_flag: Option<bool>,
    rename_flag: Option<bool>,
) -> Result<OperationConflictPolicy, McBrowserError> {
    if overwrite_flag == Some(true) && rename_flag == Some(true) {
        return Err(McBrowserError::BadRequest(
            "Conflict options 'overwrite' and 'rename' ('keep-both') cannot both be true"
                .to_string(),
        ));
    }

    let flag_derived = if overwrite_flag == Some(true) {
        Some(OperationConflictPolicy::Overwrite)
    } else if rename_flag == Some(true) {
        Some(OperationConflictPolicy::KeepBoth)
    } else if overwrite_flag == Some(false) || rename_flag == Some(false) {
        Some(OperationConflictPolicy::Error)
    } else {
        None
    };

    match (conflict, flag_derived) {
        (Some(explicit), Some(derived)) if explicit != derived => {
            if explicit != OperationConflictPolicy::Error
                && overwrite_flag != Some(true)
                && rename_flag != Some(true)
            {
                Err(McBrowserError::BadRequest(
                    "Conflicting conflict policy and boolean override/rename flags".to_string(),
                ))
            } else {
                Err(McBrowserError::BadRequest(
                    "Conflicting conflict policy and boolean override/rename flags".to_string(),
                ))
            }
        }
        (Some(explicit), _) => Ok(explicit),
        (None, Some(derived)) => Ok(derived),
        (None, None) => Ok(OperationConflictPolicy::Error),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CopyRequest {
    pub from: String,
    pub to: String,
    #[serde(default, alias = "policy", alias = "on_conflict", alias = "onConflict")]
    pub conflict: Option<OperationConflictPolicy>,
    #[serde(default, rename = "override", alias = "overwrite", alias = "replace")]
    pub overwrite_existing: Option<bool>,
    #[serde(default, alias = "keep_both", alias = "keepBoth")]
    pub rename: Option<bool>,
}

impl CopyRequest {
    pub fn resolved_conflict_policy(&self) -> Result<OperationConflictPolicy, McBrowserError> {
        resolve_operation_conflict_policy(self.conflict, self.overwrite_existing, self.rename)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RenameMoveRequest {
    pub from: String,
    pub to: String,
    #[serde(default, alias = "policy", alias = "on_conflict", alias = "onConflict")]
    pub conflict: Option<OperationConflictPolicy>,
    #[serde(default, rename = "override", alias = "overwrite", alias = "replace")]
    pub overwrite_existing: Option<bool>,
    #[serde(default, alias = "keep_both", alias = "keepBoth")]
    pub rename: Option<bool>,
}

impl RenameMoveRequest {
    pub(super) fn resolved_conflict_policy(
        &self,
    ) -> Result<OperationConflictPolicy, McBrowserError> {
        resolve_operation_conflict_policy(self.conflict, self.overwrite_existing, self.rename)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyMoveResponse {
    pub success: bool,
    pub path: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub accounting_pending: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRecursiveRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ContentResponse {
    pub path: String,
    pub content: String,
    pub etag: String,
}

#[derive(Debug, Deserialize)]
pub struct PutContentRequest {
    pub content: String,
    pub etag: String,
}

#[derive(Debug, Serialize)]
pub struct PutContentResponse {
    pub success: bool,
    pub etag: String,
    pub accounting_pending: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateFileRequest {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct InfoQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResponse {
    pub entry: Entry,
    pub checksums: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_dirs: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ArchiveRequest {
    pub paths: Vec<String>,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveTicketResponse {
    pub url: String,
    pub filename: String,
}

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

    #[allow(dead_code)]
    pub fn prune_expired_at(&self, now: Instant) -> usize {
        let mut guard = match self.entries.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|_, v| v.expires_at > now);
        guard.len()
    }

    #[allow(dead_code)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKindFilter {
    Any,
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl ChecksumAlgorithm {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarLz4,
    TarSz,
    TarBr,
    TarZst,
}

impl ArchiveFormat {
    #[allow(dead_code)]
    pub const ALL: [ArchiveFormat; 9] = [
        Self::Zip,
        Self::Tar,
        Self::TarGz,
        Self::TarBz2,
        Self::TarXz,
        Self::TarLz4,
        Self::TarSz,
        Self::TarBr,
        Self::TarZst,
    ];

    pub fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "zip" | ".zip" => Ok(Self::Zip),
            "tar" | ".tar" => Ok(Self::Tar),
            "targz" | "tar.gz" | ".tar.gz" | "tgz" => Ok(Self::TarGz),
            "tarbz2" | "tar.bz2" | ".tar.bz2" | "tbz2" => Ok(Self::TarBz2),
            "tarxz" | "tar.xz" | ".tar.xz" | "txz" => Ok(Self::TarXz),
            "tarlz4" | "tar.lz4" | ".tar.lz4" | "tlz4" => Ok(Self::TarLz4),
            "tarsz" | "tar.sz" | ".tar.sz" | "tsz" => Ok(Self::TarSz),
            "tarbr" | "tar.br" | ".tar.br" | "tbr" => Ok(Self::TarBr),
            "tarzst" | "tar.zst" | ".tar.zst" | "tzst" => Ok(Self::TarZst),
            _ => Err(McBrowserError::BadRequest(
                "Invalid archive format: expected one of 'zip', 'tar', 'targz' ('tar.gz'), 'tarbz2' ('tar.bz2'), 'tarxz' ('tar.xz'), 'tarlz4' ('tar.lz4'), 'tarsz' ('tar.sz'), 'tarbr' ('tar.br'), or 'tarzst' ('tar.zst')".to_string(),
            )),
        }
    }

    #[allow(dead_code)]
    pub fn algo_id(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "targz",
            Self::TarBz2 => "tarbz2",
            Self::TarXz => "tarxz",
            Self::TarLz4 => "tarlz4",
            Self::TarSz => "tarsz",
            Self::TarBr => "tarbr",
            Self::TarZst => "tarzst",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
            Self::TarLz4 => "tar.lz4",
            Self::TarSz => "tar.sz",
            Self::TarBr => "tar.br",
            Self::TarZst => "tar.zst",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            Self::Tar => "application/x-tar",
            Self::TarGz => "application/gzip",
            Self::TarBz2 => "application/x-bzip2",
            Self::TarXz => "application/x-xz",
            Self::TarLz4 => "application/x-lz4",
            Self::TarSz => "application/x-snappy-framed",
            Self::TarBr => "application/x-brotli",
            Self::TarZst => "application/zstd",
        }
    }
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

struct ArchiveSourceReader {
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
        let count = std::os::unix::fs::FileExt::read_at(
            &*self.file,
            &mut buffer[..maximum],
            self.offset,
        )?;
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

enum ArchiveWalkStep {
    Visit(String),
    Leave(String),
}

#[derive(Clone)]
struct ArchivePlanningControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl ArchivePlanningControl {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + ARCHIVE_PLANNING_TIMEOUT,
        }
    }

    fn check(&self) -> Result<(), McBrowserError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(McBrowserError::RequestTimeout("Archive request cancelled".to_string()));
        }
        if Instant::now() >= self.deadline {
            return Err(McBrowserError::RequestTimeout("Archive planning deadline exceeded".to_string()));
        }
        Ok(())
    }
}

struct ArchivePlanningGuard(ArchivePlanningControl);

impl Drop for ArchivePlanningGuard {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

async fn limit_editor_requests(request: Request, next: Next) -> Response {
    let Ok(_permit) = EDITOR_SEMAPHORE.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::RETRY_AFTER, "1"),
            ],
            Json(serde_json::json!({
                "code": "EDITOR_BUSY",
                "message": "Editor capacity is busy; retry shortly"
            })),
        )
            .into_response();
    };
    next.run(request).await
}

pub fn router() -> Router {
    let content_routes = Router::new()
        .route("/mcbrowser/content", get(get_content).put(put_content))
        .route("/mcbrowser/file", post(create_file))
        .layer(DefaultBodyLimit::max(CONTENT_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(limit_editor_requests));

    Router::new()
        .route("/mcbrowser/search", get(search_entries))
        .route("/mcbrowser/copy", post(copy_entry))
        .route("/mcbrowser/delete-recursive", post(delete_recursive))
        .route("/mcbrowser/info", get(get_entry_info))
        .route("/mcbrowser/archive", post(download_archive))
        .route("/mcbrowser/archive-ticket", post(create_archive_ticket))
        .route(
            "/mcbrowser/archive/:ticket",
            get(download_archive_by_ticket),
        )
        .merge(content_routes)
}

pub fn parse_search_type_filter(raw: Option<&str>) -> Result<SearchKindFilter, McBrowserError> {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(SearchKindFilter::Any);
    };
    if val.eq_ignore_ascii_case("file") {
        Ok(SearchKindFilter::File)
    } else if val.eq_ignore_ascii_case("directory") {
        Ok(SearchKindFilter::Directory)
    } else {
        Err(McBrowserError::BadRequest(
            "Invalid search type filter: must be 'file' or 'directory'".to_string(),
        ))
    }
}

pub fn filter_walked_entries(
    walked: Vec<Entry>,
    query: &str,
    kind_filter: SearchKindFilter,
    max_entries: usize,
) -> SearchResponse {
    let truncated = walked.len() > max_entries;
    let parsed_query = super::search_query::SearchQuery::parse(query);

    let entries = walked
        .into_iter()
        .take(max_entries)
        .filter(|entry| {
            let kind_ok = match kind_filter {
                SearchKindFilter::Any => entry.kind == "file" || entry.kind == "directory",
                SearchKindFilter::File => entry.kind == "file",
                SearchKindFilter::Directory => entry.kind == "directory",
            };
            if !kind_ok {
                return false;
            }
            parsed_query.matches(&entry.name)
        })
        .collect();

    SearchResponse { entries, truncated }
}

pub fn compute_etag_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("\"{}\"", hex::encode(digest))
}

pub fn etag_matches(expected: &str, current: &str) -> bool {
    let clean_expected = expected
        .trim()
        .strip_prefix("W/")
        .unwrap_or_else(|| expected.trim())
        .trim_matches('"');
    let clean_current = current
        .trim()
        .strip_prefix("W/")
        .unwrap_or_else(|| current.trim())
        .trim_matches('"');
    !clean_expected.is_empty() && clean_expected.eq_ignore_ascii_case(clean_current)
}

pub fn read_utf8_editor_content_from_file(
    mut file: File,
    normalized_path: String,
) -> Result<(ContentResponse, File), McBrowserError> {
    let meta = file
        .metadata()
        .map_err(|_| McBrowserError::Internal("Failed to inspect file metadata".to_string()))?;
    if meta.len() > MAX_EDITOR_CONTENT_BYTES as u64 {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }

    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_EDITOR_CONTENT_BYTES));
    let mut chunk = [0u8; 8192];
    let max_read = MAX_EDITOR_CONTENT_BYTES + 1;

    while buf.len() < max_read {
        let to_read = (max_read - buf.len()).min(chunk.len());
        match file.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_fs_io_error(e, "Failed to read file content")),
        }
    }

    if buf.len() > MAX_EDITOR_CONTENT_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }

    if buf.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Content editor only supports valid UTF-8 text files (binary content detected)"
                .to_string(),
        ));
    }

    let text = std::str::from_utf8(&buf).map_err(|_| {
        McBrowserError::BadRequest(
            "Content editor only supports valid UTF-8 text files".to_string(),
        )
    })?;

    let etag = compute_etag_bytes(&buf);
    Ok((
        ContentResponse {
            path: normalized_path,
            content: text.to_string(),
            etag,
        },
        file,
    ))
}

pub fn validate_editor_write_payload(content: &str) -> Result<&[u8], McBrowserError> {
    let bytes = content.as_bytes();
    if bytes.len() > MAX_EDITOR_CONTENT_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Content exceeds maximum editable size of {MAX_EDITOR_CONTENT_BYTES} bytes (10 MiB)"
        )));
    }
    if bytes.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Content must not contain NUL bytes".to_string(),
        ));
    }
    Ok(bytes)
}

pub fn parse_checksum_algorithms(
    raw: Option<&str>,
) -> Result<Vec<ChecksumAlgorithm>, McBrowserError> {
    let Some(spec) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for part in spec.split(',') {
        let token = part.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        let alg = match token.as_str() {
            "md5" => ChecksumAlgorithm::Md5,
            "sha1" => ChecksumAlgorithm::Sha1,
            "sha256" => ChecksumAlgorithm::Sha256,
            "sha512" => ChecksumAlgorithm::Sha512,
            _ => {
                return Err(McBrowserError::BadRequest(format!(
                    "Unsupported checksum algorithm '{token}': allowed values are md5, sha1, sha256, sha512"
                )))
            }
        };
        if !out.contains(&alg) {
            out.push(alg);
        }
    }
    Ok(out)
}

pub fn compute_checksums_from_reader<R: Read>(
    mut reader: R,
    algorithms: &[ChecksumAlgorithm],
) -> io::Result<BTreeMap<String, String>> {
    if algorithms.is_empty() {
        return Ok(BTreeMap::new());
    }

    let want_md5 = algorithms.contains(&ChecksumAlgorithm::Md5);
    let want_sha1 = algorithms.contains(&ChecksumAlgorithm::Sha1);
    let want_sha256 = algorithms.contains(&ChecksumAlgorithm::Sha256);
    let want_sha512 = algorithms.contains(&ChecksumAlgorithm::Sha512);

    let mut md5_state = want_md5.then(Md5Hasher::new);
    let mut sha1_state = want_sha1.then(Sha1::new);
    let mut sha256_state = want_sha256.then(Sha256::new);
    let mut sha512_state = want_sha512.then(Sha512::new);

    let mut buf = vec![0u8; IO_BUF_BYTES];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &buf[..n];
                if let Some(h) = md5_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha1_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha256_state.as_mut() {
                    h.update(slice);
                }
                if let Some(h) = sha512_state.as_mut() {
                    h.update(slice);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let mut map = BTreeMap::new();
    if let Some(h) = md5_state {
        map.insert("md5".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha1_state {
        map.insert("sha1".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha256_state {
        map.insert("sha256".to_string(), hex::encode(h.finalize()));
    }
    if let Some(h) = sha512_state {
        map.insert("sha512".to_string(), hex::encode(h.finalize()));
    }
    Ok(map)
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
    collect_archive_plan_with_control(bfs, selected_paths, &ArchivePlanningControl::new(), authorize_download)
}

fn collect_archive_plan_with_control<F>(
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
        for authorized_path in archive_authorization_paths(
            &path,
            &resolved.resolution_paths,
            &resolved.resolved_path,
        ) {
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

fn archive_authorization_paths(path: &str, trace: &[String], resolved_path: &str) -> Vec<String> {
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

fn open_planned_archive_file(item: &ArchivePlanItem) -> io::Result<ArchiveSourceReader> {
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

#[allow(dead_code)]
pub fn collect_archive_plan_for_user(
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    selected_paths: &[String],
) -> Result<Vec<ArchivePlanItem>, McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for archive authorization".to_string())
    })?;
    collect_archive_plan_for_user_with_conn(&conn, bfs, auth_user, selected_paths)
}

pub fn collect_archive_plan_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    selected_paths: &[String],
) -> Result<Vec<ArchivePlanItem>, McBrowserError> {
    collect_archive_plan_for_user_with_control_conn(conn, bfs, auth_user, selected_paths, &ArchivePlanningControl::new())
}

fn collect_archive_plan_for_user_with_control_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    selected_paths: &[String],
    control: &ArchivePlanningControl,
) -> Result<Vec<ArchivePlanItem>, McBrowserError> {
    collect_archive_plan_with_control(bfs, selected_paths, control, |path| {
        control.check()?;
        super::policy::authorize_with_conn(
            conn,
            auth_user,
            super::policy::Permission::Read,
            path,
        )?;
        super::policy::authorize_with_conn(
            conn,
            auth_user,
            super::policy::Permission::Download,
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

#[allow(dead_code)]
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

fn write_tar_archive<W: Write>(
    bfs: &BrowserFs,
    plan: &[ArchivePlanItem],
    writer: W,
) -> io::Result<()> {
    let mut builder = tar::Builder::new(writer);
    append_tar_items(bfs, plan, &mut builder)?;
    let mut inner = builder.into_inner()?;
    inner.flush()
}

fn append_tar_items<W: Write>(
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

fn write_zip_archive<W: Write>(
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

pub fn execute_create_file_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    content: Option<&str>,
    user_id: i64,
) -> Result<(), McBrowserError> {
    let payload_bytes = match content {
        Some(text) => validate_editor_write_payload(text)?,
        None => &[],
    };
    let byte_len = payload_bytes.len() as u64;

    load_active_quota_conn(conn, user_id, byte_len)?;

    let mut pending = bfs
        .begin_upload(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to create file"))?;
    let std_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to prepare file handle"))?;
    check_fd_free_space(std_file.as_raw_fd(), byte_len.max(1))?;

    if !payload_bytes.is_empty() {
        pending
            .write_all(payload_bytes)
            .map_err(|e| map_fs_io_error(e, "Failed to write file content"))?;
        pending
            .flush()
            .map_err(|e| map_fs_io_error(e, "Failed to flush file content"))?;
    }

    if byte_len > 0 {
        reserve_user_quota_atomic(conn, user_id, byte_len)?;
    }

    if let Err(commit_err) = pending.commit() {
        if byte_len > 0 {
            release_user_quota_conn(conn, user_id, byte_len).map_err(|_| {
                McBrowserError::AccountingPending(
                    "File was not created; reserved quota requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(map_fs_io_error(commit_err, "Failed to finalize new file"));
    }

    Ok(())
}

fn execute_put_content_with_loaded_target_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    resolved_target_path: &str,
    current_doc: &ContentResponse,
    expected_file: &File,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let new_bytes = validate_editor_write_payload(content)?;
    let new_size = new_bytes.len() as u64;
    let old_size = current_doc.content.len() as u64;

    if !etag_matches(expected_etag, &current_doc.etag) {
        return Err(McBrowserError::Conflict(
            "File content was modified by another request (ETag mismatch)".to_string(),
        ));
    }

    let additional_needed = new_size.saturating_sub(old_size);
    load_active_quota_conn(conn, user_id, additional_needed)?;

    let mut pending = bfs
        .begin_replace(resolved_target_path)
        .map_err(|e| map_fs_io_error(e, "Failed to stage content update"))?;
    let std_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to access staging file"))?;
    check_fd_free_space(std_file.as_raw_fd(), new_size.max(1))?;

    if !new_bytes.is_empty() {
        pending
            .write_all(new_bytes)
            .map_err(|e| map_fs_io_error(e, "Failed to write updated content"))?;
        pending
            .flush()
            .map_err(|e| map_fs_io_error(e, "Failed to flush updated content"))?;
    }

    if additional_needed > 0 {
        reserve_user_quota_atomic(conn, user_id, additional_needed)?;
    }

    if let Err(commit_err) = pending.commit_replace(expected_file) {
        if additional_needed > 0 {
            release_user_quota_conn(conn, user_id, additional_needed).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Content was not saved; reserved quota requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(match commit_err.kind() {
            ErrorKind::AlreadyExists | ErrorKind::InvalidInput | ErrorKind::NotFound => {
                McBrowserError::Conflict(
                    "Target file changed concurrently during content update".to_string(),
                )
            }
            _ => map_fs_io_error(commit_err, "Failed to commit content update"),
        });
    }

    let released_bytes = old_size.saturating_sub(new_size);
    let accounting_pending = release_user_quota_conn(conn, user_id, released_bytes).is_err();

    let byte_delta =
        (new_size.min(i64::MAX as u64) as i64).saturating_sub(old_size.min(i64::MAX as u64) as i64);

    Ok((
        PutContentResponse {
            success: true,
            etag: compute_etag_bytes(new_bytes),
            accounting_pending,
        },
        byte_delta,
    ))
}

fn execute_put_content_for_pinned_target_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    resolved_target_path: &str,
    existing_file: File,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let _ = validate_editor_write_payload(content)?;

    let (current_doc, expected_file) =
        read_utf8_editor_content_from_file(existing_file, resolved_target_path.to_string())?;

    execute_put_content_with_loaded_target_conn(
        conn,
        bfs,
        resolved_target_path,
        &current_doc,
        &expected_file,
        content,
        expected_etag,
        user_id,
    )
}

pub fn execute_put_content_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    content: &str,
    expected_etag: &str,
    user_id: i64,
) -> Result<PutContentResponse, McBrowserError> {
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }

    let _ = validate_editor_write_payload(content)?;

    let existing_file = bfs
        .open_file(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to open existing file for update"))?;

    execute_put_content_for_pinned_target_conn(
        conn,
        bfs,
        normalized_path,
        existing_file,
        content,
        expected_etag,
        user_id,
    )
    .map(|(response, _)| response)
}

pub fn execute_get_content_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    path: &str,
) -> Result<ContentResponse, McBrowserError> {
    let normalized_path = super::policy::normalize_target_path(path, false)?;
    let file = open_authorized_file_with_conn(
        conn,
        auth_user,
        bfs,
        &normalized_path,
        super::policy::Permission::Read,
    )?;
    let (doc, _) = read_utf8_editor_content_from_file(file, normalized_path)?;
    Ok(doc)
}

fn open_authorized_file_for_put_content_with_conn(
    conn: &rusqlite::Connection,
    auth_user: &AuthUser,
    bfs: &BrowserFs,
    normalized_path: &str,
) -> Result<(File, String), McBrowserError> {
    super::policy::authorize_with_conn(
        conn,
        auth_user,
        super::policy::Permission::Modify,
        normalized_path,
    )?;
    match bfs.open_file(normalized_path) {
        Ok(file) => Ok((file, normalized_path.to_string())),
        Err(_) => {
            let resolved = bfs
                .open_file_resolving_internal_links(normalized_path)
                .map_err(|error| {
                    map_fs_io_error(error, "Failed to open existing file for update")
                })?;
            for resolution_path in &resolved.resolution_paths {
                super::policy::authorize_with_conn(
                    conn,
                    auth_user,
                    super::policy::Permission::Modify,
                    resolution_path,
                )?;
            }
            super::policy::authorize_with_conn(
                conn,
                auth_user,
                super::policy::Permission::Modify,
                &resolved.resolved_path,
            )?;
            Ok((resolved.file, resolved.resolved_path))
        }
    }
}

pub fn execute_put_content_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    path: &str,
    content: &str,
    expected_etag: &str,
) -> Result<(PutContentResponse, i64), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_path = super::policy::normalize_target_path(path, false)?;
    if expected_etag.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        ));
    }
    let _ = validate_editor_write_payload(content)?;

    let (existing_file, resolved_target_path) =
        open_authorized_file_for_put_content_with_conn(conn, auth_user, bfs, &normalized_path)?;

    execute_put_content_for_pinned_target_conn(
        conn,
        bfs,
        &resolved_target_path,
        existing_file,
        content,
        expected_etag,
        user_id,
    )
}

const MAX_VERSION_SUFFIX_ATTEMPTS: usize = 10_000;

pub fn split_version_suffix_stem_and_ext(leaf_name: &str) -> (&str, &str) {
    match leaf_name.rfind('.') {
        Some(dot_index) => (&leaf_name[..dot_index], &leaf_name[dot_index..]),
        None => (leaf_name, ""),
    }
}

pub fn format_version_suffix_candidate(normalized_path: &str, version_index: usize) -> String {
    let (parent_prefix, leaf_name) = match normalized_path.rsplit_once('/') {
        Some((parent, leaf)) => (Some(parent), leaf),
        None => (None, normalized_path),
    };
    let (stem, extension) = split_version_suffix_stem_and_ext(leaf_name);
    let suffixed_leaf = format!("{stem}({version_index}){extension}");
    match parent_prefix {
        Some(parent) if !parent.is_empty() => format!("{parent}/{suffixed_leaf}"),
        _ => suffixed_leaf,
    }
}

pub fn allocate_version_suffix_path(
    bfs: &BrowserFs,
    base_path: &str,
    start_index: usize,
) -> Result<(String, usize), McBrowserError> {
    let normalized_base = normalize_relative_path(base_path, false)?;
    let initial_index = start_index.max(1);
    for offset in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
        let candidate_index = initial_index.saturating_add(offset);
        let candidate_path = format_version_suffix_candidate(&normalized_base, candidate_index);
        let validated_candidate = super::policy::normalize_target_path(&candidate_path, false)?;
        match bfs.metadata(&validated_candidate) {
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok((validated_candidate, candidate_index));
            }
            Err(error) => {
                return Err(map_fs_io_error(
                    error,
                    "Failed to inspect versioned destination candidate",
                ));
            }
        }
    }
    Err(McBrowserError::Conflict(
        "Failed to allocate a unique versioned destination filename".to_string(),
    ))
}

fn validate_distinct_non_nested_paths(
    from_path: &str,
    to_path: &str,
    action_verb: &str,
) -> Result<String, McBrowserError> {
    if from_path == to_path {
        return Err(McBrowserError::BadRequest(
            "Source and destination paths must be different".to_string(),
        ));
    }
    let from_prefix = format!("{from_path}/");
    if to_path.starts_with(&from_prefix) {
        return Err(McBrowserError::BadRequest(format!(
            "Cannot {action_verb} a directory into itself"
        )));
    }
    Ok(from_prefix)
}

fn validate_conflict_destination(
    from_path: &str,
    to_path: &str,
    action_verb: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    if from_path == to_path && conflict_policy == OperationConflictPolicy::KeepBoth {
        return Ok(format!("{from_path}/"));
    }
    validate_distinct_non_nested_paths(from_path, to_path, action_verb)
}

#[allow(dead_code)]
fn copy_single_file_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_path: &str,
    destination_path: &str,
    expected_bytes: u64,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    match bfs.copy(source_path, destination_path) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(map_fs_io_error(copy_err, "Failed to copy entry"))
        }
    }
}

#[allow(dead_code)]
fn copy_single_file_overwrite_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_path: &str,
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    let mut source_file = bfs
        .open_file(source_path)
        .map_err(|error| map_fs_io_error(error, "Failed to open source file for copy"))?;
    let source_meta = source_file
        .metadata()
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source file for copy"))?;
    let source_size = source_meta.len();

    let expected_target = bfs.open_file(destination_path).map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to open existing destination file for overwrite",
        )
    })?;
    let target_meta = expected_target.metadata().map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to inspect existing destination file for overwrite",
        )
    })?;
    let old_size = target_meta.len();

    let additional_needed = source_size.saturating_sub(old_size);
    load_active_quota_conn(conn, user_id, additional_needed)?;

    let mut pending = bfs
        .begin_replace(destination_path)
        .map_err(|error| map_fs_io_error(error, "Failed to stage file copy overwrite"))?;
    let staging_file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to access staging file for copy"))?;
    check_fd_free_space(staging_file.as_raw_fd(), source_size.max(1))?;

    let copied_bytes = io::copy(&mut source_file, &mut pending)
        .map_err(|error| map_fs_io_error(error, "Failed to copy file content"))?;
    pending
        .flush()
        .map_err(|error| map_fs_io_error(error, "Failed to flush copied file content"))?;

    let actual_additional = copied_bytes.saturating_sub(old_size);
    if actual_additional > 0 {
        reserve_user_quota_atomic(conn, user_id, actual_additional)?;
    }

    if let Err(commit_err) = pending.commit_replace(&expected_target) {
        if actual_additional > 0 {
            release_user_quota_conn(conn, user_id, actual_additional).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy was not published; quota cleanup requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(match commit_err.kind() {
            ErrorKind::AlreadyExists | ErrorKind::InvalidInput | ErrorKind::NotFound => {
                McBrowserError::Conflict(
                    "Destination file changed concurrently during copy overwrite".to_string(),
                )
            }
            _ => map_fs_io_error(commit_err, "Failed to commit file copy overwrite"),
        });
    }

    let released_bytes = old_size.saturating_sub(copied_bytes);
    if released_bytes > 0 {
        *accounting_complete &= release_user_quota_conn(conn, user_id, released_bytes).is_ok();
    }

    Ok(())
}

fn move_single_file_overwrite_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_path: &str,
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, 0)?;
    let expected_target = bfs.open_file(destination_path).map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to open existing destination file for rename overwrite",
        )
    })?;
    let replaced_bytes = bfs
        .replace_file_by_rename(source_path, destination_path, &expected_target)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => McBrowserError::Conflict(
                "Destination file changed concurrently during rename overwrite".to_string(),
            ),
            _ => map_fs_io_error(error, "Failed to overwrite destination file by rename"),
        })?;
    if replaced_bytes > 0 {
        *accounting_complete &= release_user_quota_conn(conn, user_id, replaced_bytes).is_ok();
    }
    Ok(())
}

const MAX_COPY_DIRECTORY_DEPTH: usize = 64;

enum PlannedCopyDescendant {
    Directory {
        rel_suffix: String,
    },
    File {
        rel_suffix: String,
        file: File,
        size: u64,
    },
}

impl PlannedCopyDescendant {
    fn rel_suffix(&self) -> &str {
        match self {
            Self::Directory { rel_suffix } | Self::File { rel_suffix, .. } => rel_suffix,
        }
    }

    fn kind_str(&self) -> &'static str {
        match self {
            Self::Directory { .. } => "directory",
            Self::File { .. } => "file",
        }
    }
}

enum CopySourcePlan {
    File {
        file: File,
        size: u64,
        resolved_path: String,
    },
    Directory {
        resolved_directory_paths: Vec<String>,
        descendants: Vec<PlannedCopyDescendant>,
    },
}

impl CopySourcePlan {
    fn kind_str(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Directory { .. } => "directory",
        }
    }
}

fn push_unique_copy_hop(hops: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !hops.iter().any(|existing| existing == candidate) {
        hops.push(candidate.to_string());
    }
}

fn authorize_copy_permission_if_user(
    conn: &rusqlite::Connection,
    auth_user: Option<&AuthUser>,
    permission: super::policy::Permission,
    target_path: &str,
) -> Result<(), McBrowserError> {
    if let Some(user) = auth_user {
        super::policy::authorize_with_conn(conn, user, permission, target_path)?;
    }
    Ok(())
}

fn verify_pinned_copy_source_metadata(source_file: &File) -> Result<std::fs::Metadata, McBrowserError> {
    let source_meta = source_file
        .metadata()
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source file for copy"))?;
    if std::os::unix::fs::MetadataExt::nlink(&source_meta) > 1 {
        return Err(McBrowserError::Forbidden(
            "Hardlinked copy sources are not permitted".to_string(),
        ));
    }
    Ok(source_meta)
}

fn stage_and_commit_pinned_file_new(
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    expected_bytes: u64,
) -> Result<u64, McBrowserError> {
    let _ = verify_pinned_copy_source_metadata(source_file)?;
    std::io::Seek::seek(source_file, std::io::SeekFrom::Start(0))
        .map_err(|error| map_fs_io_error(error, "Failed to rewind source file for copy"))?;
    let mut pending = bfs
        .begin_upload(destination_path)
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    let staging_file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to access staging file for copy"))?;
    check_fd_free_space(staging_file.as_raw_fd(), expected_bytes.max(1))?;
    let actual_bytes = io::copy(source_file, &mut pending)
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    pending
        .flush()
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    pending
        .commit()
        .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
    Ok(actual_bytes)
}

fn copy_pinned_file_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    expected_bytes: u64,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    match stage_and_commit_pinned_file_new(bfs, source_file, destination_path, expected_bytes) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(copy_err)
        }
    }
}

fn copy_pinned_file_overwrite_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    source_file: &mut File,
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    let source_meta = verify_pinned_copy_source_metadata(source_file)?;
    std::io::Seek::seek(source_file, std::io::SeekFrom::Start(0))
        .map_err(|error| map_fs_io_error(error, "Failed to rewind source file for copy"))?;
    let source_size = source_meta.len();

    let expected_target = bfs.open_file(destination_path).map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to open existing destination file for overwrite",
        )
    })?;
    let target_meta = expected_target.metadata().map_err(|error| {
        map_fs_io_error(
            error,
            "Failed to inspect existing destination file for overwrite",
        )
    })?;
    let old_size = target_meta.len();

    let additional_needed = source_size.saturating_sub(old_size);
    load_active_quota_conn(conn, user_id, additional_needed)?;

    let mut pending = bfs
        .begin_replace(destination_path)
        .map_err(|error| map_fs_io_error(error, "Failed to stage file copy overwrite"))?;
    let staging_file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to access staging file for copy"))?;
    check_fd_free_space(staging_file.as_raw_fd(), source_size.max(1))?;

    let copied_bytes = io::copy(source_file, &mut pending)
        .map_err(|error| map_fs_io_error(error, "Failed to copy file content"))?;
    pending
        .flush()
        .map_err(|error| map_fs_io_error(error, "Failed to flush copied file content"))?;

    let actual_additional = copied_bytes.saturating_sub(old_size);
    if actual_additional > 0 {
        reserve_user_quota_atomic(conn, user_id, actual_additional)?;
    }

    if let Err(commit_err) = pending.commit_replace(&expected_target) {
        if actual_additional > 0 {
            release_user_quota_conn(conn, user_id, actual_additional).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy was not published; quota cleanup requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(match commit_err.kind() {
            ErrorKind::AlreadyExists | ErrorKind::InvalidInput | ErrorKind::NotFound => {
                McBrowserError::Conflict(
                    "Destination file changed concurrently during copy overwrite".to_string(),
                )
            }
            _ => map_fs_io_error(commit_err, "Failed to commit file copy overwrite"),
        });
    }

    let released_bytes = old_size.saturating_sub(copied_bytes);
    if released_bytes > 0 {
        *accounting_complete &= release_user_quota_conn(conn, user_id, released_bytes).is_ok();
    }

    Ok(())
}

fn populate_planned_directory_tree(
    bfs: &BrowserFs,
    descendants: &mut [PlannedCopyDescendant],
    destination_path: &str,
) -> Result<u64, McBrowserError> {
    let mut actual_bytes = 0u64;
    for descendant in descendants.iter_mut() {
        match descendant {
            PlannedCopyDescendant::Directory { rel_suffix } => {
                let dst_child_path = format!("{destination_path}/{rel_suffix}");
                bfs.create_directory(&dst_child_path)
                    .map_err(|error| map_fs_io_error(error, "Failed to copy entry"))?;
            }
            PlannedCopyDescendant::File {
                rel_suffix,
                file,
                size,
            } => {
                let dst_child_path = format!("{destination_path}/{rel_suffix}");
                let copied_file_bytes =
                    stage_and_commit_pinned_file_new(bfs, file, &dst_child_path, *size)?;
                actual_bytes = actual_bytes.saturating_add(copied_file_bytes);
            }
        }
    }
    Ok(actual_bytes)
}

fn copy_planned_directory_new_with_quota(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    descendants: &mut [PlannedCopyDescendant],
    destination_path: &str,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<(), McBrowserError> {
    let expected_bytes: u64 = descendants
        .iter()
        .fold(0u64, |acc, item| match item {
            PlannedCopyDescendant::Directory { .. } => acc,
            PlannedCopyDescendant::File { size, .. } => acc.saturating_add(*size),
        });

    load_active_quota_conn(conn, user_id, expected_bytes)?;
    if expected_bytes > 0 {
        reserve_user_quota_atomic(conn, user_id, expected_bytes)?;
    }

    if let Err(create_err) = bfs.create_directory(destination_path) {
        if expected_bytes > 0 {
            release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy quota cleanup requires reconciliation".to_string(),
                )
            })?;
        }
        return Err(map_fs_io_error(create_err, "Failed to copy entry"));
    }

    match populate_planned_directory_tree(bfs, descendants, destination_path) {
        Ok(actual_bytes) => {
            if actual_bytes > expected_bytes {
                let extra_bytes = actual_bytes - expected_bytes;
                if let Err(quota_err) = reserve_user_quota_atomic(conn, user_id, extra_bytes) {
                    bfs.remove_tree_with_size(destination_path).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Copy cleanup requires reconciliation".to_string(),
                        )
                    })?;
                    if expected_bytes > 0 {
                        release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                            McBrowserError::AccountingPending(
                                "Copy quota cleanup requires reconciliation".to_string(),
                            )
                        })?;
                    }
                    return Err(quota_err);
                }
            } else if expected_bytes > actual_bytes {
                let excess_bytes = expected_bytes - actual_bytes;
                *accounting_complete &=
                    release_user_quota_conn(conn, user_id, excess_bytes).is_ok();
            }
            Ok(())
        }
        Err(copy_err) => {
            bfs.remove_tree_with_size(destination_path).map_err(|_| {
                McBrowserError::AccountingPending(
                    "Copy cleanup requires reconciliation".to_string(),
                )
            })?;
            if expected_bytes > 0 {
                release_user_quota_conn(conn, user_id, expected_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Copy quota cleanup requires reconciliation".to_string(),
                    )
                })?;
            }
            Err(copy_err)
        }
    }
}

fn collect_copy_directory_descendants(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: Option<&AuthUser>,
    from_prefix: &str,
    alias_dir_path: &str,
    inherited_hops: &[String],
    depth: usize,
    active_resolved_dirs: &mut Vec<String>,
    resolved_directory_paths: &mut Vec<String>,
    descendants: &mut Vec<PlannedCopyDescendant>,
) -> Result<(), McBrowserError> {
    if depth > MAX_COPY_DIRECTORY_DEPTH {
        return Err(McBrowserError::BadRequest(
            "Path exceeds maximum directory depth".to_string(),
        ));
    }

    authorize_copy_permission_if_user(
        conn,
        auth_user,
        super::policy::Permission::Read,
        alias_dir_path,
    )?;
    for hop in inherited_hops {
        authorize_copy_permission_if_user(conn, auth_user, super::policy::Permission::Read, hop)?;
    }

    let listing = bfs
        .list_with_trace_resolving_internal_links(alias_dir_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source directory for copy"))?;
    for hop in &listing.resolution_paths {
        authorize_copy_permission_if_user(conn, auth_user, super::policy::Permission::Read, hop)?;
    }
    if !listing.resolved_path.is_empty() {
        authorize_copy_permission_if_user(
            conn,
            auth_user,
            super::policy::Permission::Read,
            &listing.resolved_path,
        )?;
    }

    if listing.resolved_path.is_empty()
        || active_resolved_dirs.iter().any(|ancestor| {
            ancestor == &listing.resolved_path
                || ancestor.starts_with(&format!("{}/", listing.resolved_path))
        })
    {
        return Err(McBrowserError::Forbidden(
            "Cannot copy cyclic directory symlink".to_string(),
        ));
    }

    push_unique_copy_hop(resolved_directory_paths, &listing.resolved_path);

    let mut current_dir_hops = Vec::new();
    for hop in inherited_hops {
        push_unique_copy_hop(&mut current_dir_hops, hop);
    }
    push_unique_copy_hop(&mut current_dir_hops, alias_dir_path);
    for hop in &listing.resolution_paths {
        push_unique_copy_hop(&mut current_dir_hops, hop);
    }
    push_unique_copy_hop(&mut current_dir_hops, &listing.resolved_path);

    active_resolved_dirs.push(listing.resolved_path);

    for child in listing.entries {
        if descendants.len() >= MAX_SEARCH_ENTRIES {
            active_resolved_dirs.pop();
            return Err(McBrowserError::Forbidden(
                "Directory tree exceeds maximum entry limit".to_string(),
            ));
        }

        let child_alias_path = format!("{alias_dir_path}/{}", child.name);
        let rel_suffix = match child_alias_path.strip_prefix(from_prefix) {
            Some(suffix) => suffix.to_string(),
            None => {
                active_resolved_dirs.pop();
                return Err(McBrowserError::Internal(
                    "Invalid source descendant path".to_string(),
                ));
            }
        };

        let child_hops: Vec<String> = current_dir_hops
            .iter()
            .map(|dir_hop| format!("{dir_hop}/{}", child.name))
            .collect();

        if let Err(auth_err) = authorize_copy_permission_if_user(
            conn,
            auth_user,
            super::policy::Permission::Read,
            &child_alias_path,
        ) {
            active_resolved_dirs.pop();
            return Err(auth_err);
        }
        for child_hop in &child_hops {
            if let Err(auth_err) = authorize_copy_permission_if_user(
                conn,
                auth_user,
                super::policy::Permission::Read,
                child_hop,
            ) {
                active_resolved_dirs.pop();
                return Err(auth_err);
            }
        }

        match child.kind.as_str() {
            "file" => {
                let opened = match bfs.open_file_resolving_internal_links(&child_alias_path) {
                    Ok(resolved_file) => resolved_file,
                    Err(error) => {
                        active_resolved_dirs.pop();
                        return Err(map_fs_io_error(error, "Failed to open source file for copy"));
                    }
                };
                for hop in &opened.resolution_paths {
                    if let Err(auth_err) = authorize_copy_permission_if_user(
                        conn,
                        auth_user,
                        super::policy::Permission::Read,
                        hop,
                    ) {
                        active_resolved_dirs.pop();
                        return Err(auth_err);
                    }
                }
                if let Err(auth_err) = authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    super::policy::Permission::Read,
                    &opened.resolved_path,
                ) {
                    active_resolved_dirs.pop();
                    return Err(auth_err);
                }
                let file_meta = match verify_pinned_copy_source_metadata(&opened.file) {
                    Ok(meta) => meta,
                    Err(error) => {
                        active_resolved_dirs.pop();
                        return Err(error);
                    }
                };
                descendants.push(PlannedCopyDescendant::File {
                    rel_suffix,
                    file: opened.file,
                    size: file_meta.len(),
                });
            }
            "directory" => {
                descendants.push(PlannedCopyDescendant::Directory { rel_suffix });
                if let Err(sub_err) = collect_copy_directory_descendants(
                    conn,
                    bfs,
                    auth_user,
                    from_prefix,
                    &child_alias_path,
                    &child_hops,
                    depth + 1,
                    active_resolved_dirs,
                    resolved_directory_paths,
                    descendants,
                ) {
                    active_resolved_dirs.pop();
                    return Err(sub_err);
                }
            }
            "symlink" => {
                match bfs.open_file_resolving_internal_links(&child_alias_path) {
                    Ok(opened) => {
                        for hop in &opened.resolution_paths {
                            if let Err(auth_err) = authorize_copy_permission_if_user(
                                conn,
                                auth_user,
                                super::policy::Permission::Read,
                                hop,
                            ) {
                                active_resolved_dirs.pop();
                                return Err(auth_err);
                            }
                        }
                        if let Err(auth_err) = authorize_copy_permission_if_user(
                            conn,
                            auth_user,
                            super::policy::Permission::Read,
                            &opened.resolved_path,
                        ) {
                            active_resolved_dirs.pop();
                            return Err(auth_err);
                        }
                        let file_meta = match verify_pinned_copy_source_metadata(&opened.file) {
                            Ok(meta) => meta,
                            Err(error) => {
                                active_resolved_dirs.pop();
                                return Err(error);
                            }
                        };
                        descendants.push(PlannedCopyDescendant::File {
                            rel_suffix,
                            file: opened.file,
                            size: file_meta.len(),
                        });
                    }
                    Err(open_err) => {
                        let resolved_child = match bfs
                            .metadata_resolving_internal_links(&child_alias_path)
                        {
                            Ok(resolved) if resolved.entry.kind == "directory" => resolved,
                            Ok(resolved) => {
                                for hop in &resolved.resolution_paths {
                                    if let Err(auth_err) = authorize_copy_permission_if_user(
                                        conn,
                                        auth_user,
                                        super::policy::Permission::Read,
                                        hop,
                                    ) {
                                        active_resolved_dirs.pop();
                                        return Err(auth_err);
                                    }
                                }
                                if !resolved.resolved_path.is_empty() {
                                    if let Err(auth_err) = authorize_copy_permission_if_user(
                                        conn,
                                        auth_user,
                                        super::policy::Permission::Read,
                                        &resolved.resolved_path,
                                    ) {
                                        active_resolved_dirs.pop();
                                        return Err(auth_err);
                                    }
                                }
                                active_resolved_dirs.pop();
                                return Err(map_fs_io_error(
                                    open_err,
                                    "Failed to open source file for copy",
                                ));
                            }
                            Err(_) => {
                                active_resolved_dirs.pop();
                                return Err(map_fs_io_error(
                                    open_err,
                                    "Failed to inspect source symlink for copy",
                                ));
                            }
                        };
                        for hop in &resolved_child.resolution_paths {
                            if let Err(auth_err) = authorize_copy_permission_if_user(
                                conn,
                                auth_user,
                                super::policy::Permission::Read,
                                hop,
                            ) {
                                active_resolved_dirs.pop();
                                return Err(auth_err);
                            }
                        }
                        if !resolved_child.resolved_path.is_empty() {
                            if let Err(auth_err) = authorize_copy_permission_if_user(
                                conn,
                                auth_user,
                                super::policy::Permission::Read,
                                &resolved_child.resolved_path,
                            ) {
                                active_resolved_dirs.pop();
                                return Err(auth_err);
                            }
                        }
                        descendants.push(PlannedCopyDescendant::Directory { rel_suffix });
                        let mut symlink_dir_hops = child_hops;
                        for hop in &resolved_child.resolution_paths {
                            push_unique_copy_hop(&mut symlink_dir_hops, hop);
                        }
                        if !resolved_child.resolved_path.is_empty() {
                            push_unique_copy_hop(
                                &mut symlink_dir_hops,
                                &resolved_child.resolved_path,
                            );
                        }
                        if let Err(sub_err) = collect_copy_directory_descendants(
                            conn,
                            bfs,
                            auth_user,
                            from_prefix,
                            &child_alias_path,
                            &symlink_dir_hops,
                            depth + 1,
                            active_resolved_dirs,
                            resolved_directory_paths,
                            descendants,
                        ) {
                            active_resolved_dirs.pop();
                            return Err(sub_err);
                        }
                    }
                }
            }
            _ => {
                active_resolved_dirs.pop();
                return Err(McBrowserError::Forbidden(
                    "Cannot copy symlinks or special files".to_string(),
                ));
            }
        }
    }

    active_resolved_dirs.pop();
    Ok(())
}

fn prepare_copy_source_plan(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    from_prefix: &str,
    auth_user: Option<&AuthUser>,
) -> Result<CopySourcePlan, McBrowserError> {
    authorize_copy_permission_if_user(
        conn,
        auth_user,
        super::policy::Permission::Read,
        from_path,
    )?;

    match bfs.open_file_resolving_internal_links(from_path) {
        Ok(opened) => {
            for hop in &opened.resolution_paths {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    super::policy::Permission::Read,
                    hop,
                )?;
            }
            authorize_copy_permission_if_user(
                conn,
                auth_user,
                super::policy::Permission::Read,
                &opened.resolved_path,
            )?;
            let file_meta = verify_pinned_copy_source_metadata(&opened.file)?;
            Ok(CopySourcePlan::File {
                file: opened.file,
                size: file_meta.len(),
                resolved_path: opened.resolved_path,
            })
        }
        Err(open_err) => {
            let root_resolved = match bfs.metadata_resolving_internal_links(from_path) {
                Ok(resolved) => resolved,
                Err(_) => {
                    return Err(map_fs_io_error(
                        open_err,
                        "Failed to inspect source entry for copy",
                    ))
                }
            };
            for hop in &root_resolved.resolution_paths {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    super::policy::Permission::Read,
                    hop,
                )?;
            }
            if !root_resolved.resolved_path.is_empty() {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    super::policy::Permission::Read,
                    &root_resolved.resolved_path,
                )?;
            }
            if root_resolved.entry.kind != "directory" {
                return Err(map_fs_io_error(
                    open_err,
                    "Failed to open source file for copy",
                ));
            }

            let mut active_resolved_dirs = Vec::new();
            let segments: Vec<&str> = from_path.split('/').collect();
            if segments.len() > 1 {
                let mut prefix_acc = String::new();
                for segment in &segments[..segments.len() - 1] {
                    if !prefix_acc.is_empty() {
                        prefix_acc.push('/');
                    }
                    prefix_acc.push_str(segment);
                    if let Ok(resolved_parent) = bfs.metadata_resolving_internal_links(&prefix_acc)
                    {
                        if !resolved_parent.resolved_path.is_empty() {
                            push_unique_copy_hop(
                                &mut active_resolved_dirs,
                                &resolved_parent.resolved_path,
                            );
                        }
                    }
                }
            }

            let mut root_hops = Vec::new();
            push_unique_copy_hop(&mut root_hops, from_path);
            for hop in &root_resolved.resolution_paths {
                push_unique_copy_hop(&mut root_hops, hop);
            }
            if !root_resolved.resolved_path.is_empty() {
                push_unique_copy_hop(&mut root_hops, &root_resolved.resolved_path);
            }

            let mut resolved_directory_paths = Vec::new();
            let mut descendants = Vec::new();
            collect_copy_directory_descendants(
                conn,
                bfs,
                auth_user,
                from_prefix,
                from_path,
                &root_hops,
                1,
                &mut active_resolved_dirs,
                &mut resolved_directory_paths,
                &mut descendants,
            )?;

            Ok(CopySourcePlan::Directory {
                resolved_directory_paths,
                descendants,
            })
        }
    }
}

fn validate_resolved_source_against_destination(
    source_plan: &CopySourcePlan,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<(), McBrowserError> {
    let allow_same_for_keep_both =
        from_path == to_path && conflict_policy == OperationConflictPolicy::KeepBoth;
    match source_plan {
        CopySourcePlan::File { resolved_path, .. } => {
            if !allow_same_for_keep_both && to_path == resolved_path {
                return Err(McBrowserError::BadRequest(
                    "Source and destination paths must be different".to_string(),
                ));
            }
        }
        CopySourcePlan::Directory {
            resolved_directory_paths,
            ..
        } => {
            for resolved_dir in resolved_directory_paths {
                if !allow_same_for_keep_both && to_path == resolved_dir {
                    return Err(McBrowserError::BadRequest(
                        "Source and destination paths must be different".to_string(),
                    ));
                }
                let resolved_prefix = format!("{resolved_dir}/");
                if to_path.starts_with(&resolved_prefix) {
                    return Err(McBrowserError::BadRequest(
                        "Cannot copy a directory into itself".to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn authorize_destination_tree_for_copy(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: Option<&AuthUser>,
    source_plan: &CopySourcePlan,
    target_to: &str,
    require_modify_on_existing: bool,
) -> Result<(), McBrowserError> {
    authorize_copy_permission_if_user(
        conn,
        auth_user,
        super::policy::Permission::Create,
        target_to,
    )?;
    if require_modify_on_existing {
        authorize_copy_permission_if_user(
            conn,
            auth_user,
            super::policy::Permission::Modify,
            target_to,
        )?;
    }

    if let CopySourcePlan::Directory { descendants, .. } = source_plan {
        for child in descendants {
            let dst_descendant = format!("{target_to}/{}", child.rel_suffix());
            authorize_copy_permission_if_user(
                conn,
                auth_user,
                super::policy::Permission::Create,
                &dst_descendant,
            )?;
            if require_modify_on_existing && bfs.metadata(&dst_descendant).is_ok() {
                authorize_copy_permission_if_user(
                    conn,
                    auth_user,
                    super::policy::Permission::Modify,
                    &dst_descendant,
                )?;
            }
        }
    }

    Ok(())
}

fn execute_copy_core_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
    auth_user: Option<&AuthUser>,
) -> Result<String, McBrowserError> {
    let from_prefix = validate_conflict_destination(from_path, to_path, "copy", conflict_policy)?;
    let mut source_plan =
        prepare_copy_source_plan(conn, bfs, from_path, &from_prefix, auth_user)?;
    validate_resolved_source_against_destination(&source_plan, from_path, to_path, conflict_policy)?;

    let dst_meta_opt = match bfs.metadata(to_path) {
        Ok(entry) => Some(entry),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(map_fs_io_error(error, "Failed to inspect copy destination")),
    };

    match (conflict_policy, dst_meta_opt) {
        (_, None) => {
            authorize_destination_tree_for_copy(
                conn,
                bfs,
                auth_user,
                &source_plan,
                to_path,
                false,
            )?;
            match &mut source_plan {
                CopySourcePlan::File { file, size, .. } => {
                    copy_pinned_file_new_with_quota(
                        conn,
                        bfs,
                        file,
                        to_path,
                        *size,
                        user_id,
                        accounting_complete,
                    )?;
                }
                CopySourcePlan::Directory { descendants, .. } => {
                    copy_planned_directory_new_with_quota(
                        conn,
                        bfs,
                        descendants,
                        to_path,
                        user_id,
                        accounting_complete,
                    )?;
                }
            }
            Ok(to_path.to_string())
        }
        (OperationConflictPolicy::Error, Some(_)) => {
            authorize_destination_tree_for_copy(
                conn,
                bfs,
                auth_user,
                &source_plan,
                to_path,
                false,
            )?;
            Err(McBrowserError::Conflict(
                "Failed to copy entry: destination path already exists".to_string(),
            ))
        }
        (OperationConflictPolicy::KeepBoth, Some(_)) => {
            let mut next_index = 1usize;
            for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
                let (candidate_to, allocated_index) =
                    allocate_version_suffix_path(bfs, to_path, next_index)?;
                let _ = validate_distinct_non_nested_paths(from_path, &candidate_to, "copy")?;
                validate_resolved_source_against_destination(
                    &source_plan,
                    from_path,
                    &candidate_to,
                    OperationConflictPolicy::Error,
                )?;
                authorize_destination_tree_for_copy(
                    conn,
                    bfs,
                    auth_user,
                    &source_plan,
                    &candidate_to,
                    false,
                )?;
                let copy_result = match &mut source_plan {
                    CopySourcePlan::File { file, size, .. } => copy_pinned_file_new_with_quota(
                        conn,
                        bfs,
                        file,
                        &candidate_to,
                        *size,
                        user_id,
                        accounting_complete,
                    ),
                    CopySourcePlan::Directory { descendants, .. } => {
                        copy_planned_directory_new_with_quota(
                            conn,
                            bfs,
                            descendants,
                            &candidate_to,
                            user_id,
                            accounting_complete,
                        )
                    }
                };
                match copy_result {
                    Ok(()) => return Ok(candidate_to),
                    Err(McBrowserError::Conflict(_)) => {
                        next_index = allocated_index.saturating_add(1);
                        continue;
                    }
                    Err(other_err) => return Err(other_err),
                }
            }
            Err(McBrowserError::Conflict(
                "Failed to allocate a unique versioned destination filename".to_string(),
            ))
        }
        (OperationConflictPolicy::Overwrite, Some(dst_meta)) => {
            authorize_destination_tree_for_copy(
                conn,
                bfs,
                auth_user,
                &source_plan,
                to_path,
                true,
            )?;

            if dst_meta.kind != "file" && dst_meta.kind != "directory" {
                return Err(McBrowserError::Forbidden(
                    "Cannot overwrite symlinks or special files".to_string(),
                ));
            }
            if source_plan.kind_str() != dst_meta.kind {
                return Err(McBrowserError::Conflict(
                    "Cannot overwrite destination entry with a different entry type".to_string(),
                ));
            }

            match &mut source_plan {
                CopySourcePlan::File { file, .. } => {
                    copy_pinned_file_overwrite_with_quota(
                        conn,
                        bfs,
                        file,
                        to_path,
                        user_id,
                        accounting_complete,
                    )?;
                    Ok(to_path.to_string())
                }
                CopySourcePlan::Directory { descendants, .. } => {
                    for child in descendants.iter() {
                        let dst_child_path = format!("{to_path}/{}", child.rel_suffix());
                        match bfs.metadata(&dst_child_path) {
                            Ok(existing_dst_child) => {
                                if existing_dst_child.kind != "file"
                                    && existing_dst_child.kind != "directory"
                                {
                                    return Err(McBrowserError::Forbidden(
                                        "Cannot overwrite symlinks or special files".to_string(),
                                    ));
                                }
                                if existing_dst_child.kind != child.kind_str() {
                                    return Err(McBrowserError::Conflict(format!(
                                        "Cannot overwrite destination descendant '{dst_child_path}' with a different entry type"
                                    )));
                                }
                            }
                            Err(error) if error.kind() == ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(map_fs_io_error(
                                    error,
                                    "Failed to inspect destination descendant",
                                ));
                            }
                        }
                    }

                    load_active_quota_conn(conn, user_id, 0)?;

                    for child in descendants.iter_mut() {
                        let dst_child_path = format!("{to_path}/{}", child.rel_suffix());
                        match child {
                            PlannedCopyDescendant::Directory { .. } => {
                                match bfs.metadata(&dst_child_path) {
                                    Ok(existing) if existing.kind == "directory" => {}
                                    Ok(existing)
                                        if existing.kind != "file"
                                            && existing.kind != "directory" =>
                                    {
                                        return Err(McBrowserError::Forbidden(
                                            "Cannot overwrite symlinks or special files"
                                                .to_string(),
                                        ));
                                    }
                                    Ok(_) => {
                                        return Err(McBrowserError::Conflict(format!(
                                            "Cannot overwrite non-directory '{dst_child_path}' with a directory"
                                        )));
                                    }
                                    Err(error) if error.kind() == ErrorKind::NotFound => {
                                        bfs.create_directory(&dst_child_path).map_err(|err| {
                                            map_fs_io_error(
                                                err,
                                                "Failed to create destination subdirectory",
                                            )
                                        })?;
                                    }
                                    Err(error) => {
                                        return Err(map_fs_io_error(
                                            error,
                                            "Failed to inspect destination subdirectory",
                                        ));
                                    }
                                }
                            }
                            PlannedCopyDescendant::File { file, size, .. } => {
                                match bfs.metadata(&dst_child_path) {
                                    Ok(existing) if existing.kind == "file" => {
                                        copy_pinned_file_overwrite_with_quota(
                                            conn,
                                            bfs,
                                            file,
                                            &dst_child_path,
                                            user_id,
                                            accounting_complete,
                                        )?;
                                    }
                                    Ok(existing)
                                        if existing.kind != "file"
                                            && existing.kind != "directory" =>
                                    {
                                        return Err(McBrowserError::Forbidden(
                                            "Cannot overwrite symlinks or special files"
                                                .to_string(),
                                        ));
                                    }
                                    Ok(_) => {
                                        return Err(McBrowserError::Conflict(format!(
                                            "Cannot overwrite non-file '{dst_child_path}' with a file"
                                        )));
                                    }
                                    Err(error) if error.kind() == ErrorKind::NotFound => {
                                        copy_pinned_file_new_with_quota(
                                            conn,
                                            bfs,
                                            file,
                                            &dst_child_path,
                                            *size,
                                            user_id,
                                            accounting_complete,
                                        )?;
                                    }
                                    Err(error) => {
                                        return Err(map_fs_io_error(
                                            error,
                                            "Failed to inspect destination file during directory copy",
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    Ok(to_path.to_string())
                }
            }
        }
    }
}

pub fn execute_copy_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    user_id: i64,
) -> Result<(), McBrowserError> {
    let _ = execute_copy_with_policy_conn(
        conn,
        bfs,
        from_path,
        to_path,
        OperationConflictPolicy::Error,
        user_id,
    )?;
    Ok(())
}

pub fn execute_copy_with_policy_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
) -> Result<String, McBrowserError> {
    execute_copy_with_accounting_conn(
        conn,
        bfs,
        from_path,
        to_path,
        conflict_policy,
        user_id,
        &mut true,
    )
}

fn execute_copy_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    execute_copy_core_with_accounting_conn(
        conn,
        bfs,
        from_path,
        to_path,
        conflict_policy,
        user_id,
        accounting_complete,
        None,
    )
}

pub fn execute_copy_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    execute_copy_for_user_with_accounting_conn(
        conn,
        bfs,
        auth_user,
        from_path,
        to_path,
        conflict_policy,
        &mut true,
    )
}

fn execute_copy_for_user_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_from = super::policy::normalize_target_path(from_path, false)?;
    let normalized_to = super::policy::normalize_target_path(to_path, false)?;
    execute_copy_core_with_accounting_conn(
        conn,
        bfs,
        &normalized_from,
        &normalized_to,
        conflict_policy,
        user_id,
        accounting_complete,
        Some(auth_user),
    )
}

pub fn execute_rename_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
) -> Result<String, McBrowserError> {
    execute_rename_with_accounting_conn(
        conn,
        bfs,
        from_path,
        to_path,
        conflict_policy,
        user_id,
        &mut true,
    )
}

fn execute_rename_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    user_id: i64,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    let from_prefix = validate_conflict_destination(from_path, to_path, "move", conflict_policy)?;
    load_active_quota_conn(conn, user_id, 0)?;

    let src_meta = bfs
        .metadata(from_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source entry for rename"))?;
    if src_meta.kind != "file" && src_meta.kind != "directory" && src_meta.kind != "symlink" {
        return Err(McBrowserError::Forbidden(
            "Cannot rename special files".to_string(),
        ));
    }

    let source_descendants = if src_meta.kind == "directory" {
        bfs.walk(from_path, MAX_SEARCH_ENTRIES).map_err(|error| {
            map_fs_io_error(error, "Failed to inspect source directory for rename")
        })?
    } else {
        Vec::new()
    };

    let dst_meta_opt = match bfs.metadata(to_path) {
        Ok(entry) => Some(entry),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(map_fs_io_error(
                error,
                "Failed to inspect rename destination",
            ))
        }
    };

    match (conflict_policy, dst_meta_opt) {
        (_, None) => {
            bfs.rename_allowing_leaf_symlink(from_path, to_path)
                .map_err(|error| map_fs_io_error(error, "Failed to rename entry"))?;
            Ok(to_path.to_string())
        }
        (OperationConflictPolicy::Error, Some(_)) => Err(McBrowserError::Conflict(
            "Failed to rename entry: destination path already exists".to_string(),
        )),
        (OperationConflictPolicy::KeepBoth, Some(_)) => {
            let mut next_index = 1usize;
            for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
                let (candidate_to, allocated_index) =
                    allocate_version_suffix_path(bfs, to_path, next_index)?;
                let _ = validate_distinct_non_nested_paths(from_path, &candidate_to, "move")?;
                match bfs.rename_allowing_leaf_symlink(from_path, &candidate_to) {
                    Ok(()) => return Ok(candidate_to),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        next_index = allocated_index.saturating_add(1);
                        continue;
                    }
                    Err(error) => {
                        return Err(map_fs_io_error(error, "Failed to rename entry"));
                    }
                }
            }
            Err(McBrowserError::Conflict(
                "Failed to allocate a unique versioned destination filename".to_string(),
            ))
        }
        (OperationConflictPolicy::Overwrite, Some(dst_meta)) => {
            if src_meta.kind == "symlink" || dst_meta.kind == "symlink" {
                return Err(McBrowserError::Forbidden(
                    "Overwriting with or replacing symlinks is not permitted".to_string(),
                ));
            }
            if dst_meta.kind != "file" && dst_meta.kind != "directory" {
                return Err(McBrowserError::Forbidden(
                    "Cannot overwrite special files".to_string(),
                ));
            }
            if src_meta.kind != dst_meta.kind {
                return Err(McBrowserError::Conflict(
                    "Cannot overwrite destination entry with a different entry type".to_string(),
                ));
            }

            if src_meta.kind == "file" {
                move_single_file_overwrite_with_quota(
                    conn,
                    bfs,
                    from_path,
                    to_path,
                    user_id,
                    accounting_complete,
                )?;
                return Ok(to_path.to_string());
            }

            for child in &source_descendants {
                if child.kind != "file" && child.kind != "directory" && child.kind != "symlink" {
                    return Err(McBrowserError::Forbidden(
                        "Cannot move special files".to_string(),
                    ));
                }
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_child_path = format!("{to_path}/{rel_suffix}");
                if let Ok(existing_dst_child) = bfs.metadata(&dst_child_path) {
                    if child.kind == "symlink" || existing_dst_child.kind == "symlink" {
                        return Err(McBrowserError::Forbidden(
                            "Overwriting with or replacing symlinks is not permitted".to_string(),
                        ));
                    }
                    if existing_dst_child.kind != "file" && existing_dst_child.kind != "directory" {
                        return Err(McBrowserError::Forbidden(
                            "Cannot overwrite special files".to_string(),
                        ));
                    }
                    if existing_dst_child.kind != child.kind {
                        return Err(McBrowserError::Conflict(format!(
                            "Cannot overwrite destination descendant '{dst_child_path}' with a different entry type"
                        )));
                    }
                }
            }

            let mut directories_to_remove = Vec::new();
            for child in &source_descendants {
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_child_path = format!("{to_path}/{rel_suffix}");
                match child.kind.as_str() {
                    "directory" => match bfs.metadata(&dst_child_path) {
                        Ok(existing) if existing.kind == "directory" => {
                            directories_to_remove.push(child.path.clone());
                        }
                        Ok(_) => {
                            return Err(McBrowserError::Conflict(format!(
                                "Cannot overwrite non-directory '{dst_child_path}' with a directory"
                            )));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.create_directory(&dst_child_path).map_err(|err| {
                                map_fs_io_error(err, "Failed to create destination subdirectory")
                            })?;
                            directories_to_remove.push(child.path.clone());
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination subdirectory",
                            ));
                        }
                    },
                    "file" => match bfs.metadata(&dst_child_path) {
                        Ok(existing) if existing.kind == "file" => {
                            move_single_file_overwrite_with_quota(
                                conn,
                                bfs,
                                &child.path,
                                &dst_child_path,
                                user_id,
                                accounting_complete,
                            )?;
                        }
                        Ok(_) => {
                            return Err(McBrowserError::Conflict(format!(
                                "Cannot overwrite non-file '{dst_child_path}' with a file"
                            )));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.rename(&child.path, &dst_child_path).map_err(|err| {
                                map_fs_io_error(
                                    err,
                                    "Failed to move file into destination directory",
                                )
                            })?;
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination file during directory move",
                            ));
                        }
                    },
                    "symlink" => match bfs.metadata(&dst_child_path) {
                        Ok(_) => {
                            return Err(McBrowserError::Forbidden(
                                "Overwriting with or replacing symlinks is not permitted"
                                    .to_string(),
                            ));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {
                            bfs.rename_allowing_leaf_symlink(&child.path, &dst_child_path)
                                .map_err(|err| {
                                    map_fs_io_error(
                                        err,
                                        "Failed to move symlink into destination directory",
                                    )
                                })?;
                        }
                        Err(error) => {
                            return Err(map_fs_io_error(
                                error,
                                "Failed to inspect destination symlink during directory move",
                            ));
                        }
                    },
                    _ => {
                        return Err(McBrowserError::Forbidden(
                            "Cannot move special files".to_string(),
                        ));
                    }
                }
            }

            for dir_path in directories_to_remove.iter().rev() {
                bfs.remove(dir_path).map_err(|error| {
                    map_fs_io_error(error, "Failed to remove merged source subdirectory")
                })?;
            }
            bfs.remove(from_path).map_err(|error| {
                map_fs_io_error(error, "Failed to remove merged source directory")
            })?;

            Ok(to_path.to_string())
        }
    }
}

fn authorize_symlink_target_if_internal(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    symlink_path: &str,
) -> Result<(), McBrowserError> {
    if let Ok(resolved) = bfs.metadata_resolving_internal_links(symlink_path) {
        for resolution_path in resolved
            .resolution_paths
            .iter()
            .chain(std::iter::once(&resolved.resolved_path))
        {
            super::policy::authorize_with_conn(
                conn,
                auth_user,
                super::policy::Permission::Read,
                resolution_path,
            )?;
            super::policy::authorize_with_conn(
                conn,
                auth_user,
                super::policy::Permission::Rename,
                resolution_path,
            )?;
        }
    }
    Ok(())
}

pub fn execute_rename_for_user_with_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
) -> Result<String, McBrowserError> {
    execute_rename_for_user_with_accounting_conn(
        conn,
        bfs,
        auth_user,
        from_path,
        to_path,
        conflict_policy,
        &mut true,
    )
}

fn execute_rename_for_user_with_accounting_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    auth_user: &AuthUser,
    from_path: &str,
    to_path: &str,
    conflict_policy: OperationConflictPolicy,
    accounting_complete: &mut bool,
) -> Result<String, McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_from = super::policy::normalize_target_path(from_path, false)?;
    let normalized_to = super::policy::normalize_target_path(to_path, false)?;
    let from_prefix =
        validate_conflict_destination(&normalized_from, &normalized_to, "move", conflict_policy)?;

    super::policy::authorize_with_conn(
        conn,
        auth_user,
        super::policy::Permission::Rename,
        &normalized_from,
    )?;

    let src_meta = bfs
        .metadata(&normalized_from)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect source entry for rename"))?;
    if src_meta.kind == "symlink" {
        authorize_symlink_target_if_internal(conn, bfs, auth_user, &normalized_from)?;
    }

    let source_descendants = if src_meta.kind == "directory" {
        let descendants = bfs
            .walk(&normalized_from, MAX_SEARCH_ENTRIES)
            .map_err(|error| {
                map_fs_io_error(error, "Failed to inspect source directory for rename")
            })?;
        for child in &descendants {
            super::policy::authorize_with_conn(
                conn,
                auth_user,
                super::policy::Permission::Rename,
                &child.path,
            )?;
            if child.kind == "symlink" {
                authorize_symlink_target_if_internal(conn, bfs, auth_user, &child.path)?;
            }
        }
        descendants
    } else {
        Vec::new()
    };

    let dst_exists = match bfs.metadata(&normalized_to) {
        Ok(_) => true,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => {
            return Err(map_fs_io_error(
                error,
                "Failed to inspect rename destination",
            ))
        }
    };

    let target_to = if conflict_policy == OperationConflictPolicy::KeepBoth && dst_exists {
        let (candidate, _) = allocate_version_suffix_path(bfs, &normalized_to, 1)?;
        candidate
    } else {
        normalized_to.clone()
    };

    super::policy::authorize_with_conn(
        conn,
        auth_user,
        super::policy::Permission::Rename,
        &target_to,
    )?;
    if conflict_policy == OperationConflictPolicy::Overwrite && dst_exists {
        super::policy::authorize_with_conn(
            conn,
            auth_user,
            super::policy::Permission::Modify,
            &target_to,
        )?;
    }

    for child in &source_descendants {
        let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
            McBrowserError::Internal("Invalid source descendant path".to_string())
        })?;
        let dst_descendant = format!("{target_to}/{rel_suffix}");
        super::policy::authorize_with_conn(
            conn,
            auth_user,
            super::policy::Permission::Rename,
            &dst_descendant,
        )?;
        if conflict_policy == OperationConflictPolicy::Overwrite && dst_exists {
            if bfs.metadata(&dst_descendant).is_ok() {
                super::policy::authorize_with_conn(
                    conn,
                    auth_user,
                    super::policy::Permission::Modify,
                    &dst_descendant,
                )?;
            }
        }
    }

    if conflict_policy == OperationConflictPolicy::KeepBoth && dst_exists {
        load_active_quota_conn(conn, user_id, 0)?;
        let mut next_index = 1usize;
        for _ in 0..MAX_VERSION_SUFFIX_ATTEMPTS {
            let (candidate_to, allocated_index) =
                allocate_version_suffix_path(bfs, &normalized_to, next_index)?;
            let _ = validate_distinct_non_nested_paths(&normalized_from, &candidate_to, "move")?;
            super::policy::authorize_with_conn(
                conn,
                auth_user,
                super::policy::Permission::Rename,
                &candidate_to,
            )?;
            for child in &source_descendants {
                let rel_suffix = child.path.strip_prefix(&from_prefix).ok_or_else(|| {
                    McBrowserError::Internal("Invalid source descendant path".to_string())
                })?;
                let dst_descendant = format!("{candidate_to}/{rel_suffix}");
                super::policy::authorize_with_conn(
                    conn,
                    auth_user,
                    super::policy::Permission::Rename,
                    &dst_descendant,
                )?;
            }
            match bfs.rename_allowing_leaf_symlink(&normalized_from, &candidate_to) {
                Ok(()) => return Ok(candidate_to),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    next_index = allocated_index.saturating_add(1);
                    continue;
                }
                Err(error) => {
                    return Err(map_fs_io_error(error, "Failed to rename entry"));
                }
            }
        }
        return Err(McBrowserError::Conflict(
            "Failed to allocate a unique versioned destination filename".to_string(),
        ));
    }

    execute_rename_with_accounting_conn(
        conn,
        bfs,
        &normalized_from,
        &normalized_to,
        conflict_policy,
        user_id,
        accounting_complete,
    )
}

#[allow(dead_code)]
pub(super) async fn execute_rename_request(
    auth_user: AuthUser,
    req: RenameMoveRequest,
) -> Result<CopyMoveResponse, McBrowserError> {
    let user_id = validate_mcbrowser_user(&auth_user)?;
    let from_path = normalize_relative_path(&req.from, false)?;
    let to_path = normalize_relative_path(&req.to, false)?;
    let conflict_policy = req.resolved_conflict_policy()?;
    let _ = validate_conflict_destination(&from_path, &to_path, "move", conflict_policy)?;

    let from_for_task = from_path.clone();
    let to_for_task = to_path;
    let user_for_task = auth_user;

    let task_res =
        tokio::task::spawn_blocking(move || -> Result<(String, bool), McBrowserError> {
            let _guard = user_mutation_stripe(user_id).blocking_lock_owned();
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for rename operation".to_string())
            })?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let previous_usage = load_active_quota_conn(&conn, user_id, 0)?.used_bytes;
            let audit = super::events::record_pending_intent_with_conn(
                &conn,
                &user_for_task,
                super::events::McBrowserEventTrigger::EntryRenamed,
                &from_for_task,
                Some(&to_for_task),
                0,
            )?;
            let mut accounting_complete = true;
            let final_to = execute_rename_for_user_with_accounting_conn(
                &conn,
                &bfs,
                &user_for_task,
                &from_for_task,
                &to_for_task,
                conflict_policy,
                &mut accounting_complete,
            )?;
            if let Some(quota) = load_active_quota_conn(&conn, user_id, 0)
                .ok()
                .filter(|_| accounting_complete)
            {
                super::events::finalize_published_mutation_with_conn(
                    &conn,
                    &audit,
                    None,
                    Some(&final_to),
                    quota.used_bytes.saturating_sub(previous_usage),
                );
            }
            Ok((final_to, !accounting_complete))
        })
        .await;

    match task_res {
        Ok(Ok((final_to, accounting_pending))) => Ok(CopyMoveResponse {
            success: true,
            path: final_to.clone(),
            from: from_path,
            to: final_to,
            accounting_pending,
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(McBrowserError::Internal("Rename task failed".to_string())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteRecursiveOutcome {
    pub removed_bytes: u64,
    pub accounting_pending: bool,
}

pub fn execute_delete_recursive_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    user_id: i64,
) -> Result<(), McBrowserError> {
    execute_delete_recursive_with_outcome_conn(conn, bfs, normalized_path, user_id).map(|_| ())
}

pub fn execute_delete_recursive_with_outcome_conn(
    conn: &rusqlite::Connection,
    bfs: &BrowserFs,
    normalized_path: &str,
    user_id: i64,
) -> Result<DeleteRecursiveOutcome, McBrowserError> {
    load_active_quota_conn(conn, user_id, 0)?;

    match bfs.remove_tree_with_size(normalized_path) {
        Ok(removed_bytes) => {
            let accounting_pending = if removed_bytes > 0 {
                release_user_quota_conn(conn, user_id, removed_bytes).is_err()
            } else {
                false
            };
            Ok(DeleteRecursiveOutcome {
                removed_bytes,
                accounting_pending,
            })
        }
        Err(removal_err) => {
            if removal_err.removed_bytes > 0 {
                release_user_quota_conn(conn, user_id, removal_err.removed_bytes).map_err(|_| {
                    McBrowserError::AccountingPending(
                        "Directory was only partially deleted; released quota requires reconciliation"
                            .to_string(),
                    )
                })?;
            }
            Err(map_fs_io_error(
                removal_err.error,
                "Failed to recursively delete entry",
            ))
        }
    }
}

pub fn collect_entry_info_with_auth<F>(
    bfs: &BrowserFs,
    normalized_path: &str,
    algorithms: &[ChecksumAlgorithm],
    mut can_read_path: F,
) -> Result<InfoResponse, McBrowserError>
where
    F: FnMut(&str, bool) -> bool,
{
    let resolved = bfs
        .metadata_resolving_internal_links(normalized_path)
        .map_err(|e| map_fs_io_error(e, "Failed to inspect entry metadata"))?;
    let mut authorize_resolution = |paths: &[String], target: &str| {
        if !can_read_path(normalized_path, false)
            || !paths
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(target))
                .all(|path| can_read_path(path, false))
        {
            return Err(McBrowserError::Forbidden(
                "Entry inspection is denied by user policy".to_string(),
            ));
        }
        Ok(())
    };
    authorize_resolution(&resolved.resolution_paths, &resolved.resolved_path)?;
    let mut entry = resolved.entry;

    let checksums = if algorithms.is_empty() {
        BTreeMap::new()
    } else {
        if entry.kind != "file" {
            return Err(McBrowserError::BadRequest(
                "Checksums can only be computed for regular files".to_string(),
            ));
        }
        let opened = bfs
            .open_file_resolving_internal_links(normalized_path)
            .map_err(|e| map_fs_io_error(e, "Failed to open file for checksum"))?;
        authorize_resolution(&opened.resolution_paths, &opened.resolved_path)?;
        entry = opened.entry;
        compute_checksums_from_reader(opened.file, algorithms)
            .map_err(|e| map_fs_io_error(e, "Failed to compute file checksums"))?
    };

    let (num_files, num_dirs) = if entry.kind == "directory" {
        match bfs.list_with_trace_resolving_internal_links(normalized_path) {
            Ok(listing) => {
                authorize_resolution(&listing.resolution_paths, &listing.resolved_path)?;
                entry = listing.entry;
                let mut files = 0usize;
                let mut dirs = 0usize;
                for child in listing.entries {
                    let is_dir = child.kind == "directory";
                    let visible_at_all_hops = listing
                        .resolution_paths
                        .iter()
                        .map(String::as_str)
                        .chain(std::iter::once(normalized_path))
                        .all(|parent| {
                            let child_alias = if parent.is_empty() {
                                child.name.clone()
                            } else {
                                format!("{parent}/{}", child.name)
                            };
                            can_read_path(&child_alias, is_dir)
                        });
                    if !visible_at_all_hops || !can_read_path(&child.path, is_dir) {
                        continue;
                    }
                    if is_dir {
                        dirs += 1;
                    } else if child.kind == "file" {
                        files += 1;
                    }
                }
                (Some(files), Some(dirs))
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    entry.path = normalized_path.to_string();
    entry.name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    Ok(InfoResponse {
        entry,
        checksums,
        num_files,
        num_dirs,
    })
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

async fn search_entries(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, true) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let kind_filter = match parse_search_type_filter(query.entry_type.as_deref()) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    let search_q = query.q.clone();
    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<SearchResponse, McBrowserError> {
        let conn = af_db::get_conn()
            .map_err(|_| McBrowserError::Internal("Database unavailable for search".to_string()))?;
        super::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            super::policy::Permission::Read,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let (walked, hit_walk_limit) = match bfs.walk(&normalized_path, MAX_SEARCH_ENTRIES + 1) {
            Ok(entries) => (entries, false),
            Err(e) if e.to_string() == "directory entry limit exceeded" => {
                let bounded = bfs
                    .walk(&normalized_path, MAX_SEARCH_ENTRIES)
                    .map_err(|err| map_fs_io_error(err, "Failed to search directory"))?;
                (bounded, true)
            }
            Err(e) => return Err(map_fs_io_error(e, "Failed to search directory")),
        };
        let mut resp = filter_walked_entries(walked, &search_q, kind_filter, MAX_SEARCH_ENTRIES);
        if hit_walk_limit {
            resp.truncated = true;
        }
        resp.entries.retain(|entry| {
            super::policy::authorize_with_conn(
                &conn,
                &user_for_task,
                super::policy::Permission::Read,
                &entry.path,
            )
            .is_ok()
        });
        Ok(resp)
    })
    .await;

    match res {
        Ok(Ok(search_resp)) => Json(search_resp).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Search task failed".to_string()).into_response(),
    }
}

async fn copy_entry(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CopyRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let from_path = match normalize_relative_path(&req.from, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let to_path = match normalize_relative_path(&req.to, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let conflict_policy = match req.resolved_conflict_policy() {
        Ok(policy) => policy,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = validate_conflict_destination(&from_path, &to_path, "copy", conflict_policy)
    {
        return error.into_response();
    }

    let from_for_task = from_path.clone();
    let to_for_task = to_path;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<(String, bool), McBrowserError> {
        let _guard = user_mutation_stripe(user_id).blocking_lock_owned();
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for copy quota check".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let previous_usage = load_active_quota_conn(&conn, user_id, 0)?.used_bytes;
        let audit = super::events::record_pending_intent_with_conn(
            &conn,
            &user_for_task,
            super::events::McBrowserEventTrigger::EntryCopied,
            &from_for_task,
            Some(&to_for_task),
            0,
        )?;
        let mut accounting_complete = true;
        let final_to = execute_copy_for_user_with_accounting_conn(
            &conn,
            &bfs,
            &user_for_task,
            &from_for_task,
            &to_for_task,
            conflict_policy,
            &mut accounting_complete,
        )?;
        if let Some(quota) = load_active_quota_conn(&conn, user_id, 0)
            .ok()
            .filter(|_| accounting_complete)
        {
            super::events::finalize_published_mutation_with_conn(
                &conn,
                &audit,
                None,
                Some(&final_to),
                quota.used_bytes.saturating_sub(previous_usage),
            );
        }
        Ok((final_to, !accounting_complete))
    })
    .await;

    match res {
        Ok(Ok((final_to, accounting_pending))) => Json(CopyMoveResponse {
            success: true,
            path: final_to.clone(),
            from: from_path,
            to: final_to,
            accounting_pending,
        })
        .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Copy task failed".to_string()).into_response(),
    }
}

async fn delete_recursive(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<DeleteRecursiveRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&req.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(
        move || -> Result<super::DeleteSuccessResponse, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for quota update".to_string())
            })?;
            super::policy::authorize_with_conn(
                &conn,
                &user_for_task,
                super::policy::Permission::Delete,
                &normalized_path,
            )?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let meta = bfs
                .metadata(&normalized_path)
                .map_err(|e| map_fs_io_error(e, "Failed to inspect entry for deletion"))?;
            if meta.kind == "directory" {
                let descendants = bfs
                    .walk(&normalized_path, MAX_SEARCH_ENTRIES)
                    .map_err(|e| map_fs_io_error(e, "Failed to inspect directory for deletion"))?;
                for d in &descendants {
                    super::policy::authorize_with_conn(
                        &conn,
                        &user_for_task,
                        super::policy::Permission::Delete,
                        &d.path,
                    )?;
                }
            }
            load_active_quota_conn(&conn, user_id, 0)?;
            let audit = super::events::record_pending_intent_with_conn(
                &conn,
                &user_for_task,
                super::events::McBrowserEventTrigger::EntryDeleted,
                &normalized_path,
                None,
                0,
            )?;
            let outcome =
                execute_delete_recursive_with_outcome_conn(&conn, &bfs, &normalized_path, user_id)?;
            if !outcome.accounting_pending {
                super::events::finalize_published_mutation_with_conn(
                    &conn,
                    &audit,
                    None,
                    None,
                    -(outcome.removed_bytes.min(i64::MAX as u64) as i64),
                );
            }
            Ok(super::DeleteSuccessResponse {
                success: true,
                accounting_pending: outcome.accounting_pending,
            })
        },
    )
    .await;

    match res {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Recursive delete task failed".to_string()).into_response()
        }
    }
}

async fn get_content(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<ContentResponse, McBrowserError> {
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for content read".to_string())
        })?;
        super::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            super::policy::Permission::Read,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        execute_get_content_for_user_with_conn(&conn, &bfs, &user_for_task, &normalized_path)
    })
    .await;

    match res {
        Ok(Ok(doc)) => {
            let etag_hdr = HeaderValue::from_str(&doc.etag).ok();
            let mut resp = Json(doc).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Some(hv) = etag_hdr {
                resp.headers_mut().insert(header::ETAG, hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Read content task failed".to_string()).into_response(),
    }
}

async fn put_content(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<PutContentRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = validate_editor_write_payload(&req.content) {
        return e.into_response();
    }
    if req.etag.trim().is_empty() {
        return McBrowserError::BadRequest(
            "ETag is required for optimistic concurrency control".to_string(),
        )
        .into_response();
    }

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<PutContentResponse, McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for content update".to_string())
        })?;
        super::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            super::policy::Permission::Modify,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let (existing_file, resolved_target_path) = open_authorized_file_for_put_content_with_conn(
            &conn,
            &user_for_task,
            &bfs,
            &normalized_path,
        )?;
        let (current_doc, expected_file) =
            read_utf8_editor_content_from_file(existing_file, resolved_target_path.clone())?;
        let old_size = current_doc.content.len() as u64;
        let byte_delta = (req.content.len().min(i64::MAX as usize) as i64)
            .saturating_sub(old_size.min(i64::MAX as u64) as i64);
        super::events::execute_with_audit_intent_conn(
            &conn,
            &user_for_task,
            super::events::McBrowserEventTrigger::FileSaved,
            &normalized_path,
            None,
            byte_delta,
            |connection, _| {
                let (response, committed_delta) = execute_put_content_with_loaded_target_conn(
                    connection,
                    &bfs,
                    &resolved_target_path,
                    &current_doc,
                    &expected_file,
                    &req.content,
                    &req.etag,
                    user_id,
                )?;
                let accounting_complete = !response.accounting_pending;
                Ok((None, None, committed_delta, response, accounting_complete))
            },
        )
        .map(|(response, _)| response)
    })
    .await;

    match res {
        Ok(Ok(out)) => {
            let etag_hdr = HeaderValue::from_str(&out.etag).ok();
            let mut resp = Json(out).into_response();
            if let Some(hv) = etag_hdr {
                resp.headers_mut().insert(header::ETAG, hv);
            }
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Write content task failed".to_string()).into_response(),
    }
}

async fn create_file(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CreateFileRequest>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&req.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if let Some(ref c) = req.content {
        if let Err(e) = validate_editor_write_payload(c) {
            return e.into_response();
        }
    }

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let user_for_task = auth_user;

    let res = tokio::task::spawn_blocking(move || -> Result<(), McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for file creation".to_string())
        })?;
        super::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            super::policy::Permission::Create,
            &normalized_path,
        )?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        let byte_delta = req
            .content
            .as_ref()
            .map_or(0, |content| content.len() as i64);
        super::events::execute_with_audit_intent_conn(
            &conn,
            &user_for_task,
            super::events::McBrowserEventTrigger::FileSaved,
            &normalized_path,
            None,
            byte_delta,
            |connection, _pending| {
                execute_create_file_conn(
                    connection,
                    &bfs,
                    &normalized_path,
                    req.content.as_deref(),
                    user_id,
                )?;
                Ok((None, None, byte_delta, (), true))
            },
        )
        .map(|((), _audit_outcome)| ())
    })
    .await;

    match res {
        Ok(Ok(())) => (
            StatusCode::CREATED,
            Json(MutationSuccessResponse { success: true }),
        )
            .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Create file task failed".to_string()).into_response(),
    }
}

async fn get_entry_info(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<InfoQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let algorithms = match parse_checksum_algorithms(query.checksum.as_deref()) {
        Ok(algs) => algs,
        Err(e) => return e.into_response(),
    };

    let permit = if !algorithms.is_empty() {
        let Ok(p) = Arc::clone(&CHECKSUM_SEMAPHORE).acquire_owned().await else {
            return McBrowserError::Internal("Checksum concurrency limiter closed".to_string())
                .into_response();
        };
        Some(p)
    } else {
        None
    };

    let user_for_task = auth_user;
    let res = tokio::task::spawn_blocking(move || -> Result<InfoResponse, McBrowserError> {
        let _permit = permit;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for entry info".to_string())
        })?;
        super::policy::authorize_with_conn(
            &conn,
            &user_for_task,
            super::policy::Permission::Read,
            &normalized_path,
        )?;
        let policy = super::policy::load_user_policy_conn(&conn, user_id)?;
        let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
        drop(conn);

        collect_entry_info_with_auth(&bfs, &normalized_path, &algorithms, |child_path, is_dir| {
            if is_dir {
                super::policy::is_entry_visible(&policy, child_path, true)
            } else {
                super::policy::authorize_with_policy(
                    &policy,
                    super::policy::Permission::Read,
                    child_path,
                )
                .is_ok()
            }
        })
    })
    .await;

    match res {
        Ok(Ok(info)) => {
            let mut resp = Json(info).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Entry info task failed".to_string()).into_response(),
    }
}

async fn create_archive_ticket(
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
        return McBrowserError::Internal("Archive concurrency limiter closed".to_string()).into_response();
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
            let effective_scope = super::policy::effective_scope_with_conn(&conn, user_id)?;
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

fn build_archive_stream_response(
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

async fn download_archive_by_ticket(
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
            |uid| super::policy::effective_scope_with_conn(&conn, uid),
            |uid| open_configured_user_browser_fs_with_conn(&conn, uid),
            |path| {
                control.check()?;
                super::policy::authorize_with_conn(
                    &conn,
                    &user_for_redeem,
                    super::policy::Permission::Download,
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

async fn download_archive(
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

unsafe fn load_dyn_symbol(lib_names: &[&CStr], sym_name: &CStr) -> io::Result<*mut libc::c_void> {
    for &lib in lib_names {
        let handle = unsafe { libc::dlopen(lib.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            let sym = unsafe { libc::dlsym(handle, sym_name.as_ptr()) };
            if !sym.is_null() {
                return Ok(sym);
            }
        }
    }
    Err(io::Error::new(
        ErrorKind::Unsupported,
        format!("missing system library symbol {:?}", sym_name),
    ))
}

struct OpenSslEvpApi {
    ctx_new: unsafe extern "C" fn() -> *mut libc::c_void,
    ctx_free: unsafe extern "C" fn(*mut libc::c_void),
    evp_md5: unsafe extern "C" fn() -> *const libc::c_void,
    digest_init_ex: unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int,
    digest_update:
        unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, usize) -> libc::c_int,
    digest_final_ex:
        unsafe extern "C" fn(*mut libc::c_void, *mut u8, *mut libc::c_uint) -> libc::c_int,
}

static OPENSSL_EVP_API: Lazy<OpenSslEvpApi> = Lazy::new(|| unsafe {
    let libs = [c"libcrypto.so.3", c"libcrypto.so"];
    OpenSslEvpApi {
        ctx_new: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_MD_CTX_new").expect("EVP_MD_CTX_new"),
        ),
        ctx_free: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_MD_CTX_free").expect("EVP_MD_CTX_free"),
        ),
        evp_md5: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_md5").expect("EVP_md5"),
        ),
        digest_init_ex: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_DigestInit_ex").expect("EVP_DigestInit_ex"),
        ),
        digest_update: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_DigestUpdate").expect("EVP_DigestUpdate"),
        ),
        digest_final_ex: std::mem::transmute::<*mut libc::c_void, _>(
            load_dyn_symbol(&libs, c"EVP_DigestFinal_ex").expect("EVP_DigestFinal_ex"),
        ),
    }
});

/// OpenSSL `EVP_md5` digest wrapper (zero hand-rolled cryptographic primitives).
struct Md5Hasher {
    ctx: *mut libc::c_void,
}

unsafe impl Send for Md5Hasher {}

impl Md5Hasher {
    fn new() -> Self {
        let api = &*OPENSSL_EVP_API;
        let ctx = unsafe { (api.ctx_new)() };
        assert!(!ctx.is_null(), "EVP_MD_CTX_new failed");
        let md = unsafe { (api.evp_md5)() };
        let rc = unsafe { (api.digest_init_ex)(ctx, md, std::ptr::null_mut()) };
        assert_eq!(rc, 1, "EVP_DigestInit_ex(EVP_md5) failed");
        Self { ctx }
    }

    fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }
        let api = &*OPENSSL_EVP_API;
        let rc = unsafe { (api.digest_update)(self.ctx, input.as_ptr().cast(), input.len()) };
        assert_eq!(rc, 1, "EVP_DigestUpdate(EVP_md5) failed");
    }

    fn finalize(mut self) -> [u8; 16] {
        let api = &*OPENSSL_EVP_API;
        let mut out = [0u8; 16];
        let mut out_len: libc::c_uint = 0;
        let rc = unsafe { (api.digest_final_ex)(self.ctx, out.as_mut_ptr(), &mut out_len) };
        assert_eq!(rc, 1, "EVP_DigestFinal_ex(EVP_md5) failed");
        unsafe { (api.ctx_free)(self.ctx) };
        self.ctx = std::ptr::null_mut();
        out
    }
}

impl Drop for Md5Hasher {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { (OPENSSL_EVP_API.ctx_free)(self.ctx) };
            self.ctx = std::ptr::null_mut();
        }
    }
}

type LzmaCrc32Fn = unsafe extern "C" fn(*const u8, usize, u32) -> u32;

static LZMA_CRC32_FN: Lazy<LzmaCrc32Fn> = Lazy::new(|| unsafe {
    let libs = [c"liblzma.so.5", c"liblzma.so"];
    std::mem::transmute::<*mut libc::c_void, LzmaCrc32Fn>(
        load_dyn_symbol(&libs, c"lzma_crc32").expect("lzma_crc32"),
    )
});

/// `liblzma` IEEE 802.3 CRC-32 wrapper (no hand-rolled lookup table).
struct Crc32Hasher {
    crc: u32,
}

impl Crc32Hasher {
    fn new() -> Self {
        Self { crc: 0 }
    }

    fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let f = *LZMA_CRC32_FN;
        self.crc = unsafe { f(bytes.as_ptr(), bytes.len(), self.crc) };
    }

    fn finalize(self) -> u32 {
        self.crc
    }
}

#[cfg(test)]
#[path = "operations_tests.rs"]
mod operations_tests;
