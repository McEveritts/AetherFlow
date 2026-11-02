#![allow(dead_code)]

use super::media::{
    discover_subtitles_in_fs, is_image_content_type, is_video_extension, media_type,
    read_image_dimensions_from_file, ImageResolution, MediaMetadataResponse, SubtitleTrackInfo,
};
use super::operations::{
    compute_checksums_from_reader, parse_checksum_algorithms, validate_archive_entry_name,
    write_archive_to_writer, ArchiveFormat, ChecksumAlgorithm,
};
use super::policy::{self, Permission};
use super::{
    check_fd_free_space, load_active_quota_conn, map_fs_io_error,
    open_configured_user_browser_fs_with_conn, release_user_quota_conn, reserve_user_quota_atomic,
    user_mutation_stripe, validate_mcbrowser_user, McBrowserError, MAX_UPLOAD_BYTES,
};
use crate::auth::AuthUser;
use af_files::{BrowserFs, Entry, ResolvedFile};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum::Router;
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use rusqlite::Connection;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub const MAX_ACTION_BODY_BYTES: usize = 65_536;
pub const ACTIONS_CONCURRENCY_LIMIT: usize = 4;

pub const MAX_ACTION_CHECKSUM_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_ACTION_ARCHIVE_ENTRIES: usize = 4_096;
pub const MAX_ACTION_CREATE_ARCHIVE_SOURCE_BYTES: u64 = MAX_UPLOAD_BYTES;
pub const MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES: u64 = MAX_UPLOAD_BYTES;

pub const MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES: u64 = MAX_UPLOAD_BYTES;
pub const MAX_ACTION_EXTRACT_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ACTION_EXTRACT_TOTAL_BYTES: u64 = MAX_UPLOAD_BYTES;
pub const MAX_ACTION_EXTRACT_COMPRESSION_RATIO: u64 = 100;
pub const ACTION_COMPRESSION_RATIO_GRACE_BYTES: u64 = 65_536;
pub const MAX_ACTION_DURATION: Duration = Duration::from_secs(30);

const ACTION_IO_BUF_BYTES: usize = 64 * 1024;

pub(crate) static ACTIONS_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(ACTIONS_CONCURRENCY_LIMIT)));

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action")]
pub enum Action {
    #[serde(rename = "compute_checksums")]
    ComputeChecksums {
        path: String,
        #[serde(default)]
        algorithms: Vec<String>,
    },
    #[serde(rename = "extract_archive")]
    ExtractArchive {
        archive_path: String,
        destination_dir: String,
    },
    #[serde(rename = "create_archive")]
    CreateArchive {
        source_paths: Vec<String>,
        destination_path: String,
        format: String,
    },
    #[serde(rename = "inspect_media_metadata")]
    InspectMediaMetadata { path: String },
}

pub type ActionRequest = Action;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawComputeChecksumsPayload {
    path: String,
    #[serde(default)]
    algorithms: Option<AlgorithmsSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AlgorithmsSpec {
    List(Vec<String>),
    Csv(String),
}

impl AlgorithmsSpec {
    fn into_vec(self) -> Result<Vec<String>, String> {
        match self {
            Self::List(list) => {
                if list.is_empty() {
                    return Err("At least one checksum algorithm is required".to_string());
                }
                Ok(list)
            }
            Self::Csv(raw) => {
                let items: Vec<String> = raw
                    .split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect();
                if items.is_empty() {
                    return Err("At least one checksum algorithm is required".to_string());
                }
                Ok(items)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExtractArchivePayload {
    archive_path: String,
    destination_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCreateArchivePayload {
    source_paths: Vec<String>,
    destination_path: String,
    format: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInspectMediaMetadataPayload {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
enum TaggedActionWire {
    #[serde(
        rename = "compute_checksums",
        alias = "ComputeChecksums",
        alias = "computeChecksums"
    )]
    ComputeChecksums(RawComputeChecksumsPayload),
    #[serde(
        rename = "extract_archive",
        alias = "ExtractArchive",
        alias = "extractArchive"
    )]
    ExtractArchive(RawExtractArchivePayload),
    #[serde(
        rename = "create_archive",
        alias = "CreateArchive",
        alias = "createArchive"
    )]
    CreateArchive(RawCreateArchivePayload),
    #[serde(
        rename = "inspect_media_metadata",
        alias = "InspectMediaMetadata",
        alias = "inspectMediaMetadata"
    )]
    InspectMediaMetadata(RawInspectMediaMetadataPayload),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
enum ExternalActionWire {
    #[serde(
        rename = "ComputeChecksums",
        alias = "compute_checksums",
        alias = "computeChecksums"
    )]
    ComputeChecksums(RawComputeChecksumsPayload),
    #[serde(
        rename = "ExtractArchive",
        alias = "extract_archive",
        alias = "extractArchive"
    )]
    ExtractArchive(RawExtractArchivePayload),
    #[serde(
        rename = "CreateArchive",
        alias = "create_archive",
        alias = "createArchive"
    )]
    CreateArchive(RawCreateArchivePayload),
    #[serde(
        rename = "InspectMediaMetadata",
        alias = "inspect_media_metadata",
        alias = "inspectMediaMetadata"
    )]
    InspectMediaMetadata(RawInspectMediaMetadataPayload),
}

impl Action {
    fn from_tagged(wire: TaggedActionWire) -> Result<Self, String> {
        match wire {
            TaggedActionWire::ComputeChecksums(payload) => {
                let algorithms = match payload.algorithms {
                    Some(spec) => spec.into_vec()?,
                    None => Vec::new(),
                };
                if algorithms.is_empty() {
                    return Err("At least one checksum algorithm is required".to_string());
                }
                Ok(Self::ComputeChecksums {
                    path: payload.path,
                    algorithms,
                })
            }
            TaggedActionWire::ExtractArchive(payload) => Ok(Self::ExtractArchive {
                archive_path: payload.archive_path,
                destination_dir: payload.destination_dir,
            }),
            TaggedActionWire::CreateArchive(payload) => Ok(Self::CreateArchive {
                source_paths: payload.source_paths,
                destination_path: payload.destination_path,
                format: payload.format,
            }),
            TaggedActionWire::InspectMediaMetadata(payload) => {
                Ok(Self::InspectMediaMetadata { path: payload.path })
            }
        }
    }

    fn from_external(wire: ExternalActionWire) -> Result<Self, String> {
        match wire {
            ExternalActionWire::ComputeChecksums(payload) => {
                let algorithms = match payload.algorithms {
                    Some(spec) => spec.into_vec()?,
                    None => Vec::new(),
                };
                if algorithms.is_empty() {
                    return Err("At least one checksum algorithm is required".to_string());
                }
                Ok(Self::ComputeChecksums {
                    path: payload.path,
                    algorithms,
                })
            }
            ExternalActionWire::ExtractArchive(payload) => Ok(Self::ExtractArchive {
                archive_path: payload.archive_path,
                destination_dir: payload.destination_dir,
            }),
            ExternalActionWire::CreateArchive(payload) => Ok(Self::CreateArchive {
                source_paths: payload.source_paths,
                destination_path: payload.destination_path,
                format: payload.format,
            }),
            ExternalActionWire::InspectMediaMetadata(payload) => {
                Ok(Self::InspectMediaMetadata { path: payload.path })
            }
        }
    }

    pub const fn action_name(&self) -> &'static str {
        match self {
            Self::ComputeChecksums { .. } => "compute_checksums",
            Self::ExtractArchive { .. } => "extract_archive",
            Self::CreateArchive { .. } => "create_archive",
            Self::InspectMediaMetadata { .. } => "inspect_media_metadata",
        }
    }

    pub const fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::ExtractArchive { .. } | Self::CreateArchive { .. }
        )
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let Some(obj) = value.as_object() else {
            return Err(de::Error::custom(
                "Action request payload must be a JSON object",
            ));
        };
        if obj.contains_key("action") {
            let wire: TaggedActionWire =
                serde_json::from_value(value).map_err(de::Error::custom)?;
            Self::from_tagged(wire).map_err(de::Error::custom)
        } else if obj.len() == 1 {
            let wire: ExternalActionWire =
                serde_json::from_value(value).map_err(de::Error::custom)?;
            Self::from_external(wire).map_err(de::Error::custom)
        } else {
            Err(de::Error::custom(
                "Action payload must specify a closed 'action' tag or single enum variant with no unknown fields",
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeChecksumsActionResult {
    pub path: String,
    pub size: u64,
    pub checksums: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractArchiveActionResult {
    pub archive_path: String,
    pub destination_dir: String,
    pub format: String,
    pub extracted_files: usize,
    pub extracted_directories: usize,
    pub extracted_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateArchiveActionResult {
    pub destination_path: String,
    pub format: String,
    pub entry_count: usize,
    pub archive_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectMediaMetadataActionResult {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub content_type: Option<String>,
    pub size: u64,
    pub modified: Option<String>,
    pub resolution: Option<ImageResolution>,
    pub subtitles: Vec<SubtitleTrackInfo>,
}

impl From<MediaMetadataResponse> for InspectMediaMetadataActionResult {
    fn from(value: MediaMetadataResponse) -> Self {
        Self {
            path: value.path,
            name: value.name,
            kind: value.kind,
            content_type: value.content_type,
            size: value.size,
            modified: value.modified,
            resolution: value.resolution,
            subtitles: value.subtitles,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum ActionResponse {
    #[serde(rename = "compute_checksums")]
    ComputeChecksums {
        success: bool,
        #[serde(flatten)]
        result: ComputeChecksumsActionResult,
    },
    #[serde(rename = "extract_archive")]
    ExtractArchive {
        success: bool,
        #[serde(flatten)]
        result: ExtractArchiveActionResult,
    },
    #[serde(rename = "create_archive")]
    CreateArchive {
        success: bool,
        #[serde(flatten)]
        result: CreateArchiveActionResult,
    },
    #[serde(rename = "inspect_media_metadata")]
    InspectMediaMetadata {
        success: bool,
        #[serde(flatten)]
        result: InspectMediaMetadataActionResult,
    },
}

async fn limit_action_requests(request: Request, next: Next) -> Response {
    let Ok(_permit) = ACTIONS_SEMAPHORE.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::RETRY_AFTER, "1"),
            ],
            Json(serde_json::json!({
                "code": "ACTIONS_BUSY",
                "message": "Action runner capacity is busy; retry shortly"
            })),
        )
            .into_response();
    };
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn router() -> Router {
    Router::new()
        .route("/mcbrowser/actions", post(dispatch_action))
        .layer(DefaultBodyLimit::max(MAX_ACTION_BODY_BYTES))
        .layer(middleware::from_fn(limit_action_requests))
}

fn no_store_json_status<T: Serialize>(status: StatusCode, payload: T) -> Response {
    let mut resp = (status, Json(payload)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub fn parse_action_payload_bytes(body: &[u8]) -> Result<Action, McBrowserError> {
    if body.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Action request body cannot be empty".to_string(),
        ));
    }
    if body.len() > MAX_ACTION_BODY_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Action request body exceeds maximum size of {MAX_ACTION_BODY_BYTES} bytes (64 KiB)"
        )));
    }
    serde_json::from_slice::<Action>(body).map_err(|err| {
        McBrowserError::BadRequest(format!(
            "Invalid action JSON payload or unsupported fields: {err}"
        ))
    })
}

pub fn parse_action_checksum_algorithms(
    raw_algorithms: &[String],
) -> Result<Vec<ChecksumAlgorithm>, McBrowserError> {
    if raw_algorithms.is_empty() {
        return Err(McBrowserError::BadRequest(
            "ComputeChecksums requires at least one checksum algorithm".to_string(),
        ));
    }
    if raw_algorithms.len() > 16 {
        return Err(McBrowserError::BadRequest(
            "ComputeChecksums specifies too many algorithm entries".to_string(),
        ));
    }
    for item in raw_algorithms {
        if item.trim().is_empty() {
            return Err(McBrowserError::BadRequest(
                "Checksum algorithm name cannot be empty".to_string(),
            ));
        }
    }
    let joined = raw_algorithms.join(",");
    let parsed = parse_checksum_algorithms(Some(&joined))?;
    if parsed.is_empty() {
        return Err(McBrowserError::BadRequest(
            "ComputeChecksums requires at least one valid checksum algorithm (md5, sha1, sha256, sha512)".to_string(),
        ));
    }
    Ok(parsed)
}

fn open_authorized_action_file_with_conn(
    conn: &Connection,
    user: &AuthUser,
    bfs: &BrowserFs,
    path: &str,
    permissions: &[Permission],
) -> Result<(File, Entry, String), McBrowserError> {
    for &perm in permissions {
        policy::authorize_with_conn(conn, user, perm, path)?;
    }

    match bfs.open_file(path) {
        Ok(file) => {
            let meta = file
                .metadata()
                .map_err(|e| map_fs_io_error(e, "Failed to inspect file metadata"))?;
            let entry = bfs.metadata(path).unwrap_or_else(|_| Entry {
                name: path.rsplit('/').next().unwrap_or(path).to_string(),
                path: path.to_string(),
                kind: "file".to_string(),
                size: meta.len(),
                modified: None,
            });
            Ok((file, entry, path.to_string()))
        }
        Err(direct_err) => {
            if let Ok(meta_entry) = bfs.metadata(path) {
                if meta_entry.kind == "directory" {
                    return Err(McBrowserError::BadRequest(format!(
                        "Expected a regular file at '{path}', found a directory"
                    )));
                }
            }
            let ResolvedFile {
                file,
                resolved_path,
                resolution_paths,
                entry,
            } = bfs
                .open_file_resolving_internal_links(path)
                .map_err(|_| map_fs_io_error(direct_err, "Failed to open file"))?;

            for hop in &resolution_paths {
                for &perm in permissions {
                    policy::authorize_with_conn(conn, user, perm, hop)?;
                }
            }
            for &perm in permissions {
                policy::authorize_with_conn(conn, user, perm, &resolved_path)?;
            }
            Ok((file, entry, resolved_path))
        }
    }
}

fn check_action_deadline(deadline: Instant, action_label: &str) -> Result<(), McBrowserError> {
    if Instant::now() > deadline {
        return Err(McBrowserError::RequestTimeout(format!(
            "{action_label} exceeded maximum execution time of {} seconds",
            MAX_ACTION_DURATION.as_secs()
        )));
    }
    Ok(())
}

struct BoundedDeadlineReader<R> {
    inner: R,
    bytes_read: u64,
    max_bytes: u64,
    deadline: Instant,
    context: &'static str,
}

impl<R> BoundedDeadlineReader<R> {
    fn new(inner: R, max_bytes: u64, deadline: Instant, context: &'static str) -> Self {
        Self {
            inner,
            bytes_read: 0,
            max_bytes,
            deadline,
            context,
        }
    }
}

impl<R: Read> Read for BoundedDeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("{} timed out", self.context),
            ));
        }
        let n = self.inner.read(buf)?;
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        if self.bytes_read > self.max_bytes {
            return Err(io::Error::new(
                ErrorKind::FileTooLarge,
                format!(
                    "{} exceeded maximum byte limit of {} bytes",
                    self.context, self.max_bytes
                ),
            ));
        }
        Ok(n)
    }
}

impl<R: Seek> Seek for BoundedDeadlineReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("{} timed out", self.context),
            ));
        }
        self.inner.seek(pos)
    }
}

struct CappedDeadlineWriter<W> {
    inner: W,
    written: u64,
    max_bytes: u64,
    quota_capped: bool,
    deadline: Instant,
}

impl<W> CappedDeadlineWriter<W> {
    fn new(inner: W, max_bytes: u64, quota_capped: bool, deadline: Instant) -> Self {
        Self {
            inner,
            written: 0,
            max_bytes,
            quota_capped,
            deadline,
        }
    }
}

impl<W: Write> Write for CappedDeadlineWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "archive write timed out",
            ));
        }
        let next_written = self.written.saturating_add(buf.len() as u64);
        if next_written > self.max_bytes {
            let kind = if self.quota_capped {
                ErrorKind::PermissionDenied
            } else {
                ErrorKind::FileTooLarge
            };
            return Err(io::Error::new(
                kind,
                if self.quota_capped {
                    "archive output exceeds available user storage quota"
                } else {
                    "archive output exceeds maximum allowed size"
                },
            ));
        }
        let n = self.inner.write(buf)?;
        self.written = self.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "archive flush timed out",
            ));
        }
        self.inner.flush()
    }
}

pub fn execute_compute_checksums_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_path: &str,
    raw_algorithms: &[String],
) -> Result<ComputeChecksumsActionResult, McBrowserError> {
    let _ = validate_mcbrowser_user(user)?;
    let normalized_path = policy::normalize_target_path(raw_path, false)?;
    let algorithms = parse_action_checksum_algorithms(raw_algorithms)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    let (file, _entry, _resolved_path) = open_authorized_action_file_with_conn(
        conn,
        user,
        bfs,
        &normalized_path,
        &[Permission::Execute, Permission::Read],
    )?;

    let meta = file
        .metadata()
        .map_err(|e| map_fs_io_error(e, "Failed to inspect file for checksum"))?;
    let size = meta.len();
    if size > MAX_ACTION_CHECKSUM_FILE_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File size ({size} bytes) exceeds maximum checksum limit of {MAX_ACTION_CHECKSUM_FILE_BYTES} bytes"
        )));
    }

    let reader = BoundedDeadlineReader::new(
        file,
        MAX_ACTION_CHECKSUM_FILE_BYTES,
        deadline,
        "ComputeChecksums",
    );
    let checksums = compute_checksums_from_reader(reader, &algorithms).map_err(|err| {
        if err.kind() == ErrorKind::TimedOut {
            McBrowserError::RequestTimeout(
                "ComputeChecksums exceeded maximum execution time".to_string(),
            )
        } else if err.kind() == ErrorKind::FileTooLarge {
            McBrowserError::PayloadTooLarge(
                "File grew beyond maximum checksum size limit during read".to_string(),
            )
        } else {
            map_fs_io_error(err, "Failed to compute file checksums")
        }
    })?;

    Ok(ComputeChecksumsActionResult {
        path: normalized_path,
        size,
        checksums,
    })
}

pub fn execute_inspect_media_metadata_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_path: &str,
) -> Result<InspectMediaMetadataActionResult, McBrowserError> {
    let _ = validate_mcbrowser_user(user)?;
    let normalized_path = policy::normalize_target_path(raw_path, false)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    policy::authorize_with_conn(conn, user, Permission::Execute, &normalized_path)?;
    policy::authorize_with_conn(conn, user, Permission::Read, &normalized_path)?;

    let resolved = bfs
        .metadata_resolving_internal_links(&normalized_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect media metadata"))?;
    for path in resolved
        .resolution_paths
        .iter()
        .chain(std::iter::once(&resolved.resolved_path))
    {
        policy::authorize_with_conn(conn, user, Permission::Execute, path)?;
        policy::authorize_with_conn(conn, user, Permission::Read, path)?;
    }
    let mut entry = resolved.entry;

    let mut content_type = None;
    let mut resolution = None;
    let mut subtitles = Vec::new();

    if entry.kind == "file" {
        match open_authorized_action_file_with_conn(
            conn,
            user,
            bfs,
            &normalized_path,
            &[Permission::Execute, Permission::Read],
        ) {
            Ok((mut file, verified_entry, _)) => {
                entry = verified_entry;
                if let Ok(meta) = file.metadata() {
                    entry.size = meta.len();
                    entry.modified = meta.modified().ok().map(|modified| {
                        chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339()
                    });
                }
                let mut sig = [0u8; 64];
                if let Ok(n) = file.read(&mut sig) {
                    content_type = media_type(&normalized_path, &sig[..n]).map(str::to_owned);
                }
                check_action_deadline(deadline, "InspectMediaMetadata")?;
                if content_type.as_deref().is_some_and(is_image_content_type) {
                    resolution = read_image_dimensions_from_file(&normalized_path, &mut file).ok();
                }
                check_action_deadline(deadline, "InspectMediaMetadata")?;
                if is_video_extension(&normalized_path) {
                    let discovered = discover_subtitles_in_fs(bfs, &normalized_path, |path| {
                        [Permission::Read, Permission::Execute]
                            .into_iter()
                            .all(|permission| {
                                policy::authorize_with_conn(conn, user, permission, path).is_ok()
                            })
                    })?;
                    check_action_deadline(deadline, "InspectMediaMetadata")?;
                    subtitles = discovered;
                }
            }
            Err(McBrowserError::Forbidden(err)) => return Err(McBrowserError::Forbidden(err)),
            Err(err) => return Err(err),
        }
    }

    check_action_deadline(deadline, "InspectMediaMetadata")?;
    entry.path = normalized_path.clone();
    entry.name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or(&normalized_path)
        .to_string();
    Ok(InspectMediaMetadataActionResult {
        path: entry.path,
        name: entry.name,
        kind: entry.kind,
        content_type,
        size: entry.size,
        modified: entry.modified,
        resolution,
        subtitles,
    })
}

pub fn execute_create_archive_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    source_paths: &[String],
    raw_destination_path: &str,
    raw_format: &str,
) -> Result<CreateArchiveActionResult, McBrowserError> {
    let user_id = validate_mcbrowser_user(user)?;
    let format = ArchiveFormat::parse(raw_format)?;
    let destination_path = policy::normalize_target_path(raw_destination_path, false)?;
    let _ = validate_archive_entry_name(&destination_path)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    policy::authorize_with_conn(conn, user, Permission::Execute, &destination_path)?;
    policy::authorize_with_conn(conn, user, Permission::Create, &destination_path)?;

    match bfs.metadata(&destination_path) {
        Ok(_) => {
            return Err(McBrowserError::Conflict(format!(
                "Archive destination '{destination_path}' already exists"
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(map_fs_io_error(
                err,
                "Failed to inspect archive destination",
            ));
        }
    }

    for source in source_paths {
        let normalized_source = policy::normalize_target_path(source, false)?;
        for permission in [Permission::Execute, Permission::Read, Permission::Download] {
            policy::authorize_with_conn(conn, user, permission, &normalized_source)?;
        }
    }

    let plan =
        super::operations::collect_archive_plan_for_user_with_conn(conn, bfs, user, source_paths)?;

    if plan.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive plan produced no entries".to_string(),
        ));
    }
    if plan.len() > MAX_ACTION_ARCHIVE_ENTRIES {
        return Err(McBrowserError::BadRequest(format!(
            "Archive exceeds maximum action entry limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
        )));
    }

    let dst_prefix = format!("{destination_path}/");
    let mut total_source_bytes: u64 = 0;

    for item in &plan {
        check_action_deadline(deadline, "CreateArchive")?;
        if item.fs_path == destination_path
            || item.fs_path.starts_with(&dst_prefix)
            || destination_path.starts_with(&format!("{}/", item.fs_path))
            || item.resolved_path == destination_path
            || item.resolved_path.starts_with(&dst_prefix)
            || item.resolved_path.is_empty()
            || destination_path.starts_with(&format!("{}/", item.resolved_path))
        {
            return Err(McBrowserError::BadRequest(
                "Archive destination path cannot overlap with source paths".to_string(),
            ));
        }
        for source_path in &item.authorization_paths {
            policy::authorize_with_conn(conn, user, Permission::Execute, source_path)?;
            policy::authorize_with_conn(conn, user, Permission::Read, source_path)?;
        }

        if !item.is_dir {
            total_source_bytes = total_source_bytes.saturating_add(item.source_size);
            if total_source_bytes > MAX_ACTION_CREATE_ARCHIVE_SOURCE_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Total source file size exceeds maximum CreateArchive limit of {MAX_ACTION_CREATE_ARCHIVE_SOURCE_BYTES} bytes"
                )));
            }
        }
    }

    let quota_snapshot = load_active_quota_conn(conn, user_id, 0)?;
    let (max_output_bytes, quota_capped) = if quota_snapshot.quota_bytes > 0 {
        let remaining = quota_snapshot
            .quota_bytes
            .saturating_sub(quota_snapshot.used_bytes)
            .max(0) as u64;
        if remaining == 0 {
            return Err(McBrowserError::QuotaExceeded(
                "Storage quota exceeded. Free up space or contact an administrator.".to_string(),
            ));
        }
        if remaining < MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES {
            (remaining, true)
        } else {
            (MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES, false)
        }
    } else {
        (MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES, false)
    };

    let mut parent_dirs_to_create: Vec<String> = Vec::new();
    if let Some((parent_path, _)) = destination_path.rsplit_once('/') {
        let mut prefix = String::new();
        for seg in parent_path.split('/') {
            prefix = if prefix.is_empty() {
                seg.to_string()
            } else {
                format!("{prefix}/{seg}")
            };
            match bfs.metadata(&prefix) {
                Ok(existing) if existing.kind == "directory" => {}
                Ok(_) => {
                    return Err(McBrowserError::Conflict(format!(
                        "Ancestor path '{prefix}' exists and is not a directory"
                    )));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
                    policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
                    parent_dirs_to_create.push(prefix.clone());
                }
                Err(err) => {
                    return Err(map_fs_io_error(
                        err,
                        "Failed to inspect archive destination ancestor directory",
                    ));
                }
            }
        }
    }

    let audit = super::events::record_pending_intent_with_conn(
        conn,
        user,
        super::events::McBrowserEventTrigger::UploadCompleted,
        &destination_path,
        None,
        0,
    )?;
    let quota_cleanup_complete = std::cell::Cell::new(true);
    let fail_unpublished = |error: McBrowserError, created_dirs: &[String]| {
        let mut cleanup_complete = quota_cleanup_complete.get();
        for directory in created_dirs.iter().rev() {
            if let Err(cleanup_error) = bfs.remove(directory) {
                if cleanup_error.kind() != ErrorKind::NotFound {
                    cleanup_complete = false;
                }
            }
        }
        if cleanup_complete {
            let _ = super::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("ARCHIVE_NOT_PUBLISHED"),
            );
        }
        error
    };
    for (created_count, ancestor) in parent_dirs_to_create.iter().enumerate() {
        if let Err(error) = bfs.create_directory(ancestor) {
            return Err(fail_unpublished(
                map_fs_io_error(
                    error,
                    "Failed to create archive destination parent directory",
                ),
                &parent_dirs_to_create[..created_count],
            ));
        }
    }

    let pending = match bfs.begin_upload(&destination_path) {
        Ok(pending) => pending,
        Err(error) => {
            return Err(fail_unpublished(
                map_fs_io_error(error, "Failed to stage destination archive"),
                &parent_dirs_to_create,
            ));
        }
    };
    let staging_file = match pending.file() {
        Ok(file) => file,
        Err(error) => {
            drop(pending);
            return Err(fail_unpublished(
                map_fs_io_error(error, "Failed to access archive staging descriptor"),
                &parent_dirs_to_create,
            ));
        }
    };
    if let Err(err) = check_fd_free_space(staging_file.as_raw_fd(), total_source_bytes.max(4096)) {
        drop(staging_file);
        drop(pending);
        return Err(fail_unpublished(err, &parent_dirs_to_create));
    }

    let mut capped_writer =
        CappedDeadlineWriter::new(staging_file, max_output_bytes, quota_capped, deadline);

    if let Err(write_err) = write_archive_to_writer(bfs, &plan, format, &mut capped_writer) {
        drop(capped_writer);
        drop(pending);
        let error = match write_err.kind() {
            ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                "CreateArchive exceeded maximum execution time".to_string(),
            ),
            ErrorKind::PermissionDenied
                if write_err
                    .to_string()
                    .contains("available user storage quota") =>
            {
                McBrowserError::QuotaExceeded(
                    "Created archive exceeds available user storage quota".to_string(),
                )
            }
            ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(format!(
                "Created archive exceeds maximum allowed size of {MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES} bytes"
            )),
            _ => map_fs_io_error(write_err, "Failed to stream archive to staging file"),
        };
        return Err(fail_unpublished(error, &parent_dirs_to_create));
    }

    let archive_bytes = capped_writer.written;
    drop(capped_writer);

    if let Err(err) =
        policy::authorize_with_conn(conn, user, Permission::Execute, &destination_path).and_then(
            |()| policy::authorize_with_conn(conn, user, Permission::Create, &destination_path),
        )
    {
        drop(pending);
        return Err(fail_unpublished(err, &parent_dirs_to_create));
    }
    if archive_bytes > 0 {
        if let Err(err) = reserve_user_quota_atomic(conn, user_id, archive_bytes) {
            drop(pending);
            return Err(fail_unpublished(err, &parent_dirs_to_create));
        }
    }

    if let Err(commit_err) = pending.commit() {
        if archive_bytes > 0 {
            quota_cleanup_complete
                .set(release_user_quota_conn(conn, user_id, archive_bytes).is_ok());
        }
        return Err(fail_unpublished(
            map_fs_io_error(commit_err, "Failed to publish archive file"),
            &parent_dirs_to_create,
        ));
    }

    super::events::finalize_published_mutation_with_conn(
        conn,
        &audit,
        None,
        None,
        archive_bytes.min(i64::MAX as u64) as i64,
    );
    Ok(CreateArchiveActionResult {
        destination_path,
        format: format.algo_id().to_string(),
        entry_count: plan.len(),
        archive_bytes,
    })
}

pub fn detect_archive_format_from_path(path: &str) -> Result<ArchiveFormat, McBrowserError> {
    let lower = path.trim().to_ascii_lowercase();
    let compound = [
        (".tar.gz", ArchiveFormat::TarGz),
        (".tgz", ArchiveFormat::TarGz),
        (".tar.bz2", ArchiveFormat::TarBz2),
        (".tbz2", ArchiveFormat::TarBz2),
        (".tar.xz", ArchiveFormat::TarXz),
        (".txz", ArchiveFormat::TarXz),
        (".tar.lz4", ArchiveFormat::TarLz4),
        (".tlz4", ArchiveFormat::TarLz4),
        (".tar.sz", ArchiveFormat::TarSz),
        (".tsz", ArchiveFormat::TarSz),
        (".tar.br", ArchiveFormat::TarBr),
        (".tbr", ArchiveFormat::TarBr),
        (".tar.zst", ArchiveFormat::TarZst),
        (".tzst", ArchiveFormat::TarZst),
        (".zip", ArchiveFormat::Zip),
        (".tar", ArchiveFormat::Tar),
    ];
    for (suffix, fmt) in compound {
        if lower.ends_with(suffix) && lower.len() > suffix.len() {
            return Ok(fmt);
        }
    }
    Err(McBrowserError::BadRequest(
        "Unsupported archive filename extension: expected .zip, .tar, .tar.gz (.tgz), .tar.bz2 (.tbz2), .tar.xz (.txz), .tar.lz4 (.tlz4), .tar.sz (.tsz), .tar.br (.tbr), or .tar.zst (.tzst)".to_string(),
    ))
}

pub fn validate_extract_entry_relative_path(
    raw_name: &str,
) -> Result<(String, bool), McBrowserError> {
    if raw_name.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive contains an entry with an empty name".to_string(),
        ));
    }
    if raw_name.as_bytes().contains(&0) || raw_name.chars().any(char::is_control) {
        return Err(McBrowserError::BadRequest(
            "Archive entry name contains NUL or control characters".to_string(),
        ));
    }
    if raw_name.starts_with('/') || raw_name.contains('\\') || raw_name.contains(':') {
        return Err(McBrowserError::BadRequest(
            "Archive entry name contains forbidden absolute, backslash, or drive characters"
                .to_string(),
        ));
    }

    let is_dir_hint = raw_name.ends_with('/');
    let trimmed = raw_name.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive entry resolves to root directory".to_string(),
        ));
    }

    for segment in trimmed.split('/') {
        if segment.is_empty() || segment.trim().is_empty() {
            return Err(McBrowserError::BadRequest(
                "Archive entry contains an empty or whitespace-only path segment".to_string(),
            ));
        }
        if segment == "." || segment == ".." {
            return Err(McBrowserError::BadRequest(
                "Archive entry contains path traversal segments".to_string(),
            ));
        }
        if segment.starts_with(".af-upload-tmp.") || segment == ".af-upload-staging" {
            return Err(McBrowserError::BadRequest(
                "Archive entry uses a reserved staging filename".to_string(),
            ));
        }
    }

    let normalized = policy::normalize_target_path(trimmed, false)?;
    let _ = validate_archive_entry_name(&normalized)?;
    Ok((normalized, is_dir_hint))
}

fn check_compression_ratio(
    archive_compressed_size: u64,
    expanded_bytes: u64,
) -> Result<(), McBrowserError> {
    if expanded_bytes <= ACTION_COMPRESSION_RATIO_GRACE_BYTES {
        return Ok(());
    }
    let baseline = archive_compressed_size.max(1);
    let max_allowed = baseline
        .saturating_mul(MAX_ACTION_EXTRACT_COMPRESSION_RATIO)
        .saturating_add(ACTION_COMPRESSION_RATIO_GRACE_BYTES);
    if expanded_bytes > max_allowed {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Archive decompression ratio exceeds maximum safety limit ({MAX_ACTION_EXTRACT_COMPRESSION_RATIO}:1)"
        )));
    }
    Ok(())
}

fn preflight_authorize_and_check_destination_entry(
    conn: &Connection,
    _bfs: &BrowserFs,
    user: &AuthUser,
    destination_dir: &str,
    rel_entry_path: &str,
    seen_files: &mut HashSet<String>,
    seen_dirs: &mut HashSet<String>,
    is_dir: bool,
) -> Result<String, McBrowserError> {
    let full_target = format!("{destination_dir}/{rel_entry_path}");
    let normalized_target = policy::normalize_target_path(&full_target, false)?;

    let mut prefix = destination_dir.to_string();
    let segments: Vec<&str> = rel_entry_path.split('/').collect();
    for (idx, seg) in segments.iter().enumerate() {
        prefix = format!("{prefix}/{seg}");
        let is_last = idx + 1 == segments.len();
        if !is_last || is_dir {
            if seen_files.contains(&prefix) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains conflicting file and directory paths at '{rel_entry_path}'"
                )));
            }
            if is_last && is_dir && !seen_dirs.insert(prefix.clone()) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains duplicate directory entry '{rel_entry_path}'"
                )));
            }
            seen_dirs.insert(prefix.clone());
            policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
            policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        } else {
            if seen_dirs.contains(&prefix) || !seen_files.insert(prefix.clone()) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains duplicate or conflicting entry path '{rel_entry_path}'"
                )));
            }
            policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
            policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        }
    }

    Ok(normalized_target)
}

const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const ZIP_CENTRAL_DIR_HEADER_SIG: u32 = 0x02014b50;
const ZIP_EOCD_SIG: u32 = 0x06054b50;
const ZIP_EOCD64_SIG: u32 = 0x06064b50;
const ZIP_EOCD64_LOCATOR_SIG: u32 = 0x07064b50;
pub const MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES: u64 = 8 * 1024 * 1024;
const ZIP_ADMISSION_READ_LIMIT_BYTES: u64 = MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES + 131_072;

#[derive(Debug, Clone, Copy)]
struct ZipDirectoryAdmission {
    entries: usize,
    offset: u64,
    size: u64,
}

struct AdmittedZipReader {
    file: File,
    directory_end: u64,
    footer: [u8; 98],
    position: u64,
    length: u64,
}

impl AdmittedZipReader {
    fn new(file: File, admission: ZipDirectoryAdmission) -> io::Result<Self> {
        let directory_end = admission
            .offset
            .checked_add(admission.size)
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "ZIP directory extent overflow")
            })?;
        let length = directory_end.checked_add(98).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "ZIP metadata extent overflow")
        })?;
        let mut footer = [0u8; 98];
        footer[0..4].copy_from_slice(&ZIP_EOCD64_SIG.to_le_bytes());
        footer[4..12].copy_from_slice(&44u64.to_le_bytes());
        footer[12..14].copy_from_slice(&45u16.to_le_bytes());
        footer[14..16].copy_from_slice(&45u16.to_le_bytes());
        footer[24..32].copy_from_slice(&(admission.entries as u64).to_le_bytes());
        footer[32..40].copy_from_slice(&(admission.entries as u64).to_le_bytes());
        footer[40..48].copy_from_slice(&admission.size.to_le_bytes());
        footer[48..56].copy_from_slice(&admission.offset.to_le_bytes());
        footer[56..60].copy_from_slice(&ZIP_EOCD64_LOCATOR_SIG.to_le_bytes());
        footer[64..72].copy_from_slice(&directory_end.to_le_bytes());
        footer[72..76].copy_from_slice(&1u32.to_le_bytes());
        footer[76..80].copy_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
        footer[84..86].copy_from_slice(&u16::MAX.to_le_bytes());
        footer[86..88].copy_from_slice(&u16::MAX.to_le_bytes());
        footer[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
        footer[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
        Ok(Self {
            file,
            directory_end,
            footer,
            position: 0,
            length,
        })
    }
}

impl Read for AdmittedZipReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || buffer.is_empty() {
            return Ok(0);
        }
        let bytes_read = if self.position < self.directory_end {
            let limit = (self.directory_end - self.position).min(buffer.len() as u64) as usize;
            self.file.seek(SeekFrom::Start(self.position))?;
            self.file.read(&mut buffer[..limit])?
        } else {
            let footer_offset = (self.position - self.directory_end) as usize;
            let limit = (self.footer.len() - footer_offset).min(buffer.len());
            buffer[..limit].copy_from_slice(&self.footer[footer_offset..footer_offset + limit]);
            limit
        };
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for AdmittedZipReader {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        let position = match offset {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "ZIP seek is out of bounds"))?;
        Ok(self.position)
    }
}

fn map_zip_io_error(err: io::Error, default_msg: &str) -> McBrowserError {
    match err.kind() {
        ErrorKind::TimedOut => McBrowserError::RequestTimeout(
            "ExtractArchive exceeded maximum execution time".to_string(),
        ),
        ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
            "ZIP archive metadata or stream exceeds safety limit".to_string(),
        ),
        _ => McBrowserError::BadRequest(default_msg.to_string()),
    }
}

fn skip_exact_bounded<R: Read>(reader: &mut R, mut remaining: u64) -> Result<(), McBrowserError> {
    let mut scratch = [0u8; 4096];
    while remaining > 0 {
        let step = (remaining as usize).min(scratch.len());
        reader
            .read_exact(&mut scratch[..step])
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory"))?;
        remaining -= step as u64;
    }
    Ok(())
}

fn preflight_zip_raw_headers_for_encryption(
    file: &mut File,
    file_len: u64,
    deadline: Instant,
) -> Result<ZipDirectoryAdmission, McBrowserError> {
    check_action_deadline(deadline, "ExtractArchive ZIP admission")?;
    if file_len < 22 {
        return Err(McBrowserError::BadRequest(
            "Corrupt or truncated ZIP archive".to_string(),
        ));
    }

    let cloned = file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone ZIP descriptor for admission"))?;
    let mut reader = BoundedDeadlineReader::new(
        cloned,
        ZIP_ADMISSION_READ_LIMIT_BYTES,
        deadline,
        "ExtractArchive ZIP admission",
    );

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP archive"))?;
    let mut sig_buf = [0u8; 4];
    reader
        .read_exact(&mut sig_buf)
        .map_err(|e| map_zip_io_error(e, "Corrupt or unreadable ZIP header"))?;
    let first_sig = u32::from_le_bytes(sig_buf);
    if first_sig != ZIP_LOCAL_FILE_HEADER_SIG && first_sig != ZIP_EOCD_SIG {
        return Err(McBrowserError::BadRequest(
            "Invalid ZIP archive signature".to_string(),
        ));
    }
    if first_sig == ZIP_LOCAL_FILE_HEADER_SIG {
        let mut lfh_rest = [0u8; 26];
        reader
            .read_exact(&mut lfh_rest)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP local file header"))?;
        let flags = u16::from_le_bytes([lfh_rest[2], lfh_rest[3]]);
        let method = u16::from_le_bytes([lfh_rest[4], lfh_rest[5]]);
        if (flags & 0x0001) != 0 || (flags & 0x0040) != 0 || method == 99 {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }
    }

    let tail_len = file_len.min(65_577) as usize;
    let tail_start = file_len.saturating_sub(tail_len as u64);
    reader
        .seek(SeekFrom::Start(tail_start))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP central directory"))?;
    let mut tail = vec![0u8; tail_len];
    reader
        .read_exact(&mut tail)
        .map_err(|e| map_zip_io_error(e, "Failed to read ZIP central directory"))?;

    let mut eocd_pos: Option<usize> = None;
    if tail.len() >= 22 {
        for idx in (0..=tail.len() - 22).rev() {
            if u32::from_le_bytes([tail[idx], tail[idx + 1], tail[idx + 2], tail[idx + 3]])
                == ZIP_EOCD_SIG
            {
                let comment_len = u16::from_le_bytes([tail[idx + 20], tail[idx + 21]]) as usize;
                if idx + 22 + comment_len == tail.len() {
                    eocd_pos = Some(idx);
                    break;
                }
            }
        }
    }

    let Some(eocd_idx) = eocd_pos else {
        return Err(McBrowserError::BadRequest(
            "Missing or corrupt ZIP end of central directory record".to_string(),
        ));
    };

    let eocd_abs_offset = tail_start + (eocd_idx as u64);
    let disk_number = u16::from_le_bytes([tail[eocd_idx + 4], tail[eocd_idx + 5]]);
    let cd_disk_number = u16::from_le_bytes([tail[eocd_idx + 6], tail[eocd_idx + 7]]);
    let disk_entries_16 = u16::from_le_bytes([tail[eocd_idx + 8], tail[eocd_idx + 9]]);
    let total_entries_16 = u16::from_le_bytes([tail[eocd_idx + 10], tail[eocd_idx + 11]]);
    let cd_size_32 = u32::from_le_bytes([
        tail[eocd_idx + 12],
        tail[eocd_idx + 13],
        tail[eocd_idx + 14],
        tail[eocd_idx + 15],
    ]);
    let cd_offset_32 = u32::from_le_bytes([
        tail[eocd_idx + 16],
        tail[eocd_idx + 17],
        tail[eocd_idx + 18],
        tail[eocd_idx + 19],
    ]);

    let has_zip64_locator = eocd_idx >= 20
        && (cd_offset_32 == u32::MAX
            || cd_size_32 == u32::MAX
            || u64::from(cd_offset_32) + u64::from(cd_size_32) <= eocd_abs_offset - 20)
        && u32::from_le_bytes([
            tail[eocd_idx - 20],
            tail[eocd_idx - 19],
            tail[eocd_idx - 18],
            tail[eocd_idx - 17],
        ]) == ZIP_EOCD64_LOCATOR_SIG;

    let requires_zip64 = disk_number == u16::MAX
        || cd_disk_number == u16::MAX
        || disk_entries_16 == u16::MAX
        || total_entries_16 == u16::MAX
        || cd_size_32 == u32::MAX
        || cd_offset_32 == u32::MAX;

    let (declared_entries, cd_size, cd_offset, cd_upper_bound) = if has_zip64_locator
        || requires_zip64
    {
        if !has_zip64_locator || eocd_abs_offset < 20 {
            return Err(McBrowserError::BadRequest(
                "Missing or corrupt ZIP64 end of central directory locator".to_string(),
            ));
        }
        let loc_idx = eocd_idx - 20;
        let locator_abs_offset = eocd_abs_offset - 20;
        let z64_cd_disk = u32::from_le_bytes([
            tail[loc_idx + 4],
            tail[loc_idx + 5],
            tail[loc_idx + 6],
            tail[loc_idx + 7],
        ]);
        let z64_eocd_offset = u64::from_le_bytes([
            tail[loc_idx + 8],
            tail[loc_idx + 9],
            tail[loc_idx + 10],
            tail[loc_idx + 11],
            tail[loc_idx + 12],
            tail[loc_idx + 13],
            tail[loc_idx + 14],
            tail[loc_idx + 15],
        ]);
        let z64_total_disks = u32::from_le_bytes([
            tail[loc_idx + 16],
            tail[loc_idx + 17],
            tail[loc_idx + 18],
            tail[loc_idx + 19],
        ]);
        if z64_cd_disk != 0 || (z64_total_disks != 0 && z64_total_disks != 1) {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP64 archives are not supported".to_string(),
            ));
        }
        if (disk_number != 0 && disk_number != u16::MAX)
            || (cd_disk_number != 0 && cd_disk_number != u16::MAX)
        {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archives are not supported".to_string(),
            ));
        }
        if z64_eocd_offset.checked_add(56).is_none() || z64_eocd_offset + 56 > locator_abs_offset {
            return Err(McBrowserError::BadRequest(
                "Invalid or out-of-bounds ZIP64 EOCD offset".to_string(),
            ));
        }

        reader
            .seek(SeekFrom::Start(z64_eocd_offset))
            .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP64 EOCD record"))?;
        let mut z64_buf = [0u8; 56];
        reader
            .read_exact(&mut z64_buf)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP64 EOCD record"))?;

        if u32::from_le_bytes([z64_buf[0], z64_buf[1], z64_buf[2], z64_buf[3]]) != ZIP_EOCD64_SIG {
            return Err(McBrowserError::BadRequest(
                "Invalid ZIP64 EOCD signature".to_string(),
            ));
        }
        let z64_record_size = u64::from_le_bytes(z64_buf[4..12].try_into().unwrap());
        if z64_record_size < 44 {
            return Err(McBrowserError::BadRequest(
                "Malformed ZIP64 EOCD record size".to_string(),
            ));
        }
        let z64_total_record_bytes = 12u64.checked_add(z64_record_size).ok_or_else(|| {
            McBrowserError::BadRequest("ZIP64 EOCD record size overflow".to_string())
        })?;
        let z64_end = z64_eocd_offset
            .checked_add(z64_total_record_bytes)
            .ok_or_else(|| McBrowserError::BadRequest("ZIP64 EOCD span overflow".to_string()))?;
        if z64_end > locator_abs_offset {
            return Err(McBrowserError::BadRequest(
                "ZIP64 EOCD record overlaps locator".to_string(),
            ));
        }

        let z64_disk_num = u32::from_le_bytes(z64_buf[16..20].try_into().unwrap());
        let z64_cd_disk_num = u32::from_le_bytes(z64_buf[20..24].try_into().unwrap());
        if z64_disk_num != 0 || z64_cd_disk_num != 0 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP64 archives are not supported".to_string(),
            ));
        }

        let z64_disk_entries = u64::from_le_bytes(z64_buf[24..32].try_into().unwrap());
        let z64_total_entries = u64::from_le_bytes(z64_buf[32..40].try_into().unwrap());
        let z64_cd_size = u64::from_le_bytes(z64_buf[40..48].try_into().unwrap());
        let z64_cd_offset = u64::from_le_bytes(z64_buf[48..56].try_into().unwrap());

        if z64_disk_entries != z64_total_entries {
            return Err(McBrowserError::BadRequest(
                "Split central directory ZIP64 archives are not supported".to_string(),
            ));
        }
        if disk_entries_16 != u16::MAX && (disk_entries_16 as u64) != z64_disk_entries {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory entry counts".to_string(),
            ));
        }
        if total_entries_16 != u16::MAX && (total_entries_16 as u64) != z64_total_entries {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 total entry counts".to_string(),
            ));
        }
        if cd_size_32 != u32::MAX && (cd_size_32 as u64) != z64_cd_size {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory size".to_string(),
            ));
        }
        if cd_offset_32 != u32::MAX && (cd_offset_32 as u64) != z64_cd_offset {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory offset".to_string(),
            ));
        }

        (
            z64_total_entries,
            z64_cd_size,
            z64_cd_offset,
            z64_eocd_offset,
        )
    } else {
        if disk_number != 0 || cd_disk_number != 0 || disk_entries_16 != total_entries_16 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archives are not supported".to_string(),
            ));
        }
        (
            total_entries_16 as u64,
            cd_size_32 as u64,
            cd_offset_32 as u64,
            eocd_abs_offset,
        )
    };

    if declared_entries == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no entries".to_string(),
        ));
    }
    if declared_entries > MAX_ACTION_ARCHIVE_ENTRIES as u64 {
        return Err(McBrowserError::BadRequest(format!(
            "Archive entry count ({declared_entries}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
        )));
    }
    if cd_size == 0 {
        return Err(McBrowserError::BadRequest(
            "Corrupt ZIP central directory size".to_string(),
        ));
    }
    if cd_size > MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "ZIP central directory size ({cd_size} bytes) exceeds maximum limit of {MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES} bytes"
        )));
    }
    let cd_end = cd_offset.checked_add(cd_size).ok_or_else(|| {
        McBrowserError::BadRequest("ZIP central directory offset overflow".to_string())
    })?;
    if cd_end > cd_upper_bound || cd_end > file_len {
        return Err(McBrowserError::BadRequest(
            "ZIP central directory span is out of bounds".to_string(),
        ));
    }

    reader
        .seek(SeekFrom::Start(cd_offset))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP central directory"))?;

    let mut consumed = 0u64;
    let mut actual_entries = 0usize;
    let mut header_buf = [0u8; 46];
    let mut extra_buf = Vec::new();

    while consumed < cd_size {
        check_action_deadline(deadline, "ExtractArchive ZIP admission")?;
        if cd_size - consumed < 46 {
            return Err(McBrowserError::BadRequest(
                "Truncated or misaligned ZIP central directory entry".to_string(),
            ));
        }
        actual_entries = actual_entries.saturating_add(1);
        if actual_entries > MAX_ACTION_ARCHIVE_ENTRIES {
            return Err(McBrowserError::BadRequest(format!(
                "Archive entry count ({actual_entries}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
            )));
        }

        reader
            .read_exact(&mut header_buf)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory header"))?;
        let sig = u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        if sig != ZIP_CENTRAL_DIR_HEADER_SIG {
            return Err(McBrowserError::BadRequest(
                "Invalid ZIP central directory entry signature".to_string(),
            ));
        }

        let flags = u16::from_le_bytes([header_buf[8], header_buf[9]]);
        let method = u16::from_le_bytes([header_buf[10], header_buf[11]]);
        if (flags & 0x0001) != 0 || (flags & 0x0040) != 0 || method == 99 {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }

        let comp_32 = u32::from_le_bytes([
            header_buf[20],
            header_buf[21],
            header_buf[22],
            header_buf[23],
        ]);
        let uncomp_32 = u32::from_le_bytes([
            header_buf[24],
            header_buf[25],
            header_buf[26],
            header_buf[27],
        ]);
        let name_len = u16::from_le_bytes([header_buf[28], header_buf[29]]) as u64;
        let extra_len = u16::from_le_bytes([header_buf[30], header_buf[31]]) as usize;
        let comment_len = u16::from_le_bytes([header_buf[32], header_buf[33]]) as u64;
        let disk_start_16 = u16::from_le_bytes([header_buf[34], header_buf[35]]);
        let lfh_offset_32 = u32::from_le_bytes([
            header_buf[42],
            header_buf[43],
            header_buf[44],
            header_buf[45],
        ]);

        let entry_total_len = 46u64 + name_len + (extra_len as u64) + comment_len;
        if consumed + entry_total_len > cd_size {
            return Err(McBrowserError::BadRequest(
                "ZIP central directory entry extends past central directory boundary".to_string(),
            ));
        }

        skip_exact_bounded(&mut reader, name_len)?;
        extra_buf.resize(extra_len, 0);
        if extra_len > 0 {
            reader
                .read_exact(&mut extra_buf)
                .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory extra field"))?;
        }
        skip_exact_bounded(&mut reader, comment_len)?;

        let mut lfh_offset = lfh_offset_32 as u64;
        let mut disk_start = disk_start_16 as u32;
        let need_uncomp_64 = uncomp_32 == u32::MAX;
        let need_comp_64 = comp_32 == u32::MAX;
        let need_offset_64 = lfh_offset_32 == u32::MAX;
        let need_disk_64 = disk_start_16 == u16::MAX;

        {
            let mut found_z64_extra = false;
            let mut pos = 0usize;
            while pos + 4 <= extra_buf.len() {
                let header_id = u16::from_le_bytes([extra_buf[pos], extra_buf[pos + 1]]);
                let data_size =
                    u16::from_le_bytes([extra_buf[pos + 2], extra_buf[pos + 3]]) as usize;
                pos += 4;
                if pos + data_size > extra_buf.len() {
                    return Err(McBrowserError::BadRequest(
                        "Malformed ZIP central directory extra field".to_string(),
                    ));
                }
                if header_id == 0x0001 {
                    if found_z64_extra {
                        return Err(McBrowserError::BadRequest(
                            "Duplicate ZIP64 extended information extra field".to_string(),
                        ));
                    }
                    let field = &extra_buf[pos..pos + data_size];
                    let mut fpos = 0usize;
                    if need_uncomp_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 uncompressed size in extra field".to_string(),
                            ));
                        }
                        fpos += 8;
                    }
                    if need_comp_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 compressed size in extra field".to_string(),
                            ));
                        }
                        fpos += 8;
                    }
                    if need_offset_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 local header offset in extra field".to_string(),
                            ));
                        }
                        lfh_offset = u64::from_le_bytes(field[fpos..fpos + 8].try_into().unwrap());
                        fpos += 8;
                    }
                    if need_disk_64 {
                        if fpos + 4 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 disk number in extra field".to_string(),
                            ));
                        }
                        disk_start = u32::from_le_bytes(field[fpos..fpos + 4].try_into().unwrap());
                    }
                    found_z64_extra = true;
                }
                pos += data_size;
            }
            if !found_z64_extra
                && (need_uncomp_64 || need_comp_64 || need_offset_64 || need_disk_64)
            {
                return Err(McBrowserError::BadRequest(
                    "Missing required ZIP64 extended information extra field".to_string(),
                ));
            }
        }

        if disk_start != 0 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archive entries are not supported".to_string(),
            ));
        }
        if lfh_offset.checked_add(30).is_none() || lfh_offset + 30 > cd_offset {
            return Err(McBrowserError::BadRequest(
                "ZIP entry local header offset is out of bounds".to_string(),
            ));
        }

        consumed += entry_total_len;
    }

    if actual_entries as u64 != declared_entries {
        return Err(McBrowserError::BadRequest(
            "ZIP central directory entry count does not match declared EOCD count".to_string(),
        ));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind ZIP archive"))?;
    Ok(ZipDirectoryAdmission {
        entries: actual_entries,
        offset: cd_offset,
        size: cd_size,
    })
}

fn open_admitted_zip_archive(
    archive_file: &mut File,
    archive_size: u64,
    deadline: Instant,
    context: &'static str,
) -> Result<
    (
        zip::ZipArchive<BoundedDeadlineReader<AdmittedZipReader>>,
        usize,
    ),
    McBrowserError,
> {
    let admission = preflight_zip_raw_headers_for_encryption(archive_file, archive_size, deadline)?;
    let reader = archive_file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone archive descriptor"))?;
    let max_zip_read_bytes = archive_size
        .saturating_mul(4)
        .saturating_add(MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES)
        .saturating_add(1024 * 1024);
    let admitted_reader = AdmittedZipReader::new(reader, admission)
        .map_err(|error| map_zip_io_error(error, "Failed to bind admitted ZIP metadata"))?;
    let bounded_reader =
        BoundedDeadlineReader::new(admitted_reader, max_zip_read_bytes, deadline, context);
    let zip = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        bounded_reader,
    )
    .map_err(|err| {
        if Instant::now() > deadline {
            return McBrowserError::RequestTimeout(
                "ExtractArchive exceeded maximum execution time".to_string(),
            );
        }
        if let zip::result::ZipError::Io(io_err) = &err {
            if io_err.kind() == ErrorKind::TimedOut {
                return McBrowserError::RequestTimeout(
                    "ExtractArchive exceeded maximum execution time".to_string(),
                );
            }
            if io_err.kind() == ErrorKind::FileTooLarge {
                return McBrowserError::PayloadTooLarge(
                    "ZIP archive read stream exceeds safety limit".to_string(),
                );
            }
        }
        let msg = err.to_string();
        if msg.to_ascii_lowercase().contains("password")
            || msg.to_ascii_lowercase().contains("encrypt")
        {
            McBrowserError::BadRequest("Encrypted ZIP archives are not supported".to_string())
        } else {
            McBrowserError::BadRequest(format!("Invalid or corrupt ZIP archive: {msg}"))
        }
    })?;

    let entry_count = zip.len();
    if entry_count == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no entries".to_string(),
        ));
    }
    if zip.offset() != 0 || zip.central_directory_start() != admission.offset {
        return Err(McBrowserError::BadRequest(
            "ZIP decoder did not retain admitted directory identity".to_string(),
        ));
    }
    if entry_count > MAX_ACTION_ARCHIVE_ENTRIES || entry_count != admission.entries {
        return Err(McBrowserError::BadRequest(format!(
            "Archive entry count ({entry_count}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES} or mismatches central directory admission"
        )));
    }
    Ok((zip, entry_count))
}

fn is_zip_unix_symlink_or_special(unix_mode: Option<u32>) -> bool {
    let Some(mode) = unix_mode else {
        return false;
    };
    let file_type = mode & (libc::S_IFMT as u32);
    if file_type == 0 {
        return false;
    }
    file_type != (libc::S_IFREG as u32) && file_type != (libc::S_IFDIR as u32)
}

#[derive(Debug, Clone)]
struct ZipPreflightItem {
    index: usize,
    target_path: String,
    is_dir: bool,
    declared_uncompressed: u64,
}

fn preflight_zip_archive(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    archive_file: &mut File,
    archive_size: u64,
    destination_dir: &str,
    deadline: Instant,
) -> Result<Vec<ZipPreflightItem>, McBrowserError> {
    let (mut zip, entry_count) = open_admitted_zip_archive(
        archive_file,
        archive_size,
        deadline,
        "ExtractArchive ZIP preflight",
    )?;

    let mut seen_files = HashSet::new();
    let mut seen_dirs = HashSet::new();
    let mut total_declared_uncompressed: u64 = 0;
    let mut total_actual_uncompressed = 0_u64;
    let mut buffer = [0_u8; ACTION_IO_BUF_BYTES];
    let mut items = Vec::with_capacity(entry_count);

    for idx in 0..entry_count {
        check_action_deadline(deadline, "ExtractArchive preflight")?;
        let mut entry = zip.by_index(idx).map_err(|err| {
            if let zip::result::ZipError::Io(io_err) = &err {
                if io_err.kind() == ErrorKind::TimedOut {
                    return McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    );
                }
                if io_err.kind() == ErrorKind::FileTooLarge {
                    return McBrowserError::PayloadTooLarge(
                        "ZIP archive read stream exceeds safety limit".to_string(),
                    );
                }
            }
            let msg = err.to_string();
            if msg.to_ascii_lowercase().contains("password")
                || msg.to_ascii_lowercase().contains("encrypt")
            {
                McBrowserError::BadRequest(
                    "Encrypted ZIP archive entries are not supported".to_string(),
                )
            } else {
                McBrowserError::BadRequest(format!("Malformed ZIP archive entry: {msg}"))
            }
        })?;

        if entry.encrypted() {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }

        if entry.is_symlink() || is_zip_unix_symlink_or_special(entry.unix_mode()) {
            return Err(McBrowserError::BadRequest(
                "Archive contains forbidden symlink or special device entry".to_string(),
            ));
        }

        let raw_name_bytes = entry.name_raw();
        let raw_name = std::str::from_utf8(raw_name_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry name is not valid UTF-8".to_string())
        })?;

        let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_name)?;
        let is_dir = entry.is_dir() || is_dir_hint;

        let declared_size = entry.size();
        let compressed_size = entry.compressed_size();
        if is_dir && declared_size > 0 {
            return Err(McBrowserError::BadRequest(
                "Archive directory entry cannot carry file payload bytes".to_string(),
            ));
        }
        if !is_dir {
            if declared_size > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive entry '{rel_path}' size ({declared_size} bytes) exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                )));
            }
            check_compression_ratio(compressed_size.max(1), declared_size)?;
            total_declared_uncompressed = total_declared_uncompressed.saturating_add(declared_size);
            if total_declared_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive total uncompressed size exceeds maximum limit of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                )));
            }
            check_compression_ratio(archive_size, total_declared_uncompressed)?;
        }

        let target_path = preflight_authorize_and_check_destination_entry(
            conn,
            bfs,
            user,
            destination_dir,
            &rel_path,
            &mut seen_files,
            &mut seen_dirs,
            is_dir,
        )?;

        let mut actual_size = 0_u64;
        loop {
            check_action_deadline(deadline, "ExtractArchive preflight")?;
            let count = entry.read(&mut buffer).map_err(|error| {
                if error.kind() == ErrorKind::TimedOut {
                    McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    )
                } else if error.kind() == ErrorKind::FileTooLarge {
                    McBrowserError::PayloadTooLarge(
                        "ZIP archive read stream exceeds safety limit".to_string(),
                    )
                } else {
                    McBrowserError::BadRequest(format!("Corrupt ZIP entry stream: {error}"))
                }
            })?;
            if count == 0 {
                break;
            }
            actual_size = actual_size.saturating_add(count as u64);
            total_actual_uncompressed = total_actual_uncompressed.saturating_add(count as u64);
            if actual_size > MAX_ACTION_EXTRACT_ENTRY_BYTES
                || total_actual_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES
            {
                return Err(McBrowserError::PayloadTooLarge(
                    "ZIP expanded bytes exceed extraction safety limits".to_string(),
                ));
            }
            check_compression_ratio(compressed_size.max(1), actual_size)?;
            check_compression_ratio(archive_size, total_actual_uncompressed)?;
        }
        if actual_size != declared_size {
            return Err(McBrowserError::BadRequest(
                "ZIP entry expanded size does not match its declared size".to_string(),
            ));
        }

        items.push(ZipPreflightItem {
            index: idx,
            target_path,
            is_dir,
            declared_uncompressed: declared_size,
        });
    }

    Ok(items)
}

fn open_tar_stream_decoder<'a>(
    format: ArchiveFormat,
    reader: Box<dyn Read + 'a>,
) -> Result<Box<dyn Read + 'a>, McBrowserError> {
    match format {
        ArchiveFormat::Tar => Ok(reader),
        ArchiveFormat::TarGz => Ok(Box::new(GzDecoder::new(reader))),
        ArchiveFormat::TarBz2 => Ok(Box::new(bzip2::read::BzDecoder::new(reader))),
        ArchiveFormat::TarXz => Ok(Box::new(xz2::read::XzDecoder::new(reader))),
        ArchiveFormat::TarLz4 => Ok(Box::new(lz4_flex::frame::FrameDecoder::new(reader))),
        ArchiveFormat::TarSz => Ok(Box::new(snap::read::FrameDecoder::new(reader))),
        ArchiveFormat::TarBr => Ok(Box::new(brotli::Decompressor::new(
            reader,
            ACTION_IO_BUF_BYTES,
        ))),
        ArchiveFormat::TarZst => {
            let dec = zstd::stream::read::Decoder::new(reader).map_err(|e| {
                McBrowserError::BadRequest(format!("Invalid zstd stream header: {e}"))
            })?;
            Ok(Box::new(dec))
        }
        ArchiveFormat::Zip => Err(McBrowserError::Internal(
            "Unexpected ZIP format in tar decoder".to_string(),
        )),
    }
}

fn is_allowed_tar_entry_type(entry_type: tar::EntryType) -> Result<Option<bool>, McBrowserError> {
    if entry_type == tar::EntryType::Regular
        || entry_type == tar::EntryType::Continuous
        || entry_type.as_byte() == 0
    {
        return Ok(Some(false));
    }
    if entry_type == tar::EntryType::Directory {
        return Ok(Some(true));
    }
    if entry_type == tar::EntryType::XHeader || entry_type == tar::EntryType::XGlobalHeader {
        return Ok(None);
    }
    if entry_type == tar::EntryType::GNULongName {
        return Ok(None);
    }
    Err(McBrowserError::BadRequest(format!(
        "Archive contains forbidden entry type {:?} (symlinks, hardlinks, and special devices are prohibited)",
        entry_type
    )))
}

fn preflight_tar_archive(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    archive_file: &mut File,
    archive_size: u64,
    format: ArchiveFormat,
    destination_dir: &str,
    deadline: Instant,
) -> Result<(usize, u64), McBrowserError> {
    archive_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to seek archive for preflight"))?;
    let reader = archive_file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone archive handle"))?;

    let bounded_source = BoundedDeadlineReader::new(
        reader,
        MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES,
        deadline,
        "ExtractArchive source read",
    );
    let decoder = open_tar_stream_decoder(format, Box::new(bounded_source))?;
    let max_tar_stream_bytes = MAX_ACTION_EXTRACT_TOTAL_BYTES
        .saturating_add((MAX_ACTION_ARCHIVE_ENTRIES as u64) * 2048)
        .saturating_add(1024 * 1024);
    let bounded_decompressed = BoundedDeadlineReader::new(
        decoder,
        max_tar_stream_bytes,
        deadline,
        "ExtractArchive stream decompression",
    );

    let mut archive = tar::Archive::new(bounded_decompressed);
    let entries = archive.entries().map_err(|e| {
        McBrowserError::BadRequest(format!("Invalid or corrupt tar archive header: {e}"))
    })?;

    let mut seen_files = HashSet::new();
    let mut seen_dirs = HashSet::new();
    let mut total_uncompressed: u64 = 0;
    let mut entry_count: usize = 0;
    let mut copy_buf = vec![0u8; ACTION_IO_BUF_BYTES];

    for entry_res in entries {
        check_action_deadline(deadline, "ExtractArchive preflight")?;
        let mut entry = entry_res.map_err(|err| match err.kind() {
            ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                "ExtractArchive exceeded maximum execution time".to_string(),
            ),
            ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
                "Archive decompressed stream exceeds safety limit".to_string(),
            ),
            _ => McBrowserError::BadRequest(format!("Corrupt tar archive entry: {err}")),
        })?;

        let entry_type = entry.header().entry_type();
        let Some(is_dir_header) = is_allowed_tar_entry_type(entry_type)? else {
            continue;
        };

        if let Some(link_bytes) = entry.link_name_bytes() {
            if !link_bytes.is_empty() {
                return Err(McBrowserError::BadRequest(
                    "Archive entry specifies a link target (symlinks and hardlinks are prohibited)"
                        .to_string(),
                ));
            }
        }

        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_ACTION_ARCHIVE_ENTRIES {
            return Err(McBrowserError::BadRequest(format!(
                "Archive exceeds maximum entry count limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
            )));
        }

        let raw_header_bytes = entry.header().path_bytes();
        let raw_header_str = std::str::from_utf8(&raw_header_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
        })?;
        let raw_path_bytes = entry.path_bytes();
        let raw_path_str = std::str::from_utf8(&raw_path_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
        })?;

        if !raw_header_str.is_empty() && raw_header_str != "././@LongLink" {
            let _ = validate_extract_entry_relative_path(raw_header_str)?;
        }
        let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_path_str)?;
        let is_dir = is_dir_header || is_dir_hint;

        let declared_size = entry
            .header()
            .size()
            .map_err(|_| McBrowserError::BadRequest("Invalid tar entry size header".to_string()))?;

        if is_dir && declared_size > 0 {
            return Err(McBrowserError::BadRequest(
                "Archive directory entry cannot carry file payload bytes".to_string(),
            ));
        }

        let _ = preflight_authorize_and_check_destination_entry(
            conn,
            bfs,
            user,
            destination_dir,
            &rel_path,
            &mut seen_files,
            &mut seen_dirs,
            is_dir,
        )?;

        if !is_dir {
            if declared_size > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive entry '{rel_path}' size ({declared_size} bytes) exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                )));
            }

            let mut entry_actual: u64 = 0;
            loop {
                check_action_deadline(deadline, "ExtractArchive preflight")?;
                match entry.read(&mut copy_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        entry_actual = entry_actual.saturating_add(n as u64);
                        total_uncompressed = total_uncompressed.saturating_add(n as u64);
                        if entry_actual > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                            return Err(McBrowserError::PayloadTooLarge(format!(
                                "Archive entry '{rel_path}' exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                            )));
                        }
                        if total_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                            return Err(McBrowserError::PayloadTooLarge(format!(
                                "Archive total expanded size exceeds limit of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                            )));
                        }
                        check_compression_ratio(archive_size, total_uncompressed)?;
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::TimedOut => {
                        return Err(McBrowserError::RequestTimeout(
                            "ExtractArchive exceeded maximum execution time".to_string(),
                        ));
                    }
                    Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                        return Err(McBrowserError::PayloadTooLarge(
                            "Archive decompressed stream exceeds safety limit".to_string(),
                        ));
                    }
                    Err(e) => {
                        return Err(McBrowserError::BadRequest(format!(
                            "Corrupt compressed stream in archive entry '{rel_path}': {e}"
                        )));
                    }
                }
            }
            if entry_actual != declared_size {
                return Err(McBrowserError::BadRequest(
                    "Tar entry payload does not match its declared size".to_string(),
                ));
            }
        }
    }

    if entry_count == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no extractable entries".to_string(),
        ));
    }

    Ok((entry_count, total_uncompressed))
}

fn ensure_extracted_parent_dirs(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    destination_dir: &str,
    rel_entry_path: &str,
    known_dirs: &mut HashSet<String>,
    created_dirs_count: &mut usize,
) -> Result<(), McBrowserError> {
    let mut prefix = destination_dir.to_string();
    let segments: Vec<&str> = rel_entry_path.split('/').collect();
    if segments.len() <= 1 {
        return Ok(());
    }
    for seg in &segments[..segments.len() - 1] {
        prefix = format!("{prefix}/{seg}");
        if known_dirs.contains(&prefix) {
            continue;
        }
        policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
        policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        bfs.create_directory(&prefix)
            .map_err(|e| map_fs_io_error(e, "Failed to create extracted subdirectory"))?;
        known_dirs.insert(prefix.clone());
        *created_dirs_count = created_dirs_count.saturating_add(1);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stream_extract_single_file<R: Read>(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    user_id: i64,
    target_path: &str,
    mut entry_reader: R,
    archive_size: u64,
    expected_entry_size: u64,
    total_extracted_bytes: &mut u64,
    reserved_quota_bytes: &mut u64,
    deadline: Instant,
) -> Result<u64, McBrowserError> {
    policy::authorize_with_conn(conn, user, Permission::Execute, target_path)?;
    policy::authorize_with_conn(conn, user, Permission::Create, target_path)?;

    let pending = bfs
        .begin_upload(target_path)
        .map_err(|e| map_fs_io_error(e, "Failed to stage extracted file"))?;
    let mut staging_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to open extracted staging file"))?;
    check_fd_free_space(staging_file.as_raw_fd(), 65_536)?;

    let mut buf = vec![0u8; ACTION_IO_BUF_BYTES];
    let mut entry_written: u64 = 0;

    loop {
        check_action_deadline(deadline, "ExtractArchive")?;
        match entry_reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                entry_written = entry_written.saturating_add(n as u64);
                if entry_written > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                    return Err(McBrowserError::PayloadTooLarge(format!(
                        "Extracted file '{target_path}' exceeds maximum entry size of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                    )));
                }
                let next_total = total_extracted_bytes.saturating_add(n as u64);
                if next_total > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                    return Err(McBrowserError::PayloadTooLarge(format!(
                        "Extracted archive exceeds maximum total expanded size of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                    )));
                }
                check_compression_ratio(archive_size, next_total)?;

                staging_file
                    .write_all(&buf[..n])
                    .map_err(|e| map_fs_io_error(e, "Failed to write extracted file bytes"))?;
                *total_extracted_bytes = next_total;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                return Err(McBrowserError::RequestTimeout(
                    "ExtractArchive exceeded maximum execution time".to_string(),
                ));
            }
            Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                return Err(McBrowserError::PayloadTooLarge(
                    "Extracted archive stream exceeds maximum size limit".to_string(),
                ));
            }
            Err(e) => {
                return Err(McBrowserError::BadRequest(format!(
                    "Failed to decompress archive entry '{target_path}': {e}"
                )));
            }
        }
    }

    if entry_written != expected_entry_size {
        return Err(McBrowserError::BadRequest(
            "Archive entry payload size changed after preflight".to_string(),
        ));
    }

    staging_file
        .flush()
        .map_err(|e| map_fs_io_error(e, "Failed to flush extracted file"))?;
    drop(staging_file);

    if entry_written > 0 {
        reserve_user_quota_atomic(conn, user_id, entry_written)?;
    }
    *reserved_quota_bytes = reserved_quota_bytes.saturating_add(entry_written);

    if let Err(commit_err) = pending.commit() {
        if entry_written > 0 && release_user_quota_conn(conn, user_id, entry_written).is_ok() {
            *reserved_quota_bytes = reserved_quota_bytes.saturating_sub(entry_written);
        }
        return Err(map_fs_io_error(
            commit_err,
            "Failed to publish extracted file",
        ));
    }

    Ok(entry_written)
}

fn rollback_partial_extraction(
    conn: &Connection,
    bfs: &BrowserFs,
    user_id: i64,
    destination_dir: &str,
    reserved_quota_bytes: u64,
) -> bool {
    match bfs.remove_tree_with_size(destination_dir) {
        Ok(removed_bytes) => {
            let to_release = removed_bytes.min(reserved_quota_bytes);
            if to_release > 0 {
                if release_user_quota_conn(conn, user_id, to_release).is_err() {
                    return false;
                }
            }
            removed_bytes >= reserved_quota_bytes
        }
        Err(removal_err) => {
            let confirmed_removed = removal_err.removed_bytes.min(reserved_quota_bytes);
            if confirmed_removed > 0 {
                let _ = release_user_quota_conn(conn, user_id, confirmed_removed);
            }
            false
        }
    }
}

pub fn execute_extract_archive_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_archive_path: &str,
    raw_destination_dir: &str,
) -> Result<ExtractArchiveActionResult, McBrowserError> {
    let user_id = validate_mcbrowser_user(user)?;
    let archive_path = policy::normalize_target_path(raw_archive_path, false)?;
    let destination_dir = policy::normalize_target_path(raw_destination_dir, false)?;
    let _ = validate_archive_entry_name(&destination_dir)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    if archive_path == destination_dir
        || destination_dir.starts_with(&format!("{archive_path}/"))
        || archive_path.starts_with(&format!("{destination_dir}/"))
    {
        return Err(McBrowserError::BadRequest(
            "Archive path and destination directory must not overlap".to_string(),
        ));
    }

    policy::authorize_with_conn(conn, user, Permission::Execute, &destination_dir)?;
    policy::authorize_with_conn(conn, user, Permission::Create, &destination_dir)?;

    let _ = load_active_quota_conn(conn, user_id, 0)?;

    let (mut archive_file, _entry, resolved_archive_path) = open_authorized_action_file_with_conn(
        conn,
        user,
        bfs,
        &archive_path,
        &[Permission::Execute, Permission::Read],
    )?;

    if resolved_archive_path == destination_dir
        || destination_dir.starts_with(&format!("{resolved_archive_path}/"))
    {
        return Err(McBrowserError::BadRequest(
            "Resolved archive path and destination directory must not overlap".to_string(),
        ));
    }

    let format = detect_archive_format_from_path(&archive_path)
        .or_else(|_| detect_archive_format_from_path(&resolved_archive_path))?;

    let archive_meta = archive_file
        .metadata()
        .map_err(|e| map_fs_io_error(e, "Failed to inspect archive metadata"))?;
    let archive_size = archive_meta.len();
    if archive_size == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive file is empty".to_string(),
        ));
    }
    if archive_size > MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Archive file size ({archive_size} bytes) exceeds maximum extraction source limit of {MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES} bytes"
        )));
    }

    match bfs.metadata(&destination_dir) {
        Ok(_) => {
            return Err(McBrowserError::Conflict(format!(
                "Extraction destination '{destination_dir}' already exists"
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(map_fs_io_error(
                err,
                "Failed to inspect extraction destination",
            ));
        }
    }

    let mut parent_dirs_to_create: Vec<String> = Vec::new();
    if let Some((parent_path, _)) = destination_dir.rsplit_once('/') {
        let mut prefix = String::new();
        for seg in parent_path.split('/') {
            prefix = if prefix.is_empty() {
                seg.to_string()
            } else {
                format!("{prefix}/{seg}")
            };
            match bfs.metadata(&prefix) {
                Ok(existing) if existing.kind == "directory" => {}
                Ok(_) => {
                    return Err(McBrowserError::Conflict(format!(
                        "Ancestor path '{prefix}' exists and is not a directory"
                    )));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
                    policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
                    parent_dirs_to_create.push(prefix.clone());
                }
                Err(err) => {
                    return Err(map_fs_io_error(
                        err,
                        "Failed to inspect destination ancestor directory",
                    ));
                }
            }
        }
    }

    let (zip_plan, tar_entry_count, expanded_bytes) = if format == ArchiveFormat::Zip {
        let plan = preflight_zip_archive(
            conn,
            bfs,
            user,
            &mut archive_file,
            archive_size,
            &destination_dir,
            deadline,
        )?;
        let expanded_bytes = plan
            .iter()
            .map(|item| item.declared_uncompressed)
            .sum::<u64>();
        (Some(plan), None, expanded_bytes)
    } else {
        let (entry_count, expanded_bytes) = preflight_tar_archive(
            conn,
            bfs,
            user,
            &mut archive_file,
            archive_size,
            format,
            &destination_dir,
            deadline,
        )?;
        (None, Some(entry_count), expanded_bytes)
    };
    load_active_quota_conn(conn, user_id, expanded_bytes)?;

    let audit = super::events::record_pending_intent_with_conn(
        conn,
        user,
        super::events::McBrowserEventTrigger::UploadCompleted,
        &destination_dir,
        None,
        0,
    )?;
    for (created_count, ancestor) in parent_dirs_to_create.iter().enumerate() {
        if let Err(error) = bfs.create_directory(ancestor) {
            let mut removed_all = true;
            for created in parent_dirs_to_create[..created_count].iter().rev() {
                removed_all &= bfs.remove(created).is_ok();
            }
            if removed_all {
                let _ = super::events::finalize_event_failed_with_conn(
                    conn,
                    &audit.event.event_id,
                    Some("EXTRACTION_DESTINATION_FAILED"),
                );
            }
            return Err(map_fs_io_error(
                error,
                "Failed to create extraction destination parent directory",
            ));
        }
    }
    if let Err(error) = bfs.create_directory(&destination_dir) {
        let mut removed_all = true;
        for created in parent_dirs_to_create.iter().rev() {
            removed_all &= bfs.remove(created).is_ok();
        }
        if removed_all {
            let _ = super::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("EXTRACTION_DESTINATION_FAILED"),
            );
        }
        return Err(map_fs_io_error(
            error,
            "Failed to create extraction destination directory",
        ));
    }

    let mut known_dirs = HashSet::new();
    let mut extracted_files: usize = 0;
    let mut extracted_directories: usize = 0;
    let mut total_extracted_bytes: u64 = 0;
    let mut reserved_quota_bytes: u64 = 0;

    let extraction_outcome: Result<(), McBrowserError> = (|| {
        if let Some(items) = zip_plan {
            let (mut zip, replay_count) = open_admitted_zip_archive(
                &mut archive_file,
                archive_size,
                deadline,
                "ExtractArchive ZIP replay",
            )?;
            if replay_count != items.len() {
                return Err(McBrowserError::BadRequest(
                    "Archive entry count changed after preflight".to_string(),
                ));
            }

            for item in items {
                check_action_deadline(deadline, "ExtractArchive")?;
                let rel_inside = item
                    .target_path
                    .strip_prefix(&format!("{destination_dir}/"))
                    .ok_or_else(|| {
                        McBrowserError::Internal("Invalid extraction target path".to_string())
                    })?;

                ensure_extracted_parent_dirs(
                    conn,
                    bfs,
                    user,
                    &destination_dir,
                    rel_inside,
                    &mut known_dirs,
                    &mut extracted_directories,
                )?;

                if item.is_dir {
                    if !known_dirs.contains(&item.target_path) {
                        policy::authorize_with_conn(
                            conn,
                            user,
                            Permission::Execute,
                            &item.target_path,
                        )?;
                        policy::authorize_with_conn(
                            conn,
                            user,
                            Permission::Create,
                            &item.target_path,
                        )?;
                        bfs.create_directory(&item.target_path).map_err(|e| {
                            map_fs_io_error(e, "Failed to create archive directory")
                        })?;
                        known_dirs.insert(item.target_path.clone());
                        extracted_directories = extracted_directories.saturating_add(1);
                    }
                } else {
                    let entry = zip.by_index(item.index).map_err(|err| {
                        if let zip::result::ZipError::Io(io_err) = &err {
                            if io_err.kind() == ErrorKind::TimedOut {
                                return McBrowserError::RequestTimeout(
                                    "ExtractArchive exceeded maximum execution time".to_string(),
                                );
                            }
                            if io_err.kind() == ErrorKind::FileTooLarge {
                                return McBrowserError::PayloadTooLarge(
                                    "ZIP archive read stream exceeds safety limit".to_string(),
                                );
                            }
                        }
                        let msg = err.to_string();
                        if msg.to_ascii_lowercase().contains("password")
                            || msg.to_ascii_lowercase().contains("encrypt")
                        {
                            McBrowserError::BadRequest(
                                "Encrypted ZIP archive entries are not supported".to_string(),
                            )
                        } else {
                            McBrowserError::BadRequest(format!(
                                "Failed to open ZIP entry '{}': {msg}",
                                item.target_path
                            ))
                        }
                    })?;

                    if entry.is_symlink() || is_zip_unix_symlink_or_special(entry.unix_mode()) {
                        return Err(McBrowserError::BadRequest(
                            "Archive contains forbidden symlink or special entry".to_string(),
                        ));
                    }

                    stream_extract_single_file(
                        conn,
                        bfs,
                        user,
                        user_id,
                        &item.target_path,
                        entry,
                        archive_size,
                        item.declared_uncompressed,
                        &mut total_extracted_bytes,
                        &mut reserved_quota_bytes,
                        deadline,
                    )?;
                    extracted_files = extracted_files.saturating_add(1);
                }
            }
        } else {
            archive_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| map_fs_io_error(e, "Failed to seek tar archive"))?;
            let bounded_source = BoundedDeadlineReader::new(
                archive_file,
                MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES,
                deadline,
                "ExtractArchive source read",
            );
            let decoder = open_tar_stream_decoder(format, Box::new(bounded_source))?;
            let max_tar_stream_bytes = MAX_ACTION_EXTRACT_TOTAL_BYTES
                .saturating_add((MAX_ACTION_ARCHIVE_ENTRIES as u64) * 2048)
                .saturating_add(1024 * 1024);
            let bounded_decompressed = BoundedDeadlineReader::new(
                decoder,
                max_tar_stream_bytes,
                deadline,
                "ExtractArchive stream decompression",
            );

            let mut archive = tar::Archive::new(bounded_decompressed);
            let entries = archive.entries().map_err(|e| {
                McBrowserError::BadRequest(format!("Failed to read tar entries: {e}"))
            })?;

            let mut replayed_entries = 0_usize;
            for entry_res in entries {
                check_action_deadline(deadline, "ExtractArchive")?;
                let entry = entry_res.map_err(|error| match error.kind() {
                    ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    ),
                    ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
                        "Archive decompressed stream exceeds safety limit".to_string(),
                    ),
                    _ => McBrowserError::BadRequest(format!(
                        "Corrupt tar entry during extraction: {error}"
                    )),
                })?;

                let entry_type = entry.header().entry_type();
                let Some(is_dir_header) = is_allowed_tar_entry_type(entry_type)? else {
                    continue;
                };
                replayed_entries = replayed_entries.saturating_add(1);
                if replayed_entries > MAX_ACTION_ARCHIVE_ENTRIES {
                    return Err(McBrowserError::PayloadTooLarge(
                        "Archive replay exceeds entry count limit".to_string(),
                    ));
                }
                let raw_header = entry.header().path_bytes();
                let raw_header = std::str::from_utf8(&raw_header).map_err(|_| {
                    McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
                })?;
                if !raw_header.is_empty() && raw_header != "././@LongLink" {
                    validate_extract_entry_relative_path(raw_header)?;
                }
                if let Some(link_bytes) = entry.link_name_bytes() {
                    if !link_bytes.is_empty() {
                        return Err(McBrowserError::BadRequest(
                            "Archive entry specifies a link target".to_string(),
                        ));
                    }
                }

                let raw_path_bytes = entry.path_bytes();
                let raw_path_str = std::str::from_utf8(&raw_path_bytes).map_err(|_| {
                    McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
                })?;
                let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_path_str)?;
                let is_dir = is_dir_header || is_dir_hint;
                let target_path =
                    policy::normalize_target_path(&format!("{destination_dir}/{rel_path}"), false)?;

                ensure_extracted_parent_dirs(
                    conn,
                    bfs,
                    user,
                    &destination_dir,
                    &rel_path,
                    &mut known_dirs,
                    &mut extracted_directories,
                )?;

                if is_dir {
                    if !known_dirs.contains(&target_path) {
                        policy::authorize_with_conn(conn, user, Permission::Execute, &target_path)?;
                        policy::authorize_with_conn(conn, user, Permission::Create, &target_path)?;
                        bfs.create_directory(&target_path).map_err(|e| {
                            map_fs_io_error(e, "Failed to create archive directory")
                        })?;
                        known_dirs.insert(target_path);
                        extracted_directories = extracted_directories.saturating_add(1);
                    }
                } else {
                    let expected_entry_size = entry.header().size().map_err(|_| {
                        McBrowserError::BadRequest("Invalid replayed tar entry size".to_string())
                    })?;
                    stream_extract_single_file(
                        conn,
                        bfs,
                        user,
                        user_id,
                        &target_path,
                        entry,
                        archive_size,
                        expected_entry_size,
                        &mut total_extracted_bytes,
                        &mut reserved_quota_bytes,
                        deadline,
                    )?;
                    extracted_files = extracted_files.saturating_add(1);
                }
            }
            if Some(replayed_entries) != tar_entry_count {
                return Err(McBrowserError::BadRequest(
                    "Archive entry count changed after preflight".to_string(),
                ));
            }
        }
        Ok(())
    })();

    if let Err(err) = extraction_outcome {
        let mut removed_all =
            rollback_partial_extraction(conn, bfs, user_id, &destination_dir, reserved_quota_bytes);
        for anc in parent_dirs_to_create.iter().rev() {
            removed_all &= bfs.remove(anc).is_ok();
        }
        if removed_all {
            let _ = super::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("EXTRACTION_ROLLED_BACK"),
            );
        }
        return Err(err);
    }

    super::events::finalize_published_mutation_with_conn(
        conn,
        &audit,
        None,
        None,
        total_extracted_bytes.min(i64::MAX as u64) as i64,
    );
    Ok(ExtractArchiveActionResult {
        archive_path,
        destination_dir,
        format: format.algo_id().to_string(),
        extracted_files,
        extracted_directories,
        extracted_bytes: total_extracted_bytes,
    })
}

pub fn execute_action_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    action: Action,
) -> Result<ActionResponse, McBrowserError> {
    match action {
        Action::ComputeChecksums { path, algorithms } => {
            let result = execute_compute_checksums_with_conn(conn, bfs, user, &path, &algorithms)?;
            Ok(ActionResponse::ComputeChecksums {
                success: true,
                result,
            })
        }
        Action::ExtractArchive {
            archive_path,
            destination_dir,
        } => {
            let result = execute_extract_archive_with_conn(
                conn,
                bfs,
                user,
                &archive_path,
                &destination_dir,
            )?;
            Ok(ActionResponse::ExtractArchive {
                success: true,
                result,
            })
        }
        Action::CreateArchive {
            source_paths,
            destination_path,
            format,
        } => {
            let result = execute_create_archive_with_conn(
                conn,
                bfs,
                user,
                &source_paths,
                &destination_path,
                &format,
            )?;
            Ok(ActionResponse::CreateArchive {
                success: true,
                result,
            })
        }
        Action::InspectMediaMetadata { path } => {
            let result = execute_inspect_media_metadata_with_conn(conn, bfs, user, &path)?;
            Ok(ActionResponse::InspectMediaMetadata {
                success: true,
                result,
            })
        }
    }
}

async fn dispatch_action(auth_ext: Option<Extension<AuthUser>>, body: Bytes) -> Response {
    let Some(Extension(auth_user)) = auth_ext else {
        return McBrowserError::Unauthorized("Authentication required".to_string()).into_response();
    };
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(err) => return err.into_response(),
    };
    let action = match parse_action_payload_bytes(&body) {
        Ok(act) => act,
        Err(err) => return err.into_response(),
    };

    let is_mutating = action.is_mutating();
    let mutation_guard = if is_mutating {
        Some(user_mutation_stripe(user_id).lock_owned().await)
    } else {
        None
    };

    let task_res =
        tokio::task::spawn_blocking(move || -> Result<ActionResponse, McBrowserError> {
            let _guard = mutation_guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for action dispatch".to_string())
            })?;
            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            execute_action_with_conn(&conn, &bfs, &auth_user, action)
        })
        .await;

    match task_res {
        Ok(Ok(resp)) => {
            let status = if is_mutating {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            no_store_json_status(status, resp)
        }
        Ok(Err(err)) => err.into_response(),
        Err(_) => {
            McBrowserError::Internal("Action execution task failed".to_string()).into_response()
        }
    }
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod actions_tests;
