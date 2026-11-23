mod basic;
mod extract;
mod zip_preflight;

use basic::{check_action_deadline, open_authorized_action_file_with_conn, BoundedDeadlineReader};
pub use basic::{
    execute_compute_checksums_with_conn, execute_create_archive_with_conn,
    execute_inspect_media_metadata_with_conn,
};
pub use extract::execute_extract_archive_with_conn;
#[cfg(test)]
use extract::{rollback_partial_extraction, stream_extract_single_file};
#[cfg(test)]
use zip_preflight::preflight_zip_raw_headers_for_encryption;
#[allow(unused_imports)]
pub use zip_preflight::MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES;
use zip_preflight::{
    check_compression_ratio, is_zip_unix_symlink_or_special, open_admitted_zip_archive,
    preflight_authorize_and_check_destination_entry, preflight_zip_archive,
};
pub use zip_preflight::{detect_archive_format_from_path, validate_extract_entry_relative_path};

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

pub(super) fn tracked_router() -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{post, TrackedRouter};
    TrackedRouter::new()
        .route("/mcbrowser/actions", post(dispatch_action))
        .layer(DefaultBodyLimit::max(MAX_ACTION_BODY_BYTES))
        .layer(middleware::from_fn(limit_action_requests))
}

#[allow(dead_code)]
pub fn router() -> Router {
    tracked_router().into_router()
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
