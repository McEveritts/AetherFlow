//! Resumable / chunked TUS 1.0.0 upload backend for McBrowser (`uploads.rs`).
//!
//! Owns:
//! - `POST /mcbrowser/uploads` (Creation with `Tus-Resumable: 1.0.0`, `Upload-Length`, `Upload-Metadata` path & fingerprint)
//! - `GET /mcbrowser/uploads` (Resumable session discovery by exact `(user_id, path, length, fingerprint)`)
//! - `HEAD /mcbrowser/uploads/:id` (Offset, length, `Upload-Status: uploading|completed`, and `Upload-Metadata` recovery)
//! - `PATCH /mcbrowser/uploads/:id` (`application/offset+octet-stream`, `Upload-Offset`, 4 MiB chunk cap, atomic publish on completion)
//! - `DELETE /mcbrowser/uploads/:id` (Cancel unfinished upload and release full reserved quota; `409 Conflict` if already completed)
//!
//! Security & Durability invariants:
//! - Staging files live in a private service-owned directory (`<base_root>/.af-upload-staging/user-<uid>/<id>.part`)
//!   with mode `0700` on directories and `0600` on regular files, completely outside browsable `user-<uid>` roots.
//! - Every directory hop and staging file open uses `O_NOFOLLOW` (and `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
//!   when supported by the kernel) plus `fstat` ownership (`geteuid()`) and single-hardlink (`st_nlink == 1`) checks.
//! - Full `Upload-Length` quota is reserved upfront in SQLite inside the same `BEGIN IMMEDIATE` transaction that inserts
//!   the upload session row, enforcing max 32 active (`uploading` / `publishing`) sessions per user and 24-hour expiration.
//! - Per-user global lock is held only during brief metadata/commit/cancel sections; active chunk streaming holds a
//!   per-upload session lock so a slow chunk transfer does not block other operations for the user.
//! - On restart or reconnect, `HEAD` / `PATCH` reconciles SQLite `offset_bytes` with the actual staging file size on disk
//!   (truncating any uncommitted tail beyond `offset_bytes` or rolling `offset_bytes` back to disk size if smaller).
//! - Durable publication & crash-recovery reconciliation:
//!   - Before invoking `PendingUpload::commit()` (`renameat2(RENAME_NOREPLACE)`), the session transitions to
//!     `status = 'publishing'` (with `offset_bytes = upload_length`) in SQLite.
//!   - Once `PendingUpload::commit()` succeeds, the session transitions to `status = 'completed'` and retains its
//!     DB record for 24h so lost completion ACKs can be recovered via `HEAD`.
//!   - If a crash or DB error occurs after `status = 'publishing'` is recorded (or after the file rename succeeds
//!     before `status = 'completed'` is persisted), `reconcile_publishing_session_at` inspects the target path and
//!     private staging file to deterministically promote published uploads to `'completed'`, retry publication from
//!     the intact staging file on `HEAD`/`PATCH`, or CONSERVATIVELY retain the quota reservation when publication
//!     state is ambiguous. Expiry and cancellation NEVER release quota for a published or ambiguously-published file.

use super::{
    check_fd_free_space, load_active_quota_conn, map_fs_io_error, normalize_relative_path,
    open_user_browser_fs_at, release_user_quota_conn, resolve_configured_base_root,
    user_mutation_stripe, validate_mcbrowser_user, McBrowserError,
};
use crate::auth::{api_error, AuthUser};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Extension, Path as AxumPath, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{head, post};
use axum::Router;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_NO_PAD};
use base64::Engine as _;
use futures::StreamExt;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

pub const TUS_VERSION: &str = "1.0.0";
pub const MAX_CHUNK_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB per PATCH chunk
pub const DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB default max file size
pub const MAX_ACTIVE_UPLOADS_PER_USER: i64 = 32;
pub const UPLOAD_SESSION_EXPIRY_SECS: i64 = 24 * 3600; // 24 hours
pub const MAX_FINGERPRINT_LEN: usize = 512;
const CHUNK_STREAM_TIMEOUT: Duration = Duration::from_secs(120);
const STAGING_DIR_NAME: &str = ".af-upload-staging";

const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

static SESSION_LOCKS: Lazy<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn session_lock(upload_id: &str) -> Arc<AsyncMutex<()>> {
    let mut map = SESSION_LOCKS.lock().unwrap();
    if map.len() > 4096 {
        map.retain(|_, v| Arc::strong_count(v) > 1);
    }
    Arc::clone(
        map.entry(upload_id.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
    )
}

/// Resolves the maximum allowed resumable upload size in bytes.
/// Reads `AF_MCBROWSER_MAX_UPLOAD_BYTES` if set to a positive integer,
/// falling back to `DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES` (64 GiB).
pub fn resolve_max_upload_bytes_from_str(raw: Option<&str>) -> u64 {
    if let Some(s) = raw {
        if let Ok(parsed) = s.trim().parse::<u64>() {
            if parsed > 0 {
                return parsed;
            }
        }
    }
    DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES
}

pub fn configured_max_upload_bytes() -> u64 {
    let raw = env::var("AF_MCBROWSER_MAX_UPLOAD_BYTES").ok();
    resolve_max_upload_bytes_from_str(raw.as_deref())
}

fn configured_base_root() -> Result<PathBuf, McBrowserError> {
    let env_val = env::var("AF_MCBROWSER_ROOT").ok();
    resolve_configured_base_root(env_val.as_deref())
}

/// Enforces `super::policy::Permission::Create` on the target path using the active SQLite
/// `Connection` (`super::policy::authorize_with_conn`), avoiding nested pool checkouts when
/// `af_db` pool `max_size == 1`.
#[inline]
pub(crate) fn authorize_create_permission_with_conn(
    conn: &Connection,
    user: &AuthUser,
    normalized_path: &str,
) -> Result<(), McBrowserError> {
    super::policy::authorize_with_conn(
        conn,
        user,
        super::policy::Permission::Create,
        normalized_path,
    )
}

/// Enforces `super::policy::Permission::Modify` on the target path using the active SQLite
/// `Connection` (`super::policy::authorize_with_conn`), avoiding nested pool checkouts when
/// `af_db` pool `max_size == 1`.
#[inline]
pub(crate) fn authorize_modify_permission_with_conn(
    conn: &Connection,
    user: &AuthUser,
    normalized_path: &str,
) -> Result<(), McBrowserError> {
    super::policy::authorize_with_conn(
        conn,
        user,
        super::policy::Permission::Modify,
        normalized_path,
    )
}

/// Enforces policy permissions required for the session's `ConflictPolicy` and target state:
/// - `ConflictPolicy::Overwrite` and `ConflictPolicy::Resume` always require `Permission::Modify`
///   (and if `Overwrite` is creating a brand-new file where `!base_target_exists`, also `Permission::Create`).
/// - `ConflictPolicy::Error` and `ConflictPolicy::Skip` require `Permission::Create`.
pub(crate) fn authorize_conflict_policy_permissions_with_conn(
    conn: &Connection,
    user: &AuthUser,
    normalized_path: &str,
    policy: ConflictPolicy,
    base_target_exists: bool,
) -> Result<(), McBrowserError> {
    match policy {
        ConflictPolicy::Error | ConflictPolicy::Skip => {
            authorize_create_permission_with_conn(conn, user, normalized_path)
        }
        ConflictPolicy::Resume => {
            authorize_modify_permission_with_conn(conn, user, normalized_path)
        }
        ConflictPolicy::Overwrite => {
            if !base_target_exists {
                authorize_create_permission_with_conn(conn, user, normalized_path)?;
            }
            authorize_modify_permission_with_conn(conn, user, normalized_path)
        }
    }
}

/// Supported upload conflict resolution policies for McBrowser TUS uploads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictPolicy {
    /// Fail with `409 Conflict` if the target file already exists (`RENAME_NOREPLACE`).
    Error,
    /// Atomically replace an existing regular file (`BrowserFs::begin_replace` + `PendingUpload::commit_replace`),
    /// bound to the original `(st_dev, st_ino, st_size)` observed at session creation.
    Overwrite,
    /// Leave an existing regular file untouched and complete the session with `0` additional quota reserved.
    Skip,
    /// Resume an interrupted legacy/partial upload by copying the existing regular file prefix into the
    /// private staging file, starting at `Upload-Offset = existing_len`, reserving only `upload_length - existing_len`,
    /// and atomically replacing the bound original inode upon completion without ever truncating live files.
    Resume,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        Self::Error
    }
}

impl ConflictPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Overwrite => "overwrite",
            Self::Skip => "skip",
            Self::Resume => "resume",
        }
    }

    pub fn parse_opt(raw: Option<&str>) -> Result<Option<Self>, McBrowserError> {
        let Some(trimmed) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        if trimmed.eq_ignore_ascii_case("error") {
            Ok(Some(Self::Error))
        } else if trimmed.eq_ignore_ascii_case("overwrite")
            || trimmed.eq_ignore_ascii_case("replace")
        {
            Ok(Some(Self::Overwrite))
        } else if trimmed.eq_ignore_ascii_case("skip") {
            Ok(Some(Self::Skip))
        } else if trimmed.eq_ignore_ascii_case("resume") {
            Ok(Some(Self::Resume))
        } else {
            Err(McBrowserError::BadRequest(format!(
                "Unsupported conflict policy '{trimmed}': supported policies are 'error', 'overwrite', 'skip', and 'resume'"
            )))
        }
    }

    fn from_db_str(raw: &str) -> Self {
        Self::parse_opt(Some(raw))
            .ok()
            .flatten()
            .unwrap_or(Self::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUploadMetadata {
    pub path: String,
    pub fingerprint: Option<String>,
    pub conflict_policy: Option<ConflictPolicy>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DiscoverUploadsQuery {
    pub path: Option<String>,
    pub length: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConflictPolicyQuery {
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadSessionSummary {
    pub id: String,
    pub path: String,
    pub length: u64,
    pub offset: u64,
    pub status: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverUploadsResponse {
    pub uploads: Vec<UploadSessionSummary>,
}

#[derive(Debug, Clone)]
pub(crate) struct UploadSessionRecord {
    pub id: String,
    pub user_id: i64,
    pub owner_scope: String,
    pub scope_root_dev: u64,
    pub scope_root_ino: u64,
    pub target_path: String,
    pub fingerprint: String,
    pub upload_length: u64,
    pub offset_bytes: u64,
    pub status: String,
    pub staging_rel_path: String,
    pub quota_reserved: bool,
    pub reserved_bytes: u64,
    pub conflict_policy: ConflictPolicy,
    pub base_target_exists: bool,
    pub base_target_dev: u64,
    pub base_target_ino: u64,
    pub base_target_size: u64,
    pub audit_event_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishingResolution {
    Completed,
    UnpublishedStagingIntact,
    AmbiguousRetainQuota,
}

pub fn router() -> Router {
    Router::new()
        .route(
            "/mcbrowser/uploads",
            post(create_upload).get(discover_uploads),
        )
        .route(
            "/mcbrowser/uploads/:id",
            head(head_upload).patch(patch_upload).delete(delete_upload),
        )
        .layer(DefaultBodyLimit::max((MAX_CHUNK_BYTES + 1024) as usize))
}

fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn with_tus_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn tus_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    with_tus_headers(api_error(status, code, message))
}

fn map_mcbrowser_err_tus(err: McBrowserError) -> Response {
    with_tus_headers(err.into_response())
}

/// Validates `Tus-Resumable: 1.0.0`. Returns `412 Precondition Failed` with `Tus-Version: 1.0.0` if missing or unsupported.
pub fn validate_tus_version(headers: &HeaderMap) -> Result<(), Response> {
    let Some(hv) = headers.get("Tus-Resumable") else {
        let mut resp = api_error(
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            "Missing required Tus-Resumable: 1.0.0 header",
        );
        resp.headers_mut()
            .insert("Tus-Version", HeaderValue::from_static(TUS_VERSION));
        return Err(with_tus_headers(resp));
    };
    let Ok(val) = hv.to_str() else {
        let mut resp = api_error(
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            "Invalid Tus-Resumable header",
        );
        resp.headers_mut()
            .insert("Tus-Version", HeaderValue::from_static(TUS_VERSION));
        return Err(with_tus_headers(resp));
    };
    if val.trim() != TUS_VERSION {
        let mut resp = api_error(
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            format!(
                "Unsupported Tus-Resumable version '{}'; expected 1.0.0",
                val.trim()
            ),
        );
        resp.headers_mut()
            .insert("Tus-Version", HeaderValue::from_static(TUS_VERSION));
        return Err(with_tus_headers(resp));
    }
    Ok(())
}

/// Validates optional `?policy=` / `X-Upload-Conflict` / `Upload-Metadata conflict` value.
/// Supported modes are `error`, `overwrite` (alias `replace`), `skip`, and `resume`.
/// Unimplemented modes such as `keep-both` are explicitly rejected with `400 Bad Request`.
pub fn validate_conflict_policy(policy: Option<&str>) -> Result<(), McBrowserError> {
    ConflictPolicy::parse_opt(policy).map(|_| ())
}

fn resolve_effective_conflict_policy(
    query_policy: Option<&str>,
    header_policy: Option<&str>,
    metadata_policy: Option<ConflictPolicy>,
) -> Result<ConflictPolicy, McBrowserError> {
    let q = ConflictPolicy::parse_opt(query_policy)?;
    let h = ConflictPolicy::parse_opt(header_policy)?;
    let mut effective: Option<ConflictPolicy> = None;

    for candidate in [q, h, metadata_policy].into_iter().flatten() {
        if let Some(prev) = effective {
            if prev != candidate {
                return Err(McBrowserError::BadRequest(format!(
                    "Conflicting upload conflict policies specified ('{}' vs '{}')",
                    prev.as_str(),
                    candidate.as_str()
                )));
            }
        } else {
            effective = Some(candidate);
        }
    }

    Ok(effective.unwrap_or(ConflictPolicy::Error))
}

fn decode_base64_utf8(b64: &str, field_name: &str) -> Result<String, McBrowserError> {
    let trimmed = b64.trim();
    if trimmed.is_empty() {
        return Err(McBrowserError::BadRequest(format!(
            "Upload-Metadata '{field_name}' base64 value cannot be empty"
        )));
    }
    let bytes = BASE64_STD
        .decode(trimmed)
        .or_else(|_| BASE64_NO_PAD.decode(trimmed))
        .map_err(|_| {
            McBrowserError::BadRequest(format!(
                "Invalid base64 encoding for Upload-Metadata '{field_name}'"
            ))
        })?;
    if bytes.contains(&0) {
        return Err(McBrowserError::BadRequest(format!(
            "Upload-Metadata '{field_name}' must not contain NUL bytes"
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        McBrowserError::BadRequest(format!(
            "Upload-Metadata '{field_name}' must be valid UTF-8"
        ))
    })
}

pub fn validate_fingerprint_value(fp: &str) -> Result<String, McBrowserError> {
    let trimmed = fp.trim();
    if trimmed.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Upload fingerprint must not be empty".to_string(),
        ));
    }
    if trimmed.len() > MAX_FINGERPRINT_LEN {
        return Err(McBrowserError::BadRequest(format!(
            "Upload fingerprint exceeds maximum length of {MAX_FINGERPRINT_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(McBrowserError::BadRequest(
            "Upload fingerprint must not contain control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Parses TUS `Upload-Metadata` header (`key base64val, key2 base64val2`).
/// Extracts and normalizes `path` (required), `fingerprint` (optional in POST, required for discovery),
/// and optional `conflict` policy.
pub fn parse_upload_metadata(
    raw_header: Option<&str>,
) -> Result<ParsedUploadMetadata, McBrowserError> {
    let Some(raw) = raw_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(McBrowserError::BadRequest(
            "Missing required Upload-Metadata header".to_string(),
        ));
    };

    let mut seen_keys = std::collections::HashSet::new();
    let mut raw_path: Option<String> = None;
    let mut fingerprint: Option<String> = None;
    let mut conflict_policy: Option<ConflictPolicy> = None;

    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            return Err(McBrowserError::BadRequest(
                "Malformed Upload-Metadata header: empty entry".to_string(),
            ));
        }
        let mut parts = pair.split_whitespace();
        let Some(key) = parts.next() else {
            return Err(McBrowserError::BadRequest(
                "Malformed Upload-Metadata header".to_string(),
            ));
        };
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(McBrowserError::BadRequest(format!(
                "Invalid Upload-Metadata key '{key}'"
            )));
        }
        if !seen_keys.insert(key.to_string()) {
            return Err(McBrowserError::BadRequest(format!(
                "Duplicate Upload-Metadata key '{key}'"
            )));
        }
        let b64_val = parts.next();
        if parts.next().is_some() {
            return Err(McBrowserError::BadRequest(format!(
                "Malformed Upload-Metadata entry for key '{key}'"
            )));
        }

        match key {
            "path" => {
                let Some(v) = b64_val else {
                    return Err(McBrowserError::BadRequest(
                        "Upload-Metadata 'path' requires a base64 value".to_string(),
                    ));
                };
                let decoded = decode_base64_utf8(v, "path")?;
                let normalized = normalize_relative_path(&decoded, false)?;
                raw_path = Some(normalized);
            }
            "fingerprint" => {
                if let Some(v) = b64_val {
                    let decoded = decode_base64_utf8(v, "fingerprint")?;
                    fingerprint = Some(validate_fingerprint_value(&decoded)?);
                } else {
                    return Err(McBrowserError::BadRequest(
                        "Upload-Metadata 'fingerprint' requires a base64 value".to_string(),
                    ));
                }
            }
            "conflict" => {
                if let Some(v) = b64_val {
                    let decoded = decode_base64_utf8(v, "conflict")?;
                    conflict_policy = ConflictPolicy::parse_opt(Some(&decoded))?;
                } else {
                    return Err(McBrowserError::BadRequest(
                        "Upload-Metadata 'conflict' requires a base64 value".to_string(),
                    ));
                }
            }
            _ => {
                // Other TUS metadata keys (e.g., filename, filetype) must still have valid base64 if present
                if let Some(v) = b64_val {
                    let _ = BASE64_STD
                        .decode(v.trim())
                        .or_else(|_| BASE64_NO_PAD.decode(v.trim()))
                        .map_err(|_| {
                            McBrowserError::BadRequest(format!(
                                "Invalid base64 value in Upload-Metadata key '{key}'"
                            ))
                        })?;
                }
            }
        }
    }

    let Some(path) = raw_path else {
        return Err(McBrowserError::BadRequest(
            "Upload-Metadata must include 'path'".to_string(),
        ));
    };

    Ok(ParsedUploadMetadata {
        path,
        fingerprint,
        conflict_policy,
    })
}

/// Encodes `path` and optional `fingerprint` back into a canonical TUS `Upload-Metadata` header value.
pub fn encode_upload_metadata_header(path: &str, fingerprint: &str) -> String {
    let path_b64 = BASE64_STD.encode(path.as_bytes());
    if fingerprint.is_empty() {
        format!("path {path_b64}")
    } else {
        let fp_b64 = BASE64_STD.encode(fingerprint.as_bytes());
        format!("path {path_b64},fingerprint {fp_b64}")
    }
}

fn encode_session_metadata_header(session: &UploadSessionRecord) -> String {
    format!(
        "{},conflict {}",
        encode_upload_metadata_header(&session.target_path, &session.fingerprint),
        BASE64_STD.encode(session.conflict_policy.as_str().as_bytes())
    )
}

pub fn validate_upload_id(raw_id: &str) -> Result<String, McBrowserError> {
    let trimmed = raw_id.trim();
    if trimmed.len() != 32 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Schema & Durable State Management
// ─────────────────────────────────────────────────────────────────────────────

const SESSION_SELECT_COLUMNS: &str = "\
    id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, \
    staging_rel_path, quota_reserved, created_at, updated_at, expires_at, \
    owner_scope, scope_root_dev, scope_root_ino, conflict_policy, reserved_bytes, \
    base_target_exists, base_target_dev, base_target_ino, base_target_size, audit_event_id";

pub fn ensure_uploads_schema(conn: &Connection) -> Result<(), McBrowserError> {
    super::events::ensure_events_tables(conn)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mcbrowser_uploads (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            owner_scope TEXT NOT NULL DEFAULT '',
            scope_root_dev INTEGER NOT NULL DEFAULT 0,
            scope_root_ino INTEGER NOT NULL DEFAULT 0,
            target_path TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
            offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0 AND offset_bytes <= upload_length),
            status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'publishing', 'completed')),
            staging_rel_path TEXT NOT NULL DEFAULT '',
            quota_reserved INTEGER NOT NULL DEFAULT 1,
            conflict_policy TEXT NOT NULL DEFAULT 'error',
            reserved_bytes INTEGER NOT NULL DEFAULT 0,
            base_target_exists INTEGER NOT NULL DEFAULT 0,
            base_target_dev INTEGER NOT NULL DEFAULT 0,
            base_target_ino INTEGER NOT NULL DEFAULT 0,
            base_target_size INTEGER NOT NULL DEFAULT 0,
            audit_event_id TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_user_status
            ON mcbrowser_uploads(user_id, status);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expires
            ON mcbrowser_uploads(expires_at);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_lookup
            ON mcbrowser_uploads(user_id, status, target_path, upload_length, fingerprint);
        CREATE TABLE IF NOT EXISTS mcbrowser_upload_cleanup_cursor (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            expires_at INTEGER NOT NULL,
            upload_id TEXT NOT NULL
        );
        INSERT OR IGNORE INTO mcbrowser_upload_cleanup_cursor
            (singleton, expires_at, upload_id) VALUES (1, -9223372036854775808, '');
        "#,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to initialize mcbrowser_uploads schema");
        McBrowserError::Internal("Failed to initialize upload session storage".to_string())
    })?;

    // Ensure scope-binding and conflict-parity columns exist on any pre-existing table.
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN owner_scope TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN scope_root_dev INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN scope_root_ino INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN conflict_policy TEXT NOT NULL DEFAULT 'error'",
        [],
    );
    if conn
        .execute(
            "ALTER TABLE mcbrowser_uploads ADD COLUMN reserved_bytes INTEGER NOT NULL DEFAULT -1",
            [],
        )
        .is_ok()
    {
        let _ = conn.execute(
            "UPDATE mcbrowser_uploads \
             SET reserved_bytes = CASE WHEN quota_reserved != 0 THEN upload_length ELSE 0 END \
             WHERE reserved_bytes < 0",
            [],
        );
    }
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_exists INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_dev INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_ino INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN base_target_size INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_uploads ADD COLUMN audit_event_id TEXT NOT NULL DEFAULT ''",
        [],
    );

    // Transparently upgrade any pre-existing table created before `'publishing'` was added to the
    // `status` CHECK constraint.
    let schema_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'mcbrowser_uploads'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| {
            McBrowserError::Internal("Failed to inspect upload session schema".to_string())
        })?;

    if let Some(sql) = schema_sql {
        if !sql.contains("'publishing'") {
            conn.execute_batch(
                r#"
                BEGIN IMMEDIATE TRANSACTION;
                CREATE TABLE mcbrowser_uploads_v2 (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    owner_scope TEXT NOT NULL DEFAULT '',
                    scope_root_dev INTEGER NOT NULL DEFAULT 0,
                    scope_root_ino INTEGER NOT NULL DEFAULT 0,
                    target_path TEXT NOT NULL,
                    fingerprint TEXT NOT NULL DEFAULT '',
                    upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
                    offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0 AND offset_bytes <= upload_length),
                    status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'publishing', 'completed')),
                    staging_rel_path TEXT NOT NULL DEFAULT '',
                    quota_reserved INTEGER NOT NULL DEFAULT 1,
                    conflict_policy TEXT NOT NULL DEFAULT 'error',
                    reserved_bytes INTEGER NOT NULL DEFAULT 0,
                    base_target_exists INTEGER NOT NULL DEFAULT 0,
                    base_target_dev INTEGER NOT NULL DEFAULT 0,
                    base_target_ino INTEGER NOT NULL DEFAULT 0,
                    base_target_size INTEGER NOT NULL DEFAULT 0,
                    audit_event_id TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                INSERT INTO mcbrowser_uploads_v2
                    (id, user_id, owner_scope, scope_root_dev, scope_root_ino, target_path, fingerprint,
                     upload_length, offset_bytes, status, staging_rel_path, quota_reserved,
                     conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size,
                     audit_event_id, created_at, updated_at, expires_at)
                    SELECT id, user_id, CASE WHEN owner_scope = '/' THEN '' ELSE COALESCE(owner_scope, '') END,
                           scope_root_dev, scope_root_ino,
                           target_path, fingerprint, upload_length, offset_bytes, status,
                           staging_rel_path, quota_reserved,
                           COALESCE(conflict_policy, 'error'),
                           CASE WHEN reserved_bytes >= 0 THEN reserved_bytes WHEN quota_reserved != 0 THEN upload_length ELSE 0 END,
                           COALESCE(base_target_exists, 0),
                           COALESCE(base_target_dev, 0),
                           COALESCE(base_target_ino, 0),
                           COALESCE(base_target_size, 0),
                           COALESCE(audit_event_id, ''),
                           created_at, updated_at, expires_at
                    FROM mcbrowser_uploads;
                DROP TABLE mcbrowser_uploads;
                ALTER TABLE mcbrowser_uploads_v2 RENAME TO mcbrowser_uploads;
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_user_status
                    ON mcbrowser_uploads(user_id, status);
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expires
                    ON mcbrowser_uploads(expires_at);
                CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_lookup
                    ON mcbrowser_uploads(user_id, status, target_path, upload_length, fingerprint);
                COMMIT;
                "#,
            )
            .map_err(|e| {
                let _ = conn.execute_batch("ROLLBACK");
                tracing::error!(error = %e, "Failed to migrate mcbrowser_uploads schema to support 'publishing' status");
                McBrowserError::Internal("Failed to migrate upload session storage".to_string())
            })?;
        }
    }

    Ok(())
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<UploadSessionRecord> {
    let len_i64: i64 = row.get(4)?;
    let off_i64: i64 = row.get(5)?;
    let reserved_flag_i64: i64 = row.get(8)?;
    let raw_scope: String = row.get(12).unwrap_or_default();
    let dev_i64: i64 = row.get(13).unwrap_or(0);
    let ino_i64: i64 = row.get(14).unwrap_or(0);
    let raw_policy: String = row.get(15).unwrap_or_else(|_| "error".to_string());
    let reserved_bytes_i64: i64 = row.get(16).unwrap_or(-1);
    let base_exists_i64: i64 = row.get(17).unwrap_or(0);
    let base_dev_i64: i64 = row.get(18).unwrap_or(0);
    let base_ino_i64: i64 = row.get(19).unwrap_or(0);
    let base_size_i64: i64 = row.get(20).unwrap_or(0);
    let audit_event_id: String = row.get(21).unwrap_or_default();

    let upload_length = u64::try_from(len_i64.max(0)).unwrap_or(0);
    let quota_reserved = reserved_flag_i64 != 0;
    let reserved_bytes = if reserved_bytes_i64 >= 0 {
        u64::try_from(reserved_bytes_i64).unwrap_or(0)
    } else if quota_reserved {
        upload_length
    } else {
        0
    };

    Ok(UploadSessionRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        owner_scope: if raw_scope == "/" {
            String::new()
        } else {
            raw_scope
        },
        scope_root_dev: dev_i64 as u64,
        scope_root_ino: ino_i64 as u64,
        target_path: row.get(2)?,
        fingerprint: row.get(3)?,
        upload_length,
        offset_bytes: u64::try_from(off_i64.max(0)).unwrap_or(0),
        status: row.get(6)?,
        staging_rel_path: row.get(7)?,
        quota_reserved,
        reserved_bytes,
        conflict_policy: ConflictPolicy::from_db_str(&raw_policy),
        base_target_exists: base_exists_i64 != 0,
        base_target_dev: base_dev_i64 as u64,
        base_target_ino: base_ino_i64 as u64,
        base_target_size: u64::try_from(base_size_i64.max(0)).unwrap_or(0),
        audit_event_id,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        expires_at: row.get(11)?,
    })
}

fn load_session_conn(
    conn: &Connection,
    upload_id: &str,
) -> Result<Option<UploadSessionRecord>, McBrowserError> {
    let sql = format!("SELECT {SESSION_SELECT_COLUMNS} FROM mcbrowser_uploads WHERE id = ?1");
    conn.query_row(&sql, params![upload_id], row_to_session)
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to query upload session".to_string()))
}

fn upload_audit_error_code(err: &McBrowserError) -> &'static str {
    match err {
        McBrowserError::BadRequest(_) => "BAD_REQUEST",
        McBrowserError::Unauthorized(_) => "UNAUTHORIZED",
        McBrowserError::Forbidden(_) => "FORBIDDEN",
        McBrowserError::NotFound(_) => "NOT_FOUND",
        McBrowserError::Conflict(_) => "CONFLICT",
        McBrowserError::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
        McBrowserError::QuotaExceeded(_) => "QUOTA_EXCEEDED",
        McBrowserError::InsufficientStorage(_) => "INSUFFICIENT_STORAGE",
        McBrowserError::RangeNotSatisfiable(_) => "RANGE_NOT_SATISFIABLE",
        McBrowserError::RequestTimeout(_) => "REQUEST_TIMEOUT",
        McBrowserError::Internal(_) => "INTERNAL_ERROR",
        McBrowserError::AccountingPending(_) => "ACCOUNTING_PENDING",
    }
}

fn session_published_byte_delta(session: &UploadSessionRecord) -> i64 {
    if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
        return 0;
    }
    if session.base_target_exists {
        let new_len = i128::from(session.upload_length);
        let old_len = i128::from(session.base_target_size);
        let diff = new_len - old_len;
        diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    } else {
        i64::try_from(session.upload_length).unwrap_or(i64::MAX)
    }
}

fn load_session_actor_conn(conn: &Connection, user_id: i64) -> Result<AuthUser, McBrowserError> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![user_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            },
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to load upload session actor".to_string()))?;
    let (username, role) = row.unwrap_or_else(|| (format!("user-{user_id}"), "user".to_string()));
    Ok(AuthUser {
        user_id,
        username,
        role: if role.trim().is_empty() {
            "user".to_string()
        } else {
            role
        },
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    })
}

fn ensure_session_pending_audit_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
) -> Result<String, McBrowserError> {
    super::events::ensure_events_tables(conn)?;
    let existing_id = session.audit_event_id.trim();
    if !existing_id.is_empty() {
        if let Some(rec) = super::events::load_audit_record_by_id_with_conn(conn, existing_id)? {
            if matches!(
                rec.status,
                super::events::AuditEventStatus::Pending
                    | super::events::AuditEventStatus::Completed
            ) {
                return Ok(rec.event.event_id);
            }
        }
    }
    conn.execute_batch("SAVEPOINT mcbrowser_upload_audit_binding")
        .map_err(|_| McBrowserError::Internal("Failed to begin upload audit binding".to_string()))?;
    let binding = (|| -> Result<String, McBrowserError> {
        let actor = load_session_actor_conn(conn, session.user_id)?;
        let pending = super::events::record_pending_intent_with_conn(
            conn,
            &actor,
            super::events::McBrowserEventTrigger::UploadCompleted,
            &session.target_path,
            None,
            session_published_byte_delta(session),
        )?;
        let event_id = pending.event.event_id;
        let changed = conn.execute(
            "UPDATE mcbrowser_uploads SET audit_event_id = ?1 WHERE id = ?2 AND user_id = ?3",
            params![event_id, session.id, session.user_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to bind upload audit event ID".to_string()))?;
        if changed != 1 {
            return Err(McBrowserError::NotFound("Upload session not found".to_string()));
        }
        conn.execute_batch("RELEASE mcbrowser_upload_audit_binding")
            .map_err(|_| McBrowserError::Internal("Failed to commit upload audit binding".to_string()))?;
        Ok(event_id)
    })();
    let event_id = match binding {
        Ok(event_id) => event_id,
        Err(error) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_upload_audit_binding; RELEASE mcbrowser_upload_audit_binding",
            );
            return Err(error);
        }
    };
    session.audit_event_id = event_id.clone();
    Ok(event_id)
}

fn discard_unpublished_session_conn(
    conn: &Connection,
    session: &UploadSessionRecord,
    error: &McBrowserError,
) -> Result<(), McBrowserError> {
    conn.execute_batch("SAVEPOINT mcbrowser_upload_discard")
        .map_err(|_| McBrowserError::Internal("Failed to begin upload cleanup".to_string()))?;
    let cleanup = (|| {
        let Some(current) = load_session_conn(conn, &session.id)? else {
            conn.execute_batch("RELEASE mcbrowser_upload_discard")
                .map_err(|_| {
                    McBrowserError::Internal("Failed to commit upload cleanup".to_string())
                })?;
            return Ok(());
        };
        if current.user_id != session.user_id || current.status == "completed" {
            return Err(McBrowserError::Conflict(
                "Upload is no longer unpublished".to_string(),
            ));
        }
        if !current.audit_event_id.is_empty() {
            super::events::finalize_event_failed_with_conn(
                conn,
                &current.audit_event_id,
                Some(upload_audit_error_code(error)),
            )?;
        }
        if current.quota_reserved && current.reserved_bytes > 0 {
            release_user_quota_conn(conn, current.user_id, current.reserved_bytes)?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1 AND user_id = ?2",
            params![current.id, current.user_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to delete unpublished upload".to_string()))?;
        conn.execute_batch("RELEASE mcbrowser_upload_discard")
            .map_err(|_| McBrowserError::Internal("Failed to commit upload cleanup".to_string()))?;
        Ok(())
    })();
    match cleanup {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_upload_discard; RELEASE mcbrowser_upload_discard",
            );
            Err(error)
        }
    }
}

fn mark_session_skipped_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> Result<(), McBrowserError> {
    if session.conflict_policy != ConflictPolicy::Skip {
        return Err(McBrowserError::Internal(
            "Cannot skip a non-skip upload".to_string(),
        ));
    }
    let expires_at = now_secs + UPLOAD_SESSION_EXPIRY_SECS;
    conn.execute_batch("SAVEPOINT mcbrowser_upload_skip")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin skipped upload completion".to_string())
        })?;
    let completion = (|| -> Result<(), McBrowserError> {
        let changed = conn
            .execute(
                "UPDATE mcbrowser_uploads SET offset_bytes = upload_length, status = 'completed',
             staging_rel_path = '', quota_reserved = 0, reserved_bytes = 0, audit_event_id = '',
             base_target_exists = 1, updated_at = ?1, expires_at = ?2
             WHERE id = ?3 AND user_id = ?4 AND status != 'completed'",
                params![now_secs, expires_at, session.id, session.user_id],
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to persist skipped upload completion".to_string())
            })?;
        if changed > 0 {
            if session.quota_reserved && session.reserved_bytes > 0 {
                release_user_quota_conn(conn, session.user_id, session.reserved_bytes)?;
            }
            if !session.audit_event_id.is_empty() {
                super::events::finalize_event_failed_with_conn(
                    conn,
                    &session.audit_event_id,
                    Some("SKIPPED_CONFLICT"),
                )?;
            }
        }
        conn.execute_batch("RELEASE mcbrowser_upload_skip")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit skipped upload completion".to_string())
            })?;
        Ok(())
    })();
    if let Err(error) = completion {
        let _ =
            conn.execute_batch("ROLLBACK TO mcbrowser_upload_skip; RELEASE mcbrowser_upload_skip");
        return Err(error);
    }
    session.offset_bytes = session.upload_length;
    session.status = "completed".to_string();
    session.staging_rel_path.clear();
    session.quota_reserved = false;
    session.reserved_bytes = 0;
    session.audit_event_id.clear();
    session.base_target_exists = true;
    session.updated_at = now_secs;
    session.expires_at = expires_at;
    Ok(())
}

fn mark_session_completed_conn(
    conn: &Connection,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> Result<(), McBrowserError> {
    let len_i64 = i64::try_from(session.upload_length).unwrap_or(i64::MAX);
    let new_expires = if session.expires_at > now_secs {
        session
            .expires_at
            .max(now_secs + UPLOAD_SESSION_EXPIRY_SECS)
    } else {
        session.expires_at
    };
    let no_publication = (session.conflict_policy == ConflictPolicy::Skip
        && session.base_target_exists)
        || (session.conflict_policy == ConflictPolicy::Resume
            && session.base_target_exists
            && session.base_target_size == session.upload_length);
    super::events::ensure_events_tables(conn)?;
    conn.execute_batch("SAVEPOINT mcbrowser_upload_completion")
        .map_err(|_| McBrowserError::Internal("Failed to begin upload completion".to_string()))?;
    let mut final_audit_id = session.audit_event_id.clone();
    let completion = (|| -> Result<(), McBrowserError> {
        if !no_publication && final_audit_id.trim().is_empty() {
            final_audit_id = ensure_session_pending_audit_conn(conn, session)?;
        }
        let changed = conn.execute(
            "UPDATE mcbrowser_uploads \
             SET offset_bytes = ?1, status = 'completed', staging_rel_path = '', audit_event_id = ?2, updated_at = ?3, expires_at = ?4 \
             WHERE id = ?5 AND user_id = ?6 AND status != 'completed'",
            params![
                len_i64,
                final_audit_id,
                now_secs,
                new_expires,
                session.id,
                session.user_id
            ],
        ).map_err(|_| McBrowserError::Internal("Failed to transition upload session to completed".to_string()))?;
        if changed > 0
            && session.base_target_exists
            && session.conflict_policy != ConflictPolicy::Skip
        {
            let shrink_bytes = session
                .base_target_size
                .saturating_sub(session.upload_length);
            if shrink_bytes > 0 {
                release_user_quota_conn(conn, session.user_id, shrink_bytes)?;
            }
        }
        if !no_publication {
            let delta = session_published_byte_delta(session);
            super::events::finalize_event_completed_with_conn(
                conn,
                &final_audit_id,
                None,
                None,
                delta,
            )?;
        }
        conn.execute_batch("RELEASE mcbrowser_upload_completion")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit upload completion".to_string())
            })?;
        Ok(())
    })();
    if let Err(error) = completion {
        let _ = conn.execute_batch(
            "ROLLBACK TO mcbrowser_upload_completion; RELEASE mcbrowser_upload_completion",
        );
        return Err(error);
    }
    session.audit_event_id = final_audit_id;
    session.offset_bytes = session.upload_length;
    session.status = "completed".to_string();
    session.staging_rel_path.clear();
    session.updated_at = now_secs;
    session.expires_at = new_expires;
    Ok(())
}

pub(crate) fn reconcile_publishing_session_at(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
    attempt_finish_publish: bool,
    now_secs: i64,
) -> Result<PublishingResolution, McBrowserError> {
    let proof = match read_publication_proof_at(base_root, session) {
        Ok(Some(proof)) => proof,
        _ => return Ok(PublishingResolution::AmbiguousRetainQuota),
    };
    let bfs = match open_bound_scope_browser_fs_at(
        base_root,
        session.user_id,
        &session.owner_scope,
        session.scope_root_dev,
        session.scope_root_ino,
    ) {
        Ok(bfs) => bfs,
        Err(_) => return Ok(PublishingResolution::AmbiguousRetainQuota),
    };
    match proof {
        UploadPublicationProof::Published {} => {
            mark_session_completed_conn(conn, session, now_secs)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            return Ok(PublishingResolution::Completed);
        }
        UploadPublicationProof::Prepared {
            device,
            inode,
            nonce,
        } => {
            let proven = bfs
                .open_file(&session.target_path)
                .ok()
                .is_some_and(|file| {
                    prepared_publication_matches(&file, device, inode, nonce.as_deref())
                });
            if !proven {
                return Ok(PublishingResolution::AmbiguousRetainQuota);
            }
            write_publication_proof_at(base_root, session, &UploadPublicationProof::Published {})?;
            mark_session_completed_conn(conn, session, now_secs)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            return Ok(PublishingResolution::Completed);
        }
        UploadPublicationProof::Unpublished {} => {}
    }
    if session.conflict_policy == ConflictPolicy::Skip && !session.base_target_exists {
        match inspect_existing_target_in_bfs(&bfs, &session.target_path) {
            Ok(Some(_)) => {
                mark_session_skipped_conn(conn, session, now_secs)?;
                let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
                return Ok(PublishingResolution::Completed);
            }
            Ok(None) => {}
            Err(error) => {
                discard_unpublished_session_conn(conn, session, &error)?;
                let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
                let _ = remove_publication_proof_at(base_root, session.user_id, &session.id);
                return Err(error);
            }
        }
    }
    if session.status == "publishing" {
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'uploading', updated_at = ?1 WHERE id = ?2 AND user_id = ?3 AND status = 'publishing'",
            params![now_secs, session.id, session.user_id],
        ).map_err(|_| McBrowserError::Internal("Failed to restore unpublished upload status".to_string()))?;
        session.status = "uploading".to_string();
    }
    if !attempt_finish_publish {
        return Ok(PublishingResolution::UnpublishedStagingIntact);
    }
    let current_root = open_verified_user_root_fd(conn, base_root, session.user_id)?;
    verify_session_scope_matches(session, &current_root)?;
    let expected = verify_bound_target_unchanged(&bfs, session)?;
    ensure_session_pending_audit_conn(conn, session)?;
    if session.upload_length == 0 {
        let pending = if session.base_target_exists {
            bfs.begin_replace(&session.target_path)
        } else {
            bfs.begin_upload(&session.target_path)
        }
        .map_err(|error| map_fs_io_error(error, "Failed to prepare recovered upload"))?;
        commit_proven_upload_at(base_root, session, pending, expected.as_ref())?;
    } else {
        let staging = match open_existing_staging_file_at(base_root, session.user_id, &session.id) {
            Ok(staging) => staging,
            Err(McBrowserError::NotFound(_)) => {
                return Ok(PublishingResolution::UnpublishedStagingIntact)
            }
            Err(error) => return Err(error),
        };
        if staging
            .metadata()
            .map_err(|error| map_fs_io_error(error, "Failed to inspect recovered staging"))?
            .len()
            != session.upload_length
        {
            return Ok(PublishingResolution::UnpublishedStagingIntact);
        }
        publish_staging_file_to_browser_fs(
            staging,
            &bfs,
            &session.target_path,
            session.upload_length,
            expected.as_ref(),
            base_root,
            session,
        )?;
    }
    mark_session_completed_conn(conn, session, now_secs)?;
    let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
    Ok(PublishingResolution::Completed)
}

/// Cleans up expired upload sessions (`expires_at <= now`).
/// - Before releasing any quota, reconciles `'publishing'` sessions (and `'uploading'` sessions
///   at `offset_bytes == upload_length`) against disk:
///   - If the file was already published to `BrowserFs`, transitions the session to `'completed'`
///     and NEVER releases quota.
///   - If publication state is ambiguous, conservatively retains the quota reservation (never
///     undercounts a potentially published file).
///   - Only when an unfinished upload is proven unpublished (`status == 'uploading'` with
///     `offset_bytes < upload_length`, or `UnpublishedStagingIntact`) is its `reserved_bytes` released.
/// - For expired `'completed'` sessions: deletes the DB tracking row ONLY and NEVER releases quota.
pub fn cleanup_expired_uploads_at(
    conn: &Connection,
    base_root: &Path,
    now_secs: i64,
) -> Result<usize, McBrowserError> {
    ensure_uploads_schema(conn)?;

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_mcbrowser_uploads_expiry_cursor ON mcbrowser_uploads(expires_at, id)",
    ).map_err(|_| McBrowserError::Internal("Failed to index upload cleanup cursor".to_string()))?;
    let (cursor_expiry, cursor_id): (i64, String) = conn.query_row(
        "SELECT expires_at, upload_id FROM mcbrowser_upload_cleanup_cursor WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| McBrowserError::Internal("Failed to load upload cleanup cursor".to_string()))?;
    let sql = format!(
        "SELECT {SESSION_SELECT_COLUMNS} FROM mcbrowser_uploads WHERE expires_at <= ?1 \
         AND (expires_at, id) > (?2, ?3) ORDER BY expires_at, id LIMIT 128"
    );
    let scan = |expiry: i64, upload_id: &str| -> Result<Vec<UploadSessionRecord>, McBrowserError> {
        let mut statement = conn.prepare(&sql)
            .map_err(|_| McBrowserError::Internal("Failed to prepare expiry query".to_string()))?;
        let rows = statement.query_map(params![now_secs, expiry, upload_id], row_to_session)
            .map_err(|_| McBrowserError::Internal("Failed to scan expired uploads".to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| McBrowserError::Internal("Failed to read expired upload row".to_string()))
    };
    let mut expired = scan(cursor_expiry, &cursor_id)?;
    if expired.is_empty() && (cursor_expiry != i64::MIN || !cursor_id.is_empty()) {
        expired = scan(i64::MIN, "")?;
    }

    if expired.is_empty() {
        return Ok(0);
    }
    let last = expired.last().expect("nonempty expiry page");
    conn.execute(
        "UPDATE mcbrowser_upload_cleanup_cursor SET expires_at = ?1, upload_id = ?2 WHERE singleton = 1",
        params![last.expires_at, last.id],
    ).map_err(|_| McBrowserError::Internal("Failed to advance upload cleanup cursor".to_string()))?;

    let mut cleaned = 0usize;
    let mut staging_to_unlink: Vec<(i64, String)> = Vec::new();

    for mut rec in expired {
        let may_have_published = rec.status == "publishing"
            || (rec.status == "uploading" && rec.offset_bytes == rec.upload_length);

        let resolution = if may_have_published {
            reconcile_publishing_session_at(conn, base_root, &mut rec, false, now_secs)
                .unwrap_or(PublishingResolution::AmbiguousRetainQuota)
        } else {
            PublishingResolution::UnpublishedStagingIntact
        };

        if matches!(resolution, PublishingResolution::AmbiguousRetainQuota) {
            continue;
        }

        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
            .map_err(|_| {
                McBrowserError::Internal("Failed to start expiry cleanup transaction".to_string())
            })?;

        let step = (|| -> Result<bool, McBrowserError> {
            let Some(current) = load_session_conn(conn, &rec.id)? else {
                return Ok(false);
            };
            if current.expires_at > now_secs {
                return Ok(false);
            }

            let safe_to_release_quota = match current.status.as_str() {
                "completed" => false,
                "publishing" => {
                    matches!(resolution, PublishingResolution::UnpublishedStagingIntact)
                }
                "uploading" => {
                    if current.offset_bytes == current.upload_length {
                        matches!(resolution, PublishingResolution::UnpublishedStagingIntact)
                    } else {
                        true
                    }
                }
                _ => false,
            };

            if safe_to_release_quota && current.quota_reserved && current.reserved_bytes > 0 {
                release_user_quota_conn(conn, current.user_id, current.reserved_bytes)?;
            }

            if safe_to_release_quota && !current.audit_event_id.trim().is_empty() {
                super::events::finalize_event_failed_with_conn(
                    conn,
                    &current.audit_event_id,
                    Some("UPLOAD_EXPIRED"),
                )?;
            }

            conn.execute(
                "DELETE FROM mcbrowser_uploads WHERE id = ?1",
                params![current.id],
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to delete expired upload row".to_string())
            })?;
            Ok(true)
        })();

        match step {
            Ok(removed) => {
                conn.execute_batch("COMMIT").map_err(|_| {
                    let _ = conn.execute_batch("ROLLBACK");
                    McBrowserError::Internal("Failed to commit expiry cleanup".to_string())
                })?;
                if removed {
                    cleaned += 1;
                    staging_to_unlink.push((rec.user_id, rec.id));
                }
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }

    for (uid, id) in staging_to_unlink {
        let _ = remove_staging_file_at(base_root, uid, &id);
        let _ = remove_publication_proof_at(base_root, uid, &id);
    }

    Ok(cleaned)
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability-Oriented Private Staging Filesystem Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn openat_no_symlinks(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: flags as u64,
        mode: if (flags & libc::O_CREAT) != 0 {
            mode as u64
        } else {
            0
        },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if rc >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(rc as libc::c_int) });
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {}
        _ => return Err(err),
    }

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

fn ensure_private_dir_child(
    parent_fd: libc::c_int,
    child_name: &str,
) -> Result<OwnedFd, McBrowserError> {
    let child_c = CString::new(child_name.as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid staging directory component".to_string()))?;
    let mkdir_rc = unsafe { libc::mkdirat(parent_fd, child_c.as_ptr(), 0o700) };
    if mkdir_rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::AlreadyExists {
            return Err(McBrowserError::Internal(
                "Failed to provision upload staging directory".to_string(),
            ));
        }
    }
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(parent_fd, child_c.as_c_str(), dir_flags, 0).map_err(|_| {
        McBrowserError::Internal("Failed to open upload staging directory safely".to_string())
    })?;
    let st = fstat_fd(fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat upload staging directory".to_string())
    })?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != unsafe { libc::geteuid() } {
        return Err(McBrowserError::Internal(
            "Upload staging directory has invalid type or ownership".to_string(),
        ));
    }
    if (st.st_mode & 0o777) != 0o700 && unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } < 0 {
        return Err(McBrowserError::Internal(
            "Failed to enforce 0700 permissions on upload staging directory".to_string(),
        ));
    }
    Ok(fd)
}

/// Opens `<base_root>/.af-upload-staging/user-<user_id>` safely using `O_NOFOLLOW` and `0700` permissions.
fn open_user_staging_dir_at(base_root: &Path, user_id: i64) -> Result<OwnedFd, McBrowserError> {
    if user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }
    if !base_root.is_absolute() || base_root.parent().is_none() {
        return Err(McBrowserError::Internal(
            "McBrowser storage root is misconfigured".to_string(),
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(base_root) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(McBrowserError::Internal(
                "McBrowser storage root is not a valid directory".to_string(),
            ));
        }
    } else {
        fs::create_dir_all(base_root).map_err(|_| {
            McBrowserError::Internal("Failed to initialize McBrowser storage root".to_string())
        })?;
    }

    let base_c = CString::new(base_root.as_os_str().as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid McBrowser storage root path".to_string()))?;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let base_fd_raw = unsafe { libc::open(base_c.as_ptr(), dir_flags) };
    if base_fd_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to open McBrowser storage root".to_string(),
        ));
    }
    let base_fd = unsafe { OwnedFd::from_raw_fd(base_fd_raw) };
    let base_st = fstat_fd(base_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to inspect McBrowser storage root".to_string())
    })?;
    if (base_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || base_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "Storage root ownership is invalid".to_string(),
        ));
    }
    if (base_st.st_mode & 0o777) != 0o700 && unsafe { libc::fchmod(base_fd.as_raw_fd(), 0o700) } < 0
    {
        return Err(McBrowserError::Internal(
            "Failed to enforce private storage permissions".to_string(),
        ));
    }

    let staging_root_fd = ensure_private_dir_child(base_fd.as_raw_fd(), STAGING_DIR_NAME)?;
    let user_dir_name = format!("user-{user_id}");
    ensure_private_dir_child(staging_root_fd.as_raw_fd(), &user_dir_name)
}

struct VerifiedScopedUserRoot {
    bfs: af_files::BrowserFs,
    scope: String,
    scope_dev: u64,
    scope_ino: u64,
}

/// Opens a specific normalized policy scope directory under `base_root/user-{user_id}` using
/// descriptor-confined traversal (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`
/// / `O_NOFOLLOW`) and records its `(st_dev, st_ino)` identity.
fn open_scoped_user_root_with_scope_at(
    base_root: &Path,
    user_id: i64,
    raw_scope: &str,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let clean_scope = if raw_scope == "/" { "" } else { raw_scope };
    let normalized_scope = super::policy::normalize_scope_path(clean_scope)?;

    // Provision and validate the raw user root (`base_root/user-{user_id}`).
    let _raw_bfs = open_user_browser_fs_at(base_root, user_id)?;

    let base_c = CString::new(base_root.as_os_str().as_bytes())
        .map_err(|_| McBrowserError::Internal("Invalid McBrowser storage root path".to_string()))?;
    let dir_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let base_fd_raw = unsafe { libc::open(base_c.as_ptr(), dir_flags) };
    if base_fd_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to open McBrowser storage root descriptor".to_string(),
        ));
    }
    let base_fd = unsafe { OwnedFd::from_raw_fd(base_fd_raw) };
    let base_st = fstat_fd(base_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat McBrowser storage root descriptor".to_string())
    })?;
    if (base_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || base_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "McBrowser storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    let child_name = format!("user-{user_id}");
    let child_c = CString::new(child_name.as_bytes()).map_err(|_| {
        McBrowserError::Internal("Failed to construct user storage directory name".to_string())
    })?;
    let mut current_fd = openat_no_symlinks(base_fd.as_raw_fd(), child_c.as_c_str(), dir_flags, 0)
        .map_err(|_| {
            McBrowserError::Internal("Failed to open user storage root descriptor".to_string())
        })?;
    let user_st = fstat_fd(current_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat user storage root descriptor".to_string())
    })?;
    if (user_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || user_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "User storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    for seg in normalized_scope.split('/').filter(|s| !s.is_empty()) {
        let c_seg = CString::new(seg).map_err(|_| {
            McBrowserError::BadRequest("Invalid configured policy scope segment".to_string())
        })?;
        current_fd = openat_no_symlinks(current_fd.as_raw_fd(), c_seg.as_c_str(), dir_flags, 0)
            .map_err(|e| map_fs_io_error(e, "Failed to open configured policy scope"))?;
    }

    let scope_st = fstat_fd(current_fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to stat scoped user storage root descriptor".to_string())
    })?;
    if (scope_st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || scope_st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "Scoped user storage root descriptor ownership or type is invalid".to_string(),
        ));
    }

    let scope_dev = scope_st.st_dev as u64;
    let scope_ino = scope_st.st_ino as u64;
    let scoped_bfs = af_files::BrowserFs::from_directory(current_fd).map_err(|_| {
        McBrowserError::Internal("Failed to initialize scoped user filesystem".to_string())
    })?;

    Ok(VerifiedScopedUserRoot {
        bfs: scoped_bfs,
        scope: normalized_scope,
        scope_dev,
        scope_ino,
    })
}

/// Opens the user's currently configured effective policy scope directory using the caller's
/// existing SQLite `Connection` (`super::policy::effective_scope_with_conn`).
fn open_verified_user_root_fd(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let raw_scope = super::policy::effective_scope_with_conn(conn, user_id)?;
    open_scoped_user_root_with_scope_at(base_root, user_id, &raw_scope)
}

/// Opens the exact bound scoped root directory recorded on an `UploadSessionRecord` and verifies
/// its `(st_dev, st_ino)` identity matches.
fn open_bound_scope_browser_fs_at(
    base_root: &Path,
    user_id: i64,
    owner_scope: &str,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<af_files::BrowserFs, McBrowserError> {
    let root = open_scoped_user_root_with_scope_at(base_root, user_id, owner_scope)?;
    if (expected_dev != 0 || expected_ino != 0)
        && (root.scope_dev != expected_dev || root.scope_ino != expected_ino)
    {
        return Err(McBrowserError::Conflict(
            "Upload session scoped root directory was replaced on disk".to_string(),
        ));
    }
    Ok(root.bfs)
}

/// Ensures an upload session remains bound to the exact policy scope and scoped-root directory
/// `(scope_root_dev, scope_root_ino)` under which it was created. Any admin scope remap or
/// directory replacement fails closed with `409 Conflict`.
fn verify_session_scope_matches(
    session: &UploadSessionRecord,
    scoped_root: &VerifiedScopedUserRoot,
) -> Result<(), McBrowserError> {
    if session.owner_scope != scoped_root.scope {
        return Err(McBrowserError::Conflict(
            "Upload session scope no longer matches user's active policy scope".to_string(),
        ));
    }
    if (session.scope_root_dev != 0 || session.scope_root_ino != 0)
        && (session.scope_root_dev != scoped_root.scope_dev
            || session.scope_root_ino != scoped_root.scope_ino)
    {
        return Err(McBrowserError::Conflict(
            "Upload session scoped root directory changed on disk".to_string(),
        ));
    }
    Ok(())
}

fn staging_file_c_name(upload_id: &str) -> Result<CString, McBrowserError> {
    let valid_id = validate_upload_id(upload_id)?;
    CString::new(format!("{valid_id}.part"))
        .map_err(|_| McBrowserError::Internal("Invalid staging filename".to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum UploadPublicationProof {
    Unpublished {},
    Prepared {
        device: u64,
        inode: u64,
        nonce: Option<String>,
    },
    Published {},
}

const PUBLICATION_XATTR: &[u8] = b"user.aetherflow.upload-proof\0";

fn publication_proof_name(upload_id: &str) -> Result<CString, McBrowserError> {
    let id = validate_upload_id(upload_id)?;
    CString::new(format!("{id}.publication"))
        .map_err(|_| McBrowserError::Internal("Invalid publication proof filename".to_string()))
}

fn write_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    proof: &UploadPublicationProof,
) -> Result<(), McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, session.user_id)?;
    let name = publication_proof_name(&session.id)?;
    let temporary_name = CString::new(format!("{}.{}.tmp", session.id, Uuid::new_v4().simple()))
        .map_err(|_| {
            McBrowserError::Internal("Invalid publication proof temporary name".to_string())
        })?;
    let descriptor = openat_no_symlinks(
        directory.as_raw_fd(),
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|error| map_fs_io_error(error, "Failed to create publication proof"))?;
    let mut file = File::from(descriptor);
    let outcome = (|| {
        let bytes = serde_json::to_vec(proof).map_err(|_| {
            McBrowserError::Internal("Failed to encode publication proof".to_string())
        })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| map_fs_io_error(error, "Failed to persist publication proof"))?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } < 0
        {
            return Err(map_fs_io_error(
                io::Error::last_os_error(),
                "Failed to install publication proof",
            ));
        }
        if unsafe { libc::fsync(directory.as_raw_fd()) } < 0 {
            return Err(map_fs_io_error(
                io::Error::last_os_error(),
                "Failed to sync publication proof directory",
            ));
        }
        Ok(())
    })();
    if outcome.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0);
        }
    }
    outcome
}

fn read_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
) -> Result<Option<UploadPublicationProof>, McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, session.user_id)?;
    let name = publication_proof_name(&session.id)?;
    let descriptor = match openat_no_symlinks(
        directory.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_fs_io_error(error, "Failed to open publication proof")),
    };
    let metadata = fstat_fd(descriptor.as_raw_fd())
        .map_err(|error| map_fs_io_error(error, "Failed to inspect publication proof"))?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_size < 0
        || metadata.st_size > 4096
    {
        return Err(McBrowserError::Forbidden(
            "Invalid publication proof file".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| map_fs_io_error(error, "Failed to read publication proof"))?;
    if bytes.len() > 4096 {
        return Err(McBrowserError::Forbidden(
            "Publication proof is oversized".to_string(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| McBrowserError::Internal("Invalid publication proof document".to_string()))
}

fn remove_publication_proof_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<(), McBrowserError> {
    let directory = open_user_staging_dir_at(base_root, user_id)?;
    let name = publication_proof_name(upload_id)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::NotFound {
            return Err(map_fs_io_error(error, "Failed to remove publication proof"));
        }
    }
    Ok(())
}

fn prepare_publication_proof_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    file: &File,
) -> Result<(), McBrowserError> {
    let metadata = fstat_fd(file.as_raw_fd())
        .map_err(|error| map_fs_io_error(error, "Failed to inspect prepared publication"))?;
    let nonce = Uuid::new_v4().simple().to_string();
    let tagged = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            PUBLICATION_XATTR.as_ptr().cast(),
            nonce.as_ptr().cast(),
            nonce.len(),
            0,
        )
    };
    let nonce = if tagged == 0 {
        file.sync_all()
            .map_err(|error| map_fs_io_error(error, "Failed to sync publication identity"))?;
        Some(nonce)
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EOPNOTSUPP) | Some(libc::EPERM) => None,
            _ => {
                return Err(map_fs_io_error(
                    error,
                    "Failed to bind publication identity",
                ))
            }
        }
    };
    write_publication_proof_at(
        base_root,
        session,
        &UploadPublicationProof::Prepared {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            nonce,
        },
    )
}

fn prepared_publication_matches(file: &File, device: u64, inode: u64, nonce: Option<&str>) -> bool {
    let Some(nonce) = nonce
        .filter(|nonce| nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()))
    else {
        return false;
    };
    let Ok(metadata) = fstat_fd(file.as_raw_fd()) else {
        return false;
    };
    if metadata.st_dev as u64 != device || metadata.st_ino as u64 != inode || metadata.st_nlink != 1
    {
        return false;
    }
    let mut actual = [0_u8; 32];
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            PUBLICATION_XATTR.as_ptr().cast(),
            actual.as_mut_ptr().cast(),
            actual.len(),
        )
    };
    length == 32 && actual.as_slice() == nonce.as_bytes()
}

fn commit_proven_upload_at(
    base_root: &Path,
    session: &UploadSessionRecord,
    pending: af_files::PendingUpload,
    expected: Option<&File>,
) -> Result<(), McBrowserError> {
    let file = pending
        .file()
        .map_err(|error| map_fs_io_error(error, "Failed to open publication handle"))?;
    prepare_publication_proof_at(base_root, session, &file)?;
    let outcome = match expected {
        Some(expected) => pending.commit_replace(expected),
        None => pending.commit(),
    };
    match outcome {
        Ok(()) => {
            if let Err(error) = write_publication_proof_at(
                base_root,
                session,
                &UploadPublicationProof::Published {},
            ) {
                tracing::warn!(?error, upload_id = %session.id, "Published upload retains prepared identity for recovery");
            }
            Ok(())
        }
        Err(error) => {
            write_publication_proof_at(
                base_root,
                session,
                &UploadPublicationProof::Unpublished {},
            )?;
            Err(map_fs_io_error(
                error,
                "Failed to finalize upload publication",
            ))
        }
    }
}

fn create_exclusive_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<File, McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(
        user_staging_dir.as_raw_fd(),
        file_name.as_c_str(),
        flags,
        0o600,
    )
    .map_err(|e| map_fs_io_error(e, "Failed to create upload staging file"))?;
    let st = fstat_fd(fd.as_raw_fd())
        .map_err(|_| McBrowserError::Internal("Failed to stat upload staging file".to_string()))?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_nlink != 1
        || st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Forbidden(
            "Staging file failed security validation".to_string(),
        ));
    }
    Ok(File::from(fd))
}

fn open_existing_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<File, McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let fd = openat_no_symlinks(user_staging_dir.as_raw_fd(), file_name.as_c_str(), flags, 0)
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => {
                McBrowserError::NotFound("Upload staging file is missing".to_string())
            }
            _ => map_fs_io_error(e, "Failed to open upload staging file"),
        })?;
    let st = fstat_fd(fd.as_raw_fd()).map_err(|_| {
        McBrowserError::Internal("Failed to inspect upload staging file".to_string())
    })?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_nlink != 1
        || st.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Forbidden(
            "Staging file must be a single-link regular file owned by the service".to_string(),
        ));
    }
    Ok(File::from(fd))
}

fn remove_staging_file_at(
    base_root: &Path,
    user_id: i64,
    upload_id: &str,
) -> Result<(), McBrowserError> {
    let user_staging_dir = open_user_staging_dir_at(base_root, user_id)?;
    let file_name = staging_file_c_name(upload_id)?;
    let rc = unsafe { libc::unlinkat(user_staging_dir.as_raw_fd(), file_name.as_ptr(), 0) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::NotFound {
            return Err(map_fs_io_error(err, "Failed to remove upload staging file"));
        }
    }
    Ok(())
}

/// Reconciles SQLite `offset_bytes` with the physical staging file on disk after a crash or interrupted PATCH.
/// - If disk size > `session.offset_bytes`, truncates the uncommitted tail on disk back to `session.offset_bytes`.
/// - If disk size < `session.offset_bytes`, updates SQLite `offset_bytes` down to disk size so the client
///   re-uploads any bytes that were not durably persisted.
fn reconcile_staging_offset_at(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
) -> Result<File, McBrowserError> {
    let file = open_existing_staging_file_at(base_root, session.user_id, &session.id)?;
    let meta = file.metadata().map_err(|_| {
        McBrowserError::Internal("Failed to read staging file metadata".to_string())
    })?;
    let disk_len = meta.len();

    if disk_len > session.offset_bytes {
        file.set_len(session.offset_bytes).map_err(|e| {
            map_fs_io_error(e, "Failed to truncate uncommitted tail on staging file")
        })?;
        file.sync_data()
            .map_err(|e| map_fs_io_error(e, "Failed to sync truncated staging file"))?;
    } else if disk_len < session.offset_bytes {
        let now = now_unix_secs();
        let disk_i64 = i64::try_from(disk_len).unwrap_or(0);
        conn.execute(
            "UPDATE mcbrowser_uploads SET offset_bytes = ?1, status = 'uploading', updated_at = ?2 WHERE id = ?3 AND status IN ('uploading', 'publishing')",
            params![disk_i64, now, session.id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to reconcile upload offset in database".to_string()))?;
        session.offset_bytes = disk_len;
        session.status = "uploading".to_string();
        session.updated_at = now;
    }

    Ok(file)
}

/// Inspects whether `target_path` currently exists in `bfs`.
/// - If it exists as a single-link regular file, returns `Ok(Some((file, st_dev, st_ino, st_size)))`.
/// - If it is a directory, returns `Err(McBrowserError::BadRequest)`.
/// - If it is a symlink or multi-hardlink file, returns `Err(McBrowserError::Forbidden)`.
/// - If it does not exist (`ErrorKind::NotFound`), returns `Ok(None)`.
fn inspect_existing_target_in_bfs(
    bfs: &af_files::BrowserFs,
    target_path: &str,
) -> Result<Option<(File, u64, u64, u64)>, McBrowserError> {
    match bfs.open_file(target_path) {
        Ok(file) => {
            let st = fstat_fd(file.as_raw_fd())
                .map_err(|e| map_fs_io_error(e, "Failed to inspect target file metadata"))?;
            let file_type = st.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFDIR {
                return Err(McBrowserError::BadRequest(
                    "Target path is a directory".to_string(),
                ));
            }
            if file_type != libc::S_IFREG || st.st_nlink != 1 {
                return Err(McBrowserError::Forbidden(
                    "Target file must be a single-link regular file".to_string(),
                ));
            }
            let dev = st.st_dev as u64;
            let ino = st.st_ino as u64;
            let size = u64::try_from(st.st_size.max(0)).unwrap_or(0);
            Ok(Some((file, dev, ino, size)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(map_fs_io_error(e, "Failed to inspect target path")),
    }
}

/// Verifies that the target file in `bfs` still matches the identity and size bound at session creation:
/// - When `session.base_target_exists == true`: requires `target_path` to still exist as a single-link
///   regular file with `(st_dev, st_ino, st_size) == (base_target_dev, base_target_ino, base_target_size)`,
///   returning the opened `File` handle for `PendingUpload::commit_replace(&expected_file)`.
///   Any modification, replacement, or deletion fails closed with `409 Conflict`.
/// - When `session.base_target_exists == false`: for `Error`, `Overwrite`, and `Resume`, verifies that
///   no concurrent file was created at `target_path` since session creation (`409 Conflict` if one appeared).
fn verify_bound_target_unchanged(
    bfs: &af_files::BrowserFs,
    session: &UploadSessionRecord,
) -> Result<Option<File>, McBrowserError> {
    if session.base_target_exists {
        let Some((file, dev, ino, size)) =
            inspect_existing_target_in_bfs(bfs, &session.target_path)?
        else {
            return Err(McBrowserError::Conflict(
                "Original target file was removed before upload completed".to_string(),
            ));
        };
        if dev != session.base_target_dev
            || ino != session.base_target_ino
            || size != session.base_target_size
        {
            return Err(McBrowserError::Conflict(
                "Original target file changed since upload session was created".to_string(),
            ));
        }
        Ok(Some(file))
    } else {
        match session.conflict_policy {
            ConflictPolicy::Error | ConflictPolicy::Overwrite | ConflictPolicy::Resume => {
                if inspect_existing_target_in_bfs(bfs, &session.target_path)?.is_some() {
                    return Err(McBrowserError::Conflict(
                        "Target file was created concurrently since upload session started"
                            .to_string(),
                    ));
                }
                Ok(None)
            }
            ConflictPolicy::Skip => Ok(None),
        }
    }
}

/// Copies the existing partial prefix (`0..expected_len`) from `existing_file` into the private
/// staging file for `ConflictPolicy::Resume`, verifying before and after the copy that the source
/// file's `(st_dev, st_ino, st_size, st_nlink)` remained unchanged. Never truncates or mutates the
/// live target file in place.
fn copy_existing_prefix_to_staging(
    mut existing_file: File,
    staging_file: &mut File,
    expected_dev: u64,
    expected_ino: u64,
    expected_len: u64,
) -> Result<(), McBrowserError> {
    let pre_st = fstat_fd(existing_file.as_raw_fd())
        .map_err(|e| map_fs_io_error(e, "Failed to stat existing file before resume copy"))?;
    if (pre_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || pre_st.st_nlink != 1
        || (pre_st.st_dev as u64) != expected_dev
        || (pre_st.st_ino as u64) != expected_ino
        || u64::try_from(pre_st.st_size.max(0)).unwrap_or(0) != expected_len
    {
        return Err(McBrowserError::Conflict(
            "Existing target file changed while initializing resume staging".to_string(),
        ));
    }

    if expected_len > 0 {
        check_fd_free_space(staging_file.as_raw_fd(), expected_len)?;
    }

    existing_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind existing file for resume copy"))?;
    staging_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind staging file for resume copy"))?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let n = match existing_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(map_fs_io_error(
                    e,
                    "Failed to read existing partial file during resume staging",
                ))
            }
        };
        copied = copied.saturating_add(n as u64);
        if copied > expected_len {
            return Err(McBrowserError::Conflict(
                "Existing target file grew while initializing resume staging".to_string(),
            ));
        }
        staging_file
            .write_all(&buf[..n])
            .map_err(|e| map_fs_io_error(e, "Failed to write resume prefix to staging file"))?;
    }

    if copied != expected_len {
        return Err(McBrowserError::Conflict(
            "Existing target file shrank while initializing resume staging".to_string(),
        ));
    }

    let post_st = fstat_fd(existing_file.as_raw_fd())
        .map_err(|e| map_fs_io_error(e, "Failed to re-stat existing file after resume copy"))?;
    if (post_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || post_st.st_nlink != 1
        || (post_st.st_dev as u64) != expected_dev
        || (post_st.st_ino as u64) != expected_ino
        || u64::try_from(post_st.st_size.max(0)).unwrap_or(0) != expected_len
    {
        return Err(McBrowserError::Conflict(
            "Existing target file changed while initializing resume staging".to_string(),
        ));
    }

    staging_file
        .sync_data()
        .map_err(|e| map_fs_io_error(e, "Failed to sync resume prefix in staging file"))
}

/// Copies a completed staging file into `BrowserFs::begin_upload` (or `BrowserFs::begin_replace`
/// when `expected_replace_target` is `Some`) and commits it atomically (`commit()` or `commit_replace()`).
fn publish_staging_file_to_browser_fs(
    mut staging_file: File,
    bfs: &af_files::BrowserFs,
    target_path: &str,
    expected_length: u64,
    expected_replace_target: Option<&File>,
    base_root: &Path,
    session: &UploadSessionRecord,
) -> Result<(), McBrowserError> {
    staging_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind staging file for publication"))?;

    let mut pending = if expected_replace_target.is_some() {
        bfs.begin_replace(target_path)
            .map_err(|e| map_fs_io_error(e, "Failed to initiate replacement file publication"))?
    } else {
        bfs.begin_upload(target_path)
            .map_err(|e| map_fs_io_error(e, "Failed to initiate target file publication"))?
    };

    if expected_length > 0 {
        let pending_file = pending
            .file()
            .map_err(|e| map_fs_io_error(e, "Failed to access pending upload file handle"))?;
        check_fd_free_space(pending_file.as_raw_fd(), expected_length)?;
    }

    let mut buf = vec![0u8; 64 * 1024];
    let mut copied: u64 = 0;
    loop {
        let n = match staging_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(map_fs_io_error(
                    e,
                    "Failed to read staging file during publication",
                ))
            }
        };
        copied = copied.saturating_add(n as u64);
        if copied > expected_length {
            return Err(McBrowserError::BadRequest(
                "Staging file exceeded declared Upload-Length during publication".to_string(),
            ));
        }
        pending
            .write_all(&buf[..n])
            .map_err(|e| map_fs_io_error(e, "Failed to write target file during publication"))?;
    }

    if copied != expected_length {
        return Err(McBrowserError::Internal(
            "Staging file length did not match declared Upload-Length during publication"
                .to_string(),
        ));
    }

    commit_proven_upload_at(base_root, session, pending, expected_replace_target)
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Testable Operations (using explicit `&Connection` and `base_root: &Path`)
// ─────────────────────────────────────────────────────────────────────────────

fn publish_zero_byte_upload_conn(
    conn: &Connection,
    base_root: &Path,
    bfs: &af_files::BrowserFs,
    record: &mut UploadSessionRecord,
    pending: af_files::PendingUpload,
    expected_file: Option<&File>,
    now: i64,
) -> Result<(), McBrowserError> {
    if record.upload_length != 0 || record.offset_bytes != 0 {
        return Err(McBrowserError::Internal(
            "Invalid zero-byte publication session".to_string(),
        ));
    }
    let result = commit_proven_upload_at(base_root, record, pending, expected_file);
    if let Err(error) = result {
        let error = if record.conflict_policy == ConflictPolicy::Skip
            && matches!(error, McBrowserError::Conflict(_))
        {
            match inspect_existing_target_in_bfs(bfs, &record.target_path) {
                Ok(Some(_)) => return mark_session_skipped_conn(conn, record, now),
                Ok(None) => error,
                Err(error) => error,
            }
        } else {
            error
        };
        discard_unpublished_session_conn(conn, record, &error)?;
        let _ = remove_publication_proof_at(base_root, record.user_id, &record.id);
        return Err(error);
    }
    mark_session_completed_conn(conn, record, now)
}

pub(crate) fn create_upload_session_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    headers: &HeaderMap,
    policy_query: Option<&str>,
) -> Result<(UploadSessionRecord, Response), Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    validate_conflict_policy(policy_query).map_err(map_mcbrowser_err_tus)?;
    let header_conflict = headers
        .get("X-Upload-Conflict")
        .and_then(|v| v.to_str().ok());
    validate_conflict_policy(header_conflict).map_err(map_mcbrowser_err_tus)?;

    // Parse Upload-Length
    let Some(len_hv) = headers.get("Upload-Length") else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Missing required Upload-Length header",
        ));
    };
    let Ok(len_str) = len_hv.to_str() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid Upload-Length header",
        ));
    };
    let Ok(upload_length) = len_str.trim().parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Upload-Length must be a non-negative integer",
        ));
    };

    let max_bytes = configured_max_upload_bytes();
    if upload_length > max_bytes {
        return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
            format!(
                "Upload-Length {upload_length} exceeds maximum allowed size of {max_bytes} bytes"
            ),
        )));
    }

    // Reject Content-Length > 0 on POST (creation with upload is not part of core TUS creation)
    if let Some(cl_hv) = headers.get(header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_hv.to_str() {
            if let Ok(cl) = cl_str.trim().parse::<u64>() {
                if cl > 0 {
                    return Err(tus_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "POST /mcbrowser/uploads does not accept a request body; send data via PATCH",
                    ));
                }
            }
        }
    }

    let meta_raw = headers.get("Upload-Metadata").and_then(|v| v.to_str().ok());
    let parsed_meta = parse_upload_metadata(meta_raw).map_err(map_mcbrowser_err_tus)?;
    let conflict_policy = resolve_effective_conflict_policy(
        policy_query,
        header_conflict,
        parsed_meta.conflict_policy,
    )
    .map_err(map_mcbrowser_err_tus)?;
    let fingerprint = parsed_meta.fingerprint.unwrap_or_default();

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_at(conn, base_root, now);

    // Open the user's verified scoped root directory and inspect whether the target file exists.
    let scoped_root =
        open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
    let existing_target = inspect_existing_target_in_bfs(&scoped_root.bfs, &parsed_meta.path)
        .map_err(map_mcbrowser_err_tus)?;
    let (existing_file_opt, base_target_exists, base_target_dev, base_target_ino, base_target_size) =
        match existing_target {
            Some((file, dev, ino, size)) => (Some(file), true, dev, ino, size),
            None => (None, false, 0, 0, 0),
        };

    // Enforce policy permissions (`Permission::Modify` for Overwrite/Resume, `Permission::Create` for new files)
    authorize_conflict_policy_permissions_with_conn(
        conn,
        user,
        &parsed_meta.path,
        conflict_policy,
        base_target_exists,
    )
    .map_err(map_mcbrowser_err_tus)?;

    let upload_id = Uuid::new_v4().simple().to_string();
    let expires_at = now + UPLOAD_SESSION_EXPIRY_SECS;
    let owner_scope = scoped_root.scope.clone();
    let scope_root_dev = scoped_root.scope_dev;
    let scope_root_ino = scoped_root.scope_ino;

    // Fast path for `ConflictPolicy::Skip` when the target regular file already exists:
    // leave the existing file untouched, reserve 0 bytes of quota, and complete immediately.
    if conflict_policy == ConflictPolicy::Skip && base_target_exists {
        drop(existing_file_opt);
        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
            .map_err(|_| {
                map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to begin skipped upload session transaction".to_string(),
                ))
            })?;

        let skip_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
            let username_opt: Option<String> = conn
                .query_row(
                    "SELECT username FROM users WHERE id = ?1",
                    params![user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| McBrowserError::Internal("Failed to query user record".to_string()))?;
            if username_opt.is_none() {
                return Err(McBrowserError::Unauthorized(
                    "User account not found".to_string(),
                ));
            }
            load_active_quota_conn(conn, user_id, 0)?;

            let len_i64 = i64::try_from(upload_length).map_err(|_| {
                McBrowserError::PayloadTooLarge(
                    "Upload-Length exceeds supported integer range".to_string(),
                )
            })?;
            let dev_i64 = i64::try_from(scope_root_dev).unwrap_or(0);
            let ino_i64 = i64::try_from(scope_root_ino).unwrap_or(0);
            let base_dev_i64 = i64::try_from(base_target_dev).unwrap_or(0);
            let base_ino_i64 = i64::try_from(base_target_ino).unwrap_or(0);
            let base_size_i64 = i64::try_from(base_target_size).unwrap_or(0);

            conn.execute(
                "INSERT INTO mcbrowser_uploads \
                 (id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, staging_rel_path, \
                  quota_reserved, conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size, \
                  created_at, updated_at, expires_at, owner_scope, scope_root_dev, scope_root_ino) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 'completed', '', 0, 'skip', 0, 1, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?13)",
                params![
                    upload_id,
                    user_id,
                    parsed_meta.path,
                    fingerprint,
                    len_i64,
                    base_dev_i64,
                    base_ino_i64,
                    base_size_i64,
                    now,
                    expires_at,
                    owner_scope,
                    dev_i64,
                    ino_i64,
                ],
            )
            .map_err(|_| McBrowserError::Internal("Failed to persist skipped upload session".to_string()))?;

            Ok(UploadSessionRecord {
                id: upload_id.clone(),
                user_id,
                owner_scope: owner_scope.clone(),
                scope_root_dev,
                scope_root_ino,
                target_path: parsed_meta.path.clone(),
                fingerprint: fingerprint.clone(),
                upload_length,
                offset_bytes: upload_length,
                status: "completed".to_string(),
                staging_rel_path: String::new(),
                quota_reserved: false,
                reserved_bytes: 0,
                conflict_policy: ConflictPolicy::Skip,
                base_target_exists: true,
                base_target_dev,
                base_target_ino,
                base_target_size,
                audit_event_id: String::new(),
                created_at: now,
                updated_at: now,
                expires_at,
            })
        })();

        let record = match skip_res {
            Ok(rec) => {
                if conn.execute_batch("COMMIT").is_err() {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                        "Failed to commit skipped upload session".to_string(),
                    )));
                }
                rec
            }
            Err(err) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(err));
            }
        };

        let location = format!("/api/v1/auth/mcbrowser/uploads/{}", record.id);
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::CREATED;
        let h = resp.headers_mut();
        if let Ok(loc_hv) = HeaderValue::from_str(&location) {
            h.insert(header::LOCATION, loc_hv);
        }
        if let Ok(off_hv) = HeaderValue::from_str(&record.offset_bytes.to_string()) {
            h.insert("Upload-Offset", off_hv);
        }
        h.insert("Upload-Status", HeaderValue::from_static("completed"));
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
        let encoded_meta = encode_session_metadata_header(&record);
        if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
            h.insert("Upload-Metadata", meta_hv);
        }
        if let Ok(path_hv) = HeaderValue::from_str(&record.target_path) {
            h.insert("Upload-Path", path_hv);
        }
        return Ok((record, with_tus_headers(resp)));
    }

    // Validate conflict policy against target existence and preflight `begin_upload` / `begin_replace`.
    let preflight_pending = match conflict_policy {
        ConflictPolicy::Error => {
            if base_target_exists {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                    "Target file already exists".to_string(),
                )));
            }
            scoped_root
                .bfs
                .begin_upload(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                })?
        }
        ConflictPolicy::Skip => {
            // `base_target_exists == false` here because `base_target_exists == true` returned above.
            scoped_root
                .bfs
                .begin_upload(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                })?
        }
        ConflictPolicy::Overwrite => {
            if base_target_exists {
                scoped_root
                    .bfs
                    .begin_replace(&parsed_meta.path)
                    .map_err(|e| {
                        map_mcbrowser_err_tus(map_fs_io_error(
                            e,
                            "Failed to initiate replacement upload",
                        ))
                    })?
            } else {
                scoped_root
                    .bfs
                    .begin_upload(&parsed_meta.path)
                    .map_err(|e| {
                        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to initiate upload"))
                    })?
            }
        }
        ConflictPolicy::Resume => {
            if !base_target_exists {
                return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                    "Target file does not exist for resume".to_string(),
                )));
            }
            if base_target_size > upload_length {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(format!(
                    "Existing target file size ({base_target_size} bytes) exceeds Upload-Length ({upload_length} bytes); refusing to truncate live file"
                ))));
            }
            scoped_root
                .bfs
                .begin_replace(&parsed_meta.path)
                .map_err(|e| {
                    map_mcbrowser_err_tus(map_fs_io_error(
                        e,
                        "Failed to initiate resume replacement upload",
                    ))
                })?
        }
    };

    let preflight_file = preflight_pending.file().map_err(|e| {
        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to inspect target directory"))
    })?;
    check_fd_free_space(preflight_file.as_raw_fd(), upload_length.max(1))
        .map_err(map_mcbrowser_err_tus)?;

    let initial_offset = if conflict_policy == ConflictPolicy::Resume {
        base_target_size
    } else {
        0
    };
    let reserved_bytes = if base_target_exists {
        upload_length.saturating_sub(base_target_size)
    } else {
        upload_length
    };
    let completes_immediately = initial_offset == upload_length;
    let initial_status = if completes_immediately {
        "publishing"
    } else {
        "uploading"
    };
    let staging_rel = if completes_immediately {
        String::new()
    } else {
        format!("user-{user_id}/{upload_id}.part")
    };
    let is_noop_resume =
        completes_immediately && conflict_policy == ConflictPolicy::Resume && base_target_exists;
    super::events::ensure_events_tables(conn).map_err(map_mcbrowser_err_tus)?;

    // Reserve positive-delta quota + enforce active session cap + insert upload record in one atomic SQLite transaction
    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to begin upload creation transaction".to_string(),
            ))
        })?;

    let tx_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
        let username: Option<String> = conn
            .query_row(
                "SELECT username FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| McBrowserError::Internal("Failed to query user record".to_string()))?;

        let Some(username) = username else {
            return Err(McBrowserError::Unauthorized(
                "User account not found".to_string(),
            ));
        };

        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mcbrowser_uploads WHERE user_id = ?1 AND status IN ('uploading', 'publishing') AND expires_at > ?2",
                params![user_id, now],
                |r| r.get(0),
            )
            .map_err(|_| McBrowserError::Internal("Failed to count active upload sessions".to_string()))?;

        if !completes_immediately && active_count >= MAX_ACTIVE_UPLOADS_PER_USER {
            return Err(McBrowserError::Conflict(format!(
                "Maximum of {MAX_ACTIVE_UPLOADS_PER_USER} active resumable uploads per user reached"
            )));
        }

        let snapshot = load_active_quota_conn(conn, user_id, reserved_bytes)?;
        if reserved_bytes > 0 {
            let delta_i64 = i64::try_from(reserved_bytes).unwrap_or(i64::MAX);
            let new_used = snapshot.used_bytes.saturating_add(delta_i64);
            conn.execute(
                "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, updated_at) \
                 VALUES (?1, ?2, 0, ?3, 'active', 'manual', CURRENT_TIMESTAMP) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                    used_bytes = ?3, \
                    updated_at = CURRENT_TIMESTAMP",
                params![user_id, username, new_used],
            )
            .map_err(|_| McBrowserError::Internal("Failed to reserve user storage quota".to_string()))?;
        }

        let len_i64 = i64::try_from(upload_length).map_err(|_| {
            McBrowserError::PayloadTooLarge(
                "Upload-Length exceeds supported integer range".to_string(),
            )
        })?;
        let off_i64 = i64::try_from(initial_offset).unwrap_or(0);
        let reserved_i64 = i64::try_from(reserved_bytes).unwrap_or(i64::MAX);
        let dev_i64 = i64::try_from(scope_root_dev).unwrap_or(0);
        let ino_i64 = i64::try_from(scope_root_ino).unwrap_or(0);
        let base_exists_i64 = if base_target_exists { 1i64 } else { 0i64 };
        let base_dev_i64 = i64::try_from(base_target_dev).unwrap_or(0);
        let base_ino_i64 = i64::try_from(base_target_ino).unwrap_or(0);
        let base_size_i64 = i64::try_from(base_target_size).unwrap_or(0);

        let expected_delta = if base_target_exists {
            let diff = i128::from(upload_length) - i128::from(base_target_size);
            diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        } else {
            len_i64
        };
        let audit_event_id = if is_noop_resume {
            String::new()
        } else {
            super::events::record_pending_intent_with_conn(
                conn,
                user,
                super::events::McBrowserEventTrigger::UploadCompleted,
                &parsed_meta.path,
                None,
                expected_delta,
            )?
            .event
            .event_id
        };

        conn.execute(
            "INSERT INTO mcbrowser_uploads \
             (id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, staging_rel_path, \
              quota_reserved, conflict_policy, reserved_bytes, base_target_exists, base_target_dev, base_target_ino, base_target_size, \
              audit_event_id, created_at, updated_at, expires_at, owner_scope, scope_root_dev, scope_root_ino) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17, ?18, ?19, ?20)",
            params![
                upload_id,
                user_id,
                parsed_meta.path,
                fingerprint,
                len_i64,
                off_i64,
                initial_status,
                staging_rel,
                conflict_policy.as_str(),
                reserved_i64,
                base_exists_i64,
                base_dev_i64,
                base_ino_i64,
                base_size_i64,
                audit_event_id,
                now,
                expires_at,
                owner_scope,
                dev_i64,
                ino_i64,
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist upload session".to_string()))?;

        Ok(UploadSessionRecord {
            id: upload_id.clone(),
            user_id,
            target_path: parsed_meta.path.clone(),
            fingerprint: fingerprint.clone(),
            upload_length,
            offset_bytes: initial_offset,
            status: initial_status.to_string(),
            staging_rel_path: staging_rel,
            quota_reserved: true,
            reserved_bytes,
            conflict_policy,
            base_target_exists,
            base_target_dev,
            base_target_ino,
            base_target_size,
            audit_event_id,
            created_at: now,
            updated_at: now,
            expires_at,
            owner_scope: owner_scope.clone(),
            scope_root_dev,
            scope_root_ino,
        })
    })();

    let mut record = match tx_res {
        Ok(rec) => {
            if conn.execute_batch("COMMIT").is_err() {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to commit upload session creation".to_string(),
                )));
            }
            rec
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(map_mcbrowser_err_tus(err));
        }
    };

    if record.status != "completed" {
        if let Err(error) =
            write_publication_proof_at(base_root, &record, &UploadPublicationProof::Unpublished {})
        {
            discard_unpublished_session_conn(conn, &record, &error)
                .map_err(map_mcbrowser_err_tus)?;
            let _ = remove_publication_proof_at(base_root, user_id, &record.id);
            return Err(map_mcbrowser_err_tus(error));
        }
    }

    if completes_immediately {
        if conflict_policy != ConflictPolicy::Resume && upload_length == 0 {
            publish_zero_byte_upload_conn(
                conn,
                base_root,
                &scoped_root.bfs,
                &mut record,
                preflight_pending,
                existing_file_opt.as_ref(),
                now,
            )
            .map_err(map_mcbrowser_err_tus)?;
        } else {
            // `ConflictPolicy::Resume` where `base_target_size == upload_length`:
            // verify the existing file still matches its bound identity/size and mark completed.
            drop(preflight_pending);
            if let Err(verify_err) = verify_bound_target_unchanged(&scoped_root.bfs, &record) {
                let _ = conn.execute(
                    "DELETE FROM mcbrowser_uploads WHERE id = ?1",
                    params![record.id],
                );
                return Err(map_mcbrowser_err_tus(verify_err));
            }
            mark_session_completed_conn(conn, &mut record, now).map_err(map_mcbrowser_err_tus)?;
        }
    } else {
        // Drop preflight_pending (unlinks `.af-upload-tmp.*` in user root) and create private staging file
        drop(preflight_pending);
        let mut staging_file =
            match create_exclusive_staging_file_at(base_root, user_id, &record.id) {
                Ok(f) => f,
                Err(staging_err) => {
                    discard_unpublished_session_conn(conn, &record, &staging_err)
                        .map_err(map_mcbrowser_err_tus)?;
                    let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                    return Err(map_mcbrowser_err_tus(staging_err));
                }
            };

        if conflict_policy == ConflictPolicy::Resume && initial_offset > 0 {
            let Some(existing_file) = existing_file_opt else {
                let error =
                    McBrowserError::NotFound("Target file does not exist for resume".to_string());
                discard_unpublished_session_conn(conn, &record, &error)
                    .map_err(map_mcbrowser_err_tus)?;
                let _ = remove_staging_file_at(base_root, user_id, &record.id);
                let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                return Err(map_mcbrowser_err_tus(error));
            };

            if let Err(copy_err) = copy_existing_prefix_to_staging(
                existing_file,
                &mut staging_file,
                base_target_dev,
                base_target_ino,
                initial_offset,
            ) {
                drop(staging_file);
                discard_unpublished_session_conn(conn, &record, &copy_err)
                    .map_err(map_mcbrowser_err_tus)?;
                let _ = remove_staging_file_at(base_root, user_id, &record.id);
                let _ = remove_publication_proof_at(base_root, user_id, &record.id);
                return Err(map_mcbrowser_err_tus(copy_err));
            }
        }
    }

    let location = format!("/api/v1/auth/mcbrowser/uploads/{}", record.id);
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::CREATED;
    let h = resp.headers_mut();
    if let Ok(loc_hv) = HeaderValue::from_str(&location) {
        h.insert(header::LOCATION, loc_hv);
    }
    if let Ok(off_hv) = HeaderValue::from_str(&record.offset_bytes.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(status_hv) = HeaderValue::from_str(&record.status) {
        h.insert("Upload-Status", status_hv);
    }
    if record.status == "completed"
        && record.conflict_policy == ConflictPolicy::Skip
        && record.base_target_exists
    {
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
    }
    let encoded_meta = encode_session_metadata_header(&record);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&record.target_path) {
        h.insert("Upload-Path", path_hv);
    }
    Ok((record, with_tus_headers(resp)))
}

pub(crate) fn discover_uploads_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    query: &DiscoverUploadsQuery,
) -> Result<DiscoverUploadsResponse, Response> {
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let raw_path = query.path.as_deref().unwrap_or("");
    let normalized_path =
        normalize_relative_path(raw_path, false).map_err(map_mcbrowser_err_tus)?;

    let Some(raw_len) = query
        .length
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' is required for upload discovery",
        ));
    };
    let Ok(upload_length) = raw_len.parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' must be a non-negative integer",
        ));
    };
    let len_i64 = i64::try_from(upload_length).map_err(|_| {
        tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'length' exceeds supported range",
        )
    })?;

    // Fingerprint is required to prevent unsafe same-name+size resume across modified files
    let Some(raw_fp) = query
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Query parameter 'fingerprint' is required for safe resumable upload discovery",
        ));
    };
    let fingerprint = validate_fingerprint_value(raw_fp).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_at(conn, base_root, now);

    let scoped_root_opt = open_verified_user_root_fd(conn, base_root, user_id).ok();

    let sql = format!(
        "SELECT {SESSION_SELECT_COLUMNS} \
         FROM mcbrowser_uploads \
         WHERE user_id = ?1 AND status IN ('uploading', 'publishing') AND target_path = ?2 \
           AND upload_length = ?3 AND fingerprint = ?4 AND expires_at > ?5 \
         ORDER BY updated_at DESC, created_at DESC"
    );
    let mut stmt = conn.prepare(&sql).map_err(|_| {
        map_mcbrowser_err_tus(McBrowserError::Internal(
            "Failed to query resumable uploads".to_string(),
        ))
    })?;

    let rows: Vec<UploadSessionRecord> = stmt
        .query_map(
            params![user_id, normalized_path, len_i64, fingerprint, now],
            row_to_session,
        )
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to execute resumable uploads query".to_string(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to read resumable upload row".to_string(),
            ))
        })?;
    drop(stmt);

    let mut uploads = Vec::new();
    for mut rec in rows {
        if rec.status == "publishing"
            || (rec.status == "uploading" && rec.offset_bytes == rec.upload_length)
        {
            match reconcile_publishing_session_at(conn, base_root, &mut rec, false, now) {
                Ok(PublishingResolution::Completed) => {
                    continue;
                }
                Ok(PublishingResolution::AmbiguousRetainQuota) => {
                    continue;
                }
                Ok(PublishingResolution::UnpublishedStagingIntact) => {
                    let Some(ref scoped_root) = scoped_root_opt else {
                        continue;
                    };
                    if verify_session_scope_matches(&rec, scoped_root).is_err() {
                        continue;
                    }
                    if verify_bound_target_unchanged(&scoped_root.bfs, &rec).is_err() {
                        continue;
                    }
                    uploads.push(UploadSessionSummary {
                        id: rec.id,
                        path: rec.target_path,
                        length: rec.upload_length,
                        offset: rec.offset_bytes,
                        status: "uploading".to_string(),
                        fingerprint: rec.fingerprint,
                    });
                    continue;
                }
                Err(_) => continue,
            }
        }

        let Some(ref scoped_root) = scoped_root_opt else {
            continue;
        };
        if verify_session_scope_matches(&rec, scoped_root).is_err() {
            continue;
        }
        if verify_bound_target_unchanged(&scoped_root.bfs, &rec).is_err() {
            continue;
        }

        match reconcile_staging_offset_at(conn, base_root, &mut rec) {
            Ok(_) => {
                uploads.push(UploadSessionSummary {
                    id: rec.id,
                    path: rec.target_path,
                    length: rec.upload_length,
                    offset: rec.offset_bytes,
                    status: rec.status,
                    fingerprint: rec.fingerprint,
                });
            }
            Err(_) => {
                let _ = cancel_and_release_session_conn(conn, base_root, &rec);
            }
        }
    }

    Ok(DiscoverUploadsResponse { uploads })
}

fn cancel_and_release_session_conn(
    conn: &Connection,
    base_root: &Path,
    rec: &UploadSessionRecord,
) -> Result<(), McBrowserError> {
    let now = now_unix_secs();
    let mut probe = rec.clone();
    let may_have_published = probe.status == "publishing"
        || (probe.status == "uploading" && probe.offset_bytes == probe.upload_length);
    let resolution = if may_have_published {
        reconcile_publishing_session_conn_safe(conn, base_root, &mut probe, now)
    } else {
        PublishingResolution::UnpublishedStagingIntact
    };

    if matches!(resolution, PublishingResolution::Completed) {
        return Ok(());
    }

    if matches!(resolution, PublishingResolution::AmbiguousRetainQuota) {
        return Err(McBrowserError::Conflict(
            "Upload publication remains ambiguous".to_string(),
        ));
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin session cleanup transaction".to_string())
        })?;
    let step = (|| -> Result<(), McBrowserError> {
        let Some(cur) = load_session_conn(conn, &rec.id)? else {
            return Ok(());
        };
        if cur.status == "completed" {
            return Ok(());
        }
        let safe_to_release = matches!(resolution, PublishingResolution::UnpublishedStagingIntact)
            && cur.status == "uploading";
        if safe_to_release && cur.quota_reserved && cur.reserved_bytes > 0 {
            release_user_quota_conn(conn, cur.user_id, cur.reserved_bytes)?;
        }
        if safe_to_release && !cur.audit_event_id.trim().is_empty() {
            super::events::finalize_event_failed_with_conn(
                conn,
                &cur.audit_event_id,
                Some("STAGING_MISSING"),
            )?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1",
            params![cur.id],
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to remove broken upload session".to_string())
        })?;
        Ok(())
    })();
    match step {
        Ok(()) => {
            conn.execute_batch("COMMIT").map_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
                McBrowserError::Internal("Failed to commit upload cleanup".to_string())
            })?;
            let _ = remove_staging_file_at(base_root, rec.user_id, &rec.id);
            let _ = remove_publication_proof_at(base_root, rec.user_id, &rec.id);
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn reconcile_publishing_session_conn_safe(
    conn: &Connection,
    base_root: &Path,
    session: &mut UploadSessionRecord,
    now_secs: i64,
) -> PublishingResolution {
    reconcile_publishing_session_at(conn, base_root, session, false, now_secs)
        .unwrap_or(PublishingResolution::AmbiguousRetainQuota)
}

pub(crate) fn head_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    raw_id: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let upload_id = validate_upload_id(raw_id).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_at(conn, base_root, now);

    let Some(mut session) = load_session_conn(conn, &upload_id).map_err(map_mcbrowser_err_tus)?
    else {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    };

    // Enforce strict owner isolation (return 404 NotFound to avoid leaking cross-user session existence)
    if session.user_id != user_id || session.expires_at <= now {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    }

    if session.status == "publishing"
        || (session.status == "uploading" && session.offset_bytes == session.upload_length)
    {
        // Re-check bound scope + policy + active quota before attempting to finish an interrupted publish
        let scope_check = open_verified_user_root_fd(conn, base_root, user_id)
            .and_then(|root| verify_session_scope_matches(&session, &root));
        let perm_check = authorize_conflict_policy_permissions_with_conn(
            conn,
            user,
            &session.target_path,
            session.conflict_policy,
            session.base_target_exists,
        );
        let can_finish = scope_check.is_ok()
            && perm_check.is_ok()
            && load_active_quota_conn(conn, user_id, 0).is_ok();
        let res = reconcile_publishing_session_at(conn, base_root, &mut session, can_finish, now)
            .map_err(map_mcbrowser_err_tus)?;
        if session.status != "completed" {
            if let Err(scope_err) = scope_check {
                return Err(map_mcbrowser_err_tus(scope_err));
            }
            if let Err(perm_err) = perm_check {
                return Err(map_mcbrowser_err_tus(perm_err));
            }
            if matches!(res, PublishingResolution::AmbiguousRetainQuota) {
                return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                    "Upload session is in an ambiguous publication state; quota remains conservatively reserved".to_string(),
                )));
            }
        }
    } else if session.status == "uploading" {
        authorize_conflict_policy_permissions_with_conn(
            conn,
            user,
            &session.target_path,
            session.conflict_policy,
            session.base_target_exists,
        )
        .map_err(map_mcbrowser_err_tus)?;

        let scoped_root =
            open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
        verify_session_scope_matches(&session, &scoped_root).map_err(map_mcbrowser_err_tus)?;
        verify_bound_target_unchanged(&scoped_root.bfs, &session).map_err(map_mcbrowser_err_tus)?;

        if reconcile_staging_offset_at(conn, base_root, &mut session).is_err() {
            let _ = cancel_and_release_session_conn(conn, base_root, &session);
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload staging file is no longer available".to_string(),
            )));
        }
    }

    if session.status == "completed" && !session.audit_event_id.trim().is_empty() {
        let delta = session_published_byte_delta(&session);
        super::events::finalize_event_completed_with_conn(
            conn,
            &session.audit_event_id,
            None,
            None,
            delta,
        )
        .map_err(map_mcbrowser_err_tus)?;
    }

    let wire_status = if session.status == "completed" {
        "completed"
    } else {
        "uploading"
    };

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    if let Ok(off_hv) = HeaderValue::from_str(&session.offset_bytes.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(len_hv) = HeaderValue::from_str(&session.upload_length.to_string()) {
        h.insert("Upload-Length", len_hv);
    }
    if let Ok(st_hv) = HeaderValue::from_str(wire_status) {
        h.insert("Upload-Status", st_hv);
    }
    if session.status == "completed"
        && session.conflict_policy == ConflictPolicy::Skip
        && session.base_target_exists
    {
        h.insert("Upload-Skipped", HeaderValue::from_static("true"));
    }
    let encoded_meta = encode_session_metadata_header(&session);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&session.target_path) {
        h.insert("Upload-Path", path_hv);
    }

    Ok(with_tus_headers(resp))
}

pub(crate) fn delete_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    raw_id: &str,
    headers: &HeaderMap,
) -> Result<Response, Response> {
    validate_tus_version(headers)?;
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    let upload_id = validate_upload_id(raw_id).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_at(conn, base_root, now);

    // Pre-reconcile if the session is in 'publishing' or at full offset so we NEVER cancel and
    // release quota for a file that was already published to BrowserFs before a crash.
    if let Some(mut pre_session) =
        load_session_conn(conn, &upload_id).map_err(map_mcbrowser_err_tus)?
    {
        if pre_session.user_id == user_id
            && pre_session.expires_at > now
            && (pre_session.status == "publishing"
                || (pre_session.status == "uploading"
                    && pre_session.offset_bytes == pre_session.upload_length))
        {
            let resolution =
                reconcile_publishing_session_conn_safe(conn, base_root, &mut pre_session, now);
            match resolution {
                PublishingResolution::Completed => {
                    return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                        "Completed upload session cannot be cancelled".to_string(),
                    )));
                }
                PublishingResolution::AmbiguousRetainQuota => {
                    return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                        "Upload session is in an ambiguous publication state and cannot release quota".to_string(),
                    )));
                }
                PublishingResolution::UnpublishedStagingIntact => {
                    // Proven unpublished with staging intact: allow cancellation and quota release below.
                }
            }
        }
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to start upload cancellation transaction".to_string(),
            ))
        })?;

    let tx_res = (|| -> Result<UploadSessionRecord, McBrowserError> {
        let Some(session) = load_session_conn(conn, &upload_id)? else {
            return Err(McBrowserError::NotFound(
                "Upload session not found".to_string(),
            ));
        };
        if session.user_id != user_id || session.expires_at <= now {
            return Err(McBrowserError::NotFound(
                "Upload session not found".to_string(),
            ));
        }
        if session.status == "completed" {
            return Err(McBrowserError::Conflict(
                "Completed upload session cannot be cancelled".to_string(),
            ));
        }
        if session.quota_reserved && session.reserved_bytes > 0 {
            release_user_quota_conn(conn, user_id, session.reserved_bytes)?;
        }
        if !session.audit_event_id.trim().is_empty() {
            super::events::finalize_event_failed_with_conn(
                conn,
                &session.audit_event_id,
                Some("UPLOAD_CANCELLED"),
            )?;
        }
        conn.execute(
            "DELETE FROM mcbrowser_uploads WHERE id = ?1",
            params![upload_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to delete upload session".to_string()))?;
        Ok(session)
    })();

    let session = match tx_res {
        Ok(s) => {
            if conn.execute_batch("COMMIT").is_err() {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to commit upload cancellation".to_string(),
                )));
            }
            s
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(map_mcbrowser_err_tus(err));
        }
    };

    let _ = remove_staging_file_at(base_root, user_id, &session.id);
    let _ = remove_publication_proof_at(base_root, user_id, &session.id);

    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    Ok(with_tus_headers(resp))
}

async fn stream_patch_chunk_to_file(
    body: Body,
    std_file: File,
    start_offset: u64,
    remaining_upload_bytes: u64,
    declared_chunk_len: Option<u64>,
) -> Result<(File, u64), Response> {
    let mut async_file = tokio::fs::File::from_std(std_file);
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|_| {
            tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Failed to read upload chunk stream",
            )
        })?;
        let chunk_len = chunk.len() as u64;
        written = written.saturating_add(chunk_len);

        if written > MAX_CHUNK_BYTES {
            let _ = async_file.set_len(start_offset).await;
            return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
                format!("PATCH chunk exceeds maximum allowed chunk size of {MAX_CHUNK_BYTES} bytes (4 MiB)"),
            )));
        }

        if written > remaining_upload_bytes {
            let _ = async_file.set_len(start_offset).await;
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH chunk exceeds declared Upload-Length",
            ));
        }

        if let Some(expected_cl) = declared_chunk_len {
            if written > expected_cl {
                let _ = async_file.set_len(start_offset).await;
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "PATCH body exceeded declared Content-Length",
                ));
            }
        }

        if let Err(e) = async_file.write_all(&chunk).await {
            let _ = async_file.set_len(start_offset).await;
            return Err(map_mcbrowser_err_tus(map_fs_io_error(
                e,
                "Failed to write upload chunk",
            )));
        }
    }

    if let Some(expected_cl) = declared_chunk_len {
        if written != expected_cl {
            let _ = async_file.set_len(start_offset).await;
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH body length did not match Content-Length header",
            ));
        }
    }

    if let Err(e) = async_file.flush().await {
        let _ = async_file.set_len(start_offset).await;
        return Err(map_mcbrowser_err_tus(map_fs_io_error(
            e,
            "Failed to flush upload chunk",
        )));
    }

    let std_file = async_file.into_std().await;
    Ok((std_file, written))
}

fn parse_patch_headers(headers: &HeaderMap) -> Result<(u64, Option<u64>), Response> {
    validate_tus_version(headers)?;

    let Some(ct_hv) = headers.get(header::CONTENT_TYPE) else {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Missing Content-Type: application/offset+octet-stream",
        ));
    };
    let Ok(ct_str) = ct_hv.to_str() else {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Invalid Content-Type header",
        ));
    };
    let media_type = ct_str.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("application/offset+octet-stream") {
        return Err(tus_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "PATCH Content-Type must be application/offset+octet-stream",
        ));
    }

    let Some(off_hv) = headers.get("Upload-Offset") else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Missing required Upload-Offset header",
        ));
    };
    let Ok(off_str) = off_hv.to_str() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid Upload-Offset header",
        ));
    };
    let Ok(client_offset) = off_str.trim().parse::<u64>() else {
        return Err(tus_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Upload-Offset must be a non-negative integer",
        ));
    };

    let declared_cl = match headers.get(header::CONTENT_LENGTH) {
        Some(hv) => {
            let Ok(s) = hv.to_str() else {
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid Content-Length header",
                ));
            };
            let Ok(cl) = s.trim().parse::<u64>() else {
                return Err(tus_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid Content-Length header",
                ));
            };
            if cl > MAX_CHUNK_BYTES {
                return Err(map_mcbrowser_err_tus(McBrowserError::PayloadTooLarge(
                    format!("PATCH Content-Length {cl} exceeds maximum chunk size of {MAX_CHUNK_BYTES} bytes (4 MiB)"),
                )));
            }
            Some(cl)
        }
        None => None,
    };

    Ok((client_offset, declared_cl))
}

// ─────────────────────────────────────────────────────────────────────────────
// Axum Route Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn create_upload(
    Extension(auth_user): Extension<AuthUser>,
    Query(policy_q): Query<ConflictPolicyQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload creation".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        let (_, resp) = create_upload_session_at(
            &conn,
            &base_root,
            &auth_user,
            &headers,
            policy_q.policy.as_deref(),
        )?;
        Ok::<Response, Response>(resp)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload creation task failed".to_string(),
        )),
    }
}

async fn discover_uploads(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<DiscoverUploadsQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload discovery".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        let payload = discover_uploads_at(&conn, &base_root, &auth_user, &query)?;
        Ok::<DiscoverUploadsResponse, Response>(payload)
    })
    .await;

    match res {
        Ok(Ok(payload)) => with_tus_headers(Json(payload).into_response()),
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload discovery task failed".to_string(),
        )),
    }
}

async fn head_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let sess_guard = session_lock(&upload_id).lock_owned().await;
    let res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _ = user_id;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload status check".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        head_upload_at(&conn, &base_root, &auth_user, &upload_id, &headers)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload HEAD task failed".to_string(),
        )),
    }
}

async fn delete_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_tus_version(&headers) {
        return resp;
    }
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    let sess_guard = session_lock(&upload_id).lock_owned().await;
    let user_guard = user_mutation_stripe(user_id).lock_owned().await;

    let res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _user_guard = user_guard;
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload cancellation".to_string(),
            ))
        })?;
        ensure_uploads_schema(&conn).map_err(map_mcbrowser_err_tus)?;
        delete_upload_at(&conn, &base_root, &auth_user, &upload_id, &headers)
    })
    .await;

    match res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload DELETE task failed".to_string(),
        )),
    }
}

pub(crate) fn prepare_patch_upload_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    upload_id: &str,
    client_offset: u64,
    declared_cl: Option<u64>,
) -> Result<(UploadSessionRecord, File), Response> {
    let user_id = validate_mcbrowser_user(user).map_err(map_mcbrowser_err_tus)?;
    ensure_uploads_schema(conn).map_err(map_mcbrowser_err_tus)?;

    let now = now_unix_secs();
    let _ = cleanup_expired_uploads_at(conn, base_root, now);

    let Some(mut session) = load_session_conn(conn, upload_id).map_err(map_mcbrowser_err_tus)?
    else {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    };

    if session.user_id != user_id || session.expires_at <= now {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session not found".to_string(),
        )));
    }

    authorize_conflict_policy_permissions_with_conn(
        conn,
        user,
        &session.target_path,
        session.conflict_policy,
        session.base_target_exists,
    )
    .map_err(map_mcbrowser_err_tus)?;

    // Check user quota status is still active
    load_active_quota_conn(conn, user_id, 0).map_err(map_mcbrowser_err_tus)?;

    if session.status == "publishing"
        || (session.status == "uploading" && session.offset_bytes == session.upload_length)
    {
        // Reconcile any previously interrupted publication before accepting a new PATCH
        let res = reconcile_publishing_session_at(conn, base_root, &mut session, false, now)
            .map_err(map_mcbrowser_err_tus)?;
        if matches!(res, PublishingResolution::Completed) {
            if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
                return Err(skipped_upload_patch_response(&session));
            }
            return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                "Upload session is already completed".to_string(),
            )));
        }
        if matches!(res, PublishingResolution::AmbiguousRetainQuota) {
            return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
                "Upload session is in an ambiguous publication state".to_string(),
            )));
        }
    }

    if session.status == "completed" {
        if session.conflict_policy == ConflictPolicy::Skip && session.base_target_exists {
            return Err(skipped_upload_patch_response(&session));
        }
        return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(
            "Upload session is already completed".to_string(),
        )));
    }

    // Fail closed if the user's policy scope was remapped, the scoped root directory was replaced on disk,
    // or the bound original target file changed on disk.
    let scoped_root =
        open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
    verify_session_scope_matches(&session, &scoped_root).map_err(map_mcbrowser_err_tus)?;
    verify_bound_target_unchanged(&scoped_root.bfs, &session).map_err(map_mcbrowser_err_tus)?;

    let mut staging_file = match reconcile_staging_offset_at(conn, base_root, &mut session) {
        Ok(f) => f,
        Err(_) => {
            let _ = cancel_and_release_session_conn(conn, base_root, &session);
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload staging file is missing".to_string(),
            )));
        }
    };

    if client_offset != session.offset_bytes {
        return Err(map_mcbrowser_err_tus(McBrowserError::Conflict(format!(
            "Upload-Offset mismatch: client sent {client_offset}, server is at {}",
            session.offset_bytes
        ))));
    }

    let remaining = session.upload_length.saturating_sub(session.offset_bytes);
    if let Some(cl) = declared_cl {
        if cl > remaining {
            return Err(tus_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "PATCH Content-Length exceeds remaining Upload-Length",
            ));
        }
    }

    check_fd_free_space(
        staging_file.as_raw_fd(),
        declared_cl.unwrap_or(remaining.min(MAX_CHUNK_BYTES)).max(1),
    )
    .map_err(map_mcbrowser_err_tus)?;

    staging_file
        .seek(SeekFrom::Start(session.offset_bytes))
        .map_err(|e| {
            map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to seek upload staging file"))
        })?;

    Ok((session, staging_file))
}

fn finish_unpublished_skip_conn(
    conn: &Connection,
    base_root: &Path,
    bfs: &af_files::BrowserFs,
    session: &UploadSessionRecord,
    now: i64,
) -> Result<Option<Response>, McBrowserError> {
    if session.conflict_policy != ConflictPolicy::Skip || session.base_target_exists {
        return Ok(None);
    }
    match inspect_existing_target_in_bfs(bfs, &session.target_path) {
        Ok(None) => return Ok(None),
        Err(error) => {
            discard_unpublished_session_conn(conn, session, &error)?;
            let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
            let _ = remove_publication_proof_at(base_root, session.user_id, &session.id);
            return Err(error);
        }
        Ok(Some(_)) => {}
    }
    let mut skipped = load_session_conn(conn, &session.id)?.ok_or_else(|| {
        McBrowserError::NotFound("Upload session is no longer active".to_string())
    })?;
    mark_session_skipped_conn(conn, &mut skipped, now)?;
    let _ = remove_staging_file_at(base_root, session.user_id, &session.id);
    Ok(Some(skipped_upload_patch_response(&skipped)))
}

fn skipped_upload_patch_response(skipped: &UploadSessionRecord) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&skipped.upload_length.to_string()) {
        headers.insert("Upload-Offset", value);
    }
    headers.insert("Upload-Status", HeaderValue::from_static("completed"));
    headers.insert("Upload-Skipped", HeaderValue::from_static("true"));
    if let Ok(value) = HeaderValue::from_str(&encode_session_metadata_header(&skipped)) {
        headers.insert("Upload-Metadata", value);
    }
    if let Ok(value) = HeaderValue::from_str(&skipped.target_path) {
        headers.insert("Upload-Path", value);
    }
    with_tus_headers(response)
}

pub(crate) fn finalize_patch_upload_at(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
    session: &UploadSessionRecord,
    staging_file: File,
    new_offset: u64,
) -> Result<Response, Response> {
    staging_file.sync_data().map_err(|e| {
        map_mcbrowser_err_tus(map_fs_io_error(e, "Failed to sync upload staging file"))
    })?;

    let reaches_completion = new_offset == session.upload_length;
    let now = now_unix_secs();
    let new_expires = now + UPLOAD_SESSION_EXPIRY_SECS;
    let new_offset_i64 = i64::try_from(new_offset).unwrap_or(i64::MAX);

    let updated = conn
        .execute(
            "UPDATE mcbrowser_uploads \
                 SET offset_bytes = ?1, updated_at = ?2, expires_at = ?3 \
                 WHERE id = ?4 AND user_id = ?5 AND status = 'uploading'",
            params![new_offset_i64, now, new_expires, session.id, user_id],
        )
        .map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Failed to update upload offset".to_string(),
            ))
        })?;
    if updated == 0 {
        return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
            "Upload session is no longer active".to_string(),
        )));
    }
    if reaches_completion {
        // Re-verify active quota status and bound scoped root BEFORE publishing
        load_active_quota_conn(conn, user_id, 0).map_err(map_mcbrowser_err_tus)?;
        let scoped_root =
            open_verified_user_root_fd(conn, base_root, user_id).map_err(map_mcbrowser_err_tus)?;
        verify_session_scope_matches(session, &scoped_root).map_err(map_mcbrowser_err_tus)?;

        if let Some(response) =
            finish_unpublished_skip_conn(conn, base_root, &scoped_root.bfs, session, now)
                .map_err(map_mcbrowser_err_tus)?
        {
            return Ok(response);
        }

        // Verify bound target identity/size BEFORE entering `'publishing'`.
        // If the bound target was modified/replaced/deleted (or a concurrent file appeared),
        // persist `offset_bytes = new_offset` in `'uploading'` and fail closed with `409 Conflict`.
        let expected_replace_file = match verify_bound_target_unchanged(&scoped_root.bfs, session) {
            Ok(f) => f,
            Err(conflict_err) => {
                if let Some(response) =
                    finish_unpublished_skip_conn(conn, base_root, &scoped_root.bfs, session, now)
                        .map_err(map_mcbrowser_err_tus)?
                {
                    return Ok(response);
                }
                let _ = conn.execute(
                    "UPDATE mcbrowser_uploads \
                     SET offset_bytes = ?1, status = 'uploading', updated_at = ?2, expires_at = ?3 \
                     WHERE id = ?4 AND user_id = ?5 AND status IN ('uploading', 'publishing')",
                    params![new_offset_i64, now, new_expires, session.id, user_id],
                );
                return Err(map_mcbrowser_err_tus(conflict_err));
            }
        };

        let mut publishing_session = session.clone();
        publishing_session.offset_bytes = new_offset;
        conn.execute_batch("SAVEPOINT mcbrowser_upload_begin_publish")
            .map_err(|_| {
                map_mcbrowser_err_tus(McBrowserError::Internal(
                    "Failed to begin upload publishing transaction".to_string(),
                ))
            })?;
        let begin_publish = (|| -> Result<usize, McBrowserError> {
            let audit_id = ensure_session_pending_audit_conn(conn, &mut publishing_session)?;
            let updated = conn
                .execute(
                    "UPDATE mcbrowser_uploads \
                     SET offset_bytes = ?1, status = 'publishing', audit_event_id = ?2, updated_at = ?3, expires_at = ?4 \
                     WHERE id = ?5 AND user_id = ?6 AND status IN ('uploading', 'publishing')",
                    params![
                        new_offset_i64,
                        audit_id,
                        now,
                        new_expires,
                        session.id,
                        user_id
                    ],
                )
                .map_err(|_| {
                    McBrowserError::Internal("Failed to record upload publishing intent".to_string())
                })?;
            conn.execute_batch("RELEASE mcbrowser_upload_begin_publish")
                .map_err(|_| {
                    McBrowserError::Internal(
                        "Failed to commit upload publishing intent".to_string(),
                    )
                })?;
            Ok(updated)
        })();
        let updated = match begin_publish {
            Ok(u) => u,
            Err(err) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO mcbrowser_upload_begin_publish; RELEASE mcbrowser_upload_begin_publish",
                );
                return Err(map_mcbrowser_err_tus(err));
            }
        };
        if updated == 0 {
            return Err(map_mcbrowser_err_tus(McBrowserError::NotFound(
                "Upload session is no longer active".to_string(),
            )));
        }

        if let Err(pub_err) = publish_staging_file_to_browser_fs(
            staging_file,
            &scoped_root.bfs,
            &session.target_path,
            session.upload_length,
            expected_replace_file.as_ref(),
            base_root,
            &publishing_session,
        ) {
            if let Some(response) = finish_unpublished_skip_conn(
                conn,
                base_root,
                &scoped_root.bfs,
                &publishing_session,
                now,
            )
            .map_err(map_mcbrowser_err_tus)?
            {
                return Ok(response);
            }
            let mut probe = publishing_session.clone();
            probe.offset_bytes = new_offset;
            probe.status = "publishing".to_string();
            if matches!(
                reconcile_publishing_session_conn_safe(conn, base_root, &mut probe, now),
                PublishingResolution::UnpublishedStagingIntact
            ) {
                let _ = conn.execute(
                    "UPDATE mcbrowser_uploads \
                     SET status = 'uploading', updated_at = ?1 \
                     WHERE id = ?2 AND user_id = ?3 AND status = 'publishing'",
                    params![now, session.id, user_id],
                );
            }
            return Err(map_mcbrowser_err_tus(pub_err));
        }

        mark_session_completed_conn(conn, &mut publishing_session, now).map_err(|_| {
            tracing::error!(
                upload_id = %session.id,
                user_id,
                path = %session.target_path,
                "File published to BrowserFs, but status update to 'completed' failed; session remains in 'publishing' for reconciliation"
            );
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Upload published, but session completion state could not be updated".to_string(),
            ))
        })?;

        let _ = remove_staging_file_at(base_root, user_id, &session.id);
    }

    let final_status = if reaches_completion {
        "completed"
    } else {
        "uploading"
    };
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    let h = resp.headers_mut();
    if let Ok(off_hv) = HeaderValue::from_str(&new_offset.to_string()) {
        h.insert("Upload-Offset", off_hv);
    }
    if let Ok(st_hv) = HeaderValue::from_str(final_status) {
        h.insert("Upload-Status", st_hv);
    }
    let encoded_meta = encode_session_metadata_header(&session);
    if let Ok(meta_hv) = HeaderValue::from_str(&encoded_meta) {
        h.insert("Upload-Metadata", meta_hv);
    }
    if let Ok(path_hv) = HeaderValue::from_str(&session.target_path) {
        h.insert("Upload-Path", path_hv);
    }
    Ok(with_tus_headers(resp))
}

async fn patch_upload(
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(raw_id): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (client_offset, declared_cl) = match parse_patch_headers(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };
    let upload_id = match validate_upload_id(&raw_id) {
        Ok(id) => id,
        Err(e) => return map_mcbrowser_err_tus(e),
    };

    // Acquire per-session lock (owned) so concurrent PATCH/HEAD/DELETE on the SAME upload serialize,
    // without holding the global per-user mutation stripe during network chunk streaming.
    let sess_guard = session_lock(&upload_id).lock_owned().await;

    let id_for_prep = upload_id.clone();
    let auth_for_prep = auth_user.clone();
    let prep_res = tokio::task::spawn_blocking(move || {
        let base_root = configured_base_root().map_err(map_mcbrowser_err_tus)?;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for upload chunk".to_string(),
            ))
        })?;
        let (session, staging_file) = prepare_patch_upload_at(
            &conn,
            &base_root,
            &auth_for_prep,
            &id_for_prep,
            client_offset,
            declared_cl,
        )?;
        Ok::<(PathBuf, UploadSessionRecord, File), Response>((base_root, session, staging_file))
    })
    .await;

    let (base_root, session, staging_file) = match prep_res {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(err_resp)) => return err_resp,
        Err(_) => {
            return map_mcbrowser_err_tus(McBrowserError::Internal(
                "Upload PATCH preparation failed".to_string(),
            ))
        }
    };

    let remaining = session.upload_length.saturating_sub(session.offset_bytes);
    let stream_res = tokio::time::timeout(
        CHUNK_STREAM_TIMEOUT,
        stream_patch_chunk_to_file(
            body,
            staging_file,
            session.offset_bytes,
            remaining,
            declared_cl,
        ),
    )
    .await;

    let (staging_file, written_bytes) = match stream_res {
        Ok(Ok(pair)) => pair,
        Ok(Err(err_resp)) => return err_resp,
        Err(_) => {
            return map_mcbrowser_err_tus(McBrowserError::RequestTimeout(
                "Upload timed out while streaming PATCH chunk".to_string(),
            ))
        }
    };

    let new_offset = session.offset_bytes.saturating_add(written_bytes);
    let reaches_completion = new_offset == session.upload_length;

    // If this chunk completes the upload, acquire the user mutation stripe only for the final atomic publication step.
    let user_guard_opt = if reaches_completion {
        Some(user_mutation_stripe(user_id).lock_owned().await)
    } else {
        None
    };

    let finalize_res = tokio::task::spawn_blocking(move || {
        let _sess_guard = sess_guard;
        let _user_guard = user_guard_opt;
        let conn = af_db::get_conn().map_err(|_| {
            map_mcbrowser_err_tus(McBrowserError::Internal(
                "Database unavailable for finalizing upload chunk".to_string(),
            ))
        })?;
        finalize_patch_upload_at(
            &conn,
            &base_root,
            user_id,
            &session,
            staging_file,
            new_offset,
        )
    })
    .await;

    match finalize_res {
        Ok(Ok(resp)) => resp,
        Ok(Err(err_resp)) => err_resp,
        Err(_) => map_mcbrowser_err_tus(McBrowserError::Internal(
            "Upload PATCH finalization task failed".to_string(),
        )),
    }
}

#[cfg(test)]
#[path = "uploads_tests.rs"]
mod tests;
