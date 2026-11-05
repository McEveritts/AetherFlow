mod actions;
mod events;
pub(crate) mod lifecycle;
mod media;
mod operations;
mod policy;
mod search_query;
mod shares;
mod uploads;

use crate::auth::{api_error, AuthUser};
use af_files::{BrowserFs, Entry};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Extension, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use futures::StreamExt;
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_util_reader_stream::FileRangeStream;

pub const DEFAULT_MCBROWSER_ROOT: &str = "/var/lib/aetherflow/mcbrowser";
pub const MAX_UPLOAD_BYTES: u64 = 67_108_864;
pub const MAX_PREVIEW_BYTES: usize = 262_144;
pub const MIN_FREE_SPACE_BYTES: u64 = 1_073_741_824;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const USER_LOCK_STRIPES: usize = 64;
const PREVIEW_CONCURRENCY_LIMIT: usize = 8;

static UPLOAD_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(8)));

#[cfg(test)]
pub(crate) static TEST_DATABASE_LOCK: Lazy<AsyncMutex<()>> = Lazy::new(|| AsyncMutex::new(()));

static USER_MUTATION_STRIPES: Lazy<Vec<Arc<AsyncMutex<()>>>> = Lazy::new(|| {
    (0..USER_LOCK_STRIPES)
        .map(|_| Arc::new(AsyncMutex::new(())))
        .collect()
});

static PREVIEW_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(PREVIEW_CONCURRENCY_LIMIT)));

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McBrowserError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    PayloadTooLarge(String),
    QuotaExceeded(String),
    InsufficientStorage(String),
    RangeNotSatisfiable(u64),
    RequestTimeout(String),
    AccountingPending(String),
    Internal(String),
}

impl McBrowserError {
    pub fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            Self::Unauthorized(msg) => api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg),
            Self::Forbidden(msg) => api_error(StatusCode::FORBIDDEN, "FORBIDDEN", msg),
            Self::NotFound(msg) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            Self::Conflict(msg) => api_error(StatusCode::CONFLICT, "CONFLICT", msg),
            Self::PayloadTooLarge(msg) => {
                api_error(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", msg)
            }
            Self::QuotaExceeded(msg) => {
                api_error(StatusCode::PAYLOAD_TOO_LARGE, "QUOTA_EXCEEDED", msg)
            }
            Self::InsufficientStorage(msg) => api_error(
                StatusCode::INSUFFICIENT_STORAGE,
                "INSUFFICIENT_STORAGE",
                msg,
            ),
            Self::RangeNotSatisfiable(total_size) => {
                let mut resp = api_error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "RANGE_NOT_SATISFIABLE",
                    "Requested byte range is not satisfiable",
                );
                if let Ok(hv) = HeaderValue::from_str(&format!("bytes */{total_size}")) {
                    resp.headers_mut().insert(header::CONTENT_RANGE, hv);
                }
                resp
            }
            Self::RequestTimeout(msg) => {
                api_error(StatusCode::REQUEST_TIMEOUT, "REQUEST_TIMEOUT", msg)
            }
            Self::Internal(msg) => {
                api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg)
            }
            Self::AccountingPending(msg) => {
                api_error(StatusCode::INTERNAL_SERVER_ERROR, "ACCOUNTING_PENDING", msg)
            }
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateDirectoryRequest {
    pub path: String,
    #[serde(default)]
    pub parents: bool,
}

#[derive(Debug, Serialize)]
pub struct BrowserEntry {
    #[serde(flatten)]
    pub entry: Entry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EntriesResponse {
    pub path: String,
    pub entries: Vec<BrowserEntry>,
    pub max_upload_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub path: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct MutationSuccessResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteSuccessResponse {
    pub success: bool,
    #[serde(default)]
    pub accounting_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QuotaSnapshot {
    quota_bytes: i64,
    used_bytes: i64,
}
pub fn router() -> Router {
    let upload_route = Router::new()
        .route("/mcbrowser/upload", put(upload_entry))
        .layer(DefaultBodyLimit::max((MAX_UPLOAD_BYTES + 1) as usize));

    Router::new()
        .route("/mcbrowser/entries", get(list_entries))
        .route("/mcbrowser/directory", post(create_directory))
        .route("/mcbrowser/rename", post(rename_entry))
        .route("/mcbrowser/entry", delete(delete_entry))
        .route("/mcbrowser/download", get(download_entry))
        .route("/mcbrowser/preview", get(preview_entry))
        .merge(upload_route)
        .merge(policy::router())
        .merge(events::router())
        .merge(actions::router())
        .merge(uploads::router())
        .merge(operations::router())
        .merge(media::router())
        .merge(shares::router())
}

pub fn public_router() -> Router {
    shares::public_router()
}

pub(crate) fn user_mutation_stripe(user_id: i64) -> Arc<AsyncMutex<()>> {
    let idx = (user_id.unsigned_abs() as usize) % USER_LOCK_STRIPES;
    Arc::clone(&USER_MUTATION_STRIPES[idx])
}
pub fn validate_mcbrowser_user(user: &AuthUser) -> Result<i64, McBrowserError> {
    if user.plugin_id.is_some()
        || !user.plugin_scopes.is_empty()
        || user.role.eq_ignore_ascii_case("plugin")
        || user.username.starts_with("plugin:")
    {
        return Err(McBrowserError::Forbidden(
            "Plugin-scoped tokens are not permitted to access McBrowser".to_string(),
        ));
    }
    if user.user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }
    Ok(user.user_id)
}
pub fn normalize_relative_path(raw: &str, allow_root: bool) -> Result<String, McBrowserError> {
    if raw.as_bytes().contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Invalid path: NUL byte is not allowed".to_string(),
        ));
    }
    if raw.is_empty() {
        if allow_root {
            return Ok(String::new());
        }
        return Err(McBrowserError::BadRequest(
            "Path is required for this operation".to_string(),
        ));
    }
    if raw.starts_with('/') || raw.contains('\\') {
        return Err(McBrowserError::BadRequest(
            "Invalid path: absolute or backslash paths are not allowed".to_string(),
        ));
    }

    let mut segments = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(McBrowserError::BadRequest(
                "Invalid path: traversal segments are not allowed".to_string(),
            ));
        }
        if part.starts_with(".af-upload-tmp.") {
            return Err(McBrowserError::BadRequest(
                "Invalid path: reserved temporary filename is not allowed".to_string(),
            ));
        }
        segments.push(part);
    }

    if segments.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Invalid path: empty path segment".to_string(),
        ));
    }

    Ok(segments.join("/"))
}
pub fn resolve_configured_base_root(raw_env: Option<&str>) -> Result<PathBuf, McBrowserError> {
    let raw = match raw_env {
        Some(val) => {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                DEFAULT_MCBROWSER_ROOT
            } else {
                trimmed
            }
        }
        None => DEFAULT_MCBROWSER_ROOT,
    };

    if raw.as_bytes().contains(&0) {
        return Err(McBrowserError::Internal(
            "Invalid McBrowser storage configuration".to_string(),
        ));
    }

    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(McBrowserError::Internal(
            "McBrowser root configuration must be an absolute path".to_string(),
        ));
    }

    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(McBrowserError::Internal(
                    "McBrowser root configuration must not contain traversal segments".to_string(),
                ));
            }
        }
    }

    Ok(path)
}
pub fn derive_user_root_path(base_root: &Path, user_id: i64) -> Result<PathBuf, McBrowserError> {
    if user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }
    if !base_root.is_absolute() || base_root.parent().is_none() {
        return Err(McBrowserError::Internal(
            "McBrowser base root must be an absolute path".to_string(),
        ));
    }
    Ok(base_root.join(format!("user-{user_id}")))
}
pub fn open_user_browser_fs_at(
    base_root: &Path,
    user_id: i64,
) -> Result<BrowserFs, McBrowserError> {
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
    let mut base_stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(base_fd.as_raw_fd(), &mut base_stat) } < 0
        || base_stat.st_uid != unsafe { libc::geteuid() }
    {
        return Err(McBrowserError::Internal(
            "Storage root ownership is invalid".to_string(),
        ));
    }
    if unsafe { libc::fchmod(base_fd.as_raw_fd(), 0o700) } < 0 {
        return Err(McBrowserError::Internal(
            "Failed to enforce private storage permissions".to_string(),
        ));
    }

    let child_name = format!("user-{user_id}");
    let child_c = CString::new(child_name.as_bytes()).map_err(|_| {
        McBrowserError::Internal("Failed to construct user directory name".to_string())
    })?;

    let mkdir_rc = unsafe { libc::mkdirat(base_fd.as_raw_fd(), child_c.as_ptr(), 0o700) };
    if mkdir_rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::AlreadyExists {
            return Err(McBrowserError::Internal(
                "Failed to provision user storage directory".to_string(),
            ));
        }
    }

    let child_fd_raw = unsafe { libc::openat(base_fd.as_raw_fd(), child_c.as_ptr(), dir_flags, 0) };
    if child_fd_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to open user storage directory safely".to_string(),
        ));
    }
    let child_fd = unsafe { OwnedFd::from_raw_fd(child_fd_raw) };

    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(child_fd.as_raw_fd(), &mut st) } < 0 {
        return Err(McBrowserError::Internal(
            "Failed to inspect user storage directory".to_string(),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != unsafe { libc::geteuid() } {
        return Err(McBrowserError::Internal(
            "User storage root is not a directory".to_string(),
        ));
    }
    if (st.st_mode & 0o777) != 0o700 && unsafe { libc::fchmod(child_fd.as_raw_fd(), 0o700) } < 0 {
        return Err(McBrowserError::Internal(
            "Failed to enforce private permissions on user storage directory".to_string(),
        ));
    }
    BrowserFs::from_directory(child_fd).map_err(|_| {
        McBrowserError::Internal("Failed to initialize user filesystem handle".to_string())
    })
}

fn open_configured_user_browser_fs(user_id: i64) -> Result<BrowserFs, McBrowserError> {
    let connection = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for scope check".to_string())
    })?;
    open_configured_user_browser_fs_with_conn(&connection, user_id)
}

fn open_configured_user_browser_fs_with_conn(
    connection: &rusqlite::Connection,
    user_id: i64,
) -> Result<BrowserFs, McBrowserError> {
    let env_val = env::var("AF_MCBROWSER_ROOT").ok();
    let base_root = resolve_configured_base_root(env_val.as_deref())?;
    let filesystem = open_user_browser_fs_at(&base_root, user_id)?;
    let scope = policy::effective_scope_with_conn(connection, user_id)?;
    filesystem
        .scoped(&scope)
        .map_err(|error| map_fs_io_error(error, "Failed to open configured scope"))
}

fn open_authorized_file_with_conn(
    connection: &rusqlite::Connection,
    user: &AuthUser,
    filesystem: &BrowserFs,
    path: &str,
    permission: policy::Permission,
) -> Result<File, McBrowserError> {
    policy::authorize_with_conn(connection, user, permission, path)?;
    match filesystem.open_file(path) {
        Ok(file) => Ok(file),
        Err(_) => {
            let resolved = filesystem
                .open_file_resolving_internal_links(path)
                .map_err(|error| map_fs_io_error(error, "Failed to resolve file"))?;
            for resolution_path in &resolved.resolution_paths {
                policy::authorize_with_conn(connection, user, permission, resolution_path)?;
            }
            policy::authorize_with_conn(connection, user, permission, &resolved.resolved_path)?;
            Ok(resolved.file)
        }
    }
}
pub fn map_fs_io_error(err: io::Error, action: &str) -> McBrowserError {
    if err.to_string() == "directory entry limit exceeded" {
        return McBrowserError::BadRequest("Directory exceeds the 10,000 entry limit".to_string());
    }
    match err.kind() {
        ErrorKind::NotFound => {
            McBrowserError::NotFound(format!("{action}: requested path was not found"))
        }
        ErrorKind::AlreadyExists => {
            McBrowserError::Conflict(format!("{action}: destination path already exists"))
        }
        ErrorKind::InvalidInput | ErrorKind::InvalidData => {
            McBrowserError::BadRequest(format!("{action}: invalid path or entry type"))
        }
        ErrorKind::PermissionDenied => {
            McBrowserError::Forbidden(format!("{action}: operation is not permitted"))
        }
        _ => match err.raw_os_error() {
            Some(libc::ENOTEMPTY) | Some(libc::EEXIST) => McBrowserError::Conflict(format!(
                "{action}: directory is not empty or target already exists"
            )),
            Some(libc::ENOTDIR)
            | Some(libc::EISDIR)
            | Some(libc::EINVAL)
            | Some(libc::ENAMETOOLONG) => {
                McBrowserError::BadRequest(format!("{action}: invalid target type or path"))
            }
            Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::EACCES) | Some(libc::EPERM) => {
                McBrowserError::Forbidden(format!("{action}: symlink or cross-root access denied"))
            }
            Some(libc::ENOSPC) | Some(libc::EDQUOT) => McBrowserError::InsufficientStorage(
                "Insufficient storage space available on server".to_string(),
            ),
            _ => McBrowserError::Internal(format!("{action}: filesystem operation failed")),
        },
    }
}
fn load_active_quota_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
    additional_bytes: u64,
) -> Result<QuotaSnapshot, McBrowserError> {
    let user_exists: Option<String> = conn
        .query_row(
            "SELECT username FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify user account state".to_string()))?;

    if user_exists.is_none() {
        return Err(McBrowserError::Unauthorized(
            "User account not found".to_string(),
        ));
    }

    let row: Option<(i64, i64, String)> = conn
        .query_row(
            "SELECT COALESCE(quota_bytes, 0), COALESCE(used_bytes, 0), COALESCE(status, '') \
             FROM user_quotas WHERE user_id = ?1",
            params![user_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to read user storage quota".to_string()))?;

    let (quota_bytes, used_bytes, status) = row.unwrap_or((0, 0, String::new()));
    if !status.trim().is_empty() && !status.trim().eq_ignore_ascii_case("active") {
        return Err(McBrowserError::Forbidden(
            "Account is not active".to_owned(),
        ));
    }

    let used_non_neg = used_bytes.max(0);
    let add_i64 = i64::try_from(additional_bytes).unwrap_or(i64::MAX);
    if quota_bytes > 0 && (add_i64 > 0 && used_non_neg.saturating_add(add_i64) > quota_bytes) {
        return Err(McBrowserError::QuotaExceeded(
            "Storage quota exceeded. Free up space or contact an administrator.".to_string(),
        ));
    }

    Ok(QuotaSnapshot {
        quota_bytes,
        used_bytes: used_non_neg,
    })
}

pub(crate) fn check_user_quota_pre_mutation(
    user_id: i64,
    expected_add_bytes: u64,
) -> Result<(), McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for quota verification".to_string())
    })?;
    load_active_quota_conn(&conn, user_id, expected_add_bytes).map(|_| ())
}
pub(crate) fn reserve_user_quota_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
    delta_bytes: u64,
) -> Result<(), McBrowserError> {
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

    let snapshot = load_active_quota_conn(conn, user_id, delta_bytes)?;
    let delta_i64 = i64::try_from(delta_bytes).unwrap_or(i64::MAX);
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
    Ok(())
}

pub(crate) fn reserve_user_quota_atomic(
    conn: &rusqlite::Connection,
    user_id: i64,
    delta_bytes: u64,
) -> Result<(), McBrowserError> {
    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| McBrowserError::Internal("Failed to start quota transaction".into()))?;
    match reserve_user_quota_conn(conn, user_id, delta_bytes) {
        Ok(()) => conn.execute_batch("COMMIT").map_err(|_| {
            let _ = conn.execute_batch("ROLLBACK");
            McBrowserError::Internal("Failed to commit quota reservation".into())
        }),
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub(crate) fn release_user_quota_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
    delta_bytes: u64,
) -> Result<(), McBrowserError> {
    if delta_bytes == 0 {
        return Ok(());
    }
    let delta_i64 = i64::try_from(delta_bytes).unwrap_or(i64::MAX);
    conn.execute(
        "UPDATE user_quotas \
         SET used_bytes = MAX(0, COALESCE(used_bytes, 0) - ?2), \
             updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ?1",
        params![user_id, delta_i64],
    )
    .map_err(|_| McBrowserError::Internal("Failed to update user storage quota".to_string()))?;
    Ok(())
}

pub(crate) fn reserve_user_quota_db(user_id: i64, delta_bytes: u64) -> Result<(), McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for quota reservation".to_string())
    })?;
    reserve_user_quota_atomic(&conn, user_id, delta_bytes)
}

pub(crate) fn release_user_quota_db(user_id: i64, delta_bytes: u64) -> Result<(), McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for quota update".to_string())
    })?;
    release_user_quota_conn(&conn, user_id, delta_bytes)
}
pub fn check_fd_free_space(fd: libc::c_int, required_bytes: u64) -> Result<(), McBrowserError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    let rc = unsafe { libc::fstatvfs(fd, &mut stat) };
    if rc < 0 {
        return Err(McBrowserError::Internal(
            "Failed to inspect filesystem free space".to_string(),
        ));
    }
    let block_size = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    let avail_bytes = (stat.f_bavail as u64).saturating_mul(block_size);
    let needed = MIN_FREE_SPACE_BYTES.saturating_add(required_bytes);
    if avail_bytes < needed {
        return Err(McBrowserError::InsufficientStorage(
            "Insufficient free disk space on storage volume".to_string(),
        ));
    }
    Ok(())
}
pub fn read_utf8_preview_from_file(
    mut file: File,
    normalized_path: String,
) -> Result<PreviewResponse, McBrowserError> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let max_read = MAX_PREVIEW_BYTES + 4;

    while buf.len() < max_read {
        let to_read = (max_read - buf.len()).min(chunk.len());
        match file.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(McBrowserError::Internal(
                    "Failed to read file for preview".to_string(),
                ))
            }
        }
    }

    let truncated = buf.len() > MAX_PREVIEW_BYTES;
    let inspect_slice = if truncated {
        &buf[..MAX_PREVIEW_BYTES]
    } else {
        &buf[..]
    };

    if inspect_slice.contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Preview is only supported for UTF-8 text files (binary content detected)".to_string(),
        ));
    }

    match std::str::from_utf8(inspect_slice) {
        Ok(text) => Ok(PreviewResponse {
            path: normalized_path,
            content: text.to_string(),
            truncated,
        }),
        Err(utf8_err) => {
            let valid_up_to = utf8_err.valid_up_to();
            if truncated && utf8_err.error_len().is_none() && (MAX_PREVIEW_BYTES - valid_up_to) <= 3
            {
                if let Err(full_err) = std::str::from_utf8(&buf) {
                    if full_err.valid_up_to() <= valid_up_to {
                        return Err(McBrowserError::BadRequest(
                            "Preview is only supported for valid UTF-8 text files".to_string(),
                        ));
                    }
                }
                let text = std::str::from_utf8(&inspect_slice[..valid_up_to]).map_err(|_| {
                    McBrowserError::BadRequest(
                        "Preview is only supported for valid UTF-8 text files".to_string(),
                    )
                })?;
                Ok(PreviewResponse {
                    path: normalized_path,
                    content: text.to_string(),
                    truncated: true,
                })
            } else {
                Err(McBrowserError::BadRequest(
                    "Preview is only supported for valid UTF-8 text files".to_string(),
                ))
            }
        }
    }
}
pub fn build_attachment_content_disposition(filename: &str) -> HeaderValue {
    let raw_leaf = filename.rsplit('/').next().unwrap_or("download");
    let ascii_fallback: String = raw_leaf
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let fallback = if ascii_fallback.trim_matches('.').is_empty() {
        "download".to_string()
    } else {
        ascii_fallback
    };
    let encoded = urlencoding::encode(raw_leaf);
    let header_str = format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}");
    HeaderValue::from_str(&header_str)
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"download\""))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedByteRange {
    Full,
    Partial { start: u64, end: u64 },
}
pub fn parse_single_byte_range(
    range_header: Option<&str>,
    total_size: u64,
) -> Result<ParsedByteRange, McBrowserError> {
    let Some(raw) = range_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ParsedByteRange::Full);
    };
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return Err(McBrowserError::RangeNotSatisfiable(total_size));
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(',') {
        return Err(McBrowserError::RangeNotSatisfiable(total_size));
    }
    let Some((start_str, end_str)) = spec.split_once('-') else {
        return Err(McBrowserError::RangeNotSatisfiable(total_size));
    };
    if total_size == 0 {
        return Err(McBrowserError::RangeNotSatisfiable(0));
    }

    let start_str = start_str.trim();
    let end_str = end_str.trim();

    if start_str.is_empty() {
        let suffix_len: u64 = end_str
            .parse()
            .map_err(|_| McBrowserError::RangeNotSatisfiable(total_size))?;
        if suffix_len == 0 {
            return Err(McBrowserError::RangeNotSatisfiable(total_size));
        }
        let start = total_size.saturating_sub(suffix_len);
        let end = total_size - 1;
        Ok(ParsedByteRange::Partial { start, end })
    } else {
        let start: u64 = start_str
            .parse()
            .map_err(|_| McBrowserError::RangeNotSatisfiable(total_size))?;
        if start >= total_size {
            return Err(McBrowserError::RangeNotSatisfiable(total_size));
        }
        let end = if end_str.is_empty() {
            total_size - 1
        } else {
            let parsed_end: u64 = end_str
                .parse()
                .map_err(|_| McBrowserError::RangeNotSatisfiable(total_size))?;
            if parsed_end < start {
                return Err(McBrowserError::RangeNotSatisfiable(total_size));
            }
            parsed_end.min(total_size - 1)
        };
        Ok(ParsedByteRange::Partial { start, end })
    }
}

async fn list_entries(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, true) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let path_for_fs = normalized_path.clone();
    let res = tokio::task::spawn_blocking(move || -> Result<Vec<BrowserEntry>, McBrowserError> {
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for listing".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let document =
            policy::authorize_directory_listing_with_conn(&connection, &auth_user, &path_for_fs)?;
        let (entries, resolved_directory, resolution_paths) = match bfs.list(&path_for_fs) {
            Ok(entries) => (entries, path_for_fs.clone(), Vec::new()),
            Err(_) => {
                let listing = bfs
                    .list_with_trace_resolving_internal_links(&path_for_fs)
                    .map_err(|error| map_fs_io_error(error, "Failed to resolve directory"))?;
                (
                    listing.entries,
                    listing.resolved_path,
                    listing.resolution_paths,
                )
            }
        };
        for resolution_path in &resolution_paths {
            policy::authorize_directory_listing_with_conn(
                &connection,
                &auth_user,
                resolution_path,
            )?;
        }
        policy::authorize_directory_listing_with_conn(
            &connection,
            &auth_user,
            &resolved_directory,
        )?;
        let mut visible = Vec::new();
        for mut entry in entries {
            let alias_path = if path_for_fs.is_empty() {
                entry.name.clone()
            } else {
                format!("{path_for_fs}/{}", entry.name)
            };
            let target_kind = if entry.kind == "symlink" {
                bfs.metadata_resolving_internal_links(&alias_path)
                    .ok()
                    .filter(|resolved| {
                        resolved
                            .resolution_paths
                            .iter()
                            .chain(std::iter::once(&resolved.resolved_path))
                            .all(|resolution_path| {
                                policy::is_entry_visible(
                                    &document,
                                    resolution_path,
                                    resolved.entry.kind == "directory",
                                )
                            })
                    })
                    .map(|resolved| {
                        entry.size = resolved.entry.size;
                        resolved.entry.kind
                    })
            } else {
                None
            };
            let is_directory =
                entry.kind == "directory" || target_kind.as_deref() == Some("directory");
            if !policy::is_entry_visible(&document, &entry.path, is_directory)
                || !policy::is_entry_visible(&document, &alias_path, is_directory)
            {
                continue;
            }
            entry.path = alias_path;
            visible.push(BrowserEntry { entry, target_kind });
        }
        Ok(visible)
    })
    .await;

    match res {
        Ok(Ok(entries)) => Json(EntriesResponse {
            path: normalized_path,
            entries,
            max_upload_bytes: uploads::configured_max_upload_bytes(),
        })
        .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Directory listing task failed".to_string()).into_response()
        }
    }
}

async fn create_directory(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CreateDirectoryRequest>,
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

    let res = tokio::task::spawn_blocking(move || -> Result<(), McBrowserError> {
        let _guard = guard;
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for directory creation".to_string())
        })?;
        policy::authorize_with_conn(
            &connection,
            &auth_user,
            policy::Permission::Create,
            &normalized_path,
        )?;
        load_active_quota_conn(&connection, user_id, 0)?;
        let bfs = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let pending = events::record_pending_intent_with_conn(
            &connection,
            &auth_user,
            events::McBrowserEventTrigger::UploadCompleted,
            &normalized_path,
            None,
            0,
        )?;
        let result = if req.parents {
            bfs.create_directory_all(&normalized_path)
        } else {
            bfs.create_directory(&normalized_path)
        };
        if let Err(error) = result {
            if !req.parents {
                let _ = events::finalize_event_failed_with_conn(
                    &connection,
                    &pending.event.event_id,
                    Some("CREATE_DIRECTORY_FAILED"),
                );
            }
            return Err(map_fs_io_error(error, "Failed to create directory"));
        }
        events::finalize_published_mutation_with_conn(&connection, &pending, None, None, 0);
        Ok(())
    })
    .await;

    match res {
        Ok(Ok(())) => (
            StatusCode::CREATED,
            Json(MutationSuccessResponse { success: true }),
        )
            .into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Create directory task failed".to_string()).into_response()
        }
    }
}

async fn rename_entry(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<operations::RenameMoveRequest>,
) -> Response {
    match operations::execute_rename_request(auth_user, req).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn delete_entry(
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

    let guard = user_mutation_stripe(user_id).lock_owned().await;

    let res =
        tokio::task::spawn_blocking(move || -> Result<DeleteSuccessResponse, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for quota update".to_string())
            })?;
            policy::authorize_with_conn(
                &conn,
                &auth_user,
                policy::Permission::Delete,
                &normalized_path,
            )?;
            load_active_quota_conn(&conn, user_id, 0)?;

            let bfs = open_configured_user_browser_fs_with_conn(&conn, user_id)?;
            let pending = events::record_pending_intent_with_conn(
                &conn,
                &auth_user,
                events::McBrowserEventTrigger::EntryDeleted,
                &normalized_path,
                None,
                0,
            )?;
            let removed_file_size =
                match bfs.remove_with_size_allowing_leaf_symlink(&normalized_path) {
                    Ok(removed) => removed,
                    Err(error) => {
                        let _ = events::finalize_event_failed_with_conn(
                            &conn,
                            &pending.event.event_id,
                            Some("DELETE_ENTRY_FAILED"),
                        );
                        return Err(map_fs_io_error(error, "Failed to delete entry"));
                    }
                };
            let accounting_pending = if removed_file_size > 0 {
                release_user_quota_conn(&conn, user_id, removed_file_size).is_err()
            } else {
                false
            };
            if !accounting_pending {
                events::finalize_published_mutation_with_conn(
                    &conn,
                    &pending,
                    None,
                    None,
                    -(removed_file_size.min(i64::MAX as u64) as i64),
                );
            }
            Ok(DeleteSuccessResponse {
                success: true,
                accounting_pending,
            })
        })
        .await;

    match res {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Delete task failed".to_string()).into_response(),
    }
}
pub async fn stream_body_to_file(
    body: Body,
    std_file: File,
    max_bytes: u64,
) -> Result<u64, McBrowserError> {
    let mut async_file = tokio::fs::File::from_std(std_file);
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|_| {
            McBrowserError::BadRequest("Failed to read upload request stream".to_string())
        })?;
        let chunk_len = chunk.len() as u64;
        written = written.saturating_add(chunk_len);
        if written > max_bytes {
            return Err(McBrowserError::PayloadTooLarge(format!(
                "Upload exceeds maximum allowed size of {max_bytes} bytes (64 MiB)"
            )));
        }
        async_file
            .write_all(&chunk)
            .await
            .map_err(|e| map_fs_io_error(e, "Failed to write upload stream"))?;
    }

    async_file
        .flush()
        .await
        .map_err(|e| map_fs_io_error(e, "Failed to flush upload stream"))?;
    Ok(written)
}

async fn upload_entry(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let declared_length: Option<u64> = match headers.get(header::CONTENT_LENGTH) {
        Some(hv) => {
            let Ok(s) = hv.to_str() else {
                return McBrowserError::BadRequest("Invalid Content-Length header".to_string())
                    .into_response();
            };
            let Ok(len) = s.trim().parse::<u64>() else {
                return McBrowserError::BadRequest("Invalid Content-Length header".to_string())
                    .into_response();
            };
            if len > MAX_UPLOAD_BYTES {
                return McBrowserError::PayloadTooLarge(format!(
                    "Upload exceeds maximum allowed size of {MAX_UPLOAD_BYTES} bytes (64 MiB)"
                ))
                .into_response();
            }
            Some(len)
        }
        None => None,
    };

    let Ok(permit) = Arc::clone(&UPLOAD_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Upload limiter closed".to_string()).into_response();
    };
    let guard = user_mutation_stripe(user_id).lock_owned().await;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Option<axum::body::Bytes>>(2);
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || -> Result<(), McBrowserError> {
        let _permit = permit;
        let _guard = guard;
        let connection = af_db::get_conn()
            .map_err(|_| McBrowserError::Internal("Database unavailable for upload".to_string()))?;
        policy::authorize_with_conn(
            &connection,
            &auth_user,
            policy::Permission::Create,
            &normalized_path,
        )?;
        let quota = load_active_quota_conn(&connection, user_id, declared_length.unwrap_or(0))?;
        let maximum = if quota.quota_bytes > 0 {
            MAX_UPLOAD_BYTES.min(quota.quota_bytes.saturating_sub(quota.used_bytes).max(0) as u64)
        } else {
            MAX_UPLOAD_BYTES
        };
        let filesystem = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let pending = filesystem
            .begin_upload(&normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to initiate upload"))?;
        let mut file = pending
            .file()
            .map_err(|error| map_fs_io_error(error, "Failed to open staging file"))?;
        check_fd_free_space(file.as_raw_fd(), declared_length.unwrap_or(maximum).max(1))?;
        drop(connection);
        if ready_sender.send(maximum).is_err() {
            return Err(McBrowserError::BadRequest(
                "Upload cancelled before streaming".to_string(),
            ));
        }
        let mut written = 0_u64;
        while let Some(message) = receiver.blocking_recv() {
            let Some(chunk) = message else {
                if declared_length.is_some_and(|expected| expected != written) {
                    return Err(McBrowserError::BadRequest(
                        "Uploaded body length did not match Content-Length header".to_string(),
                    ));
                }
                let connection = af_db::get_conn().map_err(|_| {
                    McBrowserError::Internal(
                        "Database unavailable for upload publication".to_string(),
                    )
                })?;
                policy::authorize_with_conn(
                    &connection,
                    &auth_user,
                    policy::Permission::Create,
                    &normalized_path,
                )?;
                let audit = events::record_pending_intent_with_conn(
                    &connection,
                    &auth_user,
                    events::McBrowserEventTrigger::UploadCompleted,
                    &normalized_path,
                    None,
                    written.min(i64::MAX as u64) as i64,
                )?;
                if let Err(error) = reserve_user_quota_atomic(&connection, user_id, written) {
                    let _ = events::finalize_event_failed_with_conn(
                        &connection,
                        &audit.event.event_id,
                        Some("QUOTA_RESERVATION_FAILED"),
                    );
                    return Err(error);
                }
                if let Err(error) = pending.commit() {
                    release_user_quota_conn(&connection, user_id, written).map_err(|_| {
                        McBrowserError::AccountingPending(
                            "Upload was not published; reserved quota requires reconciliation"
                                .to_string(),
                        )
                    })?;
                    let _ = events::finalize_event_failed_with_conn(
                        &connection,
                        &audit.event.event_id,
                        Some("UPLOAD_PUBLICATION_FAILED"),
                    );
                    return Err(map_fs_io_error(error, "Failed to finalize upload"));
                }
                events::finalize_published_mutation_with_conn(
                    &connection,
                    &audit,
                    None,
                    None,
                    written.min(i64::MAX as u64) as i64,
                );
                return Ok(());
            };
            written = written.saturating_add(chunk.len() as u64);
            if written > maximum {
                return Err(McBrowserError::QuotaExceeded(
                    "Upload exceeds available storage quota".to_string(),
                ));
            }
            std::io::Write::write_all(&mut file, &chunk)
                .map_err(|error| map_fs_io_error(error, "Failed to write upload stream"))?;
        }
        Err(McBrowserError::BadRequest(
            "Upload cancelled before completion".to_string(),
        ))
    });
    let maximum = match ready_receiver.await {
        Ok(maximum) => maximum,
        Err(_) => {
            return match worker.await {
                Ok(Err(error)) => error.into_response(),
                _ => McBrowserError::Internal("Upload initialization failed".to_string())
                    .into_response(),
            }
        }
    };
    let stream_result = tokio::time::timeout(UPLOAD_TIMEOUT, async {
        let mut stream = body.into_data_stream();
        let mut received = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                McBrowserError::BadRequest("Failed to read upload stream".to_string())
            })?;
            received = received.saturating_add(chunk.len() as u64);
            if received > maximum {
                return Err(if maximum < MAX_UPLOAD_BYTES {
                    McBrowserError::QuotaExceeded(
                        "Upload exceeds available storage quota".to_string(),
                    )
                } else {
                    McBrowserError::PayloadTooLarge(
                        "Upload exceeds maximum allowed size of 64 MiB".to_string(),
                    )
                });
            }
            sender
                .send(Some(chunk))
                .await
                .map_err(|_| McBrowserError::Internal("Upload writer stopped".to_string()))?;
        }
        sender
            .send(None)
            .await
            .map_err(|_| McBrowserError::Internal("Upload writer stopped".to_string()))
    })
    .await;
    drop(sender);
    let stream_error = match stream_result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(McBrowserError::RequestTimeout(
            "Upload timed out while streaming request body".to_string(),
        )),
    };
    let worker_result = worker.await;
    if let Some(error) = stream_error {
        return error.into_response();
    }
    match worker_result {
        Ok(Ok(())) => (
            StatusCode::CREATED,
            Json(MutationSuccessResponse { success: true }),
        )
            .into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("Upload task failed".to_string()).into_response(),
    }
}

async fn download_entry(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
) -> Response {
    let user_id = match validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let normalized_path = match normalize_relative_path(&query.path, false) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let range_hdr = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let path_for_open = normalized_path.clone();
    let open_res = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for download".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let mut file = open_authorized_file_with_conn(
            &connection,
            &auth_user,
            &bfs,
            &path_for_open,
            policy::Permission::Download,
        )?;
        let meta = file
            .metadata()
            .map_err(|_| McBrowserError::Internal("Failed to read file metadata".to_string()))?;
        let total_size = meta.len();
        let parsed_range = parse_single_byte_range(range_hdr.as_deref(), total_size)?;
        if let ParsedByteRange::Partial { start, .. } = parsed_range {
            file.seek(SeekFrom::Start(start)).map_err(|_| {
                McBrowserError::Internal("Failed to seek file for range download".to_string())
            })?;
        }
        Ok::<(File, u64, ParsedByteRange), McBrowserError>((file, total_size, parsed_range))
    })
    .await;

    let (std_file, total_size, parsed_range) = match open_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return e.into_response(),
        Err(_) => {
            return McBrowserError::Internal("Download open task failed".to_string())
                .into_response()
        }
    };

    let (status, content_len, content_range_hdr) = match parsed_range {
        ParsedByteRange::Full => (StatusCode::OK, total_size, None),
        ParsedByteRange::Partial { start, end } => {
            let len = end - start + 1;
            let cr = HeaderValue::from_str(&format!("bytes {start}-{end}/{total_size}")).ok();
            (StatusCode::PARTIAL_CONTENT, len, cr)
        }
    };

    let stream = FileRangeStream::new(tokio::fs::File::from_std(std_file), content_len);
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = status;

    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        build_attachment_content_disposition(&normalized_path),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(len_hv) = HeaderValue::from_str(&content_len.to_string()) {
        h.insert(header::CONTENT_LENGTH, len_hv);
    }
    if let Some(cr) = content_range_hdr {
        h.insert(header::CONTENT_RANGE, cr);
    }
    resp
}

async fn preview_entry(
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

    let Ok(permit) = Arc::clone(&PREVIEW_SEMAPHORE).acquire_owned().await else {
        return McBrowserError::Internal("Preview concurrency limiter closed".to_string())
            .into_response();
    };

    let res = tokio::task::spawn_blocking(move || -> Result<PreviewResponse, McBrowserError> {
        let _permit = permit;
        let connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for preview".to_string())
        })?;
        let bfs = open_configured_user_browser_fs_with_conn(&connection, user_id)?;
        let file = open_authorized_file_with_conn(
            &connection,
            &auth_user,
            &bfs,
            &normalized_path,
            policy::Permission::Read,
        )?;
        read_utf8_preview_from_file(file, normalized_path)
    })
    .await;

    match res {
        Ok(Ok(preview)) => {
            let mut resp = Json(preview).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Preview task failed".to_string()).into_response(),
    }
}
mod tokio_util_reader_stream {
    use axum::body::Bytes;
    use futures::Stream;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    const STREAM_CHUNK_SIZE: usize = 64 * 1024;

    pub struct FileRangeStream {
        file: tokio::fs::File,
        remaining: u64,
        buf: Vec<u8>,
    }

    impl FileRangeStream {
        pub fn new(file: tokio::fs::File, remaining: u64) -> Self {
            let cap = (remaining.min(STREAM_CHUNK_SIZE as u64)) as usize;
            Self {
                file,
                remaining,
                buf: vec![0u8; cap.max(1)],
            }
        }
    }

    impl Stream for FileRangeStream {
        type Item = Result<Bytes, io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            let max_to_read = (self.remaining.min(STREAM_CHUNK_SIZE as u64)) as usize;
            let this = self.as_mut().get_mut();
            if this.buf.len() < max_to_read {
                this.buf.resize(max_to_read, 0);
            }
            let mut read_buf = ReadBuf::new(&mut this.buf[..max_to_read]);
            match Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.remaining = 0;
                    Poll::Ready(Some(Err(e)))
                }
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.remaining = 0;
                        Poll::Ready(None)
                    } else {
                        let n = filled.len() as u64;
                        this.remaining = this.remaining.saturating_sub(n);
                        Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "mcbrowser_http_tests.rs"]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new() -> Self {
            let mut rng = rand::thread_rng();
            for _ in 0..64 {
                let token: u128 = rng.gen();
                let path = std::env::temp_dir().join(format!("af-mcbrowser-test-{token:032x}"));
                if fs::create_dir(&path).is_ok() {
                    return Self { path };
                }
            }
            panic!("failed to allocate test temp dir");
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn human_user(user_id: i64) -> AuthUser {
        AuthUser {
            user_id,
            username: format!("user{user_id}"),
            role: "user".to_string(),
            jti: "jti-1".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    #[test]
    fn rejects_invalid_user_ids_and_plugin_scoped_tokens() {
        assert_eq!(validate_mcbrowser_user(&human_user(42)).unwrap(), 42);

        for invalid_id in [0, -1, -999] {
            assert!(matches!(
                validate_mcbrowser_user(&human_user(invalid_id)),
                Err(McBrowserError::Unauthorized(_))
            ));
        }

        let mut with_plugin_id = human_user(7);
        with_plugin_id.plugin_id = Some("sonarr".to_string());
        assert!(matches!(
            validate_mcbrowser_user(&with_plugin_id),
            Err(McBrowserError::Forbidden(_))
        ));

        let mut with_scopes = human_user(7);
        with_scopes.plugin_scopes = vec!["/api/v1/auth/mcbrowser/*".to_string()];
        assert!(matches!(
            validate_mcbrowser_user(&with_scopes),
            Err(McBrowserError::Forbidden(_))
        ));

        let mut with_plugin_role = human_user(7);
        with_plugin_role.role = "plugin".to_string();
        assert!(matches!(
            validate_mcbrowser_user(&with_plugin_role),
            Err(McBrowserError::Forbidden(_))
        ));
    }

    #[test]
    fn root_derivation_enforces_absolute_path_and_private_mode_700_without_following_symlinks() {
        assert_eq!(
            resolve_configured_base_root(None).unwrap(),
            PathBuf::from(DEFAULT_MCBROWSER_ROOT)
        );
        assert_eq!(
            resolve_configured_base_root(Some("   ")).unwrap(),
            PathBuf::from(DEFAULT_MCBROWSER_ROOT)
        );
        assert_eq!(
            resolve_configured_base_root(Some("/var/lib/aetherflow/custom")).unwrap(),
            PathBuf::from("/var/lib/aetherflow/custom")
        );

        for bad_root in [
            "relative/path",
            "./local",
            "/var/lib/../escape",
            "/tmp/bad\0root",
        ] {
            assert!(
                resolve_configured_base_root(Some(bad_root)).is_err(),
                "should reject invalid base root {bad_root:?}"
            );
        }

        let tmp = TestTempDir::new();
        let user_root = derive_user_root_path(tmp.path(), 15).unwrap();
        assert_eq!(user_root, tmp.path().join("user-15"));
        assert!(derive_user_root_path(tmp.path(), 0).is_err());
        assert!(derive_user_root_path(tmp.path(), -5).is_err());

        let bfs = open_user_browser_fs_at(tmp.path(), 15).unwrap();
        assert!(bfs.list("").unwrap().is_empty());

        let meta = fs::symlink_metadata(&user_root).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let outside = TestTempDir::new();
        let symlink_child = tmp.path().join("user-99");
        symlink(outside.path(), &symlink_child).unwrap();
        let err = open_user_browser_fs_at(tmp.path(), 99).unwrap_err();
        assert!(matches!(err, McBrowserError::Internal(_)));
        assert!(fs::symlink_metadata(&symlink_child)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn path_normalization_and_error_mapping_do_not_expose_host_paths() {
        assert_eq!(normalize_relative_path("", true).unwrap(), "");
        assert!(normalize_relative_path("", false).is_err());
        assert_eq!(
            normalize_relative_path("media//movies/clip.mkv", false).unwrap(),
            "media/movies/clip.mkv"
        );

        for bad in [
            "/etc/passwd",
            "../secret",
            "a/../../b",
            "./file",
            "dir\\file",
            ".af-upload-tmp.123",
            "nested/.af-upload-tmp.123",
            "bad\0name",
        ] {
            assert!(normalize_relative_path(bad, true).is_err());
            assert!(normalize_relative_path(bad, false).is_err());
        }

        let not_found = map_fs_io_error(
            io::Error::new(
                ErrorKind::NotFound,
                "/var/lib/aetherflow/mcbrowser/user-1/secret",
            ),
            "Open failed",
        );
        if let McBrowserError::NotFound(msg) = not_found {
            assert!(!msg.contains("/var/lib"));
        } else {
            panic!("expected NotFound");
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_keeps_mutation_locked_until_blocking_work_finishes() {
        let stripe = user_mutation_stripe(71);
        let guard = Arc::clone(&stripe).lock_owned().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let guard = guard;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(guard);
                finished_tx.send(()).unwrap();
            })
            .await
            .unwrap();
        });
        started_rx.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(stripe.try_lock().is_err());
        release_tx.send(()).unwrap();
        finished_rx.await.unwrap();
        assert!(stripe.try_lock().is_ok());
    }

    #[test]
    fn preview_validates_full_codepoints_crossing_the_truncation_boundary() {
        let tmp = TestTempDir::new();
        let path = tmp.path().join("boundary.txt");
        for suffix in ["😀tail".as_bytes(), "€tail".as_bytes()] {
            let mut bytes = vec![b'a'; MAX_PREVIEW_BYTES - 1];
            bytes.extend_from_slice(suffix);
            fs::write(&path, bytes).unwrap();
            let preview =
                read_utf8_preview_from_file(File::open(&path).unwrap(), "boundary.txt".into())
                    .unwrap();
            assert!(preview.truncated);
            assert_eq!(preview.content.len(), MAX_PREVIEW_BYTES - 1);
        }
        for suffix in [&[0xE2, 0x20][..], &[0xF0, 0x9F, 0x20, 0x80], &[0xF0, 0x9F]] {
            let mut bytes = vec![b'a'; MAX_PREVIEW_BYTES - 1];
            bytes.extend_from_slice(suffix);
            fs::write(&path, bytes).unwrap();
            assert!(matches!(
                read_utf8_preview_from_file(File::open(&path).unwrap(), "boundary.txt".into()),
                Err(McBrowserError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn directory_requests_preserve_existing_semantics_and_opt_in_to_parents() {
        let regular: CreateDirectoryRequest = serde_json::from_str(r#"{"path":"folder"}"#).unwrap();
        assert!(!regular.parents);
        let nested: CreateDirectoryRequest =
            serde_json::from_str(r#"{"path":"folder/sub","parents":true}"#).unwrap();
        assert!(nested.parents);
    }

    #[test]
    fn filesystem_root_is_not_a_valid_storage_base() {
        assert!(open_user_browser_fs_at(Path::new("/"), 1).is_err());
    }

    #[test]
    fn preview_enforces_256kib_cap_and_rejects_binary_or_invalid_utf8() {
        let tmp = TestTempDir::new();
        let small_path = tmp.path().join("hello.txt");
        fs::write(&small_path, "Hello, AetherFlow!\nLine 2").unwrap();
        let preview =
            read_utf8_preview_from_file(File::open(&small_path).unwrap(), "hello.txt".to_string())
                .unwrap();
        assert_eq!(preview.path, "hello.txt");
        assert_eq!(preview.content, "Hello, AetherFlow!\nLine 2");
        assert!(!preview.truncated);
        let exact_path = tmp.path().join("exact.txt");
        fs::write(&exact_path, vec![b'a'; MAX_PREVIEW_BYTES]).unwrap();
        let exact_preview =
            read_utf8_preview_from_file(File::open(&exact_path).unwrap(), "exact.txt".to_string())
                .unwrap();
        assert_eq!(exact_preview.content.len(), MAX_PREVIEW_BYTES);
        assert!(!exact_preview.truncated);
        let trunc_path = tmp.path().join("trunc.txt");
        let mut trunc_bytes = vec![b'x'; MAX_PREVIEW_BYTES - 1];
        trunc_bytes.extend_from_slice("€after".as_bytes());
        fs::write(&trunc_path, &trunc_bytes).unwrap();
        let trunc_preview =
            read_utf8_preview_from_file(File::open(&trunc_path).unwrap(), "trunc.txt".to_string())
                .unwrap();
        assert!(trunc_preview.truncated);
        assert_eq!(trunc_preview.content.len(), MAX_PREVIEW_BYTES - 1);
        let bin_path = tmp.path().join("bin.dat");
        fs::write(&bin_path, b"hello\0world").unwrap();
        assert!(matches!(
            read_utf8_preview_from_file(File::open(&bin_path).unwrap(), "bin.dat".to_string()),
            Err(McBrowserError::BadRequest(_))
        ));
        let bad_utf8_path = tmp.path().join("bad.txt");
        fs::write(&bad_utf8_path, [0x66, 0x6f, 0x80, 0xff, 0x6f]).unwrap();
        assert!(matches!(
            read_utf8_preview_from_file(File::open(&bad_utf8_path).unwrap(), "bad.txt".to_string()),
            Err(McBrowserError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn upload_streaming_enforces_size_limit_and_cleans_up_temp_file_on_overflow() {
        let tmp = TestTempDir::new();
        let bfs = open_user_browser_fs_at(tmp.path(), 7).unwrap();
        let pending = bfs.begin_upload("too_big.bin").unwrap();
        let writer = pending.file().unwrap();
        let body = Body::from(vec![b'z'; 1024]);
        let err = stream_body_to_file(body, writer, 512).await.unwrap_err();
        assert!(matches!(err, McBrowserError::PayloadTooLarge(_)));
        drop(pending);

        assert!(bfs.list("").unwrap().is_empty());
        let pending_ok = bfs.begin_upload("ok.bin").unwrap();
        let writer_ok = pending_ok.file().unwrap();
        let written = stream_body_to_file(Body::from("stream-ok"), writer_ok, 1024)
            .await
            .unwrap();
        assert_eq!(written, 9);
        pending_ok.commit().unwrap();

        let listed = bfs.list("").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "ok.bin");
        assert_eq!(listed[0].size, 9);
    }

    #[test]
    fn quota_reservation_enforces_capacity_and_storage_suspension() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
             CREATE TABLE user_quotas (
                 user_id INTEGER PRIMARY KEY,
                 username TEXT NOT NULL,
                 quota_bytes INTEGER DEFAULT 0,
                 used_bytes INTEGER DEFAULT 0,
                 status TEXT DEFAULT 'active',
                 source TEXT DEFAULT 'manual',
                 updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );
             INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'suspended_bob');
             INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
             VALUES (1, 'alice', 1000, 600, 'active'),
                    (2, 'suspended_bob', 1000, 0, 'suspended');",
        )
        .unwrap();
        assert!(matches!(
            reserve_user_quota_atomic(&conn, 1, 401),
            Err(McBrowserError::QuotaExceeded(_))
        ));
        reserve_user_quota_atomic(&conn, 1, 400).unwrap();
        let used: i64 = conn
            .query_row(
                "SELECT used_bytes FROM user_quotas WHERE user_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(used, 1000);
        release_user_quota_conn(&conn, 1, 400).unwrap();
        let used_after: i64 = conn
            .query_row(
                "SELECT used_bytes FROM user_quotas WHERE user_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(used_after, 600);
        assert!(matches!(
            reserve_user_quota_atomic(&conn, 2, 10),
            Err(McBrowserError::Forbidden(_))
        ));
        assert!(matches!(
            reserve_user_quota_atomic(&conn, 2, 0),
            Err(McBrowserError::Forbidden(_))
        ));
        assert_eq!(
            conn.query_row(
                "SELECT status FROM user_quotas WHERE user_id = 2",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "suspended"
        );
        assert_eq!(
            conn.query_row(
                "SELECT used_bytes FROM user_quotas WHERE user_id = 2",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        conn.execute(
            "UPDATE user_quotas SET status = ' ACTIVE ' WHERE user_id = 2",
            [],
        )
        .unwrap();
        reserve_user_quota_atomic(&conn, 2, 10).unwrap();
        assert!(matches!(
            reserve_user_quota_atomic(&conn, 2, 991),
            Err(McBrowserError::QuotaExceeded(_))
        ));
    }

    #[test]
    fn range_parsing_and_attachment_content_disposition_are_safe() {
        let cd = build_attachment_content_disposition("folder/evil\"name;\r\n<script>.html");
        let cd_str = cd.to_str().unwrap();
        assert!(cd_str.starts_with("attachment; filename=\"evil_name___"));
        assert!(!cd_str.contains('\r') && !cd_str.contains('\n'));

        assert_eq!(
            parse_single_byte_range(None, 100).unwrap(),
            ParsedByteRange::Full
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=0-49"), 100).unwrap(),
            ParsedByteRange::Partial { start: 0, end: 49 }
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=90-"), 100).unwrap(),
            ParsedByteRange::Partial { start: 90, end: 99 }
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=-20"), 100).unwrap(),
            ParsedByteRange::Partial { start: 80, end: 99 }
        );
        assert!(matches!(
            parse_single_byte_range(Some("bytes=100-120"), 100),
            Err(McBrowserError::RangeNotSatisfiable(100))
        ));
    }
}
