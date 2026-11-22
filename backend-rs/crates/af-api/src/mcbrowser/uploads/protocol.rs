use super::{DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES, MAX_FINGERPRINT_LEN, TUS_VERSION};
use crate::auth::{api_error, AuthUser};
use crate::mcbrowser::{normalize_relative_path, resolve_configured_base_root, McBrowserError};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_NO_PAD};
use base64::Engine as _;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

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

pub(super) fn configured_base_root() -> Result<PathBuf, McBrowserError> {
    let env_val = env::var("AF_MCBROWSER_ROOT").ok();
    resolve_configured_base_root(env_val.as_deref())
}

/// Enforces `crate::mcbrowser::policy::Permission::Create` on the target path using the active SQLite
/// `Connection` (`crate::mcbrowser::policy::authorize_with_conn`), avoiding nested pool checkouts when
/// `af_db` pool `max_size == 1`.
#[inline]
pub(crate) fn authorize_create_permission_with_conn(
    conn: &Connection,
    user: &AuthUser,
    normalized_path: &str,
) -> Result<(), McBrowserError> {
    crate::mcbrowser::policy::authorize_with_conn(
        conn,
        user,
        crate::mcbrowser::policy::Permission::Create,
        normalized_path,
    )
}

/// Enforces `crate::mcbrowser::policy::Permission::Modify` on the target path using the active SQLite
/// `Connection` (`crate::mcbrowser::policy::authorize_with_conn`), avoiding nested pool checkouts when
/// `af_db` pool `max_size == 1`.
#[inline]
pub(crate) fn authorize_modify_permission_with_conn(
    conn: &Connection,
    user: &AuthUser,
    normalized_path: &str,
) -> Result<(), McBrowserError> {
    crate::mcbrowser::policy::authorize_with_conn(
        conn,
        user,
        crate::mcbrowser::policy::Permission::Modify,
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
#[derive(Default)]
pub enum ConflictPolicy {
    /// Fail with `409 Conflict` if the target file already exists (`RENAME_NOREPLACE`).
    #[default]
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

    pub(super) fn from_db_str(raw: &str) -> Self {
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
    pub updated_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishingResolution {
    Completed,
    UnpublishedStagingIntact,
    AmbiguousRetainQuota,
}

pub(super) fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(super) fn with_tus_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("Tus-Resumable", HeaderValue::from_static(TUS_VERSION));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub(super) fn tus_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    with_tus_headers(api_error(status, code, message))
}

pub(super) fn map_mcbrowser_err_tus(err: McBrowserError) -> Response {
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

pub(super) fn resolve_effective_conflict_policy(
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

pub(super) fn decode_base64_utf8(b64: &str, field_name: &str) -> Result<String, McBrowserError> {
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

pub(super) fn encode_session_metadata_header(session: &UploadSessionRecord) -> String {
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
