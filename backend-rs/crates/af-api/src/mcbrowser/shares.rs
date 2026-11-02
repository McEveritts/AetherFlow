//! Public file & directory sharing backend for McBrowser (`shares.rs`).
//!
//! Owns:
//! - Authenticated management routes (`pub fn router() -> Router`):
//!   - `GET /mcbrowser/shares` -> `200 OK` `{ shares: [...] }`
//!   - `POST /mcbrowser/shares` -> `201 Created` `{ share: { id, path, name, is_directory, password_required, expires_at, allow_download, created_at, url } }`
//!   - `DELETE /mcbrowser/shares/:id` -> `200 OK` `{ success: true }` (owner-only revocation)
//! - Public unauthenticated routes (`pub fn public_router() -> Router`):
//!   - `GET /mcbrowser/shares/:token` -> `200 OK` `{ name, is_directory, password_required, allow_download, expires_at }`
//!   - `POST /mcbrowser/shares/:token/unlock` -> `200 OK` `{ success: true, access_token, expires_in }` + `HttpOnly; SameSite=Lax` scoped cookie
//!   - `GET /mcbrowser/shares/:token/entries` -> `200 OK` `{ path, entries }`
//!   - `GET /mcbrowser/shares/:token/download` -> `200 OK` / `206 Partial Content` attachment stream

use super::{
    build_attachment_content_disposition, load_active_quota_conn, map_fs_io_error,
    normalize_relative_path, open_user_browser_fs_at, parse_single_byte_range,
    resolve_configured_base_root, tokio_util_reader_stream::FileRangeStream,
    validate_mcbrowser_user, McBrowserError, MutationSuccessResponse, ParsedByteRange,
};
use crate::auth::{api_error, jwt_secret_bytes, secure_cookie_enabled, AuthUser};
use crate::ws::{extract_client_ip, extract_cookie};
use af_files::{BrowserFs, Entry};
use axum::body::Body;
use axum::extract::{Extension, Path as AxumPath, Query, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Error, ErrorKind, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const SHARE_TOKEN_BYTES: usize = 32; // 256 bits
pub const UNLOCK_TOKEN_TTL_SECS: i64 = 3600; // 1 hour
pub const MAX_SHARE_PASSWORD_BYTES: usize = 1024;
const BCRYPT_SHARE_COST: u32 = 10;

const MAX_THROTTLE_ENTRIES: usize = 4096;
const THROTTLE_WINDOW: Duration = Duration::from_secs(60);
const MAX_FAILED_UNLOCKS_PER_SHARE_IP: usize = 5;
const MAX_FAILED_UNLOCKS_PER_IP: usize = 20;

const MAX_UNLOCK_SESSIONS: usize = 8192;

const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Integration
// ─────────────────────────────────────────────────────────────────────────────

pub(super) type PolicyAuthorizer = Arc<
    dyn Fn(&Connection, &AuthUser, super::policy::Permission, &str) -> Result<(), McBrowserError>
        + Send
        + Sync,
>;

fn default_policy_authorizer() -> PolicyAuthorizer {
    Arc::new(|conn, user, perm, path| super::policy::authorize_with_conn(conn, user, perm, path))
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Context (Production vs Isolated Test State)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) enum ShareRuntime {
    Production,
    Isolated {
        conn: Arc<Mutex<Connection>>,
        base_root: PathBuf,
        policy: PolicyAuthorizer,
    },
}

impl ShareRuntime {
    fn with_conn_and_root<T, F>(&self, f: F) -> Result<T, McBrowserError>
    where
        F: FnOnce(&Connection, &Path, &PolicyAuthorizer) -> Result<T, McBrowserError>,
    {
        match self {
            Self::Production => {
                let env_val = env::var("AF_MCBROWSER_ROOT").ok();
                let base_root = resolve_configured_base_root(env_val.as_deref())?;
                let conn = af_db::get_conn().map_err(|_| {
                    McBrowserError::Internal("Database unavailable for share operation".to_string())
                })?;
                ensure_shares_schema(&conn)?;
                let policy = default_policy_authorizer();
                f(&conn, &base_root, &policy)
            }
            Self::Isolated {
                conn,
                base_root,
                policy,
            } => {
                let guard = match conn.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                ensure_shares_schema(&guard)?;
                f(&guard, base_root, policy)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded Brute-Force Throttler & Unlock Session Store
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ThrottleBucket {
    attempts: Vec<Instant>,
    last_attempt: Instant,
}

#[derive(Default)]
struct BoundedUnlockThrottle {
    share_ip_buckets: HashMap<String, ThrottleBucket>,
    ip_buckets: HashMap<String, ThrottleBucket>,
}

impl BoundedUnlockThrottle {
    fn prune_and_cap(map: &mut HashMap<String, ThrottleBucket>, now: Instant, window: Duration) {
        if map.len() >= MAX_THROTTLE_ENTRIES {
            map.retain(|_, bucket| {
                bucket.attempts.retain(|&t| now.duration_since(t) < window);
                !bucket.attempts.is_empty()
            });
            while map.len() >= MAX_THROTTLE_ENTRIES {
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, b)| b.last_attempt)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }
    }

    fn is_throttled(&mut self, client_ip: &str, token_hash: &str, now: Instant) -> bool {
        let share_key = format!("{client_ip}|{token_hash}");
        if let Some(bucket) = self.share_ip_buckets.get_mut(&share_key) {
            bucket
                .attempts
                .retain(|&t| now.duration_since(t) < THROTTLE_WINDOW);
            if bucket.attempts.len() >= MAX_FAILED_UNLOCKS_PER_SHARE_IP {
                return true;
            }
        }
        if let Some(bucket) = self.ip_buckets.get_mut(client_ip) {
            bucket
                .attempts
                .retain(|&t| now.duration_since(t) < THROTTLE_WINDOW);
            if bucket.attempts.len() >= MAX_FAILED_UNLOCKS_PER_IP {
                return true;
            }
        }
        false
    }

    fn record_failure(&mut self, client_ip: &str, token_hash: &str, now: Instant) {
        let share_key = format!("{client_ip}|{token_hash}");
        if !self.share_ip_buckets.contains_key(&share_key) {
            Self::prune_and_cap(&mut self.share_ip_buckets, now, THROTTLE_WINDOW);
        }
        let share_bucket =
            self.share_ip_buckets
                .entry(share_key)
                .or_insert_with(|| ThrottleBucket {
                    attempts: Vec::new(),
                    last_attempt: now,
                });
        share_bucket
            .attempts
            .retain(|&t| now.duration_since(t) < THROTTLE_WINDOW);
        share_bucket.attempts.push(now);
        share_bucket.last_attempt = now;

        if !self.ip_buckets.contains_key(client_ip) {
            Self::prune_and_cap(&mut self.ip_buckets, now, THROTTLE_WINDOW);
        }
        let ip_bucket = self
            .ip_buckets
            .entry(client_ip.to_string())
            .or_insert_with(|| ThrottleBucket {
                attempts: Vec::new(),
                last_attempt: now,
            });
        ip_bucket
            .attempts
            .retain(|&t| now.duration_since(t) < THROTTLE_WINDOW);
        ip_bucket.attempts.push(now);
        ip_bucket.last_attempt = now;
    }

    fn clear_share_ip(&mut self, client_ip: &str, token_hash: &str) {
        let share_key = format!("{client_ip}|{token_hash}");
        self.share_ip_buckets.remove(&share_key);
    }
}

static UNLOCK_THROTTLE: Lazy<Mutex<BoundedUnlockThrottle>> =
    Lazy::new(|| Mutex::new(BoundedUnlockThrottle::default()));

#[derive(Debug, Clone)]
struct UnlockSessionEntry {
    share_id: String,
    token_hash: String,
    pw_digest: String,
    expires_at_unix: i64,
    created_instant: Instant,
}

static UNLOCK_SESSIONS: Lazy<Mutex<HashMap<String, UnlockSessionEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures & Wire Contract
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub path: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub allow_download: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareRecord {
    pub id: String,
    pub path: String,
    pub name: String,
    pub is_directory: bool,
    pub password_required: bool,
    pub expires_at: Option<String>,
    pub allow_download: bool,
    pub created_at: String,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListSharesResponse {
    pub shares: Vec<ShareRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateShareResponse {
    pub share: ShareRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicShareMetadataResponse {
    pub name: String,
    pub is_directory: bool,
    pub password_required: bool,
    pub allow_download: bool,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UnlockShareRequest {
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockShareResponse {
    pub success: bool,
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize, Default)]
pub struct PublicPathQuery {
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicEntriesResponse {
    pub path: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredShareRow {
    pub id: String,
    pub token_hash: String,
    pub owner_user_id: i64,
    pub owner_scope: String,
    pub scope_root_dev: u64,
    pub scope_root_ino: u64,
    pub target_path: String,
    pub target_name: String,
    pub is_directory: bool,
    pub target_dev: u64,
    pub target_ino: u64,
    pub password_hash: Option<String>,
    pub allow_download: bool,
    pub expires_at: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub revoked: bool,
    pub created_at: String,
    #[allow(dead_code)]
    pub created_at_unix: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Routers
// ─────────────────────────────────────────────────────────────────────────────

pub fn router() -> Router {
    router_with_runtime(ShareRuntime::Production)
}

pub fn public_router() -> Router {
    public_router_with_runtime(ShareRuntime::Production)
}

pub(crate) fn router_with_runtime(runtime: ShareRuntime) -> Router {
    Router::new()
        .route("/mcbrowser/shares", get(list_shares).post(create_share))
        .route("/mcbrowser/shares/:id", delete(delete_share))
        .with_state(runtime)
}

pub(crate) fn public_router_with_runtime(runtime: ShareRuntime) -> Router {
    Router::new()
        .route("/mcbrowser/shares/:token", get(get_public_share_metadata))
        .route("/mcbrowser/shares/:token/unlock", post(unlock_public_share))
        .route(
            "/mcbrowser/shares/:token/entries",
            get(list_public_share_entries),
        )
        .route(
            "/mcbrowser/shares/:token/download",
            get(download_public_share_entry),
        )
        .with_state(runtime)
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Initialization
// ─────────────────────────────────────────────────────────────────────────────

pub fn ensure_shares_schema(conn: &Connection) -> Result<(), McBrowserError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mcbrowser_shares (
            id TEXT PRIMARY KEY,
            token_hash TEXT UNIQUE NOT NULL,
            owner_user_id INTEGER NOT NULL,
            owner_scope TEXT NOT NULL DEFAULT '',
            scope_root_dev INTEGER NOT NULL DEFAULT 0,
            scope_root_ino INTEGER NOT NULL DEFAULT 0,
            target_path TEXT NOT NULL,
            target_name TEXT NOT NULL,
            is_directory BOOLEAN NOT NULL DEFAULT 0,
            target_dev INTEGER NOT NULL DEFAULT 0,
            target_ino INTEGER NOT NULL DEFAULT 0,
            password_hash TEXT DEFAULT NULL,
            allow_download BOOLEAN NOT NULL DEFAULT 1,
            expires_at TEXT DEFAULT NULL,
            expires_at_unix INTEGER DEFAULT NULL,
            revoked BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_shares_owner
            ON mcbrowser_shares(owner_user_id, revoked);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_shares_token_hash
            ON mcbrowser_shares(token_hash);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_shares_expires
            ON mcbrowser_shares(expires_at_unix);
        "#,
    )
    .map_err(|_| {
        McBrowserError::Internal("Failed to initialize McBrowser shares schema".to_string())
    })?;

    let _ = conn.execute(
        "ALTER TABLE mcbrowser_shares ADD COLUMN owner_scope TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_shares ADD COLUMN scope_root_dev INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE mcbrowser_shares ADD COLUMN scope_root_ino INTEGER NOT NULL DEFAULT 0",
        [],
    );

    super::events::ensure_events_tables(conn)?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic & Constant-Time Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Constant-time byte comparison that never short-circuits on content mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_diff = a.len() ^ b.len();
    let max_len = a.len().max(b.len());
    let mut diff: u8 = 0;
    for i in 0..max_len {
        let byte_a = if i < a.len() {
            std::hint::black_box(a[i])
        } else {
            0
        };
        let byte_b = if i < b.len() {
            std::hint::black_box(b[i])
        } else {
            0
        };
        diff |= byte_a ^ byte_b;
    }
    std::hint::black_box(len_diff) == 0 && std::hint::black_box(diff) == 0
}

pub fn generate_raw_share_token() -> String {
    let mut bytes = [0u8; SHARE_TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_share_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-mcbrowser-share-token-v1:");
    hasher.update(raw_token.as_bytes());
    hex::encode(hasher.finalize())
}

fn prehash_share_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-mcbrowser-share-password-v1:");
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_share_password(password: &str) -> Result<String, McBrowserError> {
    if password.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Share password cannot be empty".to_string(),
        ));
    }
    if password.len() > MAX_SHARE_PASSWORD_BYTES || password.as_bytes().contains(&0) {
        return Err(McBrowserError::BadRequest(
            "Share password exceeds maximum length or contains invalid characters".to_string(),
        ));
    }
    let prehashed = prehash_share_password(password);
    bcrypt::hash(&prehashed, BCRYPT_SHARE_COST)
        .map_err(|_| McBrowserError::Internal("Failed to hash share password".to_string()))
}

pub fn verify_share_password_constant_time(password: &str, stored_hash: &str) -> bool {
    if password.is_empty()
        || password.len() > MAX_SHARE_PASSWORD_BYTES
        || password.as_bytes().contains(&0)
        || stored_hash.is_empty()
    {
        // Perform dummy work to avoid fast-return timing side-channels
        let dummy_pre = prehash_share_password("dummy-invalid-password");
        let _ = std::hint::black_box(constant_time_eq(
            dummy_pre.as_bytes(),
            stored_hash.as_bytes(),
        ));
        return false;
    }
    let prehashed = prehash_share_password(password);
    bcrypt::verify(&prehashed, stored_hash).unwrap_or(false)
}

fn share_cookie_name(token_hash: &str) -> String {
    let prefix = &token_hash[..token_hash.len().min(16)];
    format!("mcbrowser_share_{prefix}")
}

fn password_hash_digest(password_hash: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-share-pw-digest-v1:");
    hasher.update(password_hash.unwrap_or("").as_bytes());
    hex::encode(hasher.finalize())
}

fn mint_scoped_unlock_token(share: &StoredShareRow, now_unix: i64) -> (String, i64) {
    let max_exp = now_unix.saturating_add(UNLOCK_TOKEN_TTL_SECS);
    let exp_unix = match share.expires_at_unix {
        Some(share_exp) => max_exp.min(share_exp),
        None => max_exp,
    };
    let ttl_secs = (exp_unix - now_unix).max(1);

    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let pw_digest = password_hash_digest(share.password_hash.as_deref());

    let mut mac = HmacSha256::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts keys of any byte length");
    mac.update(b"af-mcbrowser-share-unlock-v1|");
    mac.update(share.id.as_bytes());
    mac.update(b"|");
    mac.update(share.token_hash.as_bytes());
    mac.update(b"|");
    mac.update(pw_digest.as_bytes());
    mac.update(b"|");
    mac.update(exp_unix.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let raw_payload = format!("v1.{}.{exp_unix}.{nonce}.{sig}", share.id);
    let opaque_token = URL_SAFE_NO_PAD.encode(raw_payload.as_bytes());

    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        if map.len() >= MAX_UNLOCK_SESSIONS {
            map.retain(|_, v| v.expires_at_unix > now_unix);
            while map.len() >= MAX_UNLOCK_SESSIONS {
                if let Some(oldest_k) = map
                    .iter()
                    .min_by_key(|(_, v)| v.created_instant)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_k);
                } else {
                    break;
                }
            }
        }
        map.insert(
            opaque_token.clone(),
            UnlockSessionEntry {
                share_id: share.id.clone(),
                token_hash: share.token_hash.clone(),
                pw_digest,
                expires_at_unix: exp_unix,
                created_instant: Instant::now(),
            },
        );
    }

    (opaque_token, ttl_secs)
}

fn verify_scoped_unlock_token(
    candidate_token: &str,
    share: &StoredShareRow,
    now_unix: i64,
) -> bool {
    let trimmed = candidate_token.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 {
        return false;
    }

    let Ok(decoded_bytes) = URL_SAFE_NO_PAD.decode(trimmed) else {
        return false;
    };
    let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) else {
        return false;
    };
    let parts: Vec<&str> = decoded_str.split('.').collect();
    if parts.len() != 5 || parts[0] != "v1" {
        return false;
    }
    let token_share_id = parts[1];
    let Ok(exp_unix) = parts[2].parse::<i64>() else {
        return false;
    };
    let nonce = parts[3];
    let provided_sig = parts[4];

    if exp_unix <= now_unix {
        return false;
    }
    if !constant_time_eq(token_share_id.as_bytes(), share.id.as_bytes()) {
        return false;
    }

    let pw_digest = password_hash_digest(share.password_hash.as_deref());
    let mut mac = HmacSha256::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts keys of any byte length");
    mac.update(b"af-mcbrowser-share-unlock-v1|");
    mac.update(share.id.as_bytes());
    mac.update(b"|");
    mac.update(share.token_hash.as_bytes());
    mac.update(b"|");
    mac.update(pw_digest.as_bytes());
    mac.update(b"|");
    mac.update(exp_unix.to_string().as_bytes());
    mac.update(b"|");
    mac.update(nonce.as_bytes());
    let expected_sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    if !constant_time_eq(provided_sig.as_bytes(), expected_sig.as_bytes()) {
        return false;
    }

    // Also verify against the in-memory session store if present
    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        if let Some(entry) = map.get(trimmed) {
            if entry.expires_at_unix <= now_unix
                || !constant_time_eq(entry.share_id.as_bytes(), share.id.as_bytes())
                || !constant_time_eq(entry.token_hash.as_bytes(), share.token_hash.as_bytes())
                || !constant_time_eq(entry.pw_digest.as_bytes(), pw_digest.as_bytes())
            {
                map.remove(trimmed);
                return false;
            }
        }
    }

    true
}

fn revoke_unlock_sessions_for_share(share_id: &str) {
    if let Ok(mut map) = UNLOCK_SESSIONS.lock() {
        map.retain(|_, v| v.share_id != share_id);
    }
}

fn extract_unlock_credential(headers: &HeaderMap, share: &StoredShareRow) -> Option<String> {
    if let Some(hv) = headers.get("X-McBrowser-Share-Token") {
        if let Ok(s) = hv.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    let scoped_cookie = share_cookie_name(&share.token_hash);
    if let Some(val) = extract_cookie(headers, &scoped_cookie) {
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    if let Some(val) = extract_cookie(headers, "mcbrowser_share_token") {
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    None
}

fn build_scoped_share_cookie(token_hash: &str, access_token: &str, max_age: i64) -> String {
    let name = share_cookie_name(token_hash);
    let mut parts = vec![
        format!("{name}={access_token}"),
        "Path=/".to_string(),
        format!("Max-Age={max_age}"),
        "SameSite=Lax".to_string(),
    ];
    if secure_cookie_enabled() {
        parts.push("Secure".to_string());
    }
    parts.push("HttpOnly".to_string());
    parts.join("; ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-Level Safe Filesystem & Inode Verification Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetStatInfo {
    is_directory: bool,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_rfc3339: Option<i64>,
}

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
    let err = Error::last_os_error();
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
        return Err(Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat_fd(fd: libc::c_int) -> io::Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(st)
}

struct VerifiedScopedUserRoot {
    bfs: BrowserFs,
    root_fd: OwnedFd,
    scope: String,
    scope_dev: u64,
    scope_ino: u64,
}

/// Opens the owner's configured scoped tenant root via the production runtime using the same
/// SQLite `Connection` for `super::policy::effective_scope_with_conn` and descriptor-confined
/// scoped root traversal.
#[allow(dead_code)]
pub fn open_configured_share_tenant_root(user_id: i64) -> Result<BrowserFs, McBrowserError> {
    ShareRuntime::Production.with_conn_and_root(|conn, base_root, _policy| {
        Ok(open_verified_user_root_fd(conn, base_root, user_id)?.bfs)
    })
}

/// Opens the owner's configured scoped tenant root directory as both a `BrowserFs` and an
/// `OwnedFd` using the active `Connection` (`super::policy::effective_scope_with_conn`) and
/// descriptor-confined traversal (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`),
/// never string canonicalization.
fn open_verified_user_root_fd(
    conn: &Connection,
    base_root: &Path,
    user_id: i64,
) -> Result<VerifiedScopedUserRoot, McBrowserError> {
    let raw_scope = super::policy::effective_scope_with_conn(conn, user_id)?;
    let normalized_scope = super::policy::normalize_scope_path(&raw_scope)?;

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

    let dup_raw = unsafe { libc::fcntl(current_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_raw < 0 {
        return Err(McBrowserError::Internal(
            "Failed to duplicate scoped user root descriptor".to_string(),
        ));
    }
    let dup_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
    let scoped_bfs = BrowserFs::from_directory(dup_fd).map_err(|_| {
        McBrowserError::Internal("Failed to initialize scoped user filesystem".to_string())
    })?;

    Ok(VerifiedScopedUserRoot {
        bfs: scoped_bfs,
        root_fd: current_fd,
        scope: normalized_scope,
        scope_dev: scope_st.st_dev as u64,
        scope_ino: scope_st.st_ino as u64,
    })
}

/// Ensures an existing share remains bound to the exact policy scope and scoped-root
/// directory inode `(scope_root_dev, scope_root_ino)` under which it was created.
fn verify_share_scope_matches(
    share: &StoredShareRow,
    scoped_root: &VerifiedScopedUserRoot,
) -> Result<(), McBrowserError> {
    if share.owner_scope != scoped_root.scope {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    if (share.scope_root_dev != 0 || share.scope_root_ino != 0)
        && (share.scope_root_dev != scoped_root.scope_dev
            || share.scope_root_ino != scoped_root.scope_ino)
    {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    Ok(())
}

fn authorize_share_resolution(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    requested_path: &str,
    resolution_paths: &[String],
    resolved_path: &str,
    require_download: bool,
) -> Result<Vec<String>, McBrowserError> {
    let mut paths = Vec::new();
    for path in std::iter::once(requested_path)
        .chain(resolution_paths.iter().map(String::as_str))
        .chain(std::iter::once(resolved_path))
    {
        if paths.iter().any(|existing| existing == path) {
            continue;
        }
        policy(conn, owner_user, super::policy::Permission::Share, path)?;
        policy(conn, owner_user, super::policy::Permission::Read, path)?;
        if require_download {
            policy(conn, owner_user, super::policy::Permission::Download, path)?;
        }
        paths.push(path.to_string());
    }
    Ok(paths)
}

fn authorize_shared_relative_resolution(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    root_paths: &[String],
    requested_path: &str,
    resolution_paths: &[String],
    resolved_path: &str,
    require_download: bool,
) -> Result<(), McBrowserError> {
    for root in root_paths {
        for relative in std::iter::once(requested_path)
            .chain(resolution_paths.iter().map(String::as_str))
            .chain(std::iter::once(resolved_path))
        {
            authorize_owner_share_subpath(
                conn,
                policy,
                owner_user,
                root,
                relative,
                require_download,
            )?;
        }
    }
    Ok(())
}

fn inspect_share_target(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    normalized_path: &str,
    require_download: bool,
) -> Result<(TargetStatInfo, String), McBrowserError> {
    let resolved = owner_bfs
        .metadata_resolving_internal_links(normalized_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect share target"))?;
    authorize_share_resolution(
        conn,
        policy,
        owner_user,
        normalized_path,
        &resolved.resolution_paths,
        &resolved.resolved_path,
        require_download,
    )?;
    let is_directory = resolved.entry.kind == "directory";
    let metadata = if is_directory {
        let opened = owner_bfs
            .scoped_resolving_internal_links(normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share directory"))?;
        authorize_share_resolution(
            conn,
            policy,
            owner_user,
            normalized_path,
            &opened.resolution_paths,
            &opened.resolved_path,
            require_download,
        )?;
        opened.fs.directory_metadata()
    } else {
        let opened = owner_bfs
            .open_file_resolving_internal_links(normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share file"))?;
        authorize_share_resolution(
            conn,
            policy,
            owner_user,
            normalized_path,
            &opened.resolution_paths,
            &opened.resolved_path,
            require_download,
        )?;
        opened.file.metadata()
    };
    let metadata =
        metadata.map_err(|error| map_fs_io_error(error, "Failed to stat share target"))?;
    let leaf_name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or(normalized_path)
        .to_string();

    Ok((
        TargetStatInfo {
            is_directory,
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: if is_directory { 0 } else { metadata.len() },
            mtime_rfc3339: Some(metadata.mtime()),
        },
        leaf_name,
    ))
}

fn open_verified_shared_directory_fs(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    share: &StoredShareRow,
    require_download: bool,
) -> Result<(BrowserFs, Vec<String>), McBrowserError> {
    if !share.is_directory {
        return Err(McBrowserError::BadRequest(
            "Share is not a directory".to_string(),
        ));
    }
    let opened = owner_bfs
        .scoped_resolving_internal_links(&share.target_path)
        .map_err(|_| {
            McBrowserError::NotFound("Shared directory is no longer available".to_string())
        })?;
    let paths = authorize_share_resolution(
        conn,
        policy,
        owner_user,
        &share.target_path,
        &opened.resolution_paths,
        &opened.resolved_path,
        require_download,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    let metadata = opened.fs.directory_metadata().map_err(|_| {
        McBrowserError::NotFound("Shared directory is no longer available".to_string())
    })?;
    if !metadata.is_dir()
        || metadata.dev() != share.target_dev
        || metadata.ino() != share.target_ino
    {
        return Err(McBrowserError::NotFound(
            "Shared directory was moved or replaced".to_string(),
        ));
    }

    Ok((opened.fs, paths))
}

fn open_verified_shared_single_file(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    owner_bfs: &BrowserFs,
    share: &StoredShareRow,
    require_download: bool,
) -> Result<(File, Entry), McBrowserError> {
    if share.is_directory {
        return Err(McBrowserError::BadRequest(
            "Share is a directory, not a single file".to_string(),
        ));
    }
    let opened = owner_bfs
        .open_file_resolving_internal_links(&share.target_path)
        .map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => {
                McBrowserError::Forbidden("Shared file is not permitted".to_string())
            }
            _ => McBrowserError::NotFound("Shared file is no longer available".to_string()),
        })?;
    authorize_share_resolution(
        conn,
        policy,
        owner_user,
        &share.target_path,
        &opened.resolution_paths,
        &opened.resolved_path,
        require_download,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    let file = opened.file;
    let st = fstat_fd(file.as_raw_fd())
        .map_err(|_| McBrowserError::NotFound("Shared file is no longer available".to_string()))?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (st.st_dev as u64) != share.target_dev
        || (st.st_ino as u64) != share.target_ino
    {
        return Err(McBrowserError::NotFound(
            "Shared file was moved or replaced".to_string(),
        ));
    }
    if st.st_nlink > 1 {
        return Err(McBrowserError::Forbidden(
            "Hardlinked files are not permitted".to_string(),
        ));
    }
    let modified = chrono::Utc
        .timestamp_opt(st.st_mtime, u32::try_from(st.st_mtime_nsec).unwrap_or(0))
        .single()
        .map(|dt| dt.to_rfc3339());
    let entry = Entry {
        name: share.target_name.clone(),
        path: share.target_name.clone(),
        kind: "file".to_string(),
        size: st.st_size.max(0) as u64,
        modified,
    };
    Ok((file, entry))
}

/// Checks if a relative file beneath `share_dir_fd` is a single-link regular file (`st_nlink == 1`).
// ─────────────────────────────────────────────────────────────────────────────
// Database & Owner Re-Evaluation Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn row_to_stored_share(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredShareRow> {
    let scope_dev_i64: i64 = r.get(4)?;
    let scope_ino_i64: i64 = r.get(5)?;
    let dev_i64: i64 = r.get(9)?;
    let ino_i64: i64 = r.get(10)?;
    Ok(StoredShareRow {
        id: r.get(0)?,
        token_hash: r.get(1)?,
        owner_user_id: r.get(2)?,
        owner_scope: r.get(3)?,
        scope_root_dev: scope_dev_i64 as u64,
        scope_root_ino: scope_ino_i64 as u64,
        target_path: r.get(6)?,
        target_name: r.get(7)?,
        is_directory: r.get(8)?,
        target_dev: dev_i64 as u64,
        target_ino: ino_i64 as u64,
        password_hash: r.get(11)?,
        allow_download: r.get(12)?,
        expires_at: r.get(13)?,
        expires_at_unix: r.get(14)?,
        revoked: r.get(15)?,
        created_at: r.get(16)?,
        created_at_unix: r.get(17)?,
    })
}

fn stored_to_share_record(row: &StoredShareRow, raw_token: Option<&str>) -> ShareRecord {
    ShareRecord {
        id: row.id.clone(),
        path: row.target_path.clone(),
        name: row.target_name.clone(),
        is_directory: row.is_directory,
        password_required: row.password_hash.is_some(),
        expires_at: row.expires_at.clone(),
        allow_download: row.allow_download,
        created_at: row.created_at.clone(),
        url: raw_token.map(|t| format!("/share?token={t}")),
    }
}

fn is_share_expired(row: &StoredShareRow, now: DateTime<Utc>) -> bool {
    if let Some(exp_unix) = row.expires_at_unix {
        if now.timestamp() >= exp_unix {
            return true;
        }
    }
    if let Some(ref raw_exp) = row.expires_at {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(raw_exp) {
            if now >= parsed.with_timezone(&Utc) {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

fn load_active_share_by_token(
    conn: &Connection,
    raw_token: &str,
    now: DateTime<Utc>,
) -> Result<StoredShareRow, McBrowserError> {
    let trimmed = raw_token.trim();
    if trimmed.len() < 16 || trimmed.len() > 256 || trimmed.chars().any(|c| c.is_control()) {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    }
    let token_hash = hash_share_token(trimmed);
    let row: Option<StoredShareRow> = conn
        .query_row(
            "SELECT id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
                    target_path, target_name, is_directory, target_dev, target_ino, \
                    password_hash, allow_download, expires_at, expires_at_unix, revoked, \
                    created_at, created_at_unix \
             FROM mcbrowser_shares \
             WHERE token_hash = ?1",
            params![token_hash],
            row_to_stored_share,
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to look up share".to_string()))?;

    let Some(share) = row else {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    };

    if share.revoked || is_share_expired(&share, now) {
        return Err(McBrowserError::NotFound(
            "Share not found or has expired".to_string(),
        ));
    }

    Ok(share)
}

/// Loads the share owner's current `AuthUser` identity and verifies that their account still
/// exists, is not a plugin identity, and has an active storage quota status.
fn load_and_verify_active_owner(
    conn: &Connection,
    owner_user_id: i64,
) -> Result<AuthUser, McBrowserError> {
    if owner_user_id <= 0 {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }
    let user_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![owner_user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify share owner".to_string()))?;

    let Some((username, role)) = user_row else {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    };

    let owner_user = AuthUser {
        user_id: owner_user_id,
        username,
        role,
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    if validate_mcbrowser_user(&owner_user).is_err() {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }

    if load_active_quota_conn(conn, owner_user_id, 0).is_err() {
        return Err(McBrowserError::NotFound(
            "Share is no longer available".to_string(),
        ));
    }

    Ok(owner_user)
}

/// Verifies owner policy (`Permission::Share` and `Permission::Read`, plus `Permission::Download`
/// when `require_download` is true) on the share root and every descendant component down to
/// `rel_sub_path`.
fn authorize_owner_share_subpath(
    conn: &Connection,
    policy: &PolicyAuthorizer,
    owner_user: &AuthUser,
    share_root_path: &str,
    rel_sub_path: &str,
    require_download: bool,
) -> Result<String, McBrowserError> {
    policy(
        conn,
        owner_user,
        super::policy::Permission::Share,
        share_root_path,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    policy(
        conn,
        owner_user,
        super::policy::Permission::Read,
        share_root_path,
    )
    .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;

    if require_download {
        policy(
            conn,
            owner_user,
            super::policy::Permission::Download,
            share_root_path,
        )
        .map_err(|_| {
            McBrowserError::Forbidden("Download of requested path is not permitted".to_string())
        })?;
    }

    if rel_sub_path.is_empty() {
        return Ok(share_root_path.to_string());
    }

    let mut current = share_root_path.to_string();
    for seg in rel_sub_path.split('/').filter(|s| !s.is_empty()) {
        current = if current.is_empty() {
            seg.to_string()
        } else {
            format!("{current}/{seg}")
        };
        policy(conn, owner_user, super::policy::Permission::Share, &current).map_err(|_| {
            McBrowserError::Forbidden("Access to requested path is not permitted".to_string())
        })?;
        policy(conn, owner_user, super::policy::Permission::Read, &current).map_err(|_| {
            McBrowserError::Forbidden("Access to requested path is not permitted".to_string())
        })?;
        if require_download {
            policy(
                conn,
                owner_user,
                super::policy::Permission::Download,
                &current,
            )
            .map_err(|_| {
                McBrowserError::Forbidden("Download of requested path is not permitted".to_string())
            })?;
        }
    }

    Ok(current)
}

/// Rejects any query string that includes `password`, `access_token`, or `share_token` so
/// secret credentials are never transmitted in URLs.
pub fn reject_secret_query_params(raw_query: Option<&str>) -> Result<(), McBrowserError> {
    let Some(q) = raw_query else {
        return Ok(());
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case("password")
            || key.eq_ignore_ascii_case("access_token")
            || key.eq_ignore_ascii_case("share_token")
        {
            return Err(McBrowserError::BadRequest(
                "Passing share passwords or unlock tokens in URL query parameters is not permitted"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Maps internal `McBrowserError` into a sanitized public HTTP response that never leaks
/// owner account states, usernames, or private paths.
fn public_share_error_response(err: McBrowserError) -> Response {
    match err {
        McBrowserError::BadRequest(msg) => api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
        McBrowserError::Unauthorized(msg) => {
            api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg)
        }
        McBrowserError::Forbidden(msg) => api_error(StatusCode::FORBIDDEN, "FORBIDDEN", msg),
        McBrowserError::NotFound(msg) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", msg),
        McBrowserError::RangeNotSatisfiable(total) => {
            McBrowserError::RangeNotSatisfiable(total).into_response()
        }
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to process public share request",
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Business Logic (`_at` functions for both Production and Isolated Tests)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn create_share_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    auth_user: &AuthUser,
    req: CreateShareRequest,
) -> Result<(ShareRecord, String), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let normalized_path = normalize_relative_path(&req.path, false)?;
    let allow_download = req.allow_download.unwrap_or(true);

    // Verify policy permissions on the requested path
    policy(
        conn,
        auth_user,
        super::policy::Permission::Share,
        &normalized_path,
    )?;
    policy(
        conn,
        auth_user,
        super::policy::Permission::Read,
        &normalized_path,
    )?;
    if allow_download {
        policy(
            conn,
            auth_user,
            super::policy::Permission::Download,
            &normalized_path,
        )?;
    }

    // Verify active user & quota state
    load_active_quota_conn(conn, user_id, 0)?;

    // Validate optional expiration timestamp
    let now = Utc::now();
    let (expires_at_rfc3339, expires_at_unix) = match req
        .expires_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_exp) => {
            let parsed = DateTime::parse_from_rfc3339(raw_exp).map_err(|_| {
                McBrowserError::BadRequest(
                    "Invalid expires_at: must be a valid RFC3339 timestamp".to_string(),
                )
            })?;
            let exp_utc = parsed.with_timezone(&Utc);
            if exp_utc <= now {
                return Err(McBrowserError::BadRequest(
                    "Share expiration timestamp must be in the future".to_string(),
                ));
            }
            (Some(exp_utc.to_rfc3339()), Some(exp_utc.timestamp()))
        }
        None => (None, None),
    };

    // Validate & hash optional password
    let password_hash = match req.password.as_deref().filter(|s| !s.is_empty()) {
        Some(pw) => Some(hash_share_password(pw)?),
        None => None,
    };

    // Inspect target on owner's scoped filesystem (rejecting missing targets, symlinks, hardlinks, special files)
    let scoped_root = open_verified_user_root_fd(conn, base_root, user_id)?;
    let (stat_info, leaf_name) = inspect_share_target(
        conn,
        policy,
        auth_user,
        &scoped_root.bfs,
        &normalized_path,
        allow_download,
    )?;

    if stat_info.is_directory {
        let shared = scoped_root
            .bfs
            .scoped_resolving_internal_links(&normalized_path)
            .map_err(|error| map_fs_io_error(error, "Failed to open share directory"))?;
        let roots = authorize_share_resolution(
            conn,
            policy,
            auth_user,
            &normalized_path,
            &shared.resolution_paths,
            &shared.resolved_path,
            allow_download,
        )?;
        let descendants = shared
            .fs
            .walk("", 10_000)
            .map_err(|e| map_fs_io_error(e, "Failed to inspect directory descendants for share"))?;
        for descendant in &descendants {
            for root in &roots {
                let owner_path = if root.is_empty() {
                    descendant.path.clone()
                } else {
                    format!("{root}/{}", descendant.path)
                };
                authorize_share_resolution(
                    conn,
                    policy,
                    auth_user,
                    &owner_path,
                    &[],
                    &owner_path,
                    allow_download,
                )?;
            }
        }
    }

    let share_id = Uuid::new_v4().to_string();
    let raw_token = generate_raw_share_token();
    let token_hash = hash_share_token(&raw_token);
    let created_at_rfc3339 = now.to_rfc3339();
    let created_at_unix = now.timestamp();

    super::events::ensure_events_tables(conn)?;
    let pending = super::events::record_pending_intent_with_conn(
        conn,
        auth_user,
        super::events::McBrowserEventTrigger::ShareCreated,
        &normalized_path,
        None,
        0,
    )?;

    conn.execute_batch("SAVEPOINT mcbrowser_share_create")
        .map_err(|_| {
            let _ = super::events::finalize_event_failed_with_conn(
                conn,
                &pending.event.event_id,
                Some("INTERNAL_ERROR"),
            );
            McBrowserError::Internal("Failed to begin share creation transaction".to_string())
        })?;

    let publish_res = (|| -> Result<(), McBrowserError> {
        conn.execute(
            "INSERT INTO mcbrowser_shares \
             (id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
              target_path, target_name, is_directory, target_dev, target_ino, \
              password_hash, allow_download, expires_at, expires_at_unix, revoked, \
              created_at, created_at_unix) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0, ?16, ?17)",
            params![
                &share_id,
                &token_hash,
                user_id,
                &scoped_root.scope,
                scoped_root.scope_dev as i64,
                scoped_root.scope_ino as i64,
                &normalized_path,
                &leaf_name,
                stat_info.is_directory,
                stat_info.dev as i64,
                stat_info.ino as i64,
                &password_hash,
                allow_download,
                &expires_at_rfc3339,
                expires_at_unix,
                &created_at_rfc3339,
                created_at_unix,
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist share record".to_string()))?;

        super::events::finalize_event_completed_with_conn(
            conn,
            &pending.event.event_id,
            None,
            None,
            0,
        )?;

        conn.execute_batch("RELEASE mcbrowser_share_create")
            .map_err(|_| McBrowserError::Internal("Failed to commit share creation".to_string()))?;
        Ok(())
    })();

    if let Err(err) = publish_res {
        let _ = conn
            .execute_batch("ROLLBACK TO mcbrowser_share_create; RELEASE mcbrowser_share_create");
        let _ = super::events::finalize_event_failed_with_conn(
            conn,
            &pending.event.event_id,
            Some(share_audit_error_code(&err)),
        );
        return Err(err);
    }

    let record = ShareRecord {
        id: share_id,
        path: normalized_path,
        name: leaf_name,
        is_directory: stat_info.is_directory,
        password_required: password_hash.is_some(),
        expires_at: expires_at_rfc3339,
        allow_download,
        created_at: created_at_rfc3339,
        url: Some(format!("/share?token={raw_token}")),
    };

    Ok((record, raw_token))
}

fn share_audit_error_code(err: &McBrowserError) -> &'static str {
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

pub(crate) fn list_shares_at(
    conn: &Connection,
    auth_user: &AuthUser,
) -> Result<Vec<ShareRecord>, McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    load_active_quota_conn(conn, user_id, 0)?;
    let raw_scope = super::policy::effective_scope_with_conn(conn, user_id)?;
    let current_scope = super::policy::normalize_scope_path(&raw_scope)?;

    let now = Utc::now();
    let mut stmt = conn
        .prepare(
            "SELECT id, token_hash, owner_user_id, owner_scope, scope_root_dev, scope_root_ino, \
                    target_path, target_name, is_directory, target_dev, target_ino, \
                    password_hash, allow_download, expires_at, expires_at_unix, revoked, \
                    created_at, created_at_unix \
             FROM mcbrowser_shares \
             WHERE owner_user_id = ?1 AND revoked = 0 \
             ORDER BY created_at_unix DESC, id DESC",
        )
        .map_err(|_| McBrowserError::Internal("Failed to query shares".to_string()))?;

    let rows: Vec<StoredShareRow> = stmt
        .query_map(params![user_id], row_to_stored_share)
        .map_err(|_| McBrowserError::Internal("Failed to read shares".to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| McBrowserError::Internal("Failed to decode share row".to_string()))?;

    let shares = rows
        .into_iter()
        .filter(|row| !is_share_expired(row, now) && row.owner_scope == current_scope)
        .map(|row| stored_to_share_record(&row, None))
        .collect();

    Ok(shares)
}

pub(crate) fn delete_share_at(
    conn: &Connection,
    auth_user: &AuthUser,
    share_id: &str,
) -> Result<(), McBrowserError> {
    let user_id = validate_mcbrowser_user(auth_user)?;
    let clean_id = share_id.trim();
    if clean_id.is_empty() || clean_id.len() > 128 {
        return Err(McBrowserError::NotFound("Share not found".to_string()));
    }

    super::events::ensure_events_tables(conn)?;
    let target_path: Option<String> = conn
        .query_row(
            "SELECT target_path FROM mcbrowser_shares WHERE id = ?1 AND owner_user_id = ?2 AND revoked = 0",
            params![clean_id, user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to query share for revocation".to_string()))?;

    let Some(target_path) = target_path else {
        return Err(McBrowserError::NotFound("Share not found".to_string()));
    };

    let pending = super::events::record_pending_intent_with_conn(
        conn,
        auth_user,
        super::events::McBrowserEventTrigger::ShareRevoked,
        &target_path,
        None,
        0,
    )?;

    conn.execute_batch("SAVEPOINT mcbrowser_share_revoke")
        .map_err(|_| {
            let _ = super::events::finalize_event_failed_with_conn(
                conn,
                &pending.event.event_id,
                Some("INTERNAL_ERROR"),
            );
            McBrowserError::Internal("Failed to begin share revocation transaction".to_string())
        })?;

    let revoke_res = (|| -> Result<(), McBrowserError> {
        let updated = conn
            .execute(
                "UPDATE mcbrowser_shares SET revoked = 1 \
                 WHERE id = ?1 AND owner_user_id = ?2 AND revoked = 0",
                params![clean_id, user_id],
            )
            .map_err(|_| McBrowserError::Internal("Failed to revoke share".to_string()))?;

        if updated == 0 {
            return Err(McBrowserError::NotFound("Share not found".to_string()));
        }

        super::events::finalize_event_completed_with_conn(
            conn,
            &pending.event.event_id,
            None,
            None,
            0,
        )?;

        conn.execute_batch("RELEASE mcbrowser_share_revoke")
            .map_err(|_| {
                McBrowserError::Internal("Failed to commit share revocation".to_string())
            })?;
        Ok(())
    })();

    if let Err(err) = revoke_res {
        let _ = conn
            .execute_batch("ROLLBACK TO mcbrowser_share_revoke; RELEASE mcbrowser_share_revoke");
        let _ = super::events::finalize_event_failed_with_conn(
            conn,
            &pending.event.event_id,
            Some(share_audit_error_code(&err)),
        );
        return Err(err);
    }

    revoke_unlock_sessions_for_share(clean_id);
    Ok(())
}

pub(crate) fn get_public_metadata_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
) -> Result<PublicShareMetadataResponse, McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;

    // Open owner's configured scoped root and verify scope & scoped-root inode have not changed
    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    // Re-evaluate owner's Share & Read policy on the shared path
    authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)?;

    if share.is_directory {
        let _ = open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
    } else {
        let _ = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
    }

    Ok(PublicShareMetadataResponse {
        name: share.target_name,
        is_directory: share.is_directory,
        password_required: share.password_hash.is_some(),
        allow_download: share.allow_download,
        expires_at: share.expires_at,
    })
}

pub(crate) fn unlock_public_share_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    password: &str,
    client_ip: &str,
) -> Result<(StoredShareRow, String, i64), Response> {
    let now = Utc::now();
    let now_inst = Instant::now();

    // Check IP-level brute-force throttle even before token lookup so invalid tokens cannot bypass IP limits
    let trimmed_token = raw_token.trim();
    let candidate_hash = hash_share_token(trimmed_token);
    {
        let mut throttle = match UNLOCK_THROTTLE.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if throttle.is_throttled(client_ip, &candidate_hash, now_inst) {
            return Err(api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_REQUESTS",
                "Too many failed password attempts. Please try again later.",
            ));
        }
    }

    let share = match load_active_share_by_token(conn, trimmed_token, now) {
        Ok(s) => s,
        Err(e) => {
            if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
                throttle.record_failure(client_ip, &candidate_hash, now_inst);
            }
            return Err(public_share_error_response(e));
        }
    };

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)
        .map_err(public_share_error_response)?;

    let scoped_root =
        open_verified_user_root_fd(conn, base_root, share.owner_user_id).map_err(|_| {
            public_share_error_response(McBrowserError::NotFound(
                "Share is no longer available".to_string(),
            ))
        })?;
    verify_share_scope_matches(&share, &scoped_root).map_err(public_share_error_response)?;

    authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)
        .map_err(public_share_error_response)?;

    if share.is_directory {
        open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )
        .map_err(public_share_error_response)?;
    } else {
        open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )
        .map_err(public_share_error_response)?;
    }

    if let Some(ref stored_pw_hash) = share.password_hash {
        if !verify_share_password_constant_time(password, stored_pw_hash) {
            if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
                throttle.record_failure(client_ip, &share.token_hash, now_inst);
            }
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "SHARE_PASSWORD_INVALID",
                "Invalid share password",
            ));
        }
        if let Ok(mut throttle) = UNLOCK_THROTTLE.lock() {
            throttle.clear_share_ip(client_ip, &share.token_hash);
        }
    }

    let (access_token, ttl_secs) = mint_scoped_unlock_token(&share, now.timestamp());
    Ok((share, access_token, ttl_secs))
}

fn require_unlocked_if_password_protected(
    headers: &HeaderMap,
    share: &StoredShareRow,
    now_unix: i64,
) -> Result<(), McBrowserError> {
    if share.password_hash.is_none() {
        return Ok(());
    }
    let Some(cred) = extract_unlock_credential(headers, share) else {
        return Err(McBrowserError::Unauthorized(
            "Password authentication is required to access this share".to_string(),
        ));
    };
    if !verify_scoped_unlock_token(&cred, share, now_unix) {
        return Err(McBrowserError::Unauthorized(
            "Share access credential is invalid or has expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn list_public_entries_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    raw_sub_path: &str,
    headers: &HeaderMap,
) -> Result<PublicEntriesResponse, McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    require_unlocked_if_password_protected(headers, &share, now.timestamp())?;

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;
    let normalized_sub_path = normalize_relative_path(raw_sub_path, true)?;

    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    if !share.is_directory {
        // Single-file share: never expose parent directory or sibling files!
        if !normalized_sub_path.is_empty() {
            return Err(McBrowserError::BadRequest(
                "Single-file share does not support directory path traversal".to_string(),
            ));
        }
        authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", false)?;
        let (_file, entry) = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            false,
        )?;
        return Ok(PublicEntriesResponse {
            path: String::new(),
            entries: vec![entry],
        });
    }

    // Directory share: re-evaluate owner policy on share root and every segment down to `normalized_sub_path`
    authorize_owner_share_subpath(
        conn,
        policy,
        &owner_user,
        &share.target_path,
        &normalized_sub_path,
        false,
    )?;

    let (scoped_bfs, root_paths) = open_verified_shared_directory_fs(
        conn,
        policy,
        &owner_user,
        &scoped_root.bfs,
        &share,
        false,
    )?;
    let listing = scoped_bfs
        .list_with_trace_resolving_internal_links(&normalized_sub_path)
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => {
                McBrowserError::NotFound("Requested directory was not found".to_string())
            }
            ErrorKind::InvalidInput | ErrorKind::InvalidData => {
                McBrowserError::BadRequest("Invalid directory path".to_string())
            }
            ErrorKind::PermissionDenied => {
                McBrowserError::Forbidden("Access to directory is not permitted".to_string())
            }
            _ => map_fs_io_error(e, "Failed to list shared directory"),
        })?;
    authorize_shared_relative_resolution(
        conn,
        policy,
        &owner_user,
        &root_paths,
        &normalized_sub_path,
        &listing.resolution_paths,
        &listing.resolved_path,
        false,
    )?;

    let mut filtered_entries = Vec::with_capacity(listing.entries.len());
    for listed in listing.entries {
        let alias_path = if normalized_sub_path.is_empty() {
            listed.name.clone()
        } else {
            format!("{normalized_sub_path}/{}", listed.name)
        };
        let Ok(resolved) = scoped_bfs.metadata_resolving_internal_links(&alias_path) else {
            continue;
        };
        if authorize_shared_relative_resolution(
            conn,
            policy,
            &owner_user,
            &root_paths,
            &alias_path,
            &resolved.resolution_paths,
            &resolved.resolved_path,
            false,
        )
        .is_err()
        {
            continue;
        }
        let mut entry = resolved.entry;
        entry.name = listed.name;
        entry.path = alias_path;
        filtered_entries.push(entry);
    }

    Ok(PublicEntriesResponse {
        path: normalized_sub_path,
        entries: filtered_entries,
    })
}

pub(crate) fn open_public_download_at(
    conn: &Connection,
    base_root: &Path,
    policy: &PolicyAuthorizer,
    raw_token: &str,
    raw_sub_path: &str,
    headers: &HeaderMap,
) -> Result<(File, String, u64, ParsedByteRange), McBrowserError> {
    let now = Utc::now();
    let share = load_active_share_by_token(conn, raw_token, now)?;
    require_unlocked_if_password_protected(headers, &share, now.timestamp())?;

    if !share.allow_download {
        return Err(McBrowserError::Forbidden(
            "Downloads are disabled for this share".to_string(),
        ));
    }

    let owner_user = load_and_verify_active_owner(conn, share.owner_user_id)?;
    let scoped_root = open_verified_user_root_fd(conn, base_root, share.owner_user_id)
        .map_err(|_| McBrowserError::NotFound("Share is no longer available".to_string()))?;
    verify_share_scope_matches(&share, &scoped_root)?;

    let (mut file, download_name) = if !share.is_directory {
        // Single-file share: only empty path or exact leaf filename is permitted
        let normalized_sub = normalize_relative_path(raw_sub_path, true)?;
        if !normalized_sub.is_empty() && normalized_sub != share.target_name {
            return Err(McBrowserError::Forbidden(
                "Requested path is outside the shared file scope".to_string(),
            ));
        }
        authorize_owner_share_subpath(conn, policy, &owner_user, &share.target_path, "", true)?;
        let (f, _) = open_verified_shared_single_file(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            true,
        )?;
        (f, share.target_name.clone())
    } else {
        // Directory share: require a non-empty relative file path beneath the shared folder
        let normalized_sub = normalize_relative_path(raw_sub_path, false)?;
        authorize_owner_share_subpath(
            conn,
            policy,
            &owner_user,
            &share.target_path,
            &normalized_sub,
            true,
        )?;
        let (scoped_bfs, root_paths) = open_verified_shared_directory_fs(
            conn,
            policy,
            &owner_user,
            &scoped_root.bfs,
            &share,
            true,
        )?;
        let opened = scoped_bfs
            .open_file_resolving_internal_links(&normalized_sub)
            .map_err(|e| match e.kind() {
                ErrorKind::NotFound => {
                    McBrowserError::NotFound("Requested file was not found".to_string())
                }
                ErrorKind::InvalidInput | ErrorKind::InvalidData => McBrowserError::BadRequest(
                    "Requested path is not a downloadable file".to_string(),
                ),
                ErrorKind::PermissionDenied => McBrowserError::Forbidden(
                    "Access to requested file is not permitted".to_string(),
                ),
                _ => map_fs_io_error(e, "Failed to open shared file"),
            })?;
        authorize_shared_relative_resolution(
            conn,
            policy,
            &owner_user,
            &root_paths,
            &normalized_sub,
            &opened.resolution_paths,
            &opened.resolved_path,
            true,
        )?;
        let f = opened.file;
        let leaf = normalized_sub
            .rsplit('/')
            .next()
            .unwrap_or("download")
            .to_string();
        (f, leaf)
    };

    let meta = file
        .metadata()
        .map_err(|_| McBrowserError::Internal("Failed to read shared file metadata".to_string()))?;
    let total_size = meta.len();

    let range_hdr = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let parsed_range = parse_single_byte_range(range_hdr.as_deref(), total_size)?;
    if let ParsedByteRange::Partial { start, .. } = parsed_range {
        file.seek(SeekFrom::Start(start)).map_err(|_| {
            McBrowserError::Internal("Failed to seek shared file for range download".to_string())
        })?;
    }

    Ok((file, download_name, total_size, parsed_range))
}

// ─────────────────────────────────────────────────────────────────────────────
// Axum HTTP Route Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn list_shares(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, _base_root, _policy| list_shares_at(conn, &auth_user))
    })
    .await;

    match res {
        Ok(Ok(shares)) => {
            let mut resp = Json(ListSharesResponse { shares }).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("List shares task failed".to_string()).into_response(),
    }
}

async fn create_share(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<CreateShareRequest>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            create_share_at(conn, base_root, policy, &auth_user, req)
        })
    })
    .await;

    match res {
        Ok(Ok((share, _raw_token))) => {
            let mut resp =
                (StatusCode::CREATED, Json(CreateShareResponse { share })).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Create share task failed".to_string()).into_response(),
    }
}

async fn delete_share(
    State(runtime): State<ShareRuntime>,
    Extension(auth_user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
) -> Response {
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, _base_root, _policy| {
            delete_share_at(conn, &auth_user, &share_id)
        })
    })
    .await;

    match res {
        Ok(Ok(())) => Json(MutationSuccessResponse { success: true }).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Delete share task failed".to_string()).into_response(),
    }
}

async fn get_public_share_metadata(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            get_public_metadata_at(conn, base_root, policy, &token)
        })
    })
    .await;

    match res {
        Ok(Ok(meta)) => {
            let mut resp = Json(meta).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share metadata task failed".to_string(),
        )),
    }
}

async fn unlock_public_share(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    Json(req): Json<UnlockShareRequest>,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let client_ip = extract_client_ip(&headers);
    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            Ok(unlock_public_share_at(
                conn,
                base_root,
                policy,
                &token,
                &req.password,
                &client_ip,
            ))
        })
    })
    .await;

    match res {
        Ok(Ok(Ok((share, access_token, ttl_secs)))) => {
            let cookie = build_scoped_share_cookie(&share.token_hash, &access_token, ttl_secs);
            let mut resp = Json(UnlockShareResponse {
                success: true,
                access_token,
                expires_in: ttl_secs,
            })
            .into_response();
            let h = resp.headers_mut();
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Ok(hv) = HeaderValue::from_str(&cookie) {
                h.insert(header::SET_COOKIE, hv);
            }
            resp
        }
        Ok(Ok(Err(err_resp))) => err_resp,
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share unlock task failed".to_string(),
        )),
    }
}

async fn list_public_share_entries(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<PublicPathQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            list_public_entries_at(conn, base_root, policy, &token, &query.path, &headers)
        })
    })
    .await;

    match res {
        Ok(Ok(entries_resp)) => {
            let mut resp = Json(entries_resp).into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Err(e)) => public_share_error_response(e),
        Err(_) => public_share_error_response(McBrowserError::Internal(
            "Public share entries task failed".to_string(),
        )),
    }
}

async fn download_public_share_entry(
    State(runtime): State<ShareRuntime>,
    AxumPath(token): AxumPath<String>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<PublicPathQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = reject_secret_query_params(raw_query.as_deref()) {
        return public_share_error_response(e);
    }

    let open_res = tokio::task::spawn_blocking(move || {
        runtime.with_conn_and_root(|conn, base_root, policy| {
            open_public_download_at(conn, base_root, policy, &token, &query.path, &headers)
        })
    })
    .await;

    let (std_file, download_name, total_size, parsed_range) = match open_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return public_share_error_response(e),
        Err(_) => {
            return public_share_error_response(McBrowserError::Internal(
                "Public share download task failed".to_string(),
            ))
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
        build_attachment_content_disposition(&download_name),
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

#[cfg(test)]
#[path = "shares_tests.rs"]
mod tests;
