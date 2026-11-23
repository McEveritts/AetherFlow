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

mod crypto;
mod fs_confinement;
mod handlers;
mod service;
mod store;

use crypto::{
    build_scoped_share_cookie, extract_unlock_credential, mint_scoped_unlock_token,
    revoke_unlock_sessions_for_share, verify_scoped_unlock_token,
};
pub use crypto::{
    generate_raw_share_token, hash_share_password, hash_share_token,
    verify_share_password_constant_time,
};
use fs_confinement::{
    authorize_share_resolution, authorize_shared_relative_resolution, inspect_share_target,
    open_verified_shared_directory_fs, open_verified_shared_single_file,
    open_verified_user_root_fd, verify_share_scope_matches,
};
use handlers::{
    create_share, delete_share, download_public_share_entry, get_public_share_metadata,
    list_public_share_entries, list_shares, unlock_public_share,
};
pub(crate) use service::{
    create_share_at, delete_share_at, get_public_metadata_at, list_public_entries_at,
    list_shares_at, open_public_download_at, unlock_public_share_at,
};
pub use store::reject_secret_query_params;
use store::{
    authorize_owner_share_subpath, is_share_expired, load_active_share_by_token,
    load_and_verify_active_owner, public_share_error_response, row_to_stored_share,
    stored_to_share_record,
};

use super::{
    build_attachment_content_disposition, load_active_quota_conn, map_fs_io_error,
    normalize_relative_path, open_user_browser_fs_at, parse_single_byte_range,
    resolve_configured_base_root, tokio_util_reader_stream::FileRangeStream,
    validate_mcbrowser_user, McBrowserError, MutationSuccessResponse, ParsedByteRange,
};
use crate::auth::{api_error, jwt_secret_bytes, secure_cookie_enabled, AuthUser};
use crate::ws::extract_cookie;
use af_files::{BrowserFs, Entry};
use axum::body::Body;
use axum::extract::{Extension, Path as AxumPath, Query, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
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
    Arc::new(super::policy::authorize_with_conn)
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Context (Production vs Isolated Test State)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) enum ShareRuntime {
    Production,
    #[allow(dead_code)]
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Routers
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn router() -> Router {
    router_with_runtime(ShareRuntime::Production)
}

pub(super) fn tracked_router() -> crate::routes::TrackedRouter {
    tracked_router_with_runtime(ShareRuntime::Production)
}

pub(super) fn tracked_public_router() -> crate::routes::TrackedRouter {
    tracked_public_router_with_runtime(ShareRuntime::Production)
}

#[allow(dead_code)]
pub fn public_router() -> Router {
    public_router_with_runtime(ShareRuntime::Production)
}

pub(crate) fn tracked_router_with_runtime(runtime: ShareRuntime) -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{delete, get, TrackedRouter};
    TrackedRouter::new()
        .route("/mcbrowser/shares", get(list_shares).post(create_share))
        .route("/mcbrowser/shares/:id", delete(delete_share))
        .with_state(runtime)
}

pub(crate) fn router_with_runtime(runtime: ShareRuntime) -> Router {
    tracked_router_with_runtime(runtime).into_router()
}

pub(crate) fn tracked_public_router_with_runtime(
    runtime: ShareRuntime,
) -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{get, post, TrackedRouter};
    TrackedRouter::new()
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

pub(crate) fn public_router_with_runtime(runtime: ShareRuntime) -> Router {
    tracked_public_router_with_runtime(runtime).into_router()
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

#[cfg(test)]
#[path = "shares_tests.rs"]
mod tests;
