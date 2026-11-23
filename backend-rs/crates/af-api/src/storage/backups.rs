use super::backup_staging::maintain_backup_upload_staging;
use super::stream_file;
use super::updater::get_local_version;
use crate::auth::{api_error, blocking_auth_work, secure_cookie_enabled, AuthUser};
use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::extract::{Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;
use std::time::{Duration as StdDuration, Instant};

static VALID_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+\.sqlite$").unwrap());
pub(super) static VALID_UPLOAD_SESSION_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap());
pub(super) const DEFAULT_BACKUP_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_RETAINED_BACKUPS: usize = 10;
const RETENTION_DAYS: i64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFile {
    pub filename: String,
    pub size: i64,
    pub timestamp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checksum: String,
}

pub fn get_active_db_path() -> PathBuf {
    let has_env_override = [
        "AF_DB_PATH",
        "DB_PATH",
        "AETHERFLOW_DB_PATH",
        "AETHERFLOW_RESTORE_STAGING_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
        "STATE_DIRECTORY",
        "DATA_DIR",
    ]
    .iter()
    .any(|k| env::var(k).ok().filter(|v| !v.trim().is_empty()).is_some());

    if has_env_override {
        return af_models::resolve_active_db_path_from_env(
            None,
            "/var/lib/aetherflow/aetherflow.sqlite",
        );
    }

    let initialized = PathBuf::from(af_db::get_db_path());
    if initialized.exists() {
        return initialized;
    }

    let base_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        base_dir.join("data").join("aetherflow.sqlite"),
        base_dir
            .join("..")
            .join("backend")
            .join("data")
            .join("aetherflow.sqlite"),
        PathBuf::from("/opt/AetherFlow/backend/data/aetherflow.sqlite"),
        PathBuf::from("/var/lib/aetherflow/aetherflow.sqlite"),
        base_dir
            .join("..")
            .join("dashboard")
            .join("db")
            .join("aetherflow.sqlite"),
        base_dir
            .join("dashboard")
            .join("db")
            .join("aetherflow.sqlite"),
        base_dir.join("aetherflow.sqlite"),
    ];

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    base_dir.join("data").join("aetherflow.sqlite")
}

pub fn get_backup_dir() -> PathBuf {
    let active_db = get_active_db_path();
    af_models::resolve_active_backup_dir_from_env(
        None,
        Some(&active_db),
        "/var/lib/aetherflow/backups",
    )
}

pub(super) fn is_valid_backup_filename(name: &str) -> bool {
    VALID_BACKUP_FILENAME_RE.is_match(name)
}

pub(super) fn safe_backup_path(base_dir: &StdPath, filename: &str) -> anyhow::Result<PathBuf> {
    if filename.trim().is_empty() {
        anyhow::bail!("filename required");
    }
    let clean_name = StdPath::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;
    if clean_name == "." || clean_name == ".." || clean_name.is_empty() || clean_name != filename {
        anyhow::bail!("invalid backup path");
    }
    Ok(base_dir.join(clean_name))
}

pub(super) fn compute_file_sha256(path: &StdPath) -> anyhow::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn read_verified_backup_checksum(
    backup_dir: &StdPath,
    filename: &str,
) -> anyhow::Result<(
    af_runner::af_host::ChecksumVerification,
    af_runner::af_host::BackupManifest,
)> {
    let (trusted_sqlite_uid, _) = af_models::resolve_trusted_sqlite_ids_from_env(None);
    let (verification, maybe_manifest) =
        af_runner::af_host::verify_backup_artifact_with_trusted_uid(
            backup_dir,
            filename,
            trusted_sqlite_uid,
        )
        .map_err(|err| anyhow::anyhow!("backup artifact verification failed: {}", err))?;
    let manifest = maybe_manifest.ok_or_else(|| {
        anyhow::anyhow!(
            "backup artifact {} is missing a verified companion manifest",
            filename
        )
    })?;
    Ok((verification, manifest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackupFileStamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    uid: u32,
    links: u64,
}

fn backup_file_stamp(meta: &fs::Metadata) -> BackupFileStamp {
    use std::os::unix::fs::MetadataExt;
    BackupFileStamp {
        device: meta.dev(),
        inode: meta.ino(),
        size: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
        mode: meta.mode(),
        uid: meta.uid(),
        links: meta.nlink(),
    }
}

type BackupStamp = Vec<(PathBuf, BackupFileStamp)>;
pub(super) struct CachedBackupVerification {
    stamp: BackupStamp,
    pub(super) checked: Instant,
    verification: af_runner::af_host::ChecksumVerification,
    manifest: af_runner::af_host::BackupManifest,
}
#[allow(clippy::type_complexity)]
pub(super) static BACKUP_VERIFICATIONS: Lazy<
    Mutex<HashMap<(PathBuf, Option<u32>), CachedBackupVerification>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));

fn backup_artifact_stamp(directory: &StdPath, filename: &str) -> anyhow::Result<BackupStamp> {
    let mut result = Vec::new();
    let prefix = format!("{}.", filename);
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name().to_string_lossy().to_string();
        if name == filename || name.starts_with(&prefix) {
            let path = af_runner::af_host::safe_backup_file_path(directory, &name)?;
            let meta = fs::symlink_metadata(&path)?;
            anyhow::ensure!(meta.is_file(), "Backup companion must be a regular file");
            result.push((path, backup_file_stamp(&meta)));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

fn open_verified_backup_with_manifest(
    directory: &StdPath,
    filename: &str,
) -> anyhow::Result<(
    fs::File,
    af_runner::af_host::ChecksumVerification,
    af_runner::af_host::BackupManifest,
)> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = af_runner::af_host::safe_backup_file_path(directory, filename)?;
    let stamp = backup_artifact_stamp(directory, filename)?;
    let (uid, _) = af_models::resolve_trusted_sqlite_ids_from_env(None);
    let key = (path.clone(), uid);
    let cached = BACKUP_VERIFICATIONS.lock().ok().and_then(|cache| {
        cache
            .get(&key)
            .filter(|value| {
                value.stamp == stamp && value.checked.elapsed() < StdDuration::from_secs(60)
            })
            .map(|value| (value.verification.clone(), value.manifest.clone()))
    });
    let (verification, manifest) = if let Some(pair) = cached {
        pair
    } else {
        let (verification, manifest) = read_verified_backup_checksum(directory, filename)?;
        anyhow::ensure!(
            backup_artifact_stamp(directory, filename)? == stamp,
            "Backup changed during verification"
        );
        if let Ok(mut cache) = BACKUP_VERIFICATIONS.lock() {
            cache.retain(|_, value| value.checked.elapsed() < StdDuration::from_secs(60));
            if cache.len() >= 32 {
                cache.clear();
            }
            cache.insert(
                key,
                CachedBackupVerification {
                    stamp: stamp.clone(),
                    checked: Instant::now(),
                    verification: verification.clone(),
                    manifest: manifest.clone(),
                },
            );
        }
        (verification, manifest)
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let actual = backup_file_stamp(&file.metadata()?);
    anyhow::ensure!(
        stamp
            .iter()
            .any(|(candidate, expected)| candidate == &path && *expected == actual),
        "Backup changed before download"
    );
    Ok((file, verification, manifest))
}

pub(super) fn open_verified_backup(
    directory: &StdPath,
    filename: &str,
) -> anyhow::Result<(fs::File, af_runner::af_host::ChecksumVerification)> {
    let (file, verification, _) = open_verified_backup_with_manifest(directory, filename)?;
    Ok((file, verification))
}

// Bound expensive verification and assembly independently from password checks.
pub(super) static BACKUP_BLOCKING_LIMIT: Lazy<tokio::sync::Semaphore> =
    Lazy::new(|| tokio::sync::Semaphore::new(2));

enum BackupWorkError {
    Busy,
    Join(tokio::task::JoinError),
}

impl BackupWorkError {
    fn into_response(self) -> Response {
        match self {
            Self::Busy => api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "Backup workers busy; retry shortly",
            ),
            Self::Join(error) => {
                tracing::warn!(%error, "Backup worker task failed");
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Backup worker failed",
                )
            }
        }
    }
}

async fn blocking_backup_work<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, BackupWorkError> {
    let permit = BACKUP_BLOCKING_LIMIT
        .try_acquire()
        .map_err(|_| BackupWorkError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(BackupWorkError::Join)
}

pub(super) fn backup_download_chunk(
    q: &HashMap<String, String>,
) -> anyhow::Result<Option<(u64, u64)>> {
    let Some(chunk) = q.get("chunk").filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let index = chunk.parse::<u64>()?;
    let size = match q.get("chunk_size").filter(|s| !s.is_empty()) {
        Some(size) => size.parse::<u64>()?,
        None => DEFAULT_BACKUP_CHUNK_SIZE,
    };
    anyhow::ensure!(
        size > 0 && size <= 64 * 1024 * 1024,
        "chunk_size must be between 1 byte and 64 MiB"
    );
    anyhow::ensure!(index.checked_mul(size).is_some(), "Chunk offset overflow");
    Ok(Some((index, size)))
}

pub(super) struct BackupReauth {
    next_id: u64,
    pub(super) attempts: HashMap<i64, Vec<(u64, Instant)>>,
    verified: HashMap<(i64, String, [u8; 32]), Instant>,
}

impl BackupReauth {
    fn reserve_attempt(&mut self, user_id: i64, now: Instant) -> Option<u64> {
        self.attempts.retain(|_, entries| {
            entries.retain(|(_, time)| now.duration_since(*time) < StdDuration::from_secs(60));
            !entries.is_empty()
        });
        if self.attempts.get(&user_id).map_or(0, Vec::len) >= 10 {
            return None;
        }
        if self.attempts.len() >= 4096 && !self.attempts.contains_key(&user_id) {
            return None;
        }
        let attempt_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.attempts
            .entry(user_id)
            .or_default()
            .push((attempt_id, now));
        Some(attempt_id)
    }

    fn refund_attempt(&mut self, user_id: i64, attempt_id: u64) {
        let mut remove_user = false;
        if let Some(entries) = self.attempts.get_mut(&user_id) {
            entries.retain(|(id, _)| *id != attempt_id);
            remove_user = entries.is_empty();
        }
        if remove_user {
            self.attempts.remove(&user_id);
        }
    }
}

pub(super) static BACKUP_REAUTH: Lazy<Mutex<BackupReauth>> = Lazy::new(|| {
    Mutex::new(BackupReauth {
        next_id: 1,
        attempts: HashMap::new(),
        verified: HashMap::new(),
    })
});

fn reserve_backup_reauth_attempt(user_id: i64) -> Option<u64> {
    let Ok(mut state) = BACKUP_REAUTH.lock() else {
        return None;
    };
    state.reserve_attempt(user_id, Instant::now())
}

fn refund_backup_reauth_attempt(user_id: i64, attempt_id: u64) {
    if let Ok(mut state) = BACKUP_REAUTH.lock() {
        state.refund_attempt(user_id, attempt_id);
    }
}

pub(super) fn verify_backup_password(
    user_id: i64,
    session: &str,
    password: &str,
    hash: &str,
) -> bool {
    let mut digest = Sha256::new();
    digest.update(hash.as_bytes());
    digest.update([0]);
    digest.update(password.as_bytes());
    let key = (
        user_id,
        session.to_string(),
        <[u8; 32]>::from(digest.finalize()),
    );
    let reserved_id = {
        let Ok(mut state) = BACKUP_REAUTH.lock() else {
            return false;
        };
        let now = Instant::now();
        state
            .verified
            .retain(|_, timestamp| now.duration_since(*timestamp) < StdDuration::from_secs(60));
        if state.verified.contains_key(&key) {
            return true;
        }
        let Some(attempt_id) = state.reserve_attempt(user_id, now) else {
            return false;
        };
        attempt_id
    };
    let valid = !hash.is_empty() && bcrypt::verify(password, hash).unwrap_or(false);
    if valid {
        if let Ok(mut state) = BACKUP_REAUTH.lock() {
            state.refund_attempt(user_id, reserved_id);
            if state.verified.len() >= 1024 {
                state.verified.clear();
            }
            state.verified.insert(key, Instant::now());
        }
    }
    valid
}

const BACKUP_DOWNLOAD_COOKIE: &str = "af_backup_download";
const BACKUP_DOWNLOAD_TTL: StdDuration = StdDuration::from_secs(60);
pub(super) struct BackupDownloadTicket {
    user_id: i64,
    session: String,
    filename: String,
    pub(super) issued: Instant,
}
pub(super) static BACKUP_DOWNLOAD_TICKETS: Lazy<Mutex<HashMap<String, BackupDownloadTicket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) fn issue_backup_download_ticket(
    user: &AuthUser,
    filename: &str,
) -> anyhow::Result<String> {
    let mut tickets = BACKUP_DOWNLOAD_TICKETS
        .lock()
        .map_err(|_| anyhow::anyhow!("Download authorization unavailable"))?;
    tickets.retain(|_, ticket| {
        ticket.issued.elapsed() < BACKUP_DOWNLOAD_TTL
            && !(ticket.user_id == user.user_id && ticket.session == user.jti)
    });
    anyhow::ensure!(
        tickets.len() < 256,
        "Download authorizations busy; retry shortly"
    );
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = hex::encode(random);
    tickets.insert(
        token.clone(),
        BackupDownloadTicket {
            user_id: user.user_id,
            session: user.jti.clone(),
            filename: filename.to_string(),
            issued: Instant::now(),
        },
    );
    Ok(token)
}

pub(super) fn redeem_backup_download_ticket(token: &str, user: &AuthUser, filename: &str) -> bool {
    let Ok(mut tickets) = BACKUP_DOWNLOAD_TICKETS.lock() else {
        return false;
    };
    tickets.retain(|_, ticket| ticket.issued.elapsed() < BACKUP_DOWNLOAD_TTL);
    let matches = tickets.get(token).is_some_and(|ticket| {
        ticket.user_id == user.user_id && ticket.session == user.jti && ticket.filename == filename
    });
    if matches {
        tickets.remove(token);
    }
    matches
}

fn backup_ticket_cookie(token: &str, max_age: i64) -> String {
    build_set_cookie(
        BACKUP_DOWNLOAD_COOKIE,
        token,
        max_age,
        "Strict",
        secure_cookie_enabled(),
        true,
    )
    .replace("Path=/;", "Path=/api/v1/admin/backup/download/;")
}

pub(super) fn percent_decode_header_utf8(raw: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = (bytes.next()? as char).to_digit(16)?;
            let low = (bytes.next()? as char).to_digit(16)?;
            decoded.push(((high << 4) | low) as u8);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).ok()
}

pub(super) fn backup_reauth_password(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| body["password"].as_str().map(str::to_owned))
        .or_else(|| {
            headers
                .get("X-Reauth-Password-Encoded")
                .and_then(|value| value.to_str().ok())
                .and_then(percent_decode_header_utf8)
        })
        .or_else(|| {
            headers
                .get("X-Reauth-Password")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .filter(|password| !password.is_empty() && password.len() <= 1024)
}

pub(super) async fn authorize_backup_password(
    user: &AuthUser,
    session_auth_time: Option<i64>,
    headers: &HeaderMap,
    body: &[u8],
) -> bool {
    let password = backup_reauth_password(headers, body).unwrap_or_default();
    let totp_code = headers
        .get("X-Reauth-TOTP")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let confirm_header = headers
        .get("X-Reauth-Confirm")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    let oauth_confirm = confirm_header.eq_ignore_ascii_case("oauth")
        || confirm_header.eq_ignore_ascii_case("download-backup");
    if totp_code.len() > 128 {
        return false;
    }
    let uid = user.user_id;
    let session = user.jti.clone();
    matches!(
        blocking_auth_work(move || -> anyhow::Result<bool> {
            let conn = af_db::get_read_conn()?;
            if crate::auth::load_active_human_subject(&conn, uid).is_err() {
                return Ok(false);
            }
            let (hash, totp_enabled): (String, i64) = conn.query_row(
                "SELECT COALESCE(password_hash, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                params![uid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !hash.is_empty() {
                drop(conn);
                if password.is_empty() {
                    let _ = reserve_backup_reauth_attempt(uid);
                    return Ok(false);
                }
                return Ok(verify_backup_password(uid, &session, &password, &hash));
            }
            // Passwordless OAuth-only admin step-up path: atomically reserve an attempt slot first.
            let Some(reserved_id) = reserve_backup_reauth_attempt(uid) else {
                return Ok(false);
            };
            if totp_enabled != 0 {
                drop(conn);
                if totp_code.is_empty() {
                    return Ok(false);
                }
                let ok = crate::auth::verify_user_totp_stepup(uid, &totp_code);
                if ok {
                    refund_backup_reauth_attempt(uid, reserved_id);
                }
                return Ok(ok);
            }
            if !oauth_confirm || session.trim().is_empty() {
                return Ok(false);
            }
            let now = Utc::now().timestamp();
            let Some(auth_ts) = session_auth_time else {
                return Ok(false);
            };
            if auth_ts <= 0 || now.saturating_sub(auth_ts) > 300 || auth_ts > now + 60 {
                return Ok(false);
            }
            let fresh_session =
                af_db::has_unexpired_active_session(&conn, &session, uid, now).unwrap_or(false);
            if fresh_session {
                refund_backup_reauth_attempt(uid, reserved_id);
            }
            Ok(fresh_session)
        })
        .await,
        Ok(Ok(true))
    )
}

fn peer_backup_download_authorized(peer: &crate::auth::PeerPrincipal, user: &AuthUser) -> bool {
    peer.run_as_user_id == user.user_id
        && user.user_id > 0
        && user.role == "admin"
        && user.plugin_id.is_none()
        && peer.access.settings.allows_write()
}

pub async fn prepare_backup_download(Path(filename): Path<String>, req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Invalid session");
    };
    if user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    if safe_backup_path(&get_backup_dir(), &filename).is_err() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid backup path",
        );
    }
    let peer = req
        .extensions()
        .get::<crate::auth::PeerPrincipal>()
        .cloned();
    let session_auth_time = req
        .extensions()
        .get::<crate::auth::SessionAuthTime>()
        .map(|t| t.0);
    let (parts, body) = req.into_parts();
    let authorized = if let Some(peer) = peer {
        peer_backup_download_authorized(&peer, &user)
    } else {
        let body = match axum::body::to_bytes(body, 8192).await {
            Ok(body) => body,
            Err(_) => {
                return api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "BAD_REQUEST",
                    "Re-authentication body could not be read within the 8192 byte limit",
                )
            }
        };
        authorize_backup_password(&user, session_auth_time, &parts.headers, &body).await
    };
    if !authorized {
        return api_error(
            StatusCode::FORBIDDEN,
            "INVALID_CURRENT_PASSWORD",
            "Re-authentication failed or attempt limit reached",
        );
    }
    let token = match issue_backup_download_ticket(&user, &filename) {
        Ok(token) => token,
        Err(error) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "BUSY", error.to_string()),
    };
    let mut response = Json(serde_json::json!({"url": format!("/api/v1/admin/backup/download/{}", urlencoding::encode(&filename))})).into_response();
    if let Ok(value) = HeaderValue::from_str(&backup_ticket_cookie(&token, 60)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn prune_old_backups() {
    let backup_dir = get_backup_dir();
    if let Err(error) = af_runner::af_host::prune_backup_inventory(
        &backup_dir,
        MAX_RETAINED_BACKUPS,
        RETENTION_DAYS,
    ) {
        tracing::warn!(%error, dir = %backup_dir.display(), "Backup inventory pruning failed");
    }
    maintain_backup_upload_staging();
}

pub fn perform_system_backup() -> anyhow::Result<BackupFile> {
    let active_db_path = get_active_db_path();
    let backup_dir = af_models::resolve_active_backup_dir_from_env(
        None,
        Some(&active_db_path),
        "/var/lib/aetherflow/backups",
    );
    fs::create_dir_all(&backup_dir)?;

    let lock_path = af_models::resolve_canonical_maintenance_lock_path_from_env(
        None,
        Some(&active_db_path),
        Some(&backup_dir),
    );
    let _maint_lock = af_runner::af_host::HostMaintenanceLockGuard::acquire(
        &lock_path,
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| anyhow::anyhow!("backup maintenance lock busy: {}", e))?;

    let (trusted_sqlite_uid, _) = af_models::resolve_trusted_sqlite_ids_from_env(None);
    let cfg = af_runner::af_host::HostBackupConfig {
        backup_dir: backup_dir.clone(),
        app_version: get_local_version(),
        sqlite_db_path: Some(active_db_path),
        config_targets: Vec::new(),
        max_retained_backups: MAX_RETAINED_BACKUPS,
        retention_days: RETENTION_DAYS,
        snapshot_options: af_runner::af_host::SnapshotOptions {
            trusted_source_uid: trusted_sqlite_uid,
            ..Default::default()
        },
        ..Default::default()
    };

    let ts_slug = Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let receipt = af_runner::af_host::create_sqlite_snapshot_backup(&cfg, Some(&ts_slug))
        .map_err(|e| anyhow::anyhow!("af-host backup failed: {}", e))?;

    let filename = receipt
        .primary_artifact_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    let size = receipt
        .manifest
        .sqlite_snapshot
        .as_ref()
        .map(|s| s.size_bytes as i64)
        .unwrap_or(0);
    let checksum = receipt
        .manifest
        .sqlite_snapshot
        .as_ref()
        .map(|s| s.sha256.clone())
        .unwrap_or_default();

    prune_old_backups();

    Ok(BackupFile {
        filename,
        size,
        timestamp: receipt.manifest.created_at,
        checksum,
    })
}

pub async fn run_backup() -> Response {
    match blocking_backup_work(perform_system_backup).await {
        Ok(Ok(bf)) => Json(serde_json::json!({
            "message": "Backup completed successfully",
            "filename": bf.filename,
            "size": bf.size,
            "checksum": bf.checksum,
            "timestamp": bf.timestamp,
        }))
        .into_response(),
        Ok(Err(e)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        ),
        Err(error) => error.into_response(),
    }
}

pub async fn get_backups_list() -> Response {
    match blocking_backup_work(list_verified_backups).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

pub(super) fn list_verified_backups_in_dir(backup_dir: &StdPath) -> Response {
    let entries = match fs::read_dir(backup_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Json(Vec::<BackupFile>::new()).into_response();
        }
        Err(error) => {
            tracing::warn!(%error, dir = %backup_dir.display(), "Failed to read backup directory");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read backup directory",
            );
        }
    };

    let mut backups = Vec::new();
    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, dir = %backup_dir.display(), "Failed to iterate backup directory entry");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to read backup directory",
                );
            }
        };
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".sqlite") {
            continue;
        }
        let Ok((_file, verification, manifest)) =
            open_verified_backup_with_manifest(backup_dir, &name)
        else {
            continue;
        };
        let ts = if !manifest.created_at.trim().is_empty() {
            manifest.created_at
        } else {
            entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .map(|m| DateTime::<Utc>::from(m).to_rfc3339())
                .unwrap_or_else(|| Utc::now().to_rfc3339())
        };
        backups.push(BackupFile {
            filename: name,
            size: verification.size_bytes as i64,
            timestamp: ts,
            checksum: verification.actual_sha256,
        });
    }
    Json(backups).into_response()
}

fn list_verified_backups() -> Response {
    let backup_dir = get_backup_dir();
    list_verified_backups_in_dir(&backup_dir)
}

pub async fn download_backup(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let chunk = match backup_download_chunk(&q) {
        Ok(chunk) => chunk,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()),
    };
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Invalid session");
    };
    if user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let peer = req
        .extensions()
        .get::<crate::auth::PeerPrincipal>()
        .cloned();
    let (authorized, ticket_authorized) = if let Some(peer) = peer {
        (peer_backup_download_authorized(&peer, &user), false)
    } else {
        let ticket = extract_cookie(req.headers(), BACKUP_DOWNLOAD_COOKIE);
        let ticket_authorized = ticket
            .as_deref()
            .is_some_and(|token| redeem_backup_download_ticket(token, &user, &filename));
        let session_auth_time = req
            .extensions()
            .get::<crate::auth::SessionAuthTime>()
            .map(|t| t.0);
        (
            ticket_authorized
                || authorize_backup_password(&user, session_auth_time, req.headers(), &[]).await,
            ticket_authorized,
        )
    };
    if !authorized {
        return api_error(
            StatusCode::FORBIDDEN,
            "INVALID_CURRENT_PASSWORD",
            "Re-authentication required for backup download",
        );
    }
    let backup_dir = get_backup_dir();
    if safe_backup_path(&backup_dir, &filename).is_err() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid backup path",
        );
    }
    let download_name = filename.clone();
    let opened = blocking_backup_work(move || -> anyhow::Result<_> {
        open_verified_backup(&backup_dir, &download_name)
    })
    .await;
    let (mut file, verification) = match opened {
        Ok(Ok(pair)) => pair,
        Ok(Err(error)) => {
            return api_error(
                StatusCode::CONFLICT,
                "INTEGRITY_ERROR",
                format!("Backup integrity verification failed: {}", error),
            )
        }
        Err(error) => return error.into_response(),
    };
    let total_size = verification.size_bytes;
    let (status, count, range) = if let Some((index, size)) = chunk {
        let start = index * size;
        if start >= total_size {
            return api_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_NOT_SATISFIABLE",
                "Chunk out of range",
            );
        }
        let count = size.min(total_size - start);
        let seek = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            file.seek(SeekFrom::Start(start))?;
            Ok(file)
        })
        .await;
        file = match seek {
            Ok(Ok(file)) => file,
            _ => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to seek backup",
                )
            }
        };
        (
            StatusCode::PARTIAL_CONTENT,
            count,
            Some((index, size, start, start + count - 1)),
        )
    } else {
        (StatusCode::OK, total_size, None)
    };
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let audit_name = filename.clone();
    tokio::task::spawn_blocking(move || {
        af_db::record_audit(
            user.user_id,
            &user.username,
            "backup_download",
            "backup",
            &audit_name,
            "",
            &ip,
            &ua,
        )
    });
    let mut response = Response::new(stream_file(file, count));
    *response.status_mut() = status;
    let h = response.headers_mut();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(count));
    h.insert("X-Backup-Size", HeaderValue::from(total_size));
    if let Ok(value) = HeaderValue::from_str(&verification.actual_sha256) {
        h.insert("X-Checksum-SHA256", value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        filename.replace(['\"', '\\'], "_")
    )) {
        h.insert(header::CONTENT_DISPOSITION, value);
    }
    if let Some((index, size, start, end)) = range {
        h.insert("X-Chunk-Index", HeaderValue::from(index));
        h.insert("X-Chunk-Size", HeaderValue::from(size));
        if let Ok(value) = HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size))
        {
            h.insert(header::CONTENT_RANGE, value);
        }
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{:.2}",
            ((end + 1) as f64 / total_size as f64) * 100.0
        )) {
            h.insert("X-Progress", value);
        }
    }
    if ticket_authorized {
        if let Ok(cookie) = HeaderValue::from_str(&backup_ticket_cookie("", -1)) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) fn query_optimal_backup_window_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<serde_json::Value> {
    let (mode, next_run): (String, String) = conn
        .query_row(
            "SELECT COALESCE(backup_schedule_mode, 'manual'), COALESCE(backup_next_run_at, '') FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or_else(|| ("manual".to_string(), String::new()));
    let analysis = af_services::workers::analyze_optimal_backup_window(conn);
    let mut payload = serde_json::json!({
        "mode": mode,
        "running": mode == "smart",
        "optimal_window": analysis,
    });
    if !next_run.is_empty() {
        payload["next_backup_at"] = serde_json::Value::String(next_run);
    }
    Ok(payload)
}

pub async fn get_optimal_backup_window() -> Response {
    let result = tokio::task::spawn_blocking(|| -> anyhow::Result<serde_json::Value> {
        let conn = af_db::get_read_conn()?;
        Ok(query_optimal_backup_window_conn(&conn)?)
    })
    .await;
    match result {
        Ok(Ok(payload)) => Json(payload).into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to query optimal backup window");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query backup schedule",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "Optimal backup window worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query backup schedule",
            )
        }
    }
}

pub async fn set_backup_schedule(Json(req): Json<serde_json::Value>) -> Response {
    let Some(mode @ ("manual" | "smart")) = req.get("mode").and_then(|v| v.as_str()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Mode must be 'manual' or 'smart'",
        );
    };
    let mode = mode.to_owned();
    tokio::task::spawn_blocking(move || set_backup_schedule_blocking(&mode))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to persist backup schedule",
            )
        })
}

fn set_backup_schedule_blocking(mode: &str) -> Response {
    af_services::workers::ensure_smart_backup_columns();
    let analysis = {
        let Ok(conn) = af_db::get_read_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        };
        af_services::workers::analyze_optimal_backup_window(&conn)
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let (next_run, window_json, smart_enabled) = if mode == "smart" {
        let aligned =
            af_services::workers::compute_next_optimal_backup_at(Utc::now(), analysis.optimal_hour)
                .to_rfc3339();
        let wjson = serde_json::to_string(&analysis).unwrap_or_default();
        (aligned, wjson, "true")
    } else {
        (String::new(), String::new(), "false")
    };
    if !matches!(
        conn.execute(
            "UPDATE settings
         SET backup_schedule_mode = ?1,
             backup_next_run_at = ?2,
             backup_optimal_window = CASE WHEN ?3 != '' THEN ?3 ELSE backup_optimal_window END,
             smart_backup_enabled = ?4,
             smart_backup_hour = ?5
         WHERE id = 1",
            params![
                mode,
                next_run,
                window_json,
                smart_enabled,
                analysis.optimal_hour as i64
            ],
        ),
        Ok(1)
    ) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to persist backup schedule",
        );
    }
    Json(serde_json::json!({
        "message": "Backup schedule mode updated",
        "mode": mode,
        "running": mode == "smart",
        "optimal_window": analysis,
        "next_backup_at": next_run,
    }))
    .into_response()
}
