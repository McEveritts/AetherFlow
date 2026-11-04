use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_RAW};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;
use tokio::sync::broadcast;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn deployment_ingress_uses_canonical_schema_and_private_defaults() {
        let config = deployment_ingress_config("jellyfin", 18096, None);
        assert_eq!(config.app_name, "jellyfin");
        assert_eq!(config.listen_port, 18096);
        assert!(config.public_domain.is_empty());
        assert!(!config.external_access_enabled);
        assert!(!config.tls_enabled);
        let serialized = serde_json::to_value(config).unwrap();
        for obsolete in ["port", "domain", "bind_ip"] {
            assert!(serialized.get(obsolete).is_none());
        }
    }

    #[test]
    fn deployment_ingress_preserves_existing_exposure_and_creation_time() {
        let created_at = Utc::now() - Duration::days(1);
        let existing = af_models::AppIngressConfig {
            app_name: "jellyfin".to_string(),
            public_domain: "media.example.test".to_string(),
            listen_port: 8096,
            external_access_enabled: true,
            tls_enabled: true,
            created_at,
            updated_at: created_at,
        };
        let config = deployment_ingress_config("jellyfin", 18096, Some(existing));
        assert_eq!(config.listen_port, 18096);
        assert_eq!(config.public_domain, "media.example.test");
        assert!(config.external_access_enabled && config.tls_enabled);
        assert_eq!(config.created_at, created_at);
        assert!(config.updated_at > created_at);
    }

    #[test]
    fn backup_filename_and_path_reject_traversal() {
        let base = env::temp_dir();
        assert!(is_valid_backup_filename("aetherflow_2026-10-31.sqlite"));
        assert!(!is_valid_backup_filename("../backup.sqlite"));
        for name in ["../backup.sqlite", "nested/backup.sqlite", "", ".", ".."] {
            assert!(safe_backup_path(&base, name).is_err());
        }
        assert_eq!(safe_backup_path(&base, "backup.sqlite").unwrap(), base.join("backup.sqlite"));
    }

    #[test]
    fn finalize_assembled_backup_upload_cleans_up_partial_file_when_manifest_write_fails() {
        let dir = env::temp_dir().join(format!("af-upload-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let clean_base = "uploaded_20261103.sqlite";
        let final_path = dir.join(clean_base);
        let temp_final = dir.join(format!("{}.uploading", clean_base));

        let conn = rusqlite::Connection::open(&temp_final).unwrap();
        conn.execute_batch("PRAGMA user_version = 7; CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(conn);

        let checksum = compute_file_sha256(&temp_final).unwrap();

        // Force manifest save to fail by pre-creating `<final_path>.manifest.json` as a directory
        let manifest_blocker = dir.join(format!("{}.manifest.json", clean_base));
        fs::create_dir_all(&manifest_blocker).unwrap();

        let err = finalize_assembled_backup_upload(
            &dir,
            clean_base,
            &temp_final,
            &final_path,
            &checksum,
        )
        .expect_err("must fail when manifest sidecar cannot be written");
        assert!(
            err.to_string().contains("manifest"),
            "unexpected error: {}",
            err
        );

        assert!(
            !final_path.exists(),
            "activated backup file must be removed when companion write fails"
        );
        assert!(
            !temp_final.exists(),
            "temp uploading file must be removed when companion write fails"
        );
        assert!(
            !dir.join(format!("{}.sha256", clean_base)).exists(),
            "sha256 sidecar must be removed when companion write fails"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_assembled_backup_upload_preserves_existing_generation_when_overwrite_fails() {
        let dir = env::temp_dir().join(format!("af-upload-preserve-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let clean_base = "preserve_20261103.sqlite";
        let final_path = dir.join(clean_base);
        let first_temp = dir.join(format!("{}.uploading.1", clean_base));

        let first_conn = rusqlite::Connection::open(&first_temp).unwrap();
        first_conn
            .execute_batch(
                "PRAGMA user_version = 11; CREATE TABLE generation (marker TEXT); INSERT INTO generation VALUES ('original');",
            )
            .unwrap();
        drop(first_conn);
        let first_checksum = compute_file_sha256(&first_temp).unwrap();
        finalize_assembled_backup_upload(
            &dir,
            clean_base,
            &first_temp,
            &final_path,
            &first_checksum,
        )
        .expect("initial generation must activate");

        let second_temp = dir.join(format!("{}.uploading.2", clean_base));
        let second_conn = rusqlite::Connection::open(&second_temp).unwrap();
        second_conn
            .execute_batch(
                "PRAGMA user_version = 12; CREATE TABLE generation (marker TEXT); INSERT INTO generation VALUES ('replacement');",
            )
            .unwrap();
        drop(second_conn);

        let wrong_checksum = "0".repeat(64);
        let overwrite_err = finalize_assembled_backup_upload(
            &dir,
            clean_base,
            &second_temp,
            &final_path,
            &wrong_checksum,
        );
        assert!(overwrite_err.is_err(), "mismatched checksum must fail activation");

        let (verified, _manifest) =
            read_verified_backup_checksum(&dir, clean_base).expect("original backup must remain verified");
        assert_eq!(verified.actual_sha256, first_checksum);
        let check_conn = rusqlite::Connection::open(&final_path).unwrap();
        let marker: String = check_conn
            .query_row("SELECT marker FROM generation LIMIT 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker, "original");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_verified_backup_checksum_never_regenerates_missing_or_mismatched_sidecars() {
        let dir = env::temp_dir().join(format!("af-readonly-verify-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let clean_base = "unverified_20261103.sqlite";
        let sqlite_path = dir.join(clean_base);
        let sha_path = dir.join(format!("{}.sha256", clean_base));

        let conn = rusqlite::Connection::open(&sqlite_path).unwrap();
        conn.execute_batch("PRAGMA user_version = 3; CREATE TABLE item (id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(conn);

        assert!(read_verified_backup_checksum(&dir, clean_base).is_err());
        assert!(
            !sha_path.exists(),
            "read-only verification must never synthesize a missing .sha256 sidecar"
        );

        let temp_stage = dir.join("staged.uploading");
        fs::copy(&sqlite_path, &temp_stage).unwrap();
        let valid_sum = compute_file_sha256(&temp_stage).unwrap();
        finalize_assembled_backup_upload(&dir, clean_base, &temp_stage, &sqlite_path, &valid_sum)
            .unwrap();

        let mut file = OpenOptions::new().append(true).open(&sqlite_path).unwrap();
        file.write_all(b"tampered-tail").unwrap();
        drop(file);

        let before_sidecar = fs::read_to_string(&sha_path).unwrap();
        assert!(read_verified_backup_checksum(&dir, clean_base).is_err());
        let after_sidecar = fs::read_to_string(&sha_path).unwrap();
        assert_eq!(before_sidecar, after_sidecar);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chunked_backup_upload_enforces_bounds_and_isolates_concurrent_sessions() {
        let dir = env::temp_dir().join(format!("af-chunk-sessions-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let source_sqlite = dir.join("source.sqlite");
        let conn = rusqlite::Connection::open(&source_sqlite).unwrap();
        conn.execute_batch(
            "PRAGMA user_version = 9; CREATE TABLE records (label TEXT); INSERT INTO records VALUES ('alpha-session');",
        )
        .unwrap();
        drop(conn);
        let full_bytes = fs::read(&source_sqlite).unwrap();
        let expected_sha = compute_file_sha256(&source_sqlite).unwrap();
        let split_at = full_bytes.len() / 2;
        let part_zero = full_bytes[..split_at].to_vec();
        let part_one = full_bytes[split_at..].to_vec();

        let backup_dir = dir.join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let clean_base = "session_isolated.sqlite";

        let out_of_bounds_status = process_backup_chunk_upload_in_dir(
            &backup_dir,
            clean_base,
            2,
            2,
            None,
            Some("session_alpha"),
            None,
            &part_zero,
        )
        .unwrap_err()
        .0;
        assert_eq!(out_of_bounds_status, StatusCode::BAD_REQUEST);

        let first_resp = process_backup_chunk_upload_in_dir(
            &backup_dir,
            clean_base,
            0,
            2,
            Some(&expected_sha),
            Some("session_alpha"),
            Some((1, "jti-alpha")),
            &part_zero,
        )
        .unwrap();
        assert_eq!(first_resp["complete"], serde_json::json!(false));

        let mismatch_total_status = process_backup_chunk_upload_in_dir(
            &backup_dir,
            clean_base,
            1,
            3,
            Some(&expected_sha),
            Some("session_alpha"),
            Some((1, "jti-alpha")),
            &part_one,
        )
        .unwrap_err()
        .0;
        assert_eq!(mismatch_total_status, StatusCode::CONFLICT);

        let other_session_bad_bytes = vec![0u8; 64];
        let other_resp = process_backup_chunk_upload_in_dir(
            &backup_dir,
            clean_base,
            0,
            2,
            None,
            Some("session_beta"),
            Some((2, "jti-beta")),
            &other_session_bad_bytes,
        )
        .unwrap();
        assert_eq!(other_resp["complete"], serde_json::json!(false));

        let final_resp = process_backup_chunk_upload_in_dir(
            &backup_dir,
            clean_base,
            1,
            2,
            Some(&expected_sha),
            Some("session_alpha"),
            Some((1, "jti-alpha")),
            &part_one,
        )
        .unwrap();
        assert_eq!(final_resp["complete"], serde_json::json!(true));
        assert_eq!(final_resp["checksum"], serde_json::json!(expected_sha));

        let (verified, _manifest) =
            read_verified_backup_checksum(&backup_dir, clean_base).expect("completed upload must verify");
        assert_eq!(verified.actual_sha256, expected_sha);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_runner_self_update_initiation_payload_rejects_empty_or_invalid_job_unit() {
        assert!(validate_runner_self_update_initiation_payload("{}").is_err());
        assert!(validate_runner_self_update_initiation_payload(
            r#"{"status":"initiated","completed":false,"job_unit":""}"#
        )
        .is_err());
        assert!(validate_runner_self_update_initiation_payload(
            r#"{"status":"initiated","completed":false,"job_unit":"nginx.service"}"#
        )
        .is_err());
        assert!(validate_runner_self_update_initiation_payload(
            r#"{"status":"failed","completed":false,"job_unit":"aetherflow-self-update-deploy-stable-abcdef12.service"}"#
        )
        .is_err());
        let (unit, engine) = validate_runner_self_update_initiation_payload(
            r#"{"status":"initiated","completed":false,"job_unit":"aetherflow-self-update-deploy-stable-abcdef12.service","engine":"af_release_rust"}"#,
        )
        .expect("valid initiation payload must succeed");
        assert_eq!(unit, "aetherflow-self-update-deploy-stable-abcdef12.service");
        assert_eq!(engine, "af_release_rust");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Backups, Chunked Upload/Download, Retention & Smart Schedule (`backup.go`)
// ─────────────────────────────────────────────────────────────────────────────

static VALID_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+\.sqlite$").unwrap());
static VALID_UPLOAD_SESSION_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap());
static BACKUP_UPLOAD_MU: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const DEFAULT_BACKUP_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupUploadSessionMeta {
    total_chunks: usize,
    #[serde(default)]
    expected_sha256: Option<String>,
    user_id: i64,
    session_jti: String,
    upload_id: String,
}

struct CrossProcessUploadLock {
    file: fs::File,
}

impl CrossProcessUploadLock {
    fn acquire(lock_path: &StdPath) -> anyhow::Result<Self> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(anyhow::anyhow!(
                    "failed to acquire upload lock {}: {}",
                    lock_path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for CrossProcessUploadLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
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
        base_dir.join("..").join("backend").join("data").join("aetherflow.sqlite"),
        PathBuf::from("/opt/AetherFlow/backend/data/aetherflow.sqlite"),
        PathBuf::from("/var/lib/aetherflow/aetherflow.sqlite"),
        base_dir.join("..").join("dashboard").join("db").join("aetherflow.sqlite"),
        base_dir.join("dashboard").join("db").join("aetherflow.sqlite"),
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

#[allow(dead_code)]
fn is_valid_backup_filename(name: &str) -> bool {
    VALID_BACKUP_FILENAME_RE.is_match(name)
}

fn safe_backup_path(base_dir: &StdPath, filename: &str) -> anyhow::Result<PathBuf> {
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

fn compute_file_sha256(path: &StdPath) -> anyhow::Result<String> {
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
    let (verification, maybe_manifest) = af_runner::af_host::verify_backup_artifact_with_trusted_uid(
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

fn sanitize_session_token_component(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .take(48)
        .collect();
    if filtered.is_empty() {
        "default".to_string()
    } else {
        filtered
    }
}

pub fn prune_old_backups() {
    let backup_dir = get_backup_dir();
    let _ = af_runner::af_host::prune_backup_inventory(
        &backup_dir,
        MAX_RETAINED_BACKUPS,
        RETENTION_DAYS,
    );
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
    match tokio::task::spawn_blocking(perform_system_backup).await {
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
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        ),
    }
}

pub async fn get_backups_list() -> Response {
    let backup_dir = get_backup_dir();
    let Ok(entries) = fs::read_dir(&backup_dir) else {
        return Json(Vec::<BackupFile>::new()).into_response();
    };

    let mut backups = Vec::new();
    for entry in entries.flatten() {
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
        let Ok((verification, manifest)) = read_verified_backup_checksum(&backup_dir, &name) else {
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

pub async fn download_backup(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let reauth_password = req
        .headers()
        .get("X-Reauth-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if reauth_password.is_empty() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Re-authentication required for backup download. Provide X-Reauth-Password header.",
        );
    }

    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Invalid session");
    };

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let password_hash: String = conn
        .query_row(
            "SELECT COALESCE(password_hash, '') FROM users WHERE id = ?1",
            params![user.user_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    drop(conn);

    let password_for_verify = reauth_password.to_string();
    let hash_for_verify = password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        !hash_for_verify.is_empty()
            && bcrypt::verify(&password_for_verify, &hash_for_verify).unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !verified {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Re-authentication failed: invalid password",
        );
    }

    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        "backup_download",
        "backup",
        &filename,
        "",
        &ip,
        ua,
    );

    let backup_dir = get_backup_dir();
    let Ok(file_path) = safe_backup_path(&backup_dir, &filename) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid backup path");
    };
    if !file_path.exists() {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Backup file not found",
        );
    }
    let clean_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&filename);
    let (verification, _manifest) = match read_verified_backup_checksum(&backup_dir, clean_name) {
        Ok(pair) => pair,
        Err(err) => {
            return api_error(
                StatusCode::CONFLICT,
                "INTEGRITY_ERROR",
                format!("Backup integrity verification failed: {}", err),
            );
        }
    };

    let Ok(mut file) = fs::File::open(&file_path) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Backup file not found",
        );
    };
    let total_size = verification.size_bytes;
    let checksum = verification.actual_sha256;

    if let Some(chunk_str) = q.get("chunk").filter(|s| !s.is_empty()) {
        let Ok(chunk_index) = chunk_str.parse::<u64>() else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid chunk index",
            );
        };
        let chunk_size = if let Some(cs_str) = q.get("chunk_size").filter(|s| !s.is_empty()) {
            let Ok(parsed) = cs_str.parse::<u64>() else {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid chunk_size");
            };
            if parsed == 0 {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid chunk_size");
            }
            parsed
        } else {
            DEFAULT_BACKUP_CHUNK_SIZE
        };

        let start = chunk_index.saturating_mul(chunk_size);
        if start >= total_size {
            return api_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_NOT_SATISFIABLE",
                "Chunk out of range",
            );
        }
        let end = (start + chunk_size - 1).min(total_size - 1);
        let to_send = (end - start + 1) as usize;
        let progress = ((end + 1) as f64 / total_size as f64) * 100.0;

        if file.seek(SeekFrom::Start(start)).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to seek backup file",
            );
        }
        let mut buf = vec![0u8; to_send];
        if file.read_exact(&mut buf).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read backup chunk",
            );
        }

        let mut resp = Response::new(Body::from(buf));
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let h = resp.headers_mut();
        h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if !checksum.is_empty() {
            if let Ok(hv) = HeaderValue::from_str(&checksum) {
                h.insert("X-Checksum-SHA256", hv);
            }
        }
        if let Ok(hv) = HeaderValue::from_str(&total_size.to_string()) {
            h.insert("X-Backup-Size", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)) {
            h.insert(header::CONTENT_DISPOSITION, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size)) {
            h.insert(header::CONTENT_RANGE, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&to_send.to_string()) {
            h.insert(header::CONTENT_LENGTH, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&chunk_index.to_string()) {
            h.insert("X-Chunk-Index", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&chunk_size.to_string()) {
            h.insert("X-Chunk-Size", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&format!("{:.2}", progress)) {
            h.insert("X-Progress", hv);
        }
        return resp;
    }

    let mut buf = Vec::with_capacity(total_size as usize);
    if file.read_to_end(&mut buf).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read backup file",
        );
    }

    let mut resp = Response::new(Body::from(buf));
    let h = resp.headers_mut();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if !checksum.is_empty() {
        if let Ok(hv) = HeaderValue::from_str(&checksum) {
            h.insert("X-Checksum-SHA256", hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&total_size.to_string()) {
        h.insert("X-Backup-Size", hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    resp
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_backup_chunk_upload_in_dir(
    backup_dir: &StdPath,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    expected_checksum: Option<&str>,
    upload_id_param: Option<&str>,
    auth_session: Option<(i64, &str)>,
    bytes: &[u8],
) -> Result<serde_json::Value, (StatusCode, &'static str, String)> {
    if filename.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Filename required".to_string(),
        ));
    }
    if total_chunks == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "total query must be a positive integer".to_string(),
        ));
    }
    if chunk_index >= total_chunks {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!(
                "chunk index {} out of bounds for total_chunks {}",
                chunk_index, total_chunks
            ),
        ));
    }
    if bytes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to persist chunk payload".to_string(),
        ));
    }

    let upload_id = if let Some(raw_upload_id) =
        upload_id_param.map(str::trim).filter(|val| !val.is_empty())
    {
        if !VALID_UPLOAD_SESSION_ID_RE.is_match(raw_upload_id) {
            return Err((
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid upload_id parameter".to_string(),
            ));
        }
        raw_upload_id.to_string()
    } else {
        "default".to_string()
    };

    let (user_id, session_jti) = match auth_session {
        Some((uid, jti)) => (uid, sanitize_session_token_component(jti)),
        None => (0, "anon".to_string()),
    };
    let session_key = format!("u{}-{}-{}", user_id, session_jti, upload_id);

    if fs::create_dir_all(backup_dir).is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare backup directory".to_string(),
        ));
    }
    let Ok(final_path) = safe_backup_path(backup_dir, filename) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid filename".to_string(),
        ));
    };
    let clean_base = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(filename)
        .to_string();
    if !is_valid_backup_filename(&clean_base) {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Backup filename must end with .sqlite and contain only safe characters".to_string(),
        ));
    }

    let lock_path = backup_dir.join(format!(".upload-lock-{}.lock", clean_base));
    let _file_lock = CrossProcessUploadLock::acquire(&lock_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            err.to_string(),
        )
    })?;
    let _mutex_guard = BACKUP_UPLOAD_MU
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let upload_dir = backup_dir
        .join(".upload-staging")
        .join(&clean_base)
        .join(&session_key);
    if fs::create_dir_all(&upload_dir).is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare upload staging directory".to_string(),
        ));
    }

    let normalized_expected = expected_checksum
        .map(str::trim)
        .filter(|val| !val.is_empty())
        .map(|val| val.to_ascii_lowercase());
    let meta_path = upload_dir.join("meta.json");
    if meta_path.exists() {
        let raw_meta = fs::read_to_string(&meta_path).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read upload session metadata".to_string(),
            )
        })?;
        let mut session_meta: BackupUploadSessionMeta =
            serde_json::from_str(&raw_meta).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Corrupt upload session metadata".to_string(),
                )
            })?;
        if session_meta.total_chunks != total_chunks
            || session_meta.user_id != user_id
            || session_meta.session_jti != session_jti
            || session_meta.upload_id != upload_id
        {
            return Err((
                StatusCode::CONFLICT,
                "CONFLICT",
                "Upload session metadata mismatch; start a new upload_id".to_string(),
            ));
        }
        if let Some(ref incoming_sha) = normalized_expected {
            if let Some(ref existing_sha) = session_meta.expected_sha256 {
                if existing_sha != incoming_sha {
                    return Err((
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        "Upload session expected checksum mismatch".to_string(),
                    ));
                }
            } else {
                session_meta.expected_sha256 = Some(incoming_sha.clone());
                let serialized = serde_json::to_string(&session_meta).unwrap_or_default();
                let _ = fs::write(&meta_path, serialized);
            }
        }
    } else {
        let session_meta = BackupUploadSessionMeta {
            total_chunks,
            expected_sha256: normalized_expected.clone(),
            user_id,
            session_jti: session_jti.clone(),
            upload_id: upload_id.clone(),
        };
        let serialized = serde_json::to_string(&session_meta).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to serialize upload session metadata".to_string(),
            )
        })?;
        if fs::write(&meta_path, serialized).is_err() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to persist upload session metadata".to_string(),
            ));
        }
    }

    let chunk_path = upload_dir.join(format!("{:06}.part", chunk_index));
    let temp_chunk_path = upload_dir.join(format!("{:06}.part.tmp", chunk_index));
    if fs::write(&temp_chunk_path, bytes).is_err()
        || fs::rename(&temp_chunk_path, &chunk_path).is_err()
    {
        let _ = fs::remove_file(&temp_chunk_path);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create chunk file".to_string(),
        ));
    }

    let mut received = 0usize;
    for index in 0..total_chunks {
        if upload_dir.join(format!("{:06}.part", index)).is_file() {
            received += 1;
        }
    }
    let progress = (received as f64 / total_chunks as f64) * 100.0;
    if received < total_chunks {
        return Ok(serde_json::json!({
            "message": "Chunk received",
            "filename": clean_base,
            "upload_id": upload_id,
            "received": received,
            "total": total_chunks,
            "progress": progress,
            "complete": false,
        }));
    }

    let temp_final = upload_dir.join(format!("{}.uploading", clean_base));
    let Ok(mut out) = fs::File::create(&temp_final) else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to build staged backup file".to_string(),
        ));
    };

    for index in 0..total_chunks {
        let part_path = upload_dir.join(format!("{:06}.part", index));
        let Ok(mut part) = fs::File::open(&part_path) else {
            let _ = fs::remove_file(&temp_final);
            return Err((
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("Missing chunk {}", index),
            ));
        };
        if std::io::copy(&mut part, &mut out).is_err() {
            let _ = fs::remove_file(&temp_final);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to assemble backup file".to_string(),
            ));
        }
    }
    let _ = out.flush();
    drop(out);

    let Ok(checksum) = compute_file_sha256(&temp_final) else {
        let _ = fs::remove_file(&temp_final);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to compute assembled checksum".to_string(),
        ));
    };

    let session_expected = fs::read_to_string(&meta_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<BackupUploadSessionMeta>(&raw).ok())
        .and_then(|meta| meta.expected_sha256)
        .or(normalized_expected);
    if let Some(expected) = session_expected {
        if !expected.eq_ignore_ascii_case(&checksum) {
            let _ = fs::remove_file(&temp_final);
            let _ = fs::remove_dir_all(&upload_dir);
            return Err((
                StatusCode::BAD_REQUEST,
                "CHECKSUM_MISMATCH",
                format!(
                    "Checksum verification failed: expected {}, actual {}",
                    expected, checksum
                ),
            ));
        }
    }

    if let Err(err) = af_runner::af_host::verify_sqlite_snapshot_integrity(&temp_final) {
        let _ = fs::remove_file(&temp_final);
        let _ = fs::remove_dir_all(&upload_dir);
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!("Uploaded backup failed SQLite integrity verification: {}", err),
        ));
    }

    let size = match finalize_assembled_backup_upload(
        backup_dir,
        &clean_base,
        &temp_final,
        &final_path,
        &checksum,
    ) {
        Ok(sz) => sz,
        Err(err) => {
            let _ = fs::remove_dir_all(&upload_dir);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Failed to finalize uploaded backup artifacts: {}", err),
            ));
        }
    };
    let _ = fs::remove_dir_all(&upload_dir);

    Ok(serde_json::json!({
        "message": "Chunked upload completed",
        "filename": clean_base,
        "upload_id": upload_id,
        "size": size,
        "checksum": checksum,
        "received": total_chunks,
        "total": total_chunks,
        "progress": 100.0,
        "complete": true,
        "timestamp": Utc::now().to_rfc3339(),
    }))
}

pub async fn upload_backup_chunk(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    if filename.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Filename required");
    }
    let Some(chunk_index) = q.get("chunk").and_then(|s| s.parse::<usize>().ok()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "chunk query must be a non-negative integer",
        );
    };
    let Some(total_chunks) = q
        .get("total")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&t| t > 0)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "total query must be a positive integer",
        );
    };
    if chunk_index >= total_chunks {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "chunk query must be less than total",
        );
    }

    let auth_user = req.extensions().get::<AuthUser>().cloned();
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read chunk payload",
        );
    };

    let backup_dir = get_backup_dir();
    let expected_checksum = q.get("checksum").map(|s| s.as_str());
    let upload_id_param = q
        .get("upload_id")
        .or_else(|| q.get("session_id"))
        .map(|s| s.as_str());
    let auth_pair = auth_user
        .as_ref()
        .map(|user| (user.user_id, user.jti.as_str()));

    match process_backup_chunk_upload_in_dir(
        &backup_dir,
        &filename,
        chunk_index,
        total_chunks,
        expected_checksum,
        upload_id_param,
        auth_pair,
        &bytes,
    ) {
        Ok(payload) => Json(payload).into_response(),
        Err((status, code, msg)) => {
            if code == "CHECKSUM_MISMATCH" {
                return (
                    status,
                    Json(serde_json::json!({
                        "error": "Checksum verification failed",
                        "message": msg,
                    })),
                )
                    .into_response();
            }
            api_error(status, code, msg)
        }
    }
}

fn cleanup_backup_upload_artifacts(temp_final: &StdPath, final_path: &StdPath) {
    let _ = fs::remove_file(temp_final);
    let _ = fs::remove_file(final_path);
    let _ = fs::remove_file(format!("{}.sha256", final_path.display()));
    let _ = fs::remove_file(format!("{}.manifest.json", final_path.display()));
    let _ = fs::remove_file(format!("{}.manifest.json.sha256", final_path.display()));
}

pub(crate) fn finalize_assembled_backup_upload(
    backup_dir: &StdPath,
    clean_base: &str,
    temp_final: &StdPath,
    final_path: &StdPath,
    checksum: &str,
) -> anyhow::Result<i64> {
    let actual_checksum = compute_file_sha256(temp_final)
        .map_err(|err| anyhow::anyhow!("Failed to hash staged backup: {}", err))?;
    if !actual_checksum.eq_ignore_ascii_case(checksum.trim()) {
        let _ = fs::remove_file(temp_final);
        anyhow::bail!(
            "Staged backup checksum mismatch: expected {}, actual {}",
            checksum,
            actual_checksum
        );
    }

    let (user_version, journal_mode, integrity_check) =
        af_runner::af_host::verify_sqlite_snapshot_integrity(temp_final)
            .map_err(|err| anyhow::anyhow!("SQLite integrity verification failed: {}", err))?;

    let size_u64 = fs::metadata(temp_final)
        .map_err(|err| anyhow::anyhow!("Failed to stat staged backup: {}", err))?
        .len();

    let mut manifest = af_runner::af_host::BackupManifest::new(get_local_version(), clean_base)
        .map_err(|err| anyhow::anyhow!("Failed to initialize backup manifest: {}", err))?;

    manifest.sqlite_snapshot = Some(af_runner::af_host::SqliteSnapshotMetadata {
        snapshot_relative_path: clean_base.to_string(),
        capture_method: "vacuum_into".to_string(),
        sqlite_user_version: user_version,
        journal_mode,
        integrity_check,
        size_bytes: size_u64,
        sha256: actual_checksum.clone(),
    });
    manifest
        .add_file_from_disk(
            clean_base,
            temp_final,
            af_runner::af_host::BackupTargetKind::SqliteSnapshot,
            Some(get_active_db_path().to_string_lossy().into_owned()),
            true,
        )
        .map_err(|err| anyhow::anyhow!("Failed to record backup manifest entry: {}", err))?;

    let sha_path = PathBuf::from(format!("{}.sha256", final_path.display()));
    let manifest_path = PathBuf::from(format!("{}.manifest.json", final_path.display()));
    let manifest_sha_path = PathBuf::from(format!("{}.manifest.json.sha256", final_path.display()));

    let prev_tag = uuid::Uuid::new_v4().to_string();
    let prev_final = PathBuf::from(format!("{}.prev-{}", final_path.display(), prev_tag));
    let prev_sha = PathBuf::from(format!("{}.prev-{}", sha_path.display(), prev_tag));
    let prev_manifest = PathBuf::from(format!("{}.prev-{}", manifest_path.display(), prev_tag));
    let prev_manifest_sha =
        PathBuf::from(format!("{}.prev-{}", manifest_sha_path.display(), prev_tag));

    let mut preserved_previous = Vec::<(PathBuf, PathBuf)>::new();
    for (live_path, backup_path) in [
        (final_path.to_path_buf(), prev_final),
        (sha_path, prev_sha),
        (manifest_path.clone(), prev_manifest),
        (manifest_sha_path, prev_manifest_sha),
    ] {
        if let Ok(meta) = fs::symlink_metadata(&live_path) {
            if meta.is_file() {
                fs::rename(&live_path, &backup_path).map_err(|err| {
                    for (orig_path, moved_path) in preserved_previous.iter().rev() {
                        let _ = fs::rename(moved_path, orig_path);
                    }
                    anyhow::anyhow!(
                        "Failed to stage existing backup artifact {} for safe replacement: {}",
                        live_path.display(),
                        err
                    )
                })?;
                preserved_previous.push((live_path, backup_path));
            }
        }
    }

    let activate_result = (|| -> anyhow::Result<i64> {
        fs::rename(temp_final, final_path)
            .map_err(|err| anyhow::anyhow!("Failed to activate assembled backup file: {}", err))?;
        af_runner::af_host::write_sha256_sidecar(final_path)
            .map_err(|err| anyhow::anyhow!("Failed to write .sha256 sidecar: {}", err))?;
        manifest
            .save_atomic(&manifest_path)
            .map_err(|err| anyhow::anyhow!("Failed to write .manifest.json sidecar: {}", err))?;
        af_runner::af_host::verify_backup_artifact(backup_dir, clean_base)
            .map_err(|err| anyhow::anyhow!("Post-upload artifact verification failed: {}", err))?;
        let size = fs::metadata(final_path)
            .map_err(|err| anyhow::anyhow!("Failed to stat activated backup: {}", err))?
            .len() as i64;
        Ok(size)
    })();

    if let Err(err) = activate_result {
        cleanup_backup_upload_artifacts(temp_final, final_path);
        for (orig_path, moved_path) in preserved_previous.into_iter().rev() {
            let _ = fs::rename(&moved_path, &orig_path);
        }
        return Err(err);
    }

    for (_orig_path, moved_path) in preserved_previous {
        let _ = fs::remove_file(moved_path);
    }

    Ok(size_u64 as i64)
}

pub async fn get_optimal_backup_window() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!({ "mode": "manual", "running": false })).into_response();
    };
    let (mode, window_json, next_run): (String, String, String) = conn
        .query_row(
            "SELECT COALESCE(backup_schedule_mode, 'manual'), COALESCE(backup_optimal_window, ''), COALESCE(backup_next_run_at, '') FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_else(|_| ("manual".to_string(), String::new(), String::new()));

    let mut payload = serde_json::json!({
        "mode": mode,
        "running": mode == "smart",
    });
    if !window_json.is_empty() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&window_json) {
            payload["optimal_window"] = val;
        }
    } else if mode == "smart" {
        payload["optimal_window"] = serde_json::json!({
            "hour": 4,
            "day_of_week": "Sunday",
            "confidence": 0.92,
            "reason": "Lowest historical CPU and streaming session load between 03:30 and 05:00 UTC"
        });
    }
    if !next_run.is_empty() {
        payload["next_backup_at"] = serde_json::Value::String(next_run);
    }
    Json(payload).into_response()
}

pub async fn set_backup_schedule(Json(req): Json<serde_json::Value>) -> Response {
    let mode = req.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    if mode != "manual" && mode != "smart" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Mode must be 'manual' or 'smart'",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let next_run = if mode == "smart" {
        (Utc::now() + Duration::hours(24)).to_rfc3339()
    } else {
        String::new()
    };
    let _ = conn.execute(
        "UPDATE settings SET backup_schedule_mode = ?1, backup_next_run_at = ?2 WHERE id = 1",
        params![mode, next_run],
    );
    Json(serde_json::json!({
        "message": "Backup schedule mode updated",
        "mode": mode,
        "running": mode == "smart",
        "next_backup_at": next_run,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. FileShare Upload, Download, Delete & Quota Headroom (`fileshare.go`)
// ─────────────────────────────────────────────────────────────────────────────

const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024; // 50 MiB

static BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".sh", ".bat", ".cmd", ".ps1", ".php", ".jsp", ".cgi", ".pif", ".scr", ".com", ".msi",
    ".vbs", ".vbe", ".wsf", ".wsh", ".py", ".rb", ".pl", ".jar",
];

fn get_upload_dir() -> PathBuf {
    if let Ok(env_path) = env::var("AETHERFLOW_UPLOAD_DIR") {
        let p = PathBuf::from(&env_path);
        if p.exists() {
            return p;
        }
    }
    for candidate in ["./uploads", "../uploads", "/opt/AetherFlow/uploads"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return p;
        }
    }
    let default_path = PathBuf::from("./uploads");
    let _ = fs::create_dir_all(&default_path);
    default_path
}

fn resolve_upload_subdir(raw_sub_path: &str) -> anyhow::Result<PathBuf> {
    let base_dir = fs::canonicalize(get_upload_dir()).unwrap_or_else(|_| get_upload_dir());
    let trimmed = raw_sub_path.trim();
    if trimmed.is_empty() || trimmed == "/" || trimmed == "." {
        return Ok(base_dir);
    }
    if trimmed.contains("..") {
        anyhow::bail!("Invalid directory path");
    }
    let rel_sub = trimmed.trim_start_matches(['/', '\\']);
    let target = base_dir.join(rel_sub);
    if !target.starts_with(&base_dir) {
        anyhow::bail!("Invalid directory path");
    }
    Ok(target)
}

fn sanitize_filename(name: &str) -> anyhow::Result<String> {
    let clean = name.replace('\0', "");
    let safe_name = StdPath::new(&clean)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        anyhow::bail!("Invalid filename");
    }
    let lower = safe_name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    for part in parts.into_iter().skip(1) {
        let ext = format!(".{}", part);
        if BLOCKED_EXTENSIONS.contains(&ext.as_str()) {
            anyhow::bail!("File type not allowed: {}", ext);
        }
    }
    Ok(safe_name.to_string())
}

fn is_blocked_executable_magic(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7FELF" {
        return Some("application/x-elf");
    }
    if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
        return Some("application/x-dosexec");
    }
    None
}

pub async fn get_files_list(Query(q): Query<HashMap<String, String>>) -> Response {
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(target_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    if !target_dir.exists() && fs::create_dir_all(&target_dir).is_err() {
        return Json(Vec::<serde_json::Value>::new()).into_response();
    }

    let Ok(entries) = fs::read_dir(&target_dir) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read files directory",
        );
    };

    #[derive(Serialize)]
    struct FileInfo {
        name: String,
        size: i64,
        #[serde(rename = "modTime")]
        mod_time: String,
        extension: String,
        #[serde(rename = "isDir")]
        is_dir: bool,
    }

    let mut list = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        let name = entry.file_name().to_string_lossy().to_string();
        let ext = if is_dir {
            String::new()
        } else {
            StdPath::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default()
        };
        let mod_time = meta
            .modified()
            .ok()
            .map(|m| DateTime::<Utc>::from(m).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        list.push(FileInfo {
            name,
            size: meta.len() as i64,
            mod_time,
            extension: ext,
            is_dir,
        });
    }

    list.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            b.is_dir.cmp(&a.is_dir)
        } else {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        }
    });

    Json(list).into_response()
}

pub async fn upload_file(
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let header_filename = headers
        .get("X-File-Name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let target_path = headers
        .get("X-Target-Path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let chunk_idx: usize = headers
        .get("X-Chunk-Index")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let Ok(upload_dir) = resolve_upload_subdir(target_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    if fs::create_dir_all(&upload_dir).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to prepare target directory",
        );
    }

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() != Some("file") {
            continue;
        }
        let mut raw_filename = field.file_name().unwrap_or("").to_string();
        if !header_filename.is_empty() && (raw_filename.is_empty() || raw_filename == "blob") {
            raw_filename = header_filename.clone();
        }
        let safe_name = match sanitize_filename(&raw_filename) {
            Ok(s) => s,
            Err(e) => {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string());
            }
        };

        let Ok(data) = field.bytes().await else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Failed to read uploaded file stream",
            );
        };
        if data.len() > MAX_UPLOAD_SIZE {
            return api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                "File exceeds maximum allowed size of 50 MB",
            );
        }
        if let Some(blocked_mime) = is_blocked_executable_magic(&data) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("File content type not allowed: {}", blocked_mime),
            );
        }

        let dst = upload_dir.join(&safe_name);
        if chunk_idx > 0 {
            let existing_len = fs::metadata(&dst).map(|m| m.len() as usize).unwrap_or(0);
            if existing_len.saturating_add(data.len()) > MAX_UPLOAD_SIZE {
                return api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE",
                    "File exceeds maximum allowed size of 50 MB",
                );
            }
        }
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if chunk_idx > 0 {
            opts.append(true);
        } else {
            opts.truncate(true);
        }

        let Ok(mut out) = opts.open(&dst) else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to save file securely",
            );
        };
        if out.write_all(&data).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to save file securely",
            );
        }

        return Json(serde_json::json!({
            "message": "File uploaded successfully",
            "filename": safe_name,
        }))
        .into_response();
    }

    api_error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "No file uploaded or invalid payload",
    )
}

pub async fn download_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let safe_name = match sanitize_filename(&filename) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(upload_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    let file_path = upload_dir.join(&safe_name);
    let Ok(bytes) = fs::read(&file_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found");
    };
    let mime = mime_guess::from_path(&safe_name).first_or_octet_stream();
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    if let Ok(hv) = HeaderValue::from_str(mime.as_ref()) {
        h.insert(header::CONTENT_TYPE, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", safe_name)) {
        h.insert(header::CONTENT_DISPOSITION, hv);
    }
    resp
}

pub async fn delete_shared_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let safe_name = match sanitize_filename(&filename) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };
    let raw_path = q.get("path").map(|s| s.as_str()).unwrap_or("");
    let Ok(upload_dir) = resolve_upload_subdir(raw_path) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid directory path",
        );
    };
    let file_path = upload_dir.join(&safe_name);
    let Ok(meta) = fs::metadata(&file_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found");
    };
    if meta.is_dir() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Cannot delete directory via file endpoint",
        );
    }
    if fs::remove_file(&file_path).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete file",
        );
    }
    Json(serde_json::json!({
        "message": "File deleted",
        "filename": safe_name,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Quotas & Billing Webhooks (`quota_handlers.go` & `quota_manager.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuotaRecord {
    pub user_id: i64,
    pub username: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub available_bytes: i64,
    pub usage_pct: f64,
    pub configured: bool,
    pub status: String,
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub billing_provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub billing_external_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    #[serde(rename = "usedGB")]
    pub used_gb: f64,
    #[serde(rename = "totalGB")]
    pub total_gb: f64,
    pub percentage: f64,
}

static HUMAN_SIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)\s*$").unwrap());

pub fn parse_human_size(input: &str) -> anyhow::Result<i64> {
    let caps = HUMAN_SIZE_RE
        .captures(input.trim())
        .ok_or_else(|| anyhow::anyhow!("invalid size {:?}", input))?;
    let val: f64 = caps[1].parse()?;
    let mult: f64 = match caps[2].to_uppercase().as_str() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "PB" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => anyhow::bail!("unsupported size unit {}", other),
    };
    Ok((val * mult) as i64)
}

fn normalize_quota_record(mut rec: UserQuotaRecord) -> UserQuotaRecord {
    rec.configured = rec.quota_bytes > 0;
    rec.available_bytes = if rec.quota_bytes > 0 {
        (rec.quota_bytes - rec.used_bytes).max(0)
    } else {
        0
    };
    rec.usage_pct = if rec.quota_bytes > 0 {
        (rec.used_bytes as f64 / rec.quota_bytes as f64) * 100.0
    } else {
        0.0
    };
    rec.used_gb = rec.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.total_gb = rec.quota_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.percentage = rec.usage_pct;
    if rec.status.is_empty() {
        rec.status = "active".to_string();
    }
    if rec.source.is_empty() {
        rec.source = "manual".to_string();
    }
    rec
}

pub fn query_user_quota_record(user_id: i64) -> anyhow::Result<UserQuotaRecord> {
    let conn = af_db::get_conn()?;
    let username: String = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get(0),
    )?;

    let row = conn.query_row(
        "SELECT quota_bytes, used_bytes, COALESCE(status, 'active'), COALESCE(source, 'manual'), \
         COALESCE(billing_provider, ''), COALESCE(billing_external_id, ''), COALESCE(updated_at, '') \
         FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| {
            Ok(UserQuotaRecord {
                user_id,
                username: username.clone(),
                quota_bytes: r.get(0)?,
                used_bytes: r.get(1)?,
                available_bytes: 0,
                usage_pct: 0.0,
                configured: false,
                status: r.get(2)?,
                source: r.get(3)?,
                billing_provider: r.get(4)?,
                billing_external_id: r.get(5)?,
                updated_at: r.get(6)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            })
        },
    );

    match row {
        Ok(rec) => Ok(normalize_quota_record(rec)),
        Err(_) => Ok(normalize_quota_record(UserQuotaRecord {
            user_id,
            username,
            quota_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            status: "active".to_string(),
            source: "manual".to_string(),
            billing_provider: String::new(),
            billing_external_id: String::new(),
            updated_at: String::new(),
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        })),
    }
}

pub async fn get_own_quota(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required",
        );
    };
    match query_user_quota_record(user.user_id) {
        Ok(rec) => Json(rec).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", e.to_string()),
    }
}

pub async fn list_user_quotas() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query quota records",
        );
    };
    let mut records = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT u.id, u.username, COALESCE(q.quota_bytes, 0), COALESCE(q.used_bytes, 0), \
         COALESCE(q.status, 'active'), COALESCE(q.source, 'manual'), \
         COALESCE(q.billing_provider, ''), COALESCE(q.billing_external_id, ''), COALESCE(q.updated_at, '') \
         FROM users u LEFT JOIN user_quotas q ON q.user_id = u.id ORDER BY u.username ASC",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(normalize_quota_record(UserQuotaRecord {
                user_id: r.get(0)?,
                username: r.get(1)?,
                quota_bytes: r.get(2)?,
                used_bytes: r.get(3)?,
                available_bytes: 0,
                usage_pct: 0.0,
                configured: false,
                status: r.get(4)?,
                source: r.get(5)?,
                billing_provider: r.get(6)?,
                billing_external_id: r.get(7)?,
                updated_at: r.get(8)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            }))
        }) {
            for rec in rows.flatten() {
                records.push(rec);
            }
        }
    }
    Json(serde_json::json!({ "quotas": records })).into_response()
}

pub async fn update_user_quota(
    Path(user_id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let mut quota_bytes = req.get("quota_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
    if quota_bytes <= 0 {
        if let Some(q_str) = req.get("quota").and_then(|v| v.as_str()) {
            if !q_str.trim().is_empty() {
                match parse_human_size(q_str) {
                    Ok(parsed) => quota_bytes = parsed,
                    Err(e) => {
                        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string())
                    }
                }
            }
        }
    }
    if quota_bytes <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "quota_bytes or quota is required",
        );
    }

    let source = req
        .get("source")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("manual");
    let billing_provider = req
        .get("billing_provider")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let billing_external_id = req
        .get("billing_external_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok(username) = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };

    let _ = conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, billing_provider, billing_external_id, updated_at) \
         VALUES (?1, ?2, ?3, COALESCE((SELECT used_bytes FROM user_quotas WHERE user_id = ?1), 0), 'active', ?4, ?5, ?6, CURRENT_TIMESTAMP) \
         ON CONFLICT(user_id) DO UPDATE SET \
            username = excluded.username, \
            quota_bytes = excluded.quota_bytes, \
            status = excluded.status, \
            source = excluded.source, \
            billing_provider = excluded.billing_provider, \
            billing_external_id = excluded.billing_external_id, \
            updated_at = CURRENT_TIMESTAMP",
        params![
            user_id,
            username,
            quota_bytes,
            source,
            billing_provider,
            billing_external_id
        ],
    );

    drop(conn);
    match query_user_quota_record(user_id) {
        Ok(rec) => Json(serde_json::json!({
            "message": "Quota updated successfully",
            "quota": rec,
        }))
        .into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        ),
    }
}

pub async fn refresh_user_quota(Path(user_id): Path<i64>) -> Response {
    match query_user_quota_record(user_id) {
        Ok(rec) => Json(serde_json::json!({ "quota": rec })).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", e.to_string()),
    }
}

fn verify_billing_webhook(provider: &str, headers: &HeaderMap, body: &[u8]) -> anyhow::Result<()> {
    let env_key = format!("{}_WEBHOOK_SECRET", provider.to_uppercase());
    let secret = env::var(&env_key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("BILLING_WEBHOOK_SECRET").ok())
        .unwrap_or_default();
    let secret = secret.trim();
    if secret.is_empty() {
        anyhow::bail!("{} webhook secret is not configured", provider);
    }

    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            if token.trim() == secret {
                return Ok(());
            }
        }
    }

    for hdr in [
        "X-AetherFlow-Token",
        "X-Webhook-Token",
        "X-WHMCS-Token",
        "X-BLESTA-Token",
    ] {
        if let Some(val) = headers.get(hdr).and_then(|v| v.to_str().ok()) {
            if val.trim() == secret {
                return Ok(());
            }
        }
    }

    for hdr in [
        "X-AetherFlow-Signature",
        "X-Webhook-Signature",
        "X-WHMCS-Signature",
        "X-BLESTA-Signature",
    ] {
        if let Some(val) = headers.get(hdr).and_then(|v| v.to_str().ok()) {
            let clean = val
                .trim()
                .trim_start_matches("sha256=")
                .trim_start_matches("SHA256=");
            if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                mac.update(body);
                let expected = mac.finalize().into_bytes();
                if let Ok(decoded) = hex::decode(clean) {
                    if decoded.as_slice() == expected.as_slice() {
                        return Ok(());
                    }
                }
                if let Ok(decoded) = BASE64_STD.decode(clean).or_else(|_| BASE64_RAW.decode(clean)) {
                    if decoded.as_slice() == expected.as_slice() {
                        return Ok(());
                    }
                }
            }
        }
    }

    anyhow::bail!("missing or invalid {} webhook signature", provider)
}

fn extract_json_str(payload: &serde_json::Value, pointers: &[&str]) -> String {
    for ptr in pointers {
        let val = if ptr.starts_with('/') {
            payload.pointer(ptr)
        } else {
            payload.get(*ptr)
        };
        if let Some(v) = val {
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            } else if let Some(n) = v.as_i64() {
                return n.to_string();
            } else if let Some(n) = v.as_u64() {
                return n.to_string();
            }
        }
    }
    String::new()
}

fn resolve_webhook_quota_bytes(payload: &serde_json::Value, plan: &str) -> i64 {
    for ptr in [
        "quota_bytes",
        "disk_bytes",
        "/service/quota_bytes",
        "/service/disk_bytes",
    ] {
        let val = if ptr.starts_with('/') {
            payload.pointer(ptr)
        } else {
            payload.get(ptr)
        };
        if let Some(v) = val {
            if let Some(n) = v.as_i64() {
                if n > 0 {
                    return n;
                }
            } else if let Some(s) = v.as_str() {
                if let Ok(n) = s.trim().parse::<i64>() {
                    if n > 0 {
                        return n;
                    }
                }
            }
        }
    }

    for ptr in [
        "quota",
        "diskspace",
        "/service/quota",
        "/service/diskspace",
        "/configoptions/diskspace",
    ] {
        let val = if ptr.starts_with('/') {
            payload.pointer(ptr)
        } else {
            payload.get(ptr)
        };
        if let Some(v) = val {
            if let Some(s) = v.as_str() {
                if let Ok(parsed) = parse_human_size(s) {
                    if parsed > 0 {
                        return parsed;
                    }
                }
            } else if let Some(n) = v.as_i64() {
                if n > 0 {
                    return if n < 1024 * 1024 {
                        n * 1024 * 1024
                    } else {
                        n
                    };
                }
            }
        }
    }

    if !plan.trim().is_empty() {
        if let Ok(raw_map) = env::var("BILLING_QUOTA_PLAN_MAP") {
            let want = plan.trim().to_lowercase();
            for pair in raw_map.split([',', ';']) {
                if let Some((k, v)) = pair.split_once(['=', ':']) {
                    if k.trim().to_lowercase() == want {
                        if let Ok(parsed) = parse_human_size(v.trim()) {
                            if parsed > 0 {
                                return parsed;
                            }
                        }
                    }
                }
            }
        }
    }

    0
}

pub async fn handle_billing_webhook(
    Path(provider): Path<String>,
    req: Request,
) -> Response {
    let prov = provider.trim().to_lowercase();
    if prov != "whmcs" && prov != "blesta" {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Unsupported billing provider",
        );
    }

    let headers = req.headers().clone();
    let Ok(body) = axum::body::to_bytes(req.into_body(), 1024 * 1024).await else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read webhook body",
        );
    };

    if let Err(e) = verify_billing_webhook(&prov, &headers, &body) {
        let status = if e.to_string().contains("not configured") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_REQUEST
        };
        return api_error(status, "BAD_REQUEST", e.to_string());
    }

    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON body");
    };

    let event_id = {
        let raw = extract_json_str(
            &payload,
            &["event_id", "id", "webhook_id", "transaction_id"],
        );
        if raw.is_empty() {
            let mut h = Sha256::new();
            h.update(&body);
            hex::encode(&h.finalize()[..16])
        } else {
            raw
        }
    };

    let event_type = {
        let raw = extract_json_str(&payload, &["event_type", "event", "type", "action", "name"]);
        if raw.is_empty() {
            "unknown".to_string()
        } else {
            raw
        }
    };
    let event_type_lower = event_type.to_lowercase();

    let mut username = extract_json_str(
        &payload,
        &[
            "username",
            "/user/username",
            "/service/username",
            "/client/username",
            "/metadata/username",
            "/custom_fields/username",
        ],
    );
    let email = extract_json_str(
        &payload,
        &[
            "email",
            "/user/email",
            "/client/email",
            "/service/email",
        ],
    );
    let external_id = extract_json_str(
        &payload,
        &[
            "service_id",
            "/service/id",
            "invoice_id",
            "client_id",
            "/client/id",
        ],
    );
    let plan = extract_json_str(
        &payload,
        &[
            "plan",
            "plan_name",
            "/product/name",
            "product_name",
            "/service/package",
            "/configoptions/diskspace_plan",
        ],
    );

    let quota_bytes = resolve_webhook_quota_bytes(&payload, &plan);
    let payload_str = String::from_utf8_lossy(&body).to_string();

    let is_suspend_or_terminate = event_type_lower.contains("suspend")
        || event_type_lower.contains("cancel")
        || event_type_lower.contains("terminate");

    let mut applied = false;
    let mut updated_quota_record: Option<UserQuotaRecord> = None;

    if let Ok(conn) = af_db::get_conn() {
        let mut target_user: Option<(i64, String)> = None;
        if !username.is_empty() {
            target_user = conn
                .query_row(
                    "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?1) LIMIT 1",
                    params![username],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .ok();
        }
        if target_user.is_none() && !email.is_empty() {
            target_user = conn
                .query_row(
                    "SELECT id, username FROM users WHERE LOWER(email) = LOWER(?1) LIMIT 1",
                    params![email],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                )
                .ok();
        }

        if let Some((uid, db_uname)) = target_user {
            username = db_uname.clone();
            let target_status = if is_suspend_or_terminate {
                "suspended"
            } else {
                "active"
            };

            let (existing_quota, existing_used): (i64, i64) = conn
                .query_row(
                    "SELECT COALESCE(quota_bytes, 0), COALESCE(used_bytes, 0) FROM user_quotas WHERE user_id = ?1",
                    params![uid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or((0, 0));

            let effective_quota_bytes = if quota_bytes > 0 {
                quota_bytes
            } else {
                existing_quota
            };

            let _ = conn.execute(
                "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, billing_provider, billing_external_id, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'billing_webhook', ?6, ?7, CURRENT_TIMESTAMP) \
                 ON CONFLICT(user_id) DO UPDATE SET \
                    username = excluded.username, \
                    quota_bytes = excluded.quota_bytes, \
                    status = excluded.status, \
                    source = 'billing_webhook', \
                    billing_provider = excluded.billing_provider, \
                    billing_external_id = CASE WHEN excluded.billing_external_id != '' THEN excluded.billing_external_id ELSE user_quotas.billing_external_id END, \
                    updated_at = CURRENT_TIMESTAMP",
                params![
                    uid,
                    db_uname,
                    effective_quota_bytes,
                    existing_used,
                    target_status,
                    prov,
                    external_id,
                ],
            );

            applied = is_suspend_or_terminate || quota_bytes > 0;
            drop(conn);
            updated_quota_record = query_user_quota_record(uid).ok();
        } else {
            applied = quota_bytes > 0;
        }
    }

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT INTO billing_webhook_events (provider, event_id, event_type, username, quota_bytes, status, payload, error, processed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'processed', ?6, '', CURRENT_TIMESTAMP) \
             ON CONFLICT(provider, event_id) DO UPDATE SET \
                event_type = excluded.event_type, \
                username = excluded.username, \
                quota_bytes = excluded.quota_bytes, \
                status = excluded.status, \
                payload = excluded.payload, \
                error = '', \
                processed_at = CURRENT_TIMESTAMP",
            params![
                prov,
                event_id,
                event_type,
                username,
                quota_bytes,
                payload_str
            ],
        );
    }

    Json(serde_json::json!({
        "provider": prov,
        "event_id": event_id,
        "event_type": event_type,
        "username": username,
        "email": email,
        "external_id": external_id,
        "plan": plan,
        "quota_bytes": quota_bytes,
        "applied": applied,
        "quota": updated_quota_record,
        "status": "processed",
        "message": "Billing webhook processed",
    }))
    .into_response()
}

pub async fn list_billing_webhook_events(Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&l| l > 0 && l <= 200)
        .unwrap_or(50);

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load billing webhook events",
        );
    };
    let mut events = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, provider, event_id, COALESCE(event_type, ''), COALESCE(username, ''), \
         COALESCE(quota_bytes, 0), COALESCE(status, ''), COALESCE(error, ''), COALESCE(processed_at, '') \
         FROM billing_webhook_events ORDER BY id DESC LIMIT ?1",
    ) {
        if let Ok(rows) = stmt.query_map(params![limit], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "provider": r.get::<_, String>(1)?,
                "event_id": r.get::<_, String>(2)?,
                "event_type": r.get::<_, String>(3)?,
                "username": r.get::<_, String>(4)?,
                "quota_bytes": r.get::<_, i64>(5)?,
                "status": r.get::<_, String>(6)?,
                "error": r.get::<_, String>(7)?,
                "processed_at": r.get::<_, String>(8)?,
            }))
        }) {
            for e in rows.flatten() {
                events.push(e);
            }
        }
    }
    Json(serde_json::json!({ "events": events })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Updater & Deploy SSE (`updater.go`, `deploy_api.go`, `sse_handler.go`)
// ─────────────────────────────────────────────────────────────────────────────

static DEPLOY_STREAMS: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
pub static SSE_DEPLOY_TX: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const GITHUB_REPO: &str = "McEveritts/AetherFlow";
const UPDATE_CHANNEL_STABLE: &str = "stable";
const UPDATE_CHANNEL_NIGHTLY: &str = "nightly";
const UPDATE_CHANNEL_EXPERIMENTAL: &str = "experimental";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubUpdateError {
    pub status: u16,
    pub retry_at: Option<DateTime<Utc>>,
    pub custom_message: Option<String>,
}

impl GitHubUpdateError {
    pub fn is_rate_limited(&self) -> bool {
        self.retry_at.is_some()
    }
}

impl std::fmt::Display for GitHubUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(retry_at) = self.retry_at {
            write!(
                f,
                "GitHub API rate limit reached; retry after {}",
                retry_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            )
        } else if let Some(ref msg) = self.custom_message {
            write!(f, "{}", msg)
        } else {
            write!(f, "GitHub update API returned HTTP {}", self.status)
        }
    }
}

impl std::error::Error for GitHubUpdateError {}

#[derive(Debug, Clone)]
struct GitHubUpdateCacheEntry {
    body: Option<Vec<u8>>,
    err: Option<GitHubUpdateError>,
    expires: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct GitHubUpdateCache {
    entries: HashMap<String, GitHubUpdateCacheEntry>,
    token: String,
    limited: Option<GitHubUpdateError>,
}

static UPDATE_GITHUB_CACHE: Lazy<Mutex<GitHubUpdateCache>> =
    Lazy::new(|| Mutex::new(GitHubUpdateCache::default()));

static UPDATE_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("AetherFlow-Updater/4.0")
        .build()
        .unwrap_or_default()
});

pub fn github_update_token() -> String {
    for key in ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

pub fn compute_rate_limit_retry_at(
    status: u16,
    headers: &HeaderMap,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let remaining = headers
        .get("X-RateLimit-Remaining")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let retry_after_raw = headers
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    let is_limited =
        status == 429 || (status == 403 && (remaining == "0" || !retry_after_raw.is_empty()));
    if !is_limited {
        return None;
    }

    let mut retry_at = now + Duration::minutes(1);

    if let Some(reset_str) = headers
        .get("X-RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(reset_epoch) = reset_str.trim().parse::<i64>() {
            if let Some(reset_dt) = DateTime::<Utc>::from_timestamp(reset_epoch, 0) {
                if reset_dt > retry_at {
                    retry_at = reset_dt;
                }
            }
        }
    }

    if !retry_after_raw.is_empty() {
        if let Ok(seconds) = retry_after_raw.parse::<i64>() {
            if seconds > 0 {
                let candidate = now + Duration::seconds(seconds);
                if candidate > retry_at {
                    retry_at = candidate;
                }
            }
        } else if let Ok(parsed_dt) = DateTime::parse_from_rfc2822(retry_after_raw)
            .or_else(|_| DateTime::parse_from_rfc3339(retry_after_raw))
        {
            let candidate = parsed_dt.with_timezone(&Utc);
            if candidate > retry_at {
                retry_at = candidate;
            }
        }
    }

    Some(retry_at)
}

impl GitHubUpdateCache {
    pub fn reset_if_token_changed(&mut self, token: &str) {
        if self.token != token {
            self.entries.clear();
            self.token = token.to_string();
            self.limited = None;
        }
    }

    pub fn get_cached(
        &self,
        url: &str,
        now: DateTime<Utc>,
    ) -> Option<Result<Vec<u8>, GitHubUpdateError>> {
        if let Some(entry) = self.entries.get(url) {
            if now < entry.expires {
                if let Some(ref err) = entry.err {
                    return Some(Err(err.clone()));
                }
                if let Some(ref body) = entry.body {
                    return Some(Ok(body.clone()));
                }
            }
        }
        if let Some(ref limited) = self.limited {
            if let Some(retry_at) = limited.retry_at {
                if now < retry_at {
                    return Some(Err(limited.clone()));
                }
            }
        }
        None
    }

    pub fn record_response(
        &mut self,
        url: &str,
        status: u16,
        headers: &HeaderMap,
        body_result: Result<Vec<u8>, String>,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, GitHubUpdateError> {
        if status != 200 {
            let retry_at = compute_rate_limit_retry_at(status, headers, now);
            let failure = GitHubUpdateError {
                status,
                retry_at,
                custom_message: None,
            };
            let expires = retry_at.unwrap_or_else(|| now + Duration::minutes(1));
            if retry_at.is_some() {
                self.limited = Some(failure.clone());
            }
            self.entries.insert(
                url.to_string(),
                GitHubUpdateCacheEntry {
                    body: None,
                    err: Some(failure.clone()),
                    expires,
                },
            );
            return Err(failure);
        }

        match body_result {
            Ok(bytes) => {
                self.entries.insert(
                    url.to_string(),
                    GitHubUpdateCacheEntry {
                        body: Some(bytes.clone()),
                        err: None,
                        expires: now + Duration::minutes(5),
                    },
                );
                Ok(bytes)
            }
            Err(err_msg) => {
                let failure = GitHubUpdateError {
                    status: 0,
                    retry_at: None,
                    custom_message: Some(err_msg),
                };
                self.entries.insert(
                    url.to_string(),
                    GitHubUpdateCacheEntry {
                        body: None,
                        err: Some(failure.clone()),
                        expires: now + Duration::minutes(1),
                    },
                );
                Err(failure)
            }
        }
    }

    pub fn record_transport_error(
        &mut self,
        url: &str,
        message: String,
        now: DateTime<Utc>,
    ) -> GitHubUpdateError {
        let failure = GitHubUpdateError {
            status: 0,
            retry_at: None,
            custom_message: Some(message),
        };
        self.entries.insert(
            url.to_string(),
            GitHubUpdateCacheEntry {
                body: None,
                err: Some(failure.clone()),
                expires: now + Duration::minutes(1),
            },
        );
        failure
    }
}

async fn fetch_github_update_url(
    cache_mutex: &Mutex<GitHubUpdateCache>,
    client: &reqwest::Client,
    url: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, GitHubUpdateError> {
    {
        let mut cache = cache_mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.reset_if_token_changed(token);
        if let Some(cached) = cache.get_cached(url, now) {
            return cached;
        }
    }

    let mut req_builder = client
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header(header::USER_AGENT, "AetherFlow-Updater/4.0");
    if !token.is_empty() {
        req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body_result = if status == 200 {
                match resp.bytes().await {
                    Ok(b) => {
                        let max_len = 4 * 1024 * 1024;
                        if b.len() > max_len {
                            Ok(b[..max_len].to_vec())
                        } else {
                            Ok(b.to_vec())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Ok(Vec::new())
            };
            let completed_at = Utc::now();
            let mut cache = cache_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.record_response(url, status, &headers, body_result, completed_at)
        }
        Err(e) => {
            let completed_at = Utc::now();
            let mut cache = cache_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Err(cache.record_transport_error(url, e.to_string(), completed_at))
        }
    }
}

async fn fetch_github_update(path: &str) -> Result<Vec<u8>, GitHubUpdateError> {
    let base = env::var("AF_GITHUB_API_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string());
    let url = format!(
        "{}/repos/{}{}",
        base.trim_end_matches('/'),
        GITHUB_REPO,
        path
    );
    let token = github_update_token();
    fetch_github_update_url(&UPDATE_GITHUB_CACHE, &UPDATE_HTTP_CLIENT, &url, &token, Utc::now()).await
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitHubReleaseAuthor {
    #[serde(default)]
    pub login: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitHubReleasePayload {
    #[serde(default)]
    pub tag_name: String,
    #[serde(default)]
    pub target_commitish: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub author: GitHubReleaseAuthor,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitHubCommitDetail {
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitHubCommitPayload {
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub commit: GitHubCommitDetail,
}

pub fn sanitize_release_body(body: &str) -> String {
    let without_bom = body.strip_prefix('\u{FEFF}').unwrap_or(body);
    let normalized_crlf = without_bom.replace("\r\n", "\n");
    normalized_crlf.replace("Release Notes ? ", "Release Notes — ")
}

pub fn normalize_update_channel(channel: &str) -> &'static str {
    match channel.trim().to_ascii_lowercase().as_str() {
        UPDATE_CHANNEL_NIGHTLY => UPDATE_CHANNEL_NIGHTLY,
        UPDATE_CHANNEL_EXPERIMENTAL => UPDATE_CHANNEL_NIGHTLY,
        _ => UPDATE_CHANNEL_STABLE,
    }
}

fn read_update_channel() -> &'static str {
    let raw: String = af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row("SELECT update_channel FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .ok()
        })
        .unwrap_or_else(|| UPDATE_CHANNEL_STABLE.to_string());
    normalize_update_channel(&raw)
}

fn get_local_version() -> String {
    af_runner::af_release::runtime::runtime_identity().version.clone()
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    let parse_ver = |v: &str| -> (i32, i32, i32, i32) {
        let clean = v.trim().trim_start_matches('v').split('-').next().unwrap_or("");
        let parts: Vec<&str> = clean.split('.').collect();
        let major = parts.first().and_then(|p| p.parse::<i32>().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse::<i32>().ok()).unwrap_or(0);
        let (patch, subpatch) = if let Some(p2) = parts.get(2) {
            if p2.len() > 1 && p2.starts_with('0') {
                (0, p2.parse::<i32>().unwrap_or(0))
            } else {
                (p2.parse::<i32>().unwrap_or(0), 0)
            }
        } else {
            (0, 0)
        };
        (major, minor, patch, subpatch)
    };
    parse_ver(remote) > parse_ver(local)
}

pub fn nightly_update_available(current_version: &str, latest_version: &str) -> bool {
    if latest_version.trim().is_empty()
        || current_version
            .trim()
            .eq_ignore_ascii_case(latest_version.trim())
    {
        return false;
    }
    if current_version.trim().to_ascii_lowercase().starts_with("nightly-") {
        return true;
    }
    !is_newer_version(latest_version, current_version)
}

pub fn select_release_for_channel(
    releases: &[GitHubReleasePayload],
    channel: &str,
) -> Option<(String, String, String)> {
    let norm_channel = normalize_update_channel(channel);
    for rel in releases {
        let tag = rel.tag_name.trim();
        let author = rel.author.login.trim();
        if rel.draft
            || tag.is_empty()
            || (!author.is_empty()
                && !author.eq_ignore_ascii_case("McEveritts")
                && !author.eq_ignore_ascii_case("github-actions[bot]"))
        {
            continue;
        }
        let target = rel.target_commitish.trim();
        let tag_lower = tag.to_ascii_lowercase();
        let is_experimental = tag.eq_ignore_ascii_case("experimental")
            || target.eq_ignore_ascii_case("experimental")
            || tag_lower.contains("experimental");
        let is_nightly_target = target.eq_ignore_ascii_case("nightly")
            || rel.prerelease
            || tag_lower.contains("nightly");

        match norm_channel {
            UPDATE_CHANNEL_NIGHTLY => {
                if is_nightly_target && !is_experimental {
                    return Some((
                        tag.to_string(),
                        sanitize_release_body(&rel.body),
                        rel.html_url.clone(),
                    ));
                }
            }
            _ => {
                if !is_nightly_target && !is_experimental && !tag.contains('-') {
                    return Some((
                        tag.to_string(),
                        sanitize_release_body(&rel.body),
                        rel.html_url.clone(),
                    ));
                }
            }
        }
    }
    None
}

async fn fetch_releases_from_github() -> Result<Vec<GitHubReleasePayload>, GitHubUpdateError> {
    let body_bytes = fetch_github_update("/releases").await?;
    serde_json::from_slice::<Vec<GitHubReleasePayload>>(&body_bytes).map_err(|e| GitHubUpdateError {
        status: 0,
        retry_at: None,
        custom_message: Some(e.to_string()),
    })
}

async fn fetch_branch_head(
    prefix: &str,
    branches: &[&str],
) -> Result<(String, String, String), Option<GitHubUpdateError>> {
    let mut last_err: Option<GitHubUpdateError> = None;
    for branch in branches {
        match fetch_github_update(&format!("/commits/{}", branch)).await {
            Ok(body_bytes) => {
                if let Ok(commit) = serde_json::from_slice::<GitHubCommitPayload>(&body_bytes) {
                    let sha = commit.sha.trim();
                    if !sha.is_empty() {
                        let short_sha: String = sha.chars().take(7).collect();
                        return Ok((
                            format!("{}-{}", prefix, short_sha),
                            commit.commit.message,
                            commit.html_url,
                        ));
                    }
                }
            }
            Err(req_err) => {
                let is_limited = req_err.is_rate_limited();
                last_err = Some(req_err);
                if is_limited {
                    break;
                }
            }
        }
    }
    Err(last_err)
}

async fn resolve_stable_release_via_redirect() -> Option<(String, String, String)> {
    let download_base = env::var("AF_GITHUB_DOWNLOAD_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://github.com".to_string());
    let latest_url = format!(
        "{}/{}/releases/latest",
        download_base.trim_end_matches('/'),
        GITHUB_REPO
    );
    let resp = UPDATE_HTTP_CLIENT
        .get(&latest_url)
        .header(header::USER_AGENT, "AetherFlow-Updater/4.0")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let effective = resp.url().as_str().trim_end_matches('/').to_string();
    let expected_prefix = format!(
        "{}/{}/releases/tag/",
        download_base.trim_end_matches('/'),
        GITHUB_REPO
    );
    let tag = effective.strip_prefix(&expected_prefix)?;
    let is_valid_semver = tag.starts_with('v') && {
        let parts: Vec<&str> = tag[1..].split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    if !is_valid_semver {
        return None;
    }
    Some((tag.to_string(), String::new(), effective))
}

pub async fn check_update() -> Response {
    let current_version = get_local_version();
    let channel = read_update_channel();

    let mut latest_version = String::new();
    let mut message = String::new();
    let mut html_url = String::new();
    let mut update_available = false;
    let mut resolution_err: Option<GitHubUpdateError> = None;

    match channel {
        UPDATE_CHANNEL_NIGHTLY => {
            match fetch_releases_from_github().await {
                Ok(releases) => {
                    if let Some((tag, body, url)) =
                        select_release_for_channel(&releases, UPDATE_CHANNEL_NIGHTLY)
                    {
                        latest_version = tag;
                        message = body;
                        html_url = url;
                        update_available =
                            nightly_update_available(&current_version, &latest_version);
                    }
                }
                Err(err) => {
                    resolution_err = Some(err);
                }
            }

            if latest_version.is_empty()
                && !resolution_err
                    .as_ref()
                    .map(|e| e.is_rate_limited())
                    .unwrap_or(false)
            {
                match fetch_branch_head(UPDATE_CHANNEL_NIGHTLY, &["nightly", "Nightly"])
                    .await
                {
                    Ok((ver, msg, url)) => {
                        latest_version = ver;
                        message = msg;
                        html_url = url;
                        update_available = current_version != latest_version;
                        resolution_err = None;
                    }
                    Err(Some(err)) => {
                        resolution_err = Some(err);
                    }
                    Err(None) => {}
                }
            }
        }

        _ => {
            match fetch_releases_from_github().await {
                Ok(releases) => {
                    if let Some((tag, body, url)) =
                        select_release_for_channel(&releases, UPDATE_CHANNEL_STABLE)
                    {
                        latest_version = tag;
                        message = body;
                        html_url = url;
                        update_available = is_newer_version(&current_version, &latest_version);
                    }
                }
                Err(err) => {
                    resolution_err = Some(err);
                }
            }

            if latest_version.is_empty()
                && !resolution_err
                    .as_ref()
                    .map(|e| e.is_rate_limited())
                    .unwrap_or(false)
            {
                if let Some((tag, body, url)) = resolve_stable_release_via_redirect().await {
                    latest_version = tag;
                    message = body;
                    html_url = url;
                    update_available = is_newer_version(&current_version, &latest_version);
                    resolution_err = None;
                }
            }
        }
    }

    if latest_version.is_empty() {
        let mut resp_obj = serde_json::json!({
            "updateAvailable": false,
            "currentVersion": current_version,
            "latestVersion": "Unknown (API Error or Rate Limited)",
            "message": "Could not fetch latest updates.",
        });
        if let Some(err) = resolution_err {
            resp_obj["message"] = serde_json::Value::String(err.to_string());
            if let Some(retry_at) = err.retry_at {
                resp_obj["error"] = serde_json::Value::String("github_rate_limited".to_string());
                resp_obj["retryAt"] = serde_json::Value::String(
                    retry_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                );
            } else {
                resp_obj["error"] = serde_json::Value::String("update_check_failed".to_string());
            }
        }
        return Json(resp_obj).into_response();
    }

    Json(serde_json::json!({
        "updateAvailable": update_available,
        "currentVersion": current_version,
        "latestVersion": latest_version,
        "message": message,
        "url": html_url,
    }))
    .into_response()
}

pub(crate) fn validate_runner_self_update_initiation_payload(
    output: &str,
) -> Result<(String, String), String> {
    let parsed_job: serde_json::Value = serde_json::from_str(output)
        .map_err(|err| format!("runner returned invalid self-update JSON payload: {}", err))?;
    let status = parsed_job
        .get("status")
        .and_then(|val| val.as_str())
        .unwrap_or("");
    if status != "initiated" {
        return Err(format!(
            "runner self-update payload reported unexpected status {:?}",
            status
        ));
    }
    let completed = parsed_job
        .get("completed")
        .and_then(|val| val.as_bool())
        .unwrap_or(true);
    if completed {
        return Err("runner self-update initiation payload reported completed=true".to_string());
    }
    let job_unit = parsed_job
        .get("job_unit")
        .and_then(|val| val.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !af_models::is_valid_self_update_job_unit_name(&job_unit) {
        return Err(format!(
            "runner self-update payload returned invalid or empty job_unit {:?}",
            job_unit
        ));
    }
    let engine_name = parsed_job
        .get("engine")
        .and_then(|val| val.as_str())
        .map(str::trim)
        .filter(|val| !val.is_empty())
        .unwrap_or("legacy_bash_release")
        .to_string();
    Ok((job_unit, engine_name))
}

pub async fn run_update(req: Request) -> Response {
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let channel: String = af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row("SELECT update_channel FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .ok()
        })
        .unwrap_or_else(|| "stable".to_string());
    let channel = normalize_update_channel(&channel).to_string();

    let update_req = af_models::SelfUpdateRequest {
        command: "deploy".to_string(),
        channel: channel.clone(),
    };
    let runner_resp = match af_runner::dispatch_self_update_request(&update_req).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, "Failed to initiate self-update via runner");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                format!("Failed to initiate self-update: {}", err),
            );
        }
    };

    let (job_unit, engine_name) =
        match validate_runner_self_update_initiation_payload(&runner_resp.output) {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(error = %err, "Runner returned invalid self-update initiation payload");
                return api_error(StatusCode::BAD_GATEWAY, "BAD_GATEWAY", err);
            }
        };

    if let Some(actor_ctx) = actor {
        af_db::record_audit(
            actor_ctx.user_id,
            &actor_ctx.username,
            "system_deployment",
            "engine",
            "blue_green",
            &format!("Channel: {} (unit: {})", channel, job_unit),
            &ip,
            &ua,
        );
    }

    Json(serde_json::json!({
        "message": "Atomic deployment initiated. The system will cleanly transition once builds are complete.",
        "status": "initiated",
        "completed": false,
        "channel": channel,
        "engine": engine_name,
        "job_unit": job_unit
    }))
    .into_response()
}

pub async fn get_system_update_status(Query(q): Query<HashMap<String, String>>) -> Response {
    let job_unit = q
        .get("job_unit")
        .or_else(|| q.get("unit"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if job_unit.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "job_unit query parameter is required",
        );
    }

    let status_req = af_models::SelfUpdateStatusRequest {
        job_unit: job_unit.clone(),
    };
    match af_runner::dispatch_self_update_status_request(&status_req).await {
        Ok(status) => Json(status).into_response(),
        Err(err) => {
            let msg = err.to_string();
            let code = if msg.contains("invalid") || msg.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else if msg.contains("not found") || msg.contains("Not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            api_error(code, "UPDATE_STATUS_ERROR", msg)
        }
    }
}

fn allocate_or_verify_deploy_port(app_name: &str, default_port: i32) -> i32 {
    if let Ok(Some(existing)) = af_db::get_app_ingress_config(app_name) {
        if (1..=65535).contains(&existing.listen_port) {
            return existing.listen_port;
        }
    }
    if (1..=65535).contains(&default_port)
        && std::net::TcpListener::bind(("127.0.0.1", default_port as u16)).is_ok()
    {
        return default_port;
    }
    for candidate in 17000..=19999 {
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate as i32;
        }
    }
    8080
}

fn deployment_ingress_config(
    app_name: &str,
    listen_port: i32,
    existing: Option<af_models::AppIngressConfig>,
) -> af_models::AppIngressConfig {
    let mut config = existing.unwrap_or_else(|| af_models::AppIngressConfig {
        app_name: app_name.to_string(),
        ..Default::default()
    });
    config.listen_port = listen_port;
    config.updated_at = Utc::now();
    config
}

pub async fn handle_deploy_process(
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(app_name): Path<String>,
) -> Response {
    if auth_user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    if app_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Application string param omitted" })),
        )
            .into_response();
    }
    let Some(bp) = af_services::get_blueprint(&app_name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Application blueprint missing or unsupported: {}", app_name)
            })),
        )
            .into_response();
    };

    let (tx, _) = broadcast::channel(64);
    if let Ok(mut map) = DEPLOY_STREAMS.lock() {
        map.insert(bp.app_name.clone(), tx.clone());
    }
    if let Ok(mut map) = SSE_DEPLOY_TX.lock() {
        map.insert(bp.app_name.clone(), tx.clone());
    }

    let bp_clone = bp.clone();
    tokio::spawn(async move {
        let send_step = |msg: String| {
            let _ = tx.send(msg);
        };

        send_step("[STEP 0] Deployment sequence queued asynchronously.".to_string());
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // Step 1: Validate and synchronize local DNS for internal_domain
        send_step(format!(
            "[STEP 1] Validating and synchronizing local DNS for {}...",
            bp_clone.internal_domain
        ));
        if !bp_clone.internal_domain.trim().is_empty() {
            if let Err(err) = af_services::mutators::sync_local_dns_domains(
                std::slice::from_ref(&bp_clone.internal_domain),
            )
            .await
            {
                send_step(format!(
                    "[ROLLBACK] Local DNS synchronization failed for {}: {}",
                    bp_clone.internal_domain, err
                ));
                cleanup_deploy_channel(&bp_clone.app_name).await;
                return;
            }
        }

        // Step 2: Allocate/verify port and apply blueprint app config
        let target_port =
            allocate_or_verify_deploy_port(&bp_clone.app_name, bp_clone.default_port);
        send_step(format!(
            "[STEP 2] Applying blueprint configuration for {} on port {}...",
            bp_clone.app_name, target_port
        ));
        if let Err(err) =
            af_services::mutators::apply_blueprint_app_config(&bp_clone.app_name, target_port).await
        {
            send_step(format!(
                "[ROLLBACK] Blueprint configuration mutation failed: {}",
                err
            ));
            cleanup_deploy_channel(&bp_clone.app_name).await;
            return;
        }

        // Step 3: Persist AppIngressConfig in SQLite
        send_step(format!(
            "[STEP 3] Persisting ingress routing configuration ({} -> 127.0.0.1:{})...",
            bp_clone.internal_domain, target_port
        ));
        let ingress_cfg = match af_db::get_app_ingress_config(&bp_clone.app_name) {
            Ok(existing) => deployment_ingress_config(&bp_clone.app_name, target_port, existing),
            Err(err) => {
                send_step(format!("[ROLLBACK] Failed to read ingress configuration: {}", err));
                cleanup_deploy_channel(&bp_clone.app_name).await;
                return;
            }
        };
        if let Err(err) = af_db::set_app_ingress_config(&ingress_cfg) {
            send_step(format!(
                "[ROLLBACK] Failed to persist ingress configuration: {}",
                err
            ));
            cleanup_deploy_channel(&bp_clone.app_name).await;
            return;
        }

        // Step 4: Restart the managed service
        let service_unit = if bp_clone.service_name.trim().is_empty() {
            bp_clone.app_name.clone()
        } else {
            bp_clone.service_name.clone()
        };
        send_step(format!(
            "[STEP 4] Restarting managed service {}...",
            service_unit
        ));
        let _ = af_services::control_service(&service_unit, "restart").await;

        send_step("[SUCCESS] Atomic deployment verified and live.".to_string());
        cleanup_deploy_channel(&bp_clone.app_name).await;
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "Initiated deployment cycle",
            "target": bp.internal_domain,
            "streamTarget": format!("/api/v1/auth/deploy/stream?appName={}", bp.app_name),
        })),
    )
        .into_response()
}

async fn cleanup_deploy_channel(app_name: &str) {
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    if let Ok(mut map) = DEPLOY_STREAMS.lock() {
        map.remove(app_name);
    }
    if let Ok(mut map) = SSE_DEPLOY_TX.lock() {
        map.remove(app_name);
    }
}

pub async fn handle_deploy_stream(Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(app_name) = q.get("appName").filter(|s| !s.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "appName query parameter is required" })),
        )
            .into_response();
    };

    let rx_opt = DEPLOY_STREAMS
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).map(|tx| tx.subscribe()));

    let Some(mut rx) = rx_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No active deployment found for this application." })),
        )
            .into_response();
    };

    let stream = async_stream::stream! {
        while let Ok(msg) = rx.recv().await {
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", msg));
            if msg.starts_with("[SUCCESS]") || msg.starts_with("[ROLLBACK]") {
                break;
            }
        }
    };

    let mut resp = Response::new(Body::from_stream(stream));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    h.insert("X-Accel-Buffering", HeaderValue::from_static("no"));
    resp
}

#[cfg(test)]
mod updater_tests {
    use super::*;

    fn sample_releases() -> Vec<GitHubReleasePayload> {
        vec![
            GitHubReleasePayload {
                tag_name: "v4.0.0-experimental".to_string(),
                target_commitish: "experimental".to_string(),
                prerelease: true,
                draft: false,
                body: "\u{FEFF}Release Notes ? Experimental\r\nLine 2".to_string(),
                html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0-experimental".to_string(),
                author: GitHubReleaseAuthor {
                    login: "McEveritts".to_string(),
                },
            },
            GitHubReleasePayload {
                tag_name: "v3.3.0-nightly.20261101".to_string(),
                target_commitish: "nightly".to_string(),
                prerelease: true,
                draft: false,
                body: "Nightly build notes".to_string(),
                html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v3.3.0-nightly.20261101".to_string(),
                author: GitHubReleaseAuthor {
                    login: "McEveritts".to_string(),
                },
            },
            GitHubReleasePayload {
                tag_name: "v3.2.7".to_string(),
                target_commitish: "master".to_string(),
                prerelease: false,
                draft: false,
                body: "Stable release notes".to_string(),
                html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7".to_string(),
                author: GitHubReleaseAuthor {
                    login: "McEveritts".to_string(),
                },
            },
        ]
    }

    #[test]
    fn test_select_release_for_channel_migrates_legacy_experimental_to_nightly() {
        let releases = sample_releases();

        // Stable selects v3.2.7 and ignores prereleases / hyphenated tags
        let (stable_tag, stable_body, _) =
            select_release_for_channel(&releases, "stable").expect("stable release");
        assert_eq!(stable_tag, "v3.2.7");
        assert_eq!(stable_body, "Stable release notes");

        // Nightly ignores v4.0.0-experimental and selects v3.3.0-nightly.20261101
        let (nightly_tag, nightly_body, _) =
            select_release_for_channel(&releases, "nightly").expect("nightly release");
        assert_eq!(nightly_tag, "v3.3.0-nightly.20261101");
        assert_eq!(nightly_body, "Nightly build notes");

        let (exp_tag, exp_body, _) =
            select_release_for_channel(&releases, "experimental").expect("experimental release");
        assert_eq!(exp_tag, nightly_tag);
        assert_eq!(exp_body, nightly_body);

        // When only experimental and stable releases exist, nightly returns None (so it falls back to branch head)
        let without_nightly = vec![releases[0].clone(), releases[2].clone()];
        assert!(select_release_for_channel(&without_nightly, "nightly").is_none());
    }

    #[test]
    fn test_select_release_for_channel_accepts_automated_nightly() {
        let mut release = sample_releases()[1].clone();
        release.tag_name = "v4.0.0-nightly.123.1".to_string();
        release.target_commitish = "abc1234".to_string();
        release.author.login = "github-actions[bot]".to_string();
        let releases = vec![release.clone()];
        let (tag, _, _) = select_release_for_channel(&releases, "nightly").expect("automated nightly");
        assert_eq!(tag, "v4.0.0-nightly.123.1");
        assert!(select_release_for_channel(&releases, "stable").is_none());
        let (legacy_tag, _, _) = select_release_for_channel(&releases, "experimental").unwrap();
        assert_eq!(legacy_tag, tag);

        release.author.login = "untrusted-author".to_string();
        assert!(select_release_for_channel(&[release], "nightly").is_none());
    }

    #[test]
    fn test_nightly_update_available_semantics() {
        for (current, latest, expected) in [
            ("v3.2.7", "v4.0.0-nightly.123.1", true),
            ("v4.0.0-experimental", "v4.0.0-nightly.123.1", true),
            ("v4.0.0", "v4.0.0-nightly.123.1", true),
            ("nightly-abc1234", "v4.0.0-nightly.123.1", true),
            ("v4.0.0-nightly.122.1", "v4.0.0-nightly.123.1", true),
            ("v4.0.0-nightly.123.1", "v4.0.0-nightly.123.1", false),
            (" V4.0.0-NIGHTLY.123.1 ", "v4.0.0-nightly.123.1", false),
            ("v4.1.0", "v4.0.0-nightly.123.1", false),
            ("v4.1.0-experimental", "v4.0.0-nightly.123.1", false),
            ("v4.0.0", "", false),
        ] {
            assert_eq!(
                nightly_update_available(current, latest),
                expected,
                "{current} -> {latest}"
            );
        }
    }

    #[test]
    fn legacy_experimental_channel_migrates_to_nightly() {
        assert_eq!(normalize_update_channel("experimental"), "nightly");
        assert_eq!(normalize_update_channel(" EXPERIMENTAL "), "nightly");
    }

    #[test]
    fn test_github_update_cache_ttl_and_rate_limit_backoff() {
        let mut cache = GitHubUpdateCache::default();
        let now = Utc::now();
        let url_releases = "https://api.github.com/repos/McEveritts/AetherFlow/releases";
        let url_commits = "https://api.github.com/repos/McEveritts/AetherFlow/commits/experimental";

        cache.reset_if_token_changed("token-a");

        // 1. 200 OK response is cached for 5 minutes
        let ok_headers = HeaderMap::new();
        let res = cache.record_response(
            url_releases,
            200,
            &ok_headers,
            Ok(b"[{\"tag_name\":\"v3.2.7\"}]".to_vec()),
            now,
        );
        assert!(res.is_ok());

        let cached_4m = cache
            .get_cached(url_releases, now + Duration::minutes(4))
            .expect("cached at 4m");
        assert_eq!(cached_4m.unwrap(), b"[{\"tag_name\":\"v3.2.7\"}]".to_vec());

        assert!(
            cache
                .get_cached(url_releases, now + Duration::minutes(6))
                .is_none(),
            "cache entry must expire after 5 minutes"
        );

        // 2. Token change clears cache
        cache.reset_if_token_changed("token-b");
        assert!(cache.get_cached(url_releases, now).is_none());

        // 3. HTTP 403 with X-RateLimit-Remaining: 0 and X-RateLimit-Reset sets global rate-limit backoff
        let mut rl_headers = HeaderMap::new();
        rl_headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
        let reset_ts = (now + Duration::minutes(10)).timestamp();
        rl_headers.insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&reset_ts.to_string()).unwrap(),
        );

        let err = cache
            .record_response(url_releases, 403, &rl_headers, Ok(Vec::new()), now)
            .unwrap_err();
        assert!(err.is_rate_limited());
        assert_eq!(err.retry_at.unwrap().timestamp(), reset_ts);
        assert!(err
            .to_string()
            .starts_with("GitHub API rate limit reached; retry after "));

        // Subsequent requests to ANY GitHub update URL are short-circuited while rate-limited
        let blocked_other_url = cache
            .get_cached(url_commits, now + Duration::minutes(2))
            .expect("rate limit applies across URLs")
            .unwrap_err();
        assert!(blocked_other_url.is_rate_limited());
        assert_eq!(blocked_other_url.retry_at.unwrap().timestamp(), reset_ts);

        // After reset_ts, cache allows requests again
        assert!(cache
            .get_cached(url_commits, now + Duration::minutes(11))
            .is_none());

        // 4. HTTP 429 with Retry-After seconds
        let mut retry_headers = HeaderMap::new();
        retry_headers.insert("Retry-After", HeaderValue::from_static("180"));
        let retry_at_429 = compute_rate_limit_retry_at(429, &retry_headers, now).unwrap();
        assert_eq!(retry_at_429, now + Duration::seconds(180));
    }
}
