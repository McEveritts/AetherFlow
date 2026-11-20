use crate::auth::{api_error, blocking_auth_work, secure_cookie_enabled, AuthUser};
use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Duration, Utc};
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::broadcast;

#[cfg(test)]
#[path = "storage_hillclimb_tests.rs"]
mod hillclimb_tests;

#[cfg(test)]
#[path = "storage_update_observability_tests.rs"]
mod update_observability_tests;

#[path = "storage_accounting.rs"]
mod accounting;

// Each response owns an already-open file. Reads stay bounded, including for
// full downloads, and never occupy a runtime worker with filesystem I/O.
fn stream_file(file: fs::File, size: u64) -> Body {
    let stream = async_stream::stream! {
        let mut file = tokio::fs::File::from_std(file).take(size);
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let count = match file.read(&mut buffer).await {
                Ok(count) => count,
                Err(error) => { yield Err(error); break; }
            };
            if count == 0 {
                break;
            }
            yield Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(&buffer[..count]));
        }
    };
    Body::from_stream(stream)
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn encoded_headers_decode_utf8_without_form_encoding_rules() {
        for (encoded, expected) in [
            (
                "%E5%AA%92%E4%BD%93%2F%E7%94%B5%E5%BD%B1.mkv",
                "媒体/电影.mkv",
            ),
            (
                "%2Fmnt%2Fm%C3%A9dias%2F%C3%A9t%C3%A9.txt",
                "/mnt/médias/été.txt",
            ),
            ("gr%C3%B6%C3%9Fe.txt", "größe.txt"),
            ("a+b%20c%25.txt", "a+b c%.txt"),
            ("%2f%6d%6e%74", "/mnt"),
            ("", ""),
        ] {
            assert_eq!(
                percent_decode_header_utf8(encoded).as_deref(),
                Some(expected)
            );
            assert_eq!(
                percent_decode_header_utf8(&urlencoding::encode(expected)).as_deref(),
                Some(expected)
            );
        }
        for invalid in ["%FF", "%C3%28", "%ED%A0%80", "%C0%AF", "%", "%0", "%GG"] {
            assert_eq!(percent_decode_header_utf8(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn backup_reauth_prefers_json_utf8_then_encoded_then_legacy_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Reauth-Password", HeaderValue::from_static("legacy"));
        headers.insert(
            "X-Reauth-Password-Encoded",
            HeaderValue::from_static("m%C3%A9dias%2Bsecret"),
        );
        for password in ["密码 媒体", "été größe blåbær español", "a+% passphrase"] {
            let body = serde_json::to_vec(&serde_json::json!({"password": password})).unwrap();
            assert_eq!(
                backup_reauth_password(&headers, &body).as_deref(),
                Some(password)
            );
        }
        for body in [b"".as_slice(), b"{}", b"{\"password\":null}"] {
            assert_eq!(
                backup_reauth_password(&headers, body).as_deref(),
                Some("médias+secret")
            );
        }
        headers.insert("X-Reauth-Password-Encoded", HeaderValue::from_static("%FF"));
        assert_eq!(
            backup_reauth_password(&headers, b"").as_deref(),
            Some("legacy")
        );
        for password in [String::new(), "x".repeat(1025), "密".repeat(342)] {
            let body = serde_json::to_vec(&serde_json::json!({"password": password})).unwrap();
            assert_eq!(backup_reauth_password(&headers, &body), None);
        }
        let body = serde_json::to_vec(&serde_json::json!({"password": "x".repeat(1024)})).unwrap();
        assert_eq!(backup_reauth_password(&headers, &body).unwrap().len(), 1024);
        assert_eq!(backup_reauth_password(&HeaderMap::new(), b"{}"), None);
    }

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
        assert_eq!(
            safe_backup_path(&base, "backup.sqlite").unwrap(),
            base.join("backup.sqlite")
        );
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

        let err =
            finalize_assembled_backup_upload(&dir, clean_base, &temp_final, &final_path, &checksum)
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
        assert!(
            overwrite_err.is_err(),
            "mismatched checksum must fail activation"
        );

        let (verified, _manifest) = read_verified_backup_checksum(&dir, clean_base)
            .expect("original backup must remain verified");
        assert_eq!(verified.actual_sha256, first_checksum);
        let check_conn = rusqlite::Connection::open(&final_path).unwrap();
        let marker: String = check_conn
            .query_row("SELECT marker FROM generation LIMIT 1", [], |row| {
                row.get(0)
            })
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

        let (verified, _manifest) = read_verified_backup_checksum(&backup_dir, clean_base)
            .expect("completed upload must verify");
        assert_eq!(verified.actual_sha256, expected_sha);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_launch_ack_accepts_only_consistent_terminal_receipts() {
        for success in [true, false] {
            let mut receipt = af_models::SelfUpdateJobStatus {
                status: if success { "succeeded" } else { "failed" }.into(),
                completed: true,
                success,
                job_unit: "aetherflow-self-update-deploy-stable-abcdef12.service".into(),
                error: if success { "" } else { "Fixture failure" }.into(),
                exit_code: Some(if success { 0 } else { 9 }),
            };
            let raw = serde_json::to_string(&receipt).unwrap();
            assert_eq!(
                validate_runner_self_update_initiation_payload(&raw)
                    .unwrap()
                    .0,
                receipt.job_unit
            );
            receipt.completed = false;
            assert!(validate_runner_self_update_initiation_payload(
                &serde_json::to_string(&receipt).unwrap()
            )
            .is_err());
        }
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
        assert_eq!(
            unit,
            "aetherflow-self-update-deploy-stable-abcdef12.service"
        );
        assert_eq!(engine, "af_release_rust");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Backups, Chunked Upload/Download, Retention & Smart Schedule
// ─────────────────────────────────────────────────────────────────────────────

static VALID_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]+\.sqlite$").unwrap());
static VALID_UPLOAD_SESSION_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap());
static BACKUP_UPLOAD_MU: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const DEFAULT_BACKUP_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
const MAX_BACKUP_UPLOAD_CHUNKS: usize = 4096;
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

fn ensure_private_backup_dir(dir: &StdPath) -> anyhow::Result<()> {
    use std::path::Component;
    let mut acc = std::path::PathBuf::new();
    for comp in dir.components() {
        match comp {
            Component::Prefix(p) => acc.push(p.as_os_str()),
            Component::RootDir => acc.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!(
                    "parent traversal rejected in backup directory {}",
                    dir.display()
                );
            }
            Component::Normal(part) => {
                acc.push(part);
                match fs::symlink_metadata(&acc) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            anyhow::bail!("symlink rejected in backup directory {}", acc.display());
                        }
                        if !meta.is_dir() {
                            anyhow::bail!(
                                "non-directory component in backup path {}",
                                acc.display()
                            );
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::DirBuilderExt;
                            let mut builder = fs::DirBuilder::new();
                            builder.mode(0o700);
                            if let Err(mk_err) = builder.create(&acc) {
                                if mk_err.kind() != std::io::ErrorKind::AlreadyExists {
                                    return Err(mk_err.into());
                                }
                            }
                        }
                        #[cfg(not(unix))]
                        {
                            fs::create_dir(&acc)?;
                        }
                        let meta = fs::symlink_metadata(&acc)?;
                        if meta.file_type().is_symlink() || !meta.is_dir() {
                            anyhow::bail!("invalid backup directory created at {}", acc.display());
                        }
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
    }
    #[cfg(unix)]
    if !acc.as_os_str().is_empty() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::symlink_metadata(&acc)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            anyhow::bail!("symlink or non-directory at backup root {}", acc.display());
        }
        let euid = unsafe { libc::geteuid() };
        if (meta.mode() & 0o777) != 0o700 && (euid == 0 || meta.uid() == euid) {
            fs::set_permissions(&acc, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

struct CrossProcessUploadLock {
    file: fs::File,
}

impl CrossProcessUploadLock {
    fn acquire(lock_path: &StdPath) -> anyhow::Result<Self> {
        if let Some(parent) = lock_path.parent() {
            ensure_private_backup_dir(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::io::AsRawFd;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 {
                anyhow::bail!(
                    "upload lock {} must be a single-link regular file",
                    lock_path.display()
                );
            }
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
struct CachedBackupVerification {
    stamp: BackupStamp,
    checked: Instant,
    verification: af_runner::af_host::ChecksumVerification,
    manifest: af_runner::af_host::BackupManifest,
}
#[allow(clippy::type_complexity)]
static BACKUP_VERIFICATIONS: Lazy<
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

fn open_verified_backup(
    directory: &StdPath,
    filename: &str,
) -> anyhow::Result<(fs::File, af_runner::af_host::ChecksumVerification)> {
    let (file, verification, _) = open_verified_backup_with_manifest(directory, filename)?;
    Ok((file, verification))
}

// Bound expensive verification and assembly independently from password checks.
static BACKUP_BLOCKING_LIMIT: Lazy<tokio::sync::Semaphore> =
    Lazy::new(|| tokio::sync::Semaphore::new(2));
async fn blocking_backup_work<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    let permit = BACKUP_BLOCKING_LIMIT
        .try_acquire()
        .map_err(|_| anyhow::anyhow!("Backup workers busy; retry shortly"))?;
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await?)
}

fn backup_download_chunk(q: &HashMap<String, String>) -> anyhow::Result<Option<(u64, u64)>> {
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

struct BackupReauth {
    next_id: u64,
    attempts: HashMap<i64, Vec<(u64, Instant)>>,
    verified: HashMap<(i64, String, [u8; 32]), Instant>,
}
static BACKUP_REAUTH: Lazy<Mutex<BackupReauth>> = Lazy::new(|| {
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
    let now = Instant::now();
    state.attempts.retain(|_, entries| {
        entries.retain(|(_, time)| now.duration_since(*time) < StdDuration::from_secs(60));
        !entries.is_empty()
    });
    if state.attempts.get(&user_id).map_or(0, Vec::len) >= 10 {
        return None;
    }
    if state.attempts.len() >= 4096 && !state.attempts.contains_key(&user_id) {
        return None;
    }
    let attempt_id = state.next_id;
    state.next_id = state.next_id.wrapping_add(1);
    state
        .attempts
        .entry(user_id)
        .or_default()
        .push((attempt_id, now));
    Some(attempt_id)
}

fn refund_backup_reauth_attempt(user_id: i64, attempt_id: u64) {
    if let Ok(mut state) = BACKUP_REAUTH.lock() {
        let mut remove_user = false;
        if let Some(entries) = state.attempts.get_mut(&user_id) {
            entries.retain(|(id, _)| *id != attempt_id);
            remove_user = entries.is_empty();
        }
        if remove_user {
            state.attempts.remove(&user_id);
        }
    }
}

fn verify_backup_password(user_id: i64, session: &str, password: &str, hash: &str) -> bool {
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
        state.attempts.retain(|_, entries| {
            entries.retain(|(_, time)| now.duration_since(*time) < StdDuration::from_secs(60));
            !entries.is_empty()
        });
        if state.attempts.get(&user_id).map_or(0, Vec::len) >= 10 {
            return false;
        }
        if state.attempts.len() >= 4096 && !state.attempts.contains_key(&user_id) {
            return false;
        }
        let attempt_id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state
            .attempts
            .entry(user_id)
            .or_default()
            .push((attempt_id, now));
        attempt_id
    };
    let valid = !hash.is_empty() && bcrypt::verify(password, hash).unwrap_or(false);
    if valid {
        if let Ok(mut state) = BACKUP_REAUTH.lock() {
            let mut remove_user = false;
            if let Some(entries) = state.attempts.get_mut(&user_id) {
                entries.retain(|(id, _)| *id != reserved_id);
                remove_user = entries.is_empty();
            }
            if remove_user {
                state.attempts.remove(&user_id);
            }
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
struct BackupDownloadTicket {
    user_id: i64,
    session: String,
    filename: String,
    issued: Instant,
}
static BACKUP_DOWNLOAD_TICKETS: Lazy<Mutex<HashMap<String, BackupDownloadTicket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn issue_backup_download_ticket(user: &AuthUser, filename: &str) -> anyhow::Result<String> {
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

fn redeem_backup_download_ticket(token: &str, user: &AuthUser, filename: &str) -> bool {
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

fn percent_decode_header_utf8(raw: &str) -> Option<String> {
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

fn backup_reauth_password(headers: &HeaderMap, body: &[u8]) -> Option<String> {
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

async fn authorize_backup_password(
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
    let session_auth_time = req
        .extensions()
        .get::<crate::auth::SessionAuthTime>()
        .map(|t| t.0);
    let (parts, body) = req.into_parts();
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
    if !authorize_backup_password(&user, session_auth_time, &parts.headers, &body).await {
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
        Err(e) => api_error(StatusCode::SERVICE_UNAVAILABLE, "BUSY", e.to_string()),
    }
}

pub async fn get_backups_list() -> Response {
    match blocking_backup_work(list_verified_backups).await {
        Ok(response) => response,
        Err(error) => api_error(StatusCode::SERVICE_UNAVAILABLE, "BUSY", error.to_string()),
    }
}

fn list_verified_backups() -> Response {
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
        let Ok((_file, verification, manifest)) =
            open_verified_backup_with_manifest(&backup_dir, &name)
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
    let ticket = extract_cookie(req.headers(), BACKUP_DOWNLOAD_COOKIE);
    let ticket_authorized = ticket
        .as_deref()
        .is_some_and(|token| redeem_backup_download_ticket(token, &user, &filename));
    let session_auth_time = req
        .extensions()
        .get::<crate::auth::SessionAuthTime>()
        .map(|t| t.0);
    if !ticket_authorized
        && !authorize_backup_password(&user, session_auth_time, req.headers(), &[]).await
    {
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
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Backup worker failed",
            )
        }
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
    if total_chunks == 0 || total_chunks > MAX_BACKUP_UPLOAD_CHUNKS {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!("total query must be between 1 and {MAX_BACKUP_UPLOAD_CHUNKS}"),
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

    let upload_id =
        if let Some(raw_upload_id) = upload_id_param.map(str::trim).filter(|val| !val.is_empty()) {
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

    if ensure_private_backup_dir(backup_dir).is_err() {
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
    for entry in fs::read_dir(&upload_dir).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Unable to inspect upload progress".to_owned(),
        )
    })? {
        let entry = entry.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Unable to inspect upload progress".to_owned(),
            )
        })?;
        let filename = entry.file_name();
        let index = filename
            .to_str()
            .and_then(|name| name.strip_suffix(".part"))
            .and_then(|index| index.parse::<usize>().ok());
        if index.is_some_and(|index| index < total_chunks)
            && entry
                .file_type()
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "Unable to inspect upload progress".to_owned(),
                    )
                })?
                .is_file()
        {
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
            format!(
                "Uploaded backup failed SQLite integrity verification: {}",
                err
            ),
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
    if total_chunks > MAX_BACKUP_UPLOAD_CHUNKS || chunk_index >= total_chunks {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid chunk count or chunk index",
        );
    }

    let permit = match BACKUP_BLOCKING_LIMIT.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "Backup workers busy; retry shortly",
            )
        }
    };
    let auth_user = req.extensions().get::<AuthUser>().cloned();
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Failed to read chunk payload",
        );
    };

    let backup_dir = get_backup_dir();
    let expected_checksum = q.get("checksum").cloned();
    let upload_id = q.get("upload_id").or_else(|| q.get("session_id")).cloned();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let auth_pair = auth_user
            .as_ref()
            .map(|user| (user.user_id, user.jti.as_str()));
        process_backup_chunk_upload_in_dir(
            &backup_dir,
            &filename,
            chunk_index,
            total_chunks,
            expected_checksum.as_deref(),
            upload_id.as_deref(),
            auth_pair,
            &bytes,
        )
    })
    .await
    {
        Ok(Ok(payload)) => Json(payload).into_response(),
        Ok(Err((status, code, msg))) => {
            if code == "CHECKSUM_MISMATCH" {
                return (
                    status,
                    Json(
                        serde_json::json!({"error":"Checksum verification failed", "message": msg}),
                    ),
                )
                    .into_response();
            }
            api_error(status, code, msg)
        }
        Err(error) => api_error(StatusCode::SERVICE_UNAVAILABLE, "BUSY", error.to_string()),
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
    let payload = tokio::task::spawn_blocking(|| {
        let conn = af_db::get_read_conn().ok()?;
        let (mode, next_run): (String, String) = conn
            .query_row(
                "SELECT COALESCE(backup_schedule_mode, 'manual'), COALESCE(backup_next_run_at, '') FROM settings WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or_else(|_| ("manual".to_string(), String::new()));
        let analysis = af_services::workers::analyze_optimal_backup_window(&conn);
        let mut payload = serde_json::json!({
            "mode": mode,
            "running": mode == "smart",
            "optimal_window": analysis,
        });
        if !next_run.is_empty() {
            payload["next_backup_at"] = serde_json::Value::String(next_run);
        }
        Some(payload)
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| serde_json::json!({ "mode": "manual", "running": false }));
    Json(payload).into_response()
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

// ─────────────────────────────────────────────────────────────────────────────
// 2. FileShare Upload, Download, Delete & Quota Headroom
// ─────────────────────────────────────────────────────────────────────────────

const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024; // 50 MiB

static BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".sh", ".bat", ".cmd", ".ps1", ".php", ".jsp", ".cgi", ".pif", ".scr", ".com", ".msi",
    ".vbs", ".vbe", ".wsf", ".wsh", ".py", ".rb", ".pl", ".jar",
];

fn upload_dir_from_config(upload: Option<&str>, state: Option<&str>) -> PathBuf {
    if let Some(path) = upload.filter(|p| !p.trim().is_empty()) {
        return PathBuf::from(path);
    }
    let state = state
        .and_then(|p| p.split(':').next())
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("/var/lib/aetherflow");
    PathBuf::from(state).join("uploads")
}

fn get_upload_dir() -> PathBuf {
    upload_dir_from_config(
        env::var("AETHERFLOW_UPLOAD_DIR").ok().as_deref(),
        env::var("STATE_DIRECTORY").ok().as_deref(),
    )
}

fn fileshare_directory(root: &StdPath, raw_sub_path: &str) -> std::io::Result<af_files::BrowserFs> {
    let browser = af_files::BrowserFs::open(root)?;
    let relative = raw_sub_path.trim().trim_start_matches('/');
    if relative.is_empty() || relative == "." {
        return Ok(browser);
    }
    browser.scoped(relative)
}

#[cfg(test)]
#[tokio::test]
async fn fileshare_reads_do_not_create_upload_directories() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let root = env::temp_dir().join(format!("af-fileshare-read-{}", uuid::Uuid::new_v4()));
    env::set_var("AETHERFLOW_UPLOAD_DIR", &root);
    let query = || Query(HashMap::from([("path".into(), "missing/nested".into())]));
    let listing = get_files_list(query()).await;
    assert_eq!(listing.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(listing.into_body(), 4096)
            .await
            .unwrap()
            .as_ref(),
        b"[]"
    );
    assert_eq!(
        download_file(Path("missing.txt".into()), query())
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(!root.exists());
    fs::create_dir(&root).unwrap();
    assert_eq!(get_files_list(query()).await.status(), StatusCode::OK);
    assert!(!root.join("missing").exists());
    fs::remove_dir(root).unwrap();
}

fn create_fileshare_directory(
    root: &StdPath,
    raw_sub_path: &str,
) -> std::io::Result<af_files::BrowserFs> {
    fs::create_dir_all(root)?;
    let browser = af_files::BrowserFs::open(root)?;
    let relative = raw_sub_path.trim().trim_start_matches('/');
    if relative.is_empty() || relative == "." {
        return Ok(browser);
    }
    browser.create_directory_all(relative)?;
    browser.scoped(relative)
}

pub(crate) async fn lock_fileshare_mutations() -> tokio::sync::OwnedMutexGuard<()> {
    accounting::MUTATIONS.clone().lock_owned().await
}

pub(crate) fn discard_fileshare_uploads(user_id: i64) {
    if let Ok(mut sessions) = FILESHARE_UPLOADS.lock() {
        sessions.retain(|(owner, _), _| *owner != user_id);
    }
}

pub(crate) fn cleanup_fileshare_object(
    root: &str,
    directory: &str,
    filename: &str,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let relative_root = root
        .strip_prefix('/')
        .filter(|path| !path.is_empty())
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid fileshare storage root"))?;
    if filename.contains('/') || filename.is_empty() || filename == "." || filename == ".." {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid fileshare object name",
        ));
    }
    let browser = af_files::BrowserFs::open(StdPath::new("/"))?
        .scoped(relative_root)?
        .scoped(directory)?;
    if browser.metadata(filename)?.kind != "file" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Fileshare object is not a regular file",
        ));
    }
    browser.remove(filename)
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
    let raw_path = q.get("path").cloned().unwrap_or_default();
    let listing = tokio::task::spawn_blocking(move || {
        fileshare_directory(&get_upload_dir(), &raw_path).and_then(|browser| browser.list(""))
    })
    .await;
    let entries = match listing {
        Ok(Ok(entries)) => entries,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Unable to open files directory",
            )
        }
    };
    let mut list: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            matches!(entry.kind.as_str(), "file" | "directory")
                && !entry.name.starts_with(".af-upload-")
        })
        .map(|entry| {
            let is_dir = entry.kind == "directory";
            let extension = if is_dir {
                String::new()
            } else {
                StdPath::new(&entry.name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{}", e))
                    .unwrap_or_default()
            };
            serde_json::json!({
                "name": entry.name, "size": entry.size, "modTime": entry.modified,
                "extension": extension, "isDir": is_dir,
            })
        })
        .collect();
    list.sort_by(|a, b| {
        b["isDir"]
            .as_bool()
            .cmp(&a["isDir"].as_bool())
            .then_with(|| {
                a["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .cmp(&b["name"].as_str().unwrap_or("").to_lowercase())
            })
    });
    Json(list).into_response()
}

const MAX_FILESHARE_CHUNK_BYTES: usize = 5 * 1024 * 1024;
const FILESHARE_UPLOAD_TTL: StdDuration = StdDuration::from_secs(10 * 60);

struct FileshareUpload {
    filename: String,
    directory: String,
    total_chunks: usize,
    next_chunk: usize,
    size: usize,
    prefix: Vec<u8>,
    pending: af_files::PendingUpload,
    original: Option<fs::File>,
    updated: Instant,
}

static FILESHARE_WORKERS: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(4)));

static FILESHARE_UPLOADS: Lazy<Mutex<HashMap<(i64, String), FileshareUpload>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[allow(clippy::too_many_arguments)]
fn append_fileshare_chunk_with(
    sessions: &mut HashMap<(i64, String), FileshareUpload>,
    root: &StdPath,
    user_id: i64,
    upload_id: &str,
    directory: &str,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    data: &[u8],
    publish: impl FnOnce(FileshareUpload) -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        total_chunks > 0 && total_chunks <= 1024 && chunk_index < total_chunks,
        "Invalid chunk index or count"
    );
    anyhow::ensure!(
        VALID_UPLOAD_SESSION_ID_RE.is_match(upload_id),
        "Invalid upload session id"
    );
    anyhow::ensure!(
        data.len() <= MAX_FILESHARE_CHUNK_BYTES,
        "Upload chunk exceeds 5 MiB"
    );
    sessions.retain(|_, session| session.updated.elapsed() < FILESHARE_UPLOAD_TTL);
    let key = (user_id, upload_id.to_string());
    if chunk_index == 0 {
        anyhow::ensure!(
            !sessions.contains_key(&key),
            "Upload session already exists"
        );
        anyhow::ensure!(sessions.len() < 64, "Too many pending uploads");
        let browser = create_fileshare_directory(root, directory)?;
        let original = match browser.open_file(filename) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let pending = if original.is_some() {
            browser.begin_replace(filename)?
        } else {
            browser.begin_upload(filename)?
        };
        sessions.insert(
            key.clone(),
            FileshareUpload {
                filename: filename.to_string(),
                directory: directory.to_string(),
                total_chunks,
                next_chunk: 0,
                size: 0,
                prefix: Vec::new(),
                pending,
                original,
                updated: Instant::now(),
            },
        );
    }
    let session = sessions
        .get_mut(&key)
        .ok_or_else(|| anyhow::anyhow!("Upload session expired or missing"))?;
    anyhow::ensure!(
        session.filename == filename
            && session.directory == directory
            && session.total_chunks == total_chunks,
        "Upload session metadata changed"
    );
    anyhow::ensure!(
        session.next_chunk == chunk_index,
        "Upload chunk out of order"
    );
    if session.size.saturating_add(data.len()) > MAX_UPLOAD_SIZE {
        sessions.remove(&key);
        anyhow::bail!("File exceeds maximum allowed size of 50 MiB");
    }
    // Inspect the assembled prefix too, so splitting an executable's magic
    // bytes between requests cannot bypass the file content check.
    let mut file = session.pending.file()?;
    let mut prefix = session.prefix.clone();
    prefix.extend_from_slice(&data[..data.len().min(4 - prefix.len())]);
    if is_blocked_executable_magic(&prefix).is_some() {
        sessions.remove(&key);
        anyhow::bail!("File content type not allowed");
    }
    session.prefix = prefix;
    file.seek(SeekFrom::Start(session.size as u64))?;
    if let Err(error) = file.write_all(data) {
        sessions.remove(&key);
        return Err(error.into());
    }
    session.size += data.len();
    session.next_chunk += 1;
    session.updated = Instant::now();
    if session.next_chunk == total_chunks {
        let session = sessions.remove(&key).expect("session exists while locked");
        publish(session)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn append_fileshare_chunk(
    sessions: &mut HashMap<(i64, String), FileshareUpload>,
    root: &StdPath,
    user_id: i64,
    upload_id: &str,
    directory: &str,
    filename: &str,
    chunk_index: usize,
    total_chunks: usize,
    data: &[u8],
) -> anyhow::Result<bool> {
    append_fileshare_chunk_with(
        sessions,
        root,
        user_id,
        upload_id,
        directory,
        filename,
        chunk_index,
        total_chunks,
        data,
        |session| {
            if let Some(original) = session.original {
                session.pending.commit_replace(&original)?;
            } else {
                session.pending.commit()?;
            }
            Ok(())
        },
    )
}

pub async fn upload_file(
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    // Admission precedes multipart body collection. The blocking closure owns
    // this permit too, including when the requesting client disconnects.
    let permit = match FILESHARE_WORKERS.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BUSY",
                "Upload workers busy; retry shortly",
            )
        }
    };
    let header_value = |key: &str| {
        headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let encoded_filename = headers
        .get("X-File-Name-Encoded")
        .and_then(|value| value.to_str().ok())
        .and_then(percent_decode_header_utf8)
        .filter(|name| !name.is_empty());
    let header_filename = encoded_filename
        .clone()
        .unwrap_or_else(|| header_value("X-File-Name"));
    let directory = headers
        .get("X-Target-Path-Encoded")
        .and_then(|value| value.to_str().ok())
        .and_then(percent_decode_header_utf8)
        .unwrap_or_else(|| header_value("X-Target-Path"));
    let upload_id = header_value("X-Upload-ID");
    let chunk_index = header_value("X-Chunk-Index");
    let total_chunks = header_value("X-Total-Chunks");
    let chunked = !upload_id.is_empty() || !chunk_index.is_empty() || !total_chunks.is_empty();
    let (chunk_index, total_chunks) = if chunked {
        match (chunk_index.parse::<usize>(), total_chunks.parse::<usize>()) {
            (Ok(index), Ok(count)) if !upload_id.is_empty() => (index, count),
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Chunked uploads require a session id, index and total",
                )
            }
        }
    } else {
        (0, 1)
    };
    let limit = if chunked {
        MAX_FILESHARE_CHUNK_BYTES
    } else {
        MAX_UPLOAD_SIZE
    };
    while let Ok(Ok(Some(mut field))) =
        tokio::time::timeout(StdDuration::from_secs(120), multipart.next_field()).await
    {
        if field.name() != Some("file") {
            continue;
        }
        let raw_filename = encoded_filename
            .as_deref()
            .or_else(|| {
                field
                    .file_name()
                    .filter(|name| !name.is_empty() && *name != "blob")
            })
            .unwrap_or(&header_filename);
        let filename = match sanitize_filename(raw_filename) {
            Ok(name) => name,
            Err(error) => {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string())
            }
        };
        let mut data = Vec::new();
        loop {
            match tokio::time::timeout(StdDuration::from_secs(120), field.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    if data.len().saturating_add(bytes.len()) > limit {
                        return api_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "PAYLOAD_TOO_LARGE",
                            "Upload exceeds file or chunk size limit",
                        );
                    }
                    data.extend_from_slice(&bytes);
                }
                Ok(Ok(None)) => break,
                _ => {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Invalid or timed out upload stream",
                    )
                }
            }
        }
        if is_blocked_executable_magic(&data).is_some() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "File content type not allowed",
            );
        }
        let response_name = filename.clone();
        let shared = accounting::MUTATIONS.clone().lock_owned().await;
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let _permit = permit;
            let _shared = shared;
            let root = get_upload_dir();
            let conn = af_db::get_conn()?;
            crate::auth::load_active_human_subject(&conn, user.user_id)
                .map_err(|_| anyhow::anyhow!("Fileshare account is no longer active"))?;
            if chunked {
                let mut sessions = FILESHARE_UPLOADS
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Upload state unavailable"))?;
                append_fileshare_chunk_with(
                    &mut sessions,
                    &root,
                    user.user_id,
                    &upload_id,
                    &directory,
                    &filename,
                    chunk_index,
                    total_chunks,
                    &data,
                    |session| accounting::publish(&conn, &root, user.user_id, session),
                )
            } else {
                let browser = create_fileshare_directory(&root, &directory)?;
                let original = match browser.open_file(&filename) {
                    Ok(file) => Some(file),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                let pending = if original.is_some() {
                    browser.begin_replace(&filename)?
                } else {
                    browser.begin_upload(&filename)?
                };
                pending.file()?.write_all(&data)?;
                accounting::publish(
                    &conn,
                    &root,
                    user.user_id,
                    FileshareUpload {
                        filename,
                        directory,
                        total_chunks: 1,
                        next_chunk: 1,
                        size: data.len(),
                        prefix: Vec::new(),
                        pending,
                        original,
                        updated: Instant::now(),
                    },
                )?;
                Ok(true)
            }
        })
        .await;
        return match result {
            Ok(Ok(complete)) => Json(serde_json::json!({ "message": if complete { "File uploaded successfully" } else { "Chunk received" }, "filename": response_name, "complete": complete })).into_response(),
            Ok(Err(error)) if error.is::<accounting::QuotaExceeded>() => api_error(StatusCode::PAYLOAD_TOO_LARGE, "QUOTA_EXCEEDED", error.to_string()),
            Ok(Err(error)) => api_error(StatusCode::CONFLICT, "UPLOAD_REJECTED", error.to_string()),
            Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Upload worker failed"),
        };
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
    let filename = match sanitize_filename(&filename) {
        Ok(name) => name,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()),
    };
    let name = filename.clone();
    let directory = q.get("path").cloned().unwrap_or_default();
    let opened = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let file = fileshare_directory(&get_upload_dir(), &directory)?.open_file(&name)?;
        let size = file.metadata()?.len();
        Ok((file, size))
    })
    .await;
    let (file, size) = match opened {
        Ok(Ok(pair)) => pair,
        _ => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "File not found"),
    };
    let mime = mime_guess::from_path(&filename).first_or_octet_stream();
    let mut resp = Response::new(stream_file(file, size));
    let h = resp.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        h.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!(
        "attachment; filename=\"{}\"",
        filename.replace(['\"', '\\'], "_")
    )) {
        h.insert(header::CONTENT_DISPOSITION, value);
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    resp
}

pub async fn delete_shared_file(
    Path(filename): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let filename = match sanitize_filename(&filename) {
        Ok(name) => name,
        Err(error) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()),
    };
    let response_name = filename.clone();
    let directory = q.get("path").cloned().unwrap_or_default();
    let shared = accounting::MUTATIONS.clone().lock_owned().await;
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let _shared = shared;
        let conn = af_db::get_conn()?;
        accounting::delete(&conn, &get_upload_dir(), &directory, &filename)
    })
    .await;
    match result {
        Ok(Ok(())) => {
            Json(serde_json::json!({"message": "File deleted", "filename": response_name}))
                .into_response()
        }
        _ => api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Unable to delete shared file",
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Storage Quotas
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
    rec.status = match rec.status.trim() {
        "" => "active".to_owned(),
        status => status.to_ascii_lowercase(),
    };
    if !matches!(rec.source.as_str(), "manual" | "runner") {
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
         COALESCE(updated_at, '') \
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
                updated_at: r.get(4)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            })
        },
    );

    match row {
        Ok(rec) => Ok(normalize_quota_record(rec)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(normalize_quota_record(UserQuotaRecord {
            user_id,
            username,
            quota_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            status: "active".to_string(),
            source: "manual".to_string(),
            updated_at: String::new(),
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        })),
        Err(error) => Err(error.into()),
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
         COALESCE(q.updated_at, '') \
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
                updated_at: r.get(6)?,
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

    accounting::quota_operation(user_id, Some(quota_bytes)).await
}

pub async fn refresh_user_quota(Path(user_id): Path<i64>) -> Response {
    accounting::quota_operation(user_id, None).await
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Updater & Deploy SSE
// ─────────────────────────────────────────────────────────────────────────────

static DEPLOY_STREAMS: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static DEPLOY_LAST_EVENT: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
pub static SSE_DEPLOY_TX: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct DeploymentRegistration {
    app_name: String,
    sender: broadcast::Sender<String>,
}

#[allow(clippy::result_large_err)]
fn register_deployment(app_name: &str) -> Result<DeploymentRegistration, Response> {
    let mut streams = DEPLOY_STREAMS.lock().map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INTERNAL_ERROR",
            "Deployment state unavailable",
        )
    })?;
    if streams.contains_key(app_name) {
        return Err(api_error(
            StatusCode::CONFLICT,
            "DEPLOYMENT_IN_PROGRESS",
            "A deployment for this application is already running",
        ));
    }
    let (sender, _) = broadcast::channel(64);
    streams.insert(app_name.to_string(), sender.clone());
    if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
        last.remove(app_name);
    }
    Ok(DeploymentRegistration {
        app_name: app_name.to_string(),
        sender,
    })
}

pub(crate) fn ensure_or_reuse_deploy_stream(app_name: &str) -> Option<broadcast::Sender<String>> {
    let mut streams = DEPLOY_STREAMS.lock().ok()?;
    let sender = if let Some(existing) = streams.get(app_name) {
        existing.clone()
    } else {
        let (sender, _) = broadcast::channel(64);
        streams.insert(app_name.to_string(), sender.clone());
        sender
    };
    Some(sender)
}

pub(crate) fn publish_deploy_json_event(
    app_name: &str,
    sender: &broadcast::Sender<String>,
    payload: &serde_json::Value,
) {
    let serialized = payload.to_string();
    if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
        last.insert(app_name.to_string(), serialized.clone());
    }
    if app_name == "mediaflow_engine" {
        af_services::publish_mediaflow_progress(payload);
    }
    let _ = sender.send(serialized);
}

pub(crate) fn release_deploy_stream_if_matching(
    app_name: &str,
    sender: &broadcast::Sender<String>,
) {
    if let Ok(mut streams) = DEPLOY_STREAMS.lock() {
        if streams
            .get(app_name)
            .is_some_and(|current| current.same_channel(sender))
        {
            streams.remove(app_name);
            if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
                last.remove(app_name);
            }
        }
    }
}

pub(crate) fn is_terminal_deploy_event(msg: &str) -> bool {
    if msg.starts_with("[SUCCESS]") || msg.starts_with("[ROLLBACK]") || msg.starts_with("[ERROR]") {
        return true;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(msg) {
        if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
            return matches!(
                status.to_ascii_lowercase().as_str(),
                "complete" | "completed" | "failed" | "error" | "success" | "done"
            );
        }
    }
    false
}

impl Drop for DeploymentRegistration {
    fn drop(&mut self) {
        release_deploy_stream_if_matching(&self.app_name, &self.sender);
    }
}

pub mod af_common {
    pub mod redact {
        pub fn redact_secrets(input: &str) -> String {
            af_services::redact_secrets(input)
        }
    }
}

fn deployment_restart_status(result: anyhow::Result<()>) -> String {
    match result {
        Ok(()) => {
            "[SUCCESS] Deployment configuration applied and managed service restarted.".to_string()
        }
        Err(error) => {
            let sanitized = af_common::redact::redact_secrets(&format!("{error:#}"));
            format!(
                "[ERROR] Deployment configuration applied, but managed service restart failed: {}",
                sanitized
            )
        }
    }
}

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
    fetch_github_update_url(
        &UPDATE_GITHUB_CACHE,
        &UPDATE_HTTP_CLIENT,
        &url,
        &token,
        Utc::now(),
    )
    .await
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
            conn.query_row(
                "SELECT update_channel FROM settings WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .ok()
        })
        .unwrap_or_else(|| UPDATE_CHANNEL_STABLE.to_string());
    normalize_update_channel(&raw)
}

fn get_local_version() -> String {
    af_runner::af_release::runtime::runtime_identity()
        .version
        .clone()
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    let parse_ver = |v: &str| -> (i32, i32, i32, i32) {
        let clean = v
            .trim()
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("");
        let parts: Vec<&str> = clean.split('.').collect();
        let major = parts
            .first()
            .and_then(|p| p.parse::<i32>().ok())
            .unwrap_or(0);
        let minor = parts
            .get(1)
            .and_then(|p| p.parse::<i32>().ok())
            .unwrap_or(0);
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
    if current_version
        .trim()
        .to_ascii_lowercase()
        .starts_with("nightly-")
    {
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
    serde_json::from_slice::<Vec<GitHubReleasePayload>>(&body_bytes).map_err(|e| {
        GitHubUpdateError {
            status: 0,
            retry_at: None,
            custom_message: Some(e.to_string()),
        }
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
                match fetch_branch_head(UPDATE_CHANNEL_NIGHTLY, &["nightly", "Nightly"]).await {
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
    if matches!(status, "succeeded" | "failed") {
        let receipt: af_models::SelfUpdateJobStatus = serde_json::from_value(parsed_job.clone())
            .map_err(|error| format!("runner returned invalid terminal receipt: {error}"))?;
        receipt.validate_invariants(None)?;
    } else if status != "initiated"
        || parsed_job
            .get("completed")
            .and_then(|value| value.as_bool())
            != Some(false)
    {
        return Err("runner returned neither a valid initiation nor a terminal receipt".into());
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
            conn.query_row(
                "SELECT update_channel FROM settings WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .ok()
        })
        .unwrap_or_else(|| "stable".to_string());
    let channel = normalize_update_channel(&channel).to_string();

    // Serialize with Marketplace lifecycle jobs. The updater restarts the API
    // and runner; a running package job would lose its runner stream and the
    // package script would be killed mid-flight. Holding the lifecycle mutex
    // across the launch also guarantees a queued job re-checks after the
    // updater is registered (see dispatch_package_lifecycle).
    // A short wait tolerates a brief af-heal restart holding the mutex.
    let lifecycle_guard = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        af_services::PACKAGE_LIFECYCLE_MUTEX.lock(),
    )
    .await;
    let _lifecycle_guard = match lifecycle_guard {
        Ok(guard) if !af_services::has_active_package_jobs() => guard,
        _ => {
            return api_error(
                StatusCode::CONFLICT,
                "PACKAGE_LIFECYCLE_IN_PROGRESS",
                "An application install, update, or removal is in progress; retry the system update after it finishes",
            );
        }
    };

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

    let (job_unit, engine_name) = match validate_runner_self_update_initiation_payload(
        &runner_resp.output,
    ) {
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

    // A fast worker can finish before systemd-run returns. Preserve its exact
    // terminal receipt instead of manufacturing a fresh pending operation.
    if let Ok(receipt) = serde_json::from_str::<af_models::SelfUpdateJobStatus>(&runner_resp.output)
    {
        if receipt.completed {
            return Json(serde_json::json!({
                "message": if receipt.success { "System deployment completed successfully." } else { "System deployment failed; inspect its receipt and authenticated logs." },
                "status": receipt.status,
                "completed": receipt.completed,
                "success": receipt.success,
                "error": receipt.error,
                "exit_code": receipt.exit_code,
                "channel": channel,
                "engine": engine_name,
                "job_unit": job_unit,
            })).into_response();
        }
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
    let action = |unit: &str| {
        unit.strip_prefix("aetherflow-self-update-")
            .and_then(|suffix| suffix.split('-').next())
            .filter(|command| matches!(*command, "deploy" | "rollback" | "restart"))
            .map(str::to_owned)
    };
    if !job_unit.is_empty() && !af_models::is_valid_self_update_job_unit_name(&job_unit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "A valid self-update job_unit is required",
        );
    }
    if q.get("action")
        .is_some_and(|expected| action(&job_unit).as_ref() != Some(expected))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Update action does not match job identity",
        );
    }

    let status_req = af_models::SelfUpdateStatusRequest {
        job_unit: job_unit.clone(),
    };
    match af_runner::dispatch_self_update_status_request(&status_req).await {
        Ok(status) => {
            let idle = job_unit.is_empty()
                && status.job_unit.is_empty()
                && status.status == "succeeded"
                && status.completed
                && status.success
                && status.exit_code == Some(0)
                && status.error.is_empty();
            let recovery = job_unit.is_empty()
                && status.job_unit.is_empty()
                && status.status == "recovery_required"
                && !status.completed
                && !status.success
                && status.exit_code.is_none();
            if !idle
                && !recovery
                && (status.job_unit != status.job_unit.trim()
                    || status
                        .validate_invariants((!job_unit.is_empty()).then_some(job_unit.as_str()))
                        .is_err())
            {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "UPDATE_STATUS_ERROR",
                    "Update status identity or state could not be verified",
                );
            }
            let state = if idle {
                "idle"
            } else if recovery {
                "interrupted"
            } else {
                match status.status.as_str() {
                    "succeeded" => "complete",
                    "failed" => "failed",
                    _ => "running",
                }
            };
            let error = if recovery {
                "System update recovery is required before another update can start"
            } else if !status.error.is_empty() {
                "System update failed; inspect authenticated updater diagnostics"
            } else {
                ""
            };
            Json(serde_json::json!({
                "state": state,
                "action": action(&status.job_unit),
                "operationId": if status.job_unit.is_empty() { None } else { Some(&status.job_unit) },
                "job_unit": status.job_unit,
                "active_job_unit": if !status.completed { &status.job_unit } else { "" },
                "status": if idle { "idle" } else { &status.status },
                "completed": status.completed,
                "success": !idle && status.success,
                "error": error,
                "exit_code": if idle { None } else { status.exit_code },
            })).into_response()
        }
        Err(err) => {
            let msg = err.to_string();
            let code = if !job_unit.is_empty()
                && (msg.contains("not found") || msg.contains("Not found"))
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            tracing::warn!(error = %err, "System update status observation failed");
            api_error(
                code,
                "UPDATE_STATUS_ERROR",
                if code == StatusCode::NOT_FOUND {
                    "Tracked update receipt was not found; its outcome is unverified"
                } else {
                    "System update status is unavailable; no idle or completed state is confirmed"
                },
            )
        }
    }
}

#[allow(clippy::result_large_err)]
fn require_admin(auth_user: &AuthUser) -> Result<(), Response> {
    if auth_user.role != "admin" {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Admin access required",
        ));
    }
    Ok(())
}

fn allocate_or_verify_deploy_port(bp: &af_services::AppBlueprint) -> i32 {
    if bp.default_port <= 0 {
        return 0;
    }
    if let Ok(Some(existing)) = af_db::get_app_ingress_config(&bp.app_name) {
        if (1..=65535).contains(&existing.listen_port) {
            return existing.listen_port;
        }
    }
    if !bp.supports_dynamic_port || bp.fallback_port_range == [0, 0] {
        return bp.default_port;
    }
    if (1..=65535).contains(&bp.default_port)
        && std::net::TcpListener::bind(("127.0.0.1", bp.default_port as u16)).is_ok()
    {
        return bp.default_port;
    }
    let start = bp.fallback_port_range[0].max(17000) as u16;
    let end = bp.fallback_port_range[1].max(19999) as u16;
    for candidate in start..=end {
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate as i32;
        }
    }
    bp.default_port
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeploySnapshotPrior {
    /// Confirmed absent prior to deploy (`symlink_metadata` returned `NotFound`).
    ConfirmedAbsent,
    /// Regular file captured with prior contents and POSIX permission mode.
    RegularFile { bytes: Vec<u8>, mode: u32 },
    /// Symbolic link captured with its target path.
    Symlink { target: std::path::PathBuf },
    /// Path existed or could not be confirmed absent (e.g., `EACCES` on a 0600 config file).
    /// Must never be deleted or overwritten by unprivileged rollback.
    Unreadable { reason: String },
}

#[derive(Clone, Debug)]
struct DeployFileSnapshot {
    path: std::path::PathBuf,
    prior: DeploySnapshotPrior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeployStage {
    BeforeHostMutation,
    HostConfigMutated { target_port: i32 },
    IngressPersisted { target_port: i32 },
}

#[derive(Clone, Debug)]
struct DeployRestoreFailure {
    path: std::path::PathBuf,
    was_confirmed_absent: bool,
    error: String,
}

#[derive(Debug, Default)]
struct RestoreFilesOutcome {
    apache_restored: bool,
    systemd_unit_restored: bool,
    apache_failures: Vec<DeployRestoreFailure>,
    native_failures: Vec<DeployRestoreFailure>,
    unreadable_apache: Vec<(std::path::PathBuf, String)>,
    unreadable_native: Vec<(std::path::PathBuf, String)>,
    systemd_units_touched: Vec<std::path::PathBuf>,
}

#[derive(Clone, Debug, Default)]
struct DeployRollbackReport {
    apache_restored: bool,
    systemd_unit_restored: bool,
    unrestored_paths: Vec<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
    fully_reverted: bool,
}

impl DeployRollbackReport {
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.unrestored_paths.is_empty() {
            parts.push(format!(
                "unrestored paths: {}",
                self.unrestored_paths.join(", ")
            ));
        }
        if !self.errors.is_empty() {
            parts.push(self.errors.join("; "));
        }
        if !self.warnings.is_empty() {
            parts.push(format!("warnings: {}", self.warnings.join("; ")));
        }
        if parts.is_empty() {
            "rollback status unknown".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

/// Captures a pre-deploy snapshot while distinguishing confirmed `NotFound`
/// from permission/metadata/read errors (`EACCES`, non-regular files, TOCTOU races).
fn read_deploy_snapshot(path: &StdPath) -> DeploySnapshotPrior {
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return DeploySnapshotPrior::ConfirmedAbsent;
        }
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("metadata lookup failed: {err}"),
            };
        }
    };
    if lmeta.file_type().is_symlink() {
        return match std::fs::read_link(path) {
            Ok(target) => DeploySnapshotPrior::Symlink { target },
            Err(err) => DeploySnapshotPrior::Unreadable {
                reason: format!("read_link failed: {err}"),
            },
        };
    }
    if !lmeta.is_file() {
        return DeploySnapshotPrior::Unreadable {
            reason: "non-regular file".to_string(),
        };
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match opts.open(path) {
        Ok(file) => file,
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("open failed: {err}"),
            };
        }
    };
    let fmeta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("fstat failed: {err}"),
            };
        }
    };
    if !fmeta.is_file() {
        return DeploySnapshotPrior::Unreadable {
            reason: "non-regular file after open".to_string(),
        };
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if lmeta.dev() != fmeta.dev() || lmeta.ino() != fmeta.ino() {
            return DeploySnapshotPrior::Unreadable {
                reason: "file identity changed during snapshot".to_string(),
            };
        }
        fmeta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600u32;

    let mut bytes = Vec::new();
    if let Err(err) = std::io::Read::read_to_end(&mut file, &mut bytes) {
        return DeploySnapshotPrior::Unreadable {
            reason: format!("read failed: {err}"),
        };
    }
    DeploySnapshotPrior::RegularFile {
        bytes,
        mode: if mode == 0 { 0o600 } else { mode },
    }
}

fn write_atomic_nofollow_mode(
    path: &std::path::Path,
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    use std::io::Write;
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing parent directory",
        ));
    };
    if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
        if pmeta.file_type().is_symlink() || !pmeta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing symlink parent directory",
            ));
        }
    } else {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if existing.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to overwrite symlink target",
            ));
        }
    }
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deploy");
    let tmp_path = parent.join(format!(
        ".{fname}.restore.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut tmp_file = opts.open(&tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let effective_mode = if mode == 0 { 0o600 } else { mode & 0o777 };
        if let Err(err) = tmp_file.set_permissions(std::fs::Permissions::from_mode(effective_mode))
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
    }
    if let Err(err) = tmp_file.write_all(bytes).and_then(|()| tmp_file.sync_all()) {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    drop(tmp_file);
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(unix)]
fn restore_symlink_nofollow(path: &StdPath, target: &StdPath) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing parent directory",
        ));
    };
    if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
        if pmeta.file_type().is_symlink() || !pmeta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing symlink parent directory",
            ));
        }
    } else {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if existing.is_dir() && !existing.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to replace directory with symlink",
            ));
        }
    }
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deploy");
    let tmp_path = parent.join(format!(
        ".{fname}.restore.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    std::os::unix::fs::symlink(target, &tmp_path)?;
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_symlink_nofollow(_path: &StdPath, _target: &StdPath) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink restoration unsupported on this platform",
    ))
}

fn snapshot_deploy_files(bp: &af_services::AppBlueprint) -> Vec<DeployFileSnapshot> {
    let mut snapshots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push_rel = |rel: &str| {
        if rel.trim().is_empty() {
            return;
        }
        let resolved = af_services::mutators::resolve_config_path(rel);
        if !resolved.as_os_str().is_empty() && seen.insert(resolved.clone()) {
            let prior = read_deploy_snapshot(&resolved);
            snapshots.push(DeployFileSnapshot {
                path: resolved,
                prior,
            });
        }
    };

    push_rel(&bp.config_file_path);
    for native_path in
        af_runner::blueprint::native_app_spec(&bp.app_name, &bp.config_file_path).config_paths
    {
        push_rel(&native_path);
    }
    match bp.app_name.as_str() {
        "transmission" => {
            push_rel("/var/lib/transmission-daemon/info/settings.json");
            push_rel("/var/lib/transmission-daemon/.config/transmission-daemon/settings.json");
        }
        "overseerr" | "jellyseerr" => {
            push_rel(&format!("/var/lib/{}/config/settings.json", bp.app_name));
            push_rel(&format!("/var/lib/{}/settings.json", bp.app_name));
        }
        "listenarr" => {
            push_rel("/var/lib/listenarr/config.xml");
            push_rel("/var/lib/listenarr/config/config.xml");
        }
        _ => {}
    }

    for vhost_rel in [
        format!(
            "/etc/apache2/sites-available/aetherflow-app-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-app-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-available/aetherflow-ext-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-ext-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-available/aetherflow-ext-{}-le-ssl.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-ext-{}-le-ssl.conf",
            bp.app_name
        ),
        format!("/etc/apache2/sites-available/{}.conf", bp.app_name),
        format!("/etc/apache2/sites-enabled/{}.conf", bp.app_name),
    ] {
        push_rel(&vhost_rel);
    }
    snapshots
}

fn is_apache2_deploy_path(path: &StdPath) -> bool {
    let apache_root = af_services::mutators::resolve_config_path("/etc/apache2");
    (!apache_root.as_os_str().is_empty() && path.starts_with(&apache_root))
        || path.starts_with("/etc/apache2")
        || path.to_string_lossy().contains("/etc/apache2/")
}

fn is_systemd_unit_deploy_path(path: &StdPath) -> bool {
    let unit_root = af_services::mutators::resolve_config_path("/etc/systemd/system");
    let in_systemd_dir = (!unit_root.as_os_str().is_empty() && path.starts_with(&unit_root))
        || path.starts_with("/etc/systemd/system")
        || path.to_string_lossy().contains("/etc/systemd/system/");
    in_systemd_dir
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("service"))
}

fn record_restored_path(outcome: &mut RestoreFilesOutcome, path: &StdPath) {
    if is_apache2_deploy_path(path) {
        outcome.apache_restored = true;
    }
    if is_systemd_unit_deploy_path(path) {
        outcome.systemd_unit_restored = true;
        outcome.systemd_units_touched.push(path.to_path_buf());
    }
}

fn record_restore_failure(
    outcome: &mut RestoreFilesOutcome,
    path: &StdPath,
    was_confirmed_absent: bool,
    error: String,
) {
    let failure = DeployRestoreFailure {
        path: path.to_path_buf(),
        was_confirmed_absent,
        error,
    };
    if is_apache2_deploy_path(path) {
        outcome.apache_failures.push(failure);
    } else {
        outcome.native_failures.push(failure);
    }
}

fn restore_deploy_files(snapshots: &[DeployFileSnapshot]) -> RestoreFilesOutcome {
    let mut outcome = RestoreFilesOutcome::default();
    for snap in snapshots {
        match &snap.prior {
            DeploySnapshotPrior::RegularFile { bytes, mode } => {
                let unchanged = match read_deploy_snapshot(&snap.path) {
                    DeploySnapshotPrior::RegularFile {
                        bytes: cur_bytes,
                        mode: cur_mode,
                    } => &cur_bytes == bytes && cur_mode == *mode,
                    _ => false,
                };
                if unchanged {
                    continue;
                }
                match write_atomic_nofollow_mode(&snap.path, bytes, *mode) {
                    Ok(()) => record_restored_path(&mut outcome, &snap.path),
                    Err(err) => record_restore_failure(
                        &mut outcome,
                        &snap.path,
                        false,
                        format!("failed to restore {}: {err}", snap.path.display()),
                    ),
                }
            }
            DeploySnapshotPrior::Symlink { target } => {
                let unchanged = match std::fs::symlink_metadata(&snap.path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        std::fs::read_link(&snap.path).ok().as_ref() == Some(target)
                    }
                    _ => false,
                };
                if unchanged {
                    continue;
                }
                match restore_symlink_nofollow(&snap.path, target) {
                    Ok(()) => record_restored_path(&mut outcome, &snap.path),
                    Err(err) => record_restore_failure(
                        &mut outcome,
                        &snap.path,
                        false,
                        format!("failed to restore symlink {}: {err}", snap.path.display()),
                    ),
                }
            }
            DeploySnapshotPrior::ConfirmedAbsent => match std::fs::symlink_metadata(&snap.path) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => record_restore_failure(
                    &mut outcome,
                    &snap.path,
                    true,
                    format!(
                        "failed to verify absence of {} during rollback: {err}",
                        snap.path.display()
                    ),
                ),
                Ok(meta) if meta.is_file() || meta.file_type().is_symlink() => {
                    match std::fs::remove_file(&snap.path) {
                        Ok(()) => record_restored_path(&mut outcome, &snap.path),
                        Err(err) => record_restore_failure(
                            &mut outcome,
                            &snap.path,
                            true,
                            format!("failed to remove new file {}: {err}", snap.path.display()),
                        ),
                    }
                }
                Ok(_) => record_restore_failure(
                    &mut outcome,
                    &snap.path,
                    true,
                    format!(
                        "refusing to remove non-regular path {} created during deploy",
                        snap.path.display()
                    ),
                ),
            },
            DeploySnapshotPrior::Unreadable { reason } => {
                // Never delete or overwrite a file that existed (or could not be confirmed
                // absent) before deploy; record it for privileged fallback / operator report.
                if is_apache2_deploy_path(&snap.path) {
                    outcome
                        .unreadable_apache
                        .push((snap.path.clone(), reason.clone()));
                } else {
                    outcome
                        .unreadable_native
                        .push((snap.path.clone(), reason.clone()));
                }
            }
        }
    }
    outcome
}

fn push_unique_string(target: &mut Vec<String>, item: String) {
    if !target.contains(&item) {
        target.push(item);
    }
}

async fn reload_systemd_units_after_rollback(
    touched_units: &[std::path::PathBuf],
    is_real_host: bool,
) -> Result<(), String> {
    if touched_units.is_empty() || !is_real_host {
        return Ok(());
    }
    if unsafe { libc::geteuid() } == 0 {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::process::Command::new("systemctl")
                .arg("daemon-reload")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| "systemctl daemon-reload timed out after 15s".to_string())?
        .map_err(|err| format!("failed to execute systemctl daemon-reload: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(());
    }
    let unit_list = touched_units
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "reverted systemd unit(s) [{unit_list}] require 'systemctl daemon-reload', which cannot be executed by unprivileged af-api (runner /v1/systemctl does not expose daemon-reload)"
    ))
}

async fn rollback_deploy_files_inner(
    snapshots: &[DeployFileSnapshot],
    bp: Option<&af_services::AppBlueprint>,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    mutated_target_port: Option<i32>,
    host_mutation_attempted: bool,
    is_real_host: bool,
) -> DeployRollbackReport {
    if !host_mutation_attempted {
        return DeployRollbackReport {
            fully_reverted: true,
            ..Default::default()
        };
    }

    let outcome = restore_deploy_files(snapshots);
    let mut report = DeployRollbackReport {
        apache_restored: outcome.apache_restored,
        systemd_unit_restored: outcome.systemd_unit_restored,
        fully_reverted: true,
        ..Default::default()
    };
    let mut apache_reloaded_by_runner = false;
    let apache_live_runner = af_services::mutators::resolve_config_path("/etc/apache2")
        == StdPath::new("/etc/apache2")
        && af_runner::is_runner_available();

    if !outcome.apache_failures.is_empty() || !outcome.unreadable_apache.is_empty() {
        let mut fallback_handled = false;
        if let (Some(bp), Some(target_port)) = (bp, mutated_target_port.filter(|p| *p > 0)) {
            if apache_live_runner {
                if let Some(prior) = prior_ingress.filter(|cfg| cfg.listen_port > 0) {
                    let internal_domain = (!bp.internal_domain.trim().is_empty())
                        .then(|| bp.internal_domain.trim().to_ascii_lowercase());
                    let base_domain = af_services::resolve_base_domain();
                    let public_domain = {
                        let candidate = prior.public_domain.trim().to_ascii_lowercase();
                        if !candidate.is_empty() {
                            Some(candidate)
                        } else {
                            let fallback =
                                af_services::format_app_public_domain(&bp.app_name, &base_domain);
                            (!fallback.is_empty()).then_some(fallback)
                        }
                    };
                    let req = af_models::RunnerApacheVhostRequest {
                        app_name: bp.app_name.clone(),
                        listen_port: prior.listen_port,
                        internal_domain,
                        public_domain,
                        external_access_enabled: prior.external_access_enabled,
                        tls_enabled: prior.tls_enabled,
                        remove_only: false,
                        reload_apache: true,
                    };
                    match af_runner::sync_apache_vhost_via_runner(&req).await {
                        Ok(_) => {
                            fallback_handled = true;
                            apache_reloaded_by_runner = true;
                            report.apache_restored = true;
                            if !outcome.unreadable_apache.is_empty() {
                                report.warnings.push(format!(
                                    "unreadable Apache vhost(s) re-synchronized to prior port {} via runner /v1/ingress/vhost",
                                    prior.listen_port
                                ));
                            }
                        }
                        Err(err) => {
                            report.fully_reverted = false;
                            report.errors.push(format!(
                                "privileged Apache vhost rollback to port {} failed (after deploy target port {target_port}): {err}",
                                prior.listen_port
                            ));
                        }
                    }
                } else if prior_ingress.is_none()
                    && outcome.unreadable_apache.is_empty()
                    && outcome
                        .apache_failures
                        .iter()
                        .all(|f| f.was_confirmed_absent)
                {
                    let req = af_models::RunnerApacheVhostRequest {
                        app_name: bp.app_name.clone(),
                        remove_only: true,
                        reload_apache: true,
                        ..Default::default()
                    };
                    match af_runner::sync_apache_vhost_via_runner(&req).await {
                        Ok(_) => {
                            fallback_handled = true;
                            apache_reloaded_by_runner = true;
                            report.apache_restored = true;
                        }
                        Err(err) => {
                            report.fully_reverted = false;
                            report.errors.push(format!(
                                "privileged Apache vhost removal via runner failed: {err}"
                            ));
                        }
                    }
                }
            }
        }
        if !fallback_handled {
            report.fully_reverted = false;
            for failure in &outcome.apache_failures {
                push_unique_string(
                    &mut report.unrestored_paths,
                    failure.path.display().to_string(),
                );
                report.errors.push(failure.error.clone());
            }
            for (path, reason) in &outcome.unreadable_apache {
                push_unique_string(&mut report.unrestored_paths, path.display().to_string());
                report.errors.push(format!(
                    "prior Apache vhost {} could not be read before deploy ({reason}); preserved untouched without removal",
                    path.display()
                ));
            }
        }
    }

    if report.apache_restored && !apache_reloaded_by_runner {
        if let Err(err) = af_services::runner_systemctl("reload", "apache2").await {
            tracing::warn!(
                error = %err,
                "deploy rollback restored Apache vhost files but reloading apache2 failed"
            );
            report.fully_reverted = false;
            report.errors.push(format!(
                "restored Apache vhost files, but reloading apache2 failed: {err}"
            ));
        }
    }

    let mut runner_reloaded_systemd = false;
    if !outcome.native_failures.is_empty() || !outcome.unreadable_native.is_empty() {
        let mut fallback_attempted = false;
        let mut fallback_succeeded = false;
        if let (Some(bp), Some(prior), Some(target_port)) = (
            bp,
            prior_ingress.filter(|cfg| cfg.listen_port > 0),
            mutated_target_port.filter(|p| *p > 0),
        ) {
            if prior.listen_port != target_port
                && !af_runner::blueprint::has_config_root()
                && af_runner::is_runner_available()
            {
                fallback_attempted = true;
                let req = af_models::RunnerBlueprintApplyRequest {
                    app_name: bp.app_name.clone(),
                    listen_port: prior.listen_port,
                    lifecycle_job_id: String::new(),
                };
                match af_runner::dispatch_blueprint_apply(&req).await {
                    Ok(_) => {
                        fallback_succeeded = true;
                        let touched_systemd = outcome
                            .native_failures
                            .iter()
                            .any(|f| is_systemd_unit_deploy_path(&f.path))
                            || outcome
                                .unreadable_native
                                .iter()
                                .any(|(p, _)| is_systemd_unit_deploy_path(p));
                        if touched_systemd {
                            runner_reloaded_systemd = true;
                            report.systemd_unit_restored = true;
                        }
                        for failure in &outcome.native_failures {
                            let verified = snapshots
                                .iter()
                                .find(|s| s.path == failure.path)
                                .is_some_and(|snap| match &snap.prior {
                                    DeploySnapshotPrior::RegularFile { .. }
                                    | DeploySnapshotPrior::Symlink { .. }
                                    | DeploySnapshotPrior::ConfirmedAbsent => {
                                        read_deploy_snapshot(&failure.path) == snap.prior
                                    }
                                    DeploySnapshotPrior::Unreadable { .. } => false,
                                });
                            if !verified {
                                report.fully_reverted = false;
                                push_unique_string(
                                    &mut report.unrestored_paths,
                                    failure.path.display().to_string(),
                                );
                                report.errors.push(format!(
                                    "{}; privileged blueprint fallback did not restore exact prior contents",
                                    failure.error
                                ));
                            }
                        }
                        for (path, _) in &outcome.unreadable_native {
                            report.warnings.push(format!(
                                "unreadable prior file {} was preserved and re-applied to prior port {} via runner /v1/blueprint/apply (non-port fields cannot be byte-verified without runner snapshot)",
                                path.display(),
                                prior.listen_port
                            ));
                        }
                    }
                    Err(err) => {
                        report.fully_reverted = false;
                        report.errors.push(format!(
                            "privileged blueprint rollback to port {} via runner failed: {err}",
                            prior.listen_port
                        ));
                    }
                }
            }
        }
        if !fallback_attempted || !fallback_succeeded {
            report.fully_reverted = false;
            for failure in &outcome.native_failures {
                push_unique_string(
                    &mut report.unrestored_paths,
                    failure.path.display().to_string(),
                );
                report.errors.push(failure.error.clone());
            }
            for (path, reason) in &outcome.unreadable_native {
                push_unique_string(&mut report.unrestored_paths, path.display().to_string());
                report.errors.push(format!(
                    "prior file {} could not be read before deploy ({reason}); preserved untouched without removal and cannot be auto-reverted by unprivileged API",
                    path.display()
                ));
            }
        }
    }

    if !outcome.systemd_units_touched.is_empty() && !runner_reloaded_systemd {
        if let Err(err) =
            reload_systemd_units_after_rollback(&outcome.systemd_units_touched, is_real_host).await
        {
            report.fully_reverted = false;
            report.errors.push(err);
        }
    }

    report
}

async fn rollback_deploy_files_with_context(
    snapshots: &[DeployFileSnapshot],
    bp: Option<&af_services::AppBlueprint>,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    mutated_target_port: Option<i32>,
    host_mutation_attempted: bool,
) -> DeployRollbackReport {
    let is_real_host = !af_runner::blueprint::has_config_root() && cfg!(target_os = "linux");
    rollback_deploy_files_inner(
        snapshots,
        bp,
        prior_ingress,
        mutated_target_port,
        host_mutation_attempted,
        is_real_host,
    )
    .await
}

#[cfg(test)]
async fn rollback_deploy_files(snapshots: &[DeployFileSnapshot]) -> bool {
    let report = rollback_deploy_files_with_context(snapshots, None, None, None, true).await;
    report.apache_restored && report.fully_reverted
}

async fn finalize_failed_deploy_rollback(
    bp: &af_services::AppBlueprint,
    service_unit: &str,
    transmission_stopped: bool,
    stage: DeployStage,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    file_snapshots: &[DeployFileSnapshot],
) -> DeployRollbackReport {
    let (host_mutation_attempted, mutated_target_port) = match stage {
        DeployStage::BeforeHostMutation => (false, None),
        DeployStage::HostConfigMutated { target_port }
        | DeployStage::IngressPersisted { target_port } => (true, Some(target_port)),
    };

    let mut report = rollback_deploy_files_with_context(
        file_snapshots,
        Some(bp),
        prior_ingress,
        mutated_target_port,
        host_mutation_attempted,
    )
    .await;

    if transmission_stopped {
        if report.fully_reverted {
            if let Err(start_err) = af_services::control_service(service_unit, "start").await {
                report.fully_reverted = false;
                report.errors.push(format!(
                    "failed to restart {service_unit} after rollback: {start_err}"
                ));
            }
        } else {
            report.errors.push(format!(
                "{service_unit} was not restarted because configuration rollback did not complete cleanly"
            ));
        }
    }

    if matches!(stage, DeployStage::IngressPersisted { .. }) {
        if report.fully_reverted {
            let db_revert = match prior_ingress {
                Some(prior) => af_db::set_app_ingress_config(prior),
                None => af_db::delete_app_ingress_config(&bp.app_name),
            };
            if let Err(db_err) = db_revert {
                report.fully_reverted = false;
                report.errors.push(format!(
                    "host state reverted, but failed to revert SQLite ingress configuration: {db_err}"
                ));
            }
        } else {
            report.errors.push(
                "SQLite ingress configuration was NOT reverted because host rollback failed; keeping persisted ingress in sync with host state".to_string(),
            );
        }
    } else if host_mutation_attempted && !report.fully_reverted {
        report.warnings.push(
            "SQLite ingress was not modified before failure, but host files may remain partially mutated".to_string(),
        );
    }

    report
}

fn is_transmission_deploy_unit(app_name: &str, service_unit: &str) -> bool {
    let unit_clean = service_unit.trim().trim_end_matches(".service");
    app_name.eq_ignore_ascii_case("transmission")
        || unit_clean.eq_ignore_ascii_case("transmission-daemon")
        || unit_clean.eq_ignore_ascii_case("transmission")
}

pub async fn handle_deploy_process(
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(app_name): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&auth_user) {
        return resp;
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

    let registration = match register_deployment(&bp.app_name) {
        Ok(registration) => registration,
        Err(response) => return response,
    };
    let tx = registration.sender.clone();

    let bp_clone = bp.clone();
    tokio::spawn(async move {
        // Release the slot and both stream registrations on every exit,
        // including task cancellation or panic.
        let _registration = registration;
        let send_step = |msg: String| {
            let _ = tx.send(msg);
        };

        send_step("[STEP 0] Deployment sequence queued asynchronously.".to_string());
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let _lifecycle_guard = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        let prior_ingress = match af_db::get_app_ingress_config(&bp_clone.app_name) {
            Ok(cfg) => cfg,
            Err(err) => {
                let sanitized = af_common::redact::redact_secrets(&format!("{err:#}"));
                send_step(format!(
                    "[ERROR] Deployment aborted before mutation: failed to read prior ingress state: {sanitized}"
                ));
                cleanup_deploy_channel(&bp_clone.app_name).await;
                return;
            }
        };
        let file_snapshots = snapshot_deploy_files(&bp_clone);

        let service_unit = if bp_clone.service_name.trim().is_empty() {
            bp_clone.app_name.clone()
        } else {
            bp_clone.service_name.clone()
        };
        let transmission_safe_lifecycle =
            is_transmission_deploy_unit(&bp_clone.app_name, &service_unit);

        let mut stage = DeployStage::BeforeHostMutation;
        let mut transmission_stopped = false;

        let configuration =
            af_services::mutators::with_blueprint_mutation(&bp_clone.app_name, async {
                send_step(format!(
                    "[STEP 1] Validating and synchronizing local DNS for {}...",
                    bp_clone.internal_domain
                ));
                if !bp_clone.internal_domain.trim().is_empty() {
                    af_services::mutators::sync_local_dns_domains(std::slice::from_ref(
                        &bp_clone.internal_domain,
                    ))
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "Local DNS synchronization failed for {}: {}",
                            bp_clone.internal_domain,
                            error
                        )
                    })?;
                }
                let target_port = allocate_or_verify_deploy_port(&bp_clone);
                if target_port > 0 {
                    if transmission_safe_lifecycle {
                        // Stop transmission-daemon BEFORE mutating settings.json so its SIGTERM
                        // exit handler flushes prior state first and never overwrites our changes!
                        send_step(format!(
                            "[STEP 2] Stopping {} prior to safe settings.json mutation...",
                            service_unit
                        ));
                        transmission_stopped =
                            af_services::control_service(&service_unit, "stop")
                                .await
                                .is_ok();
                    }
                    send_step(format!(
                        "[STEP 2] Applying blueprint configuration for {} on port {}...",
                        bp_clone.app_name, target_port
                    ));
                    stage = DeployStage::HostConfigMutated { target_port };
                    af_services::mutators::apply_blueprint_app_config(
                        &bp_clone.app_name,
                        target_port,
                    )
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("Blueprint configuration mutation failed: {}", error)
                    })?;
                    send_step(format!(
                        "[STEP 3] Persisting ingress routing configuration ({} -> 127.0.0.1:{})...",
                        bp_clone.internal_domain, target_port
                    ));
                    let existing =
                        af_db::get_app_ingress_config(&bp_clone.app_name).map_err(|error| {
                            anyhow::anyhow!("Failed to read ingress configuration: {}", error)
                        })?;
                    let ingress_cfg =
                        deployment_ingress_config(&bp_clone.app_name, target_port, existing);
                    af_db::set_app_ingress_config(&ingress_cfg).map_err(|error| {
                        anyhow::anyhow!("Failed to persist ingress configuration: {}", error)
                    })?;
                    stage = DeployStage::IngressPersisted { target_port };
                } else {
                    send_step(format!(
                        "[STEP 2] Portless service blueprint {} confirmed (port=0); skipping port mutation...",
                        bp_clone.app_name
                    ));
                    send_step(format!(
                        "[STEP 3] Skipping reverse-proxy port binding for portless service {}...",
                        bp_clone.app_name
                    ));
                }

                // Step 4: Start (for pre-stopped transmission-daemon) or Restart the managed service
                let lifecycle_action = if transmission_safe_lifecycle && target_port > 0 {
                    "start"
                } else {
                    "restart"
                };
                send_step(format!(
                    "[STEP 4] Executing '{}' on managed service {}...",
                    lifecycle_action, service_unit
                ));
                if let Err(restart_error) =
                    af_services::control_service(&service_unit, lifecycle_action).await
                {
                    return Err(anyhow::anyhow!(
                        "Managed service {} failed for {}: {}",
                        lifecycle_action,
                        service_unit,
                        restart_error
                    ));
                }
                Ok(())
            })
            .await;

        match configuration {
            Ok(()) => {
                send_step(deployment_restart_status(Ok(())));
            }
            Err(error) => {
                let rollback_report = finalize_failed_deploy_rollback(
                    &bp_clone,
                    &service_unit,
                    transmission_stopped,
                    stage,
                    prior_ingress.as_ref(),
                    &file_snapshots,
                )
                .await;
                let sanitized = af_common::redact::redact_secrets(&format!("{error:#}"));
                if rollback_report.fully_reverted {
                    if rollback_report.warnings.is_empty() {
                        send_step(format!(
                            "[ROLLBACK] Deployment configuration rejected and rolled back cleanly: {sanitized}"
                        ));
                    } else {
                        let warns =
                            af_common::redact::redact_secrets(&rollback_report.warnings.join("; "));
                        send_step(format!(
                            "[ROLLBACK] Deployment configuration rejected and rolled back ({warns}): {sanitized}"
                        ));
                    }
                } else {
                    let details = af_common::redact::redact_secrets(&rollback_report.summary());
                    tracing::error!(
                        app = %bp_clone.app_name,
                        rollback_details = %details,
                        "deploy rollback incomplete or failed"
                    );
                    send_step(format!(
                        "[ROLLBACK] Rollback INCOMPLETE after deployment failure ({sanitized}): {details}"
                    ));
                }
                send_step(format!(
                    "[ERROR] Deployment configuration rejected: {sanitized}"
                ));
            }
        }
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

async fn cleanup_deploy_channel(_app_name: &str) {
    // Give connected subscribers time to receive the terminal event. The
    // owning registration removes only its own channels when the task ends.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

fn deploy_sse_session_still_authorized(
    auth_user: &AuthUser,
    initial_revoked_after: Option<i64>,
) -> bool {
    if auth_user.plugin_id.is_some() || auth_user.role != "admin" {
        return false;
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return false;
    };
    if !crate::auth::table_exists(&conn, "users").unwrap_or(false) {
        return true;
    }
    if !auth_user.jti.is_empty()
        && crate::auth::is_session_token_revoked_beyond_grace_with_conn(
            &conn,
            &auth_user.jti,
            auth_user.user_id,
        )
    {
        return false;
    }
    let Ok(subj) = crate::auth::load_active_human_subject(&conn, auth_user.user_id) else {
        return false;
    };
    if subj.role != "admin" {
        return false;
    }
    if let Some(issued_ver) = initial_revoked_after {
        if subj.sessions_revoked_after > issued_ver {
            return false;
        }
    }
    true
}

async fn deploy_sse_session_still_authorized_async(
    auth_user: &AuthUser,
    initial_revoked_after: Option<i64>,
) -> bool {
    let cloned = auth_user.clone();
    crate::auth::blocking_auth_work(move || {
        deploy_sse_session_still_authorized(&cloned, initial_revoked_after)
    })
    .await
    .unwrap_or(false)
}

pub async fn handle_deploy_stream(
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&auth_user) {
        return resp;
    }
    let uid = auth_user.user_id;
    let initial_revoked_after = crate::auth::blocking_auth_work(move || {
        af_db::get_read_conn()
            .ok()
            .and_then(|c| crate::auth::load_active_human_subject(&c, uid).ok())
            .map(|s| s.sessions_revoked_after)
    })
    .await
    .ok()
    .flatten();
    if !deploy_sse_session_still_authorized_async(&auth_user, initial_revoked_after).await {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Administrative session is no longer active",
        );
    }
    let Some(app_name) = q.get("appName").filter(|s| !s.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "appName query parameter is required" })),
        )
            .into_response();
    };

    if app_name == "mediaflow_engine" {
        let mut rx = af_services::subscribe_mediaflow_progress();
        let cached_event = DEPLOY_LAST_EVENT
            .lock()
            .ok()
            .and_then(|map| map.get(app_name).cloned());
        let initial_snapshot = match cached_event {
            Some(ev) if !is_terminal_deploy_event(&ev) => ev,
            _ => {
                let db_snapshot = tokio::task::spawn_blocking(|| {
                    let conn = af_db::get_read_conn().ok()?;
                    let proc_file: Option<String> = conn
                        .query_row(
                            "SELECT file_path FROM mediaflow_queue WHERE status = 'PROCESSING' ORDER BY updated_at DESC LIMIT 1",
                            [],
                            |r| r.get(0),
                        )
                        .ok();
                    if let Some(file) = proc_file {
                        return Some(
                            serde_json::json!({
                                "status": "running",
                                "file": file,
                                "progress": 0,
                                "message": "Transcode in progress",
                            })
                            .to_string(),
                        );
                    }
                    let approved_file: Option<String> = conn
                        .query_row(
                            "SELECT file_path FROM mediaflow_queue WHERE status = 'APPROVED' ORDER BY updated_at ASC LIMIT 1",
                            [],
                            |r| r.get(0),
                        )
                        .ok();
                    approved_file.map(|file| {
                        serde_json::json!({
                            "status": "running",
                            "file": file,
                            "progress": 0,
                            "message": "Transcode job queued",
                        })
                        .to_string()
                    })
                })
                .await
                .ok()
                .flatten();
                db_snapshot.unwrap_or_else(|| {
                    serde_json::json!({
                        "status": "idle",
                        "progress": 0,
                        "message": "MediaFlow Engine idle",
                    })
                    .to_string()
                })
            }
        };

        let stream = async_stream::stream! {
            let mut revalidate_tick = tokio::time::interval(std::time::Duration::from_secs(5));
            revalidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let _ = revalidate_tick.tick().await;
            let safe_init = af_common::redact::redact_secrets(&initial_snapshot);
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_init));
            loop {
                tokio::select! {
                    _ = revalidate_tick.tick() => {
                        if !deploy_sse_session_still_authorized_async(&auth_user, initial_revoked_after).await {
                            break;
                        }
                    }
                    recv_res = rx.recv() => {
                        match recv_res {
                            Ok(msg) => {
                                if !deploy_sse_session_still_authorized_async(&auth_user, initial_revoked_after).await {
                                    break;
                                }
                                let safe_msg = af_common::redact::redact_secrets(&msg);
                                yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
                                if is_terminal_deploy_event(&safe_msg) {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::debug!(skipped, "mediaflow progress stream lagged; continuing");
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
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
        return resp;
    }

    let rx_opt = DEPLOY_STREAMS
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).map(|tx| tx.subscribe()));

    let Some(mut rx) = rx_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": "No active deployment found for this application." }),
            ),
        )
            .into_response();
    };
    let initial_event = DEPLOY_LAST_EVENT
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).cloned());

    let stream = async_stream::stream! {
        let mut revalidate_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        revalidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = revalidate_tick.tick().await;
        if let Some(first_msg) = initial_event {
            let safe_msg = af_common::redact::redact_secrets(&first_msg);
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
            if is_terminal_deploy_event(&safe_msg) {
                return;
            }
        }
        loop {
            tokio::select! {
                _ = revalidate_tick.tick() => {
                    if !deploy_sse_session_still_authorized_async(&auth_user, initial_revoked_after).await {
                        break;
                    }
                }
                recv_res = rx.recv() => {
                    match recv_res {
                        Ok(msg) => {
                            if !deploy_sse_session_still_authorized_async(&auth_user, initial_revoked_after).await {
                                break;
                            }
                            let safe_msg = af_common::redact::redact_secrets(&msg);
                            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
                            if is_terminal_deploy_event(&safe_msg) {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::debug!(skipped, "deploy stream lagged; continuing");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
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
                html_url:
                    "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0-experimental"
                        .to_string(),
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
                html_url:
                    "https://github.com/McEveritts/AetherFlow/releases/tag/v3.3.0-nightly.20261101"
                        .to_string(),
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
                html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7"
                    .to_string(),
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
        let (tag, _, _) =
            select_release_for_channel(&releases, "nightly").expect("automated nightly");
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

    #[tokio::test]
    async fn test_handle_deploy_stream_requires_admin_and_redacts_secrets() {
        let non_admin = AuthUser {
            user_id: 2,
            username: "viewer".to_string(),
            role: "user".to_string(),
            jti: "test-jti".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let mut q = HashMap::new();
        q.insert("appName".to_string(), "radarr".to_string());
        let resp = handle_deploy_stream(axum::Extension(non_admin), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let redacted = af_common::redact::redact_secrets(
            "Restart failed with token=supersecretvalue123 and password: hiddenpass",
        );
        assert!(!redacted.contains("supersecretvalue123"));
        assert!(!redacted.contains("hiddenpass"));
        assert!(redacted.contains("[REDACTED]"));

        assert!(is_terminal_deploy_event("[SUCCESS] done"));
        assert!(is_terminal_deploy_event("[ROLLBACK] reverted"));
        assert!(is_terminal_deploy_event("[ERROR] failed"));
        assert!(is_terminal_deploy_event(
            r#"{"status":"completed","progress":100,"message":"done"}"#
        ));
        assert!(is_terminal_deploy_event(
            r#"{"status":"failed","progress":100,"message":"err"}"#
        ));
        assert!(is_terminal_deploy_event(
            r#"{"status":"done","progress":100}"#
        ));
        assert!(!is_terminal_deploy_event(
            r#"{"status":"running","progress":50}"#
        ));
    }

    fn ensure_test_admin_user_for_stream() {
        let _ = crate::plugins::tests::ensure_shared_test_db();
        if let Ok(conn) = af_db::get_conn() {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'admin', 'admin')",
                [],
            );
            let _ = conn.execute("UPDATE users SET role = 'admin' WHERE id = 1", []);
        }
    }

    #[tokio::test]
    async fn test_mediaflow_engine_deploy_stream_returns_200_json_sse_and_closes_on_completion() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        ensure_test_admin_user_for_stream();
        let app_name = format!("mediaflow-test-{}", uuid::Uuid::new_v4());
        let sender = ensure_or_reuse_deploy_stream(&app_name).unwrap();
        publish_deploy_json_event(
            &app_name,
            &sender,
            &serde_json::json!({
                "status": "running",
                "progress": 25,
                "message": "Scanning library",
            }),
        );

        let admin = AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let mut q = HashMap::new();
        q.insert("appName".to_string(), app_name.clone());
        let resp = handle_deploy_stream(axum::Extension(admin), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");

        let sender_for_finish = sender.clone();
        let app_for_finish = app_name.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            publish_deploy_json_event(
                &app_for_finish,
                &sender_for_finish,
                &serde_json::json!({
                    "status": "completed",
                    "progress": 100,
                    "message": "Scan complete",
                }),
            );
        });

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(r#""status":"running""#), "body={text}");
        assert!(text.contains(r#""status":"completed""#), "body={text}");

        release_deploy_stream_if_matching(&app_name, &sender);
        assert!(!DEPLOY_STREAMS.lock().unwrap().contains_key(&app_name));
    }

    #[tokio::test]
    async fn test_mediaflow_engine_progress_stream_subscribes_worker_broadcasts_and_handles_lag() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        ensure_test_admin_user_for_stream();
        let admin = AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let mut q = HashMap::new();
        q.insert("appName".to_string(), "mediaflow_engine".to_string());
        let resp = handle_deploy_stream(axum::Extension(admin), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // Overflow the 256-slot broadcast buffer so subscriber experiences RecvError::Lagged
            for i in 0..300 {
                af_services::publish_mediaflow_progress(&serde_json::json!({
                    "status": "running",
                    "progress": i % 99,
                    "message": format!("Tick {i}"),
                }));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            af_services::publish_mediaflow_progress(&serde_json::json!({
                "status": "completed",
                "progress": 100,
                "message": "Worker transcode done",
            }));
        });

        let body = axum::body::to_bytes(resp.into_body(), 262_144)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains(r#""status":"#), "body={text}");
        assert!(
            text.contains(r#""status":"completed""#),
            "stream must survive lag and deliver completion: body={text}"
        );
    }

    #[test]
    fn test_allocate_or_verify_deploy_port_respects_portless_and_fixed_port_blueprints() {
        let fail2ban = af_services::get_blueprint("fail2ban").expect("fail2ban blueprint");
        assert_eq!(fail2ban.default_port, 0);
        assert!(!fail2ban.supports_dynamic_port);
        assert_eq!(allocate_or_verify_deploy_port(&fail2ban), 0);

        let plex = af_services::get_blueprint("plex").expect("plex blueprint");
        assert_eq!(plex.default_port, 32400);
        assert!(!plex.supports_dynamic_port);
        assert_eq!(allocate_or_verify_deploy_port(&plex), 32400);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_oauth_only_admin_backup_stepup_against_live_schema_v24() {
        let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("af-oauth-backup-stepup-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let db_file = tmp_dir.join("stepup.sqlite");

        let keys = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"];
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
        for &k in &keys {
            std::env::set_var(k, &db_file);
        }

        af_db::init_db().expect("initialize full v24 schema");
        let now = Utc::now().timestamp();
        {
            let conn = af_db::get_conn().unwrap();
            let max_ver: i64 = conn
                .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
                .unwrap();
            assert_eq!(max_ver, 24);
            conn.execute(
                "INSERT INTO users (id, username, role, password_hash, totp_enabled) VALUES (77, 'oauth-admin', 'admin', '', 0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active, family_id)
                 VALUES ('oauth-jti-fresh', 77, '127.0.0.1', 'TestUA', ?1, ?2, 'fam-77')",
                params![now + 3600, now],
            )
            .unwrap();
        }

        let admin = AuthUser {
            user_id: 77,
            username: "oauth-admin".to_string(),
            role: "admin".to_string(),
            jti: "oauth-jti-fresh".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Reauth-Confirm", HeaderValue::from_static("oauth"));

        // 1. Fresh authenticated OAuth session (<= 300s) with live active_sessions row succeeds
        assert!(authorize_backup_password(&admin, Some(now - 60), &headers, &[]).await);

        // 2. Stale authenticated OAuth session (> 300s) fails closed even if refreshed session is active
        assert!(!authorize_backup_password(&admin, Some(now - 301), &headers, &[]).await);

        // 3. Revoked/absent active_sessions row fails closed even with fresh auth_time
        let revoked_admin = AuthUser {
            jti: "oauth-jti-missing".to_string(),
            ..admin.clone()
        };
        assert!(!authorize_backup_password(&revoked_admin, Some(now - 10), &headers, &[]).await);

        // 4. Expired RFC3339 TEXT expires_at must fail closed (no SQLite TEXT > INTEGER affinity bypass),
        //    while fresh RFC3339 TEXT expires_at succeeds.
        {
            let conn = af_db::get_conn().unwrap();
            let future_rfc3339 = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
            conn.execute(
                "INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active, family_id)
                 VALUES ('oauth-jti-expired-text', 77, '127.0.0.1', 'TestUA', '1970-01-01T00:00:00+00:00', ?1, 'fam-78'),
                        ('oauth-jti-fresh-text', 77, '127.0.0.1', 'TestUA', ?2, ?1, 'fam-79')",
                params![now, future_rfc3339],
            )
            .unwrap();
        }
        let expired_text_admin = AuthUser {
            jti: "oauth-jti-expired-text".to_string(),
            ..admin.clone()
        };
        assert!(
            !authorize_backup_password(&expired_text_admin, Some(now - 10), &headers, &[]).await
        );
        let fresh_text_admin = AuthUser {
            jti: "oauth-jti-fresh-text".to_string(),
            ..admin
        };
        assert!(authorize_backup_password(&fresh_text_admin, Some(now - 10), &headers, &[]).await);

        for (k, val) in saved {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn backup_reauth_reserves_quota_atomically_under_concurrency() {
        let user_id: i64 = 999_881;
        if let Ok(mut state) = BACKUP_REAUTH.lock() {
            state.attempts.remove(&user_id);
        }
        let hash = bcrypt::hash("correct-horse-battery-staple", 4).expect("hash");

        // Launch 16 concurrent invalid password verifications; at most 10 may reserve a slot
        // and execute bcrypt, while all 16 fail closed and leave exactly 10 active attempts.
        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for idx in 0..16 {
                let h = hash.clone();
                handles.push(s.spawn(move || {
                    verify_backup_password(user_id, &format!("sess-{idx}"), "wrong-pass", &h)
                }));
            }
            for handle in handles {
                assert!(!handle.join().expect("thread join"));
            }
        });

        let active_after_burst = BACKUP_REAUTH
            .lock()
            .expect("lock")
            .attempts
            .get(&user_id)
            .map_or(0, Vec::len);
        assert_eq!(active_after_burst, 10);
        // Even the valid password is now rate-limited while 10 failures are active in the window.
        assert!(!verify_backup_password(
            user_id,
            "sess-valid",
            "correct-horse-battery-staple",
            &hash,
        ));

        // Clear one slot and verify a valid password check refunds its own temporary reservation.
        if let Ok(mut state) = BACKUP_REAUTH.lock() {
            if let Some(entries) = state.attempts.get_mut(&user_id) {
                entries.pop();
            }
        }
        assert!(verify_backup_password(
            user_id,
            "sess-valid-2",
            "correct-horse-battery-staple",
            &hash,
        ));
        let active_after_valid = BACKUP_REAUTH
            .lock()
            .expect("lock")
            .attempts
            .get(&user_id)
            .map_or(0, Vec::len);
        assert_eq!(active_after_valid, 9);

        if let Ok(mut state) = BACKUP_REAUTH.lock() {
            state.attempts.remove(&user_id);
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_deploy_rollback_reloads_apache_transmission_lifecycle_and_smart_backup_window() {
        let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp_dir = std::env::temp_dir().join(format!("af-storage-p4-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let db_file = tmp_dir.join("storage_p4.sqlite");
        let keys = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"];
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
        for &k in &keys {
            std::env::set_var(k, &db_file);
        }
        af_db::init_db().unwrap();

        // 1. Smart Backup with <24 samples returns heuristic_default (confidence=0.35, optimal_hour=3)
        let win_resp = get_optimal_backup_window().await;
        let win_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(win_resp.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(win_body["optimal_window"]["source"], "heuristic_default");
        assert_eq!(win_body["optimal_window"]["optimal_hour"], 3);
        assert_eq!(win_body["optimal_window"]["confidence"], 0.35);

        // Seed >=24 samples across 24 UTC hours with lowest load at 04:00 UTC
        {
            let conn = af_db::get_conn().unwrap();
            for h in 0..24 {
                let (cpu, mem_used) = if h == 4 { (3.0, 1.5) } else { (72.0, 13.0) };
                conn.execute(
                    "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, ?2, ?3, 16.0)",
                    params![format!("2026-11-19T{h:02}:20:00Z"), cpu, mem_used],
                )
                .unwrap();
            }
        }

        let sched_resp = set_backup_schedule(Json(serde_json::json!({ "mode": "smart" }))).await;
        assert_eq!(sched_resp.status(), StatusCode::OK);
        let sched_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(sched_resp.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sched_body["optimal_window"]["source"], "metrics_history");
        assert_eq!(sched_body["optimal_window"]["optimal_hour"], 4);
        use chrono::Timelike;
        let next_str = sched_body["next_backup_at"].as_str().unwrap();
        let next_dt = chrono::DateTime::parse_from_rfc3339(next_str)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(next_dt.hour(), 4);
        assert_eq!(next_dt.minute(), 0);
        assert_eq!(next_dt.second(), 0);
        assert!(next_dt >= Utc::now() + chrono::Duration::minutes(55));

        // 2. Transmission safe deploy guard
        assert!(is_transmission_deploy_unit(
            "transmission",
            "transmission-daemon"
        ));
        assert!(!is_transmission_deploy_unit("sonarr", "sonarr"));

        // 3. Apache vhost rollback invokes runner_systemctl("reload", "apache2")
        #[cfg(unix)]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let sock_path = tmp_dir.join("runner.sock");
            let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");
            let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
            let cfg_root = tmp_dir.join("cfg_root");
            let vhost_dir = cfg_root.join("etc/apache2/sites-enabled");
            fs::create_dir_all(&vhost_dir).unwrap();
            std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
            std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

            let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
            let srv = tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut req_buf = vec![0u8; 4096];
                    let n = stream.read(&mut req_buf).await.unwrap_or(0);
                    let _ = reload_tx.send(String::from_utf8_lossy(&req_buf[..n]).into_owned());
                    let body = r#"{"success":true,"output":"reloaded","error":""}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });

            let vhost_file = vhost_dir.join("aetherflow-app-overseerr.conf");
            let snaps = vec![DeployFileSnapshot {
                path: vhost_file.clone(),
                prior: DeploySnapshotPrior::RegularFile {
                    bytes: b"<VirtualHost *:80>prior</VirtualHost>\n".to_vec(),
                    mode: 0o644,
                },
            }];
            fs::write(&vhost_file, b"<VirtualHost *:80>broken</VirtualHost>\n").unwrap();

            assert!(rollback_deploy_files(&snaps).await);
            assert_eq!(
                fs::read(&vhost_file).unwrap(),
                b"<VirtualHost *:80>prior</VirtualHost>\n"
            );
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(3), reload_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(received.contains("POST /v1/systemctl"));
            assert!(received.contains(r#""action":"reload""#));
            assert!(received.contains(r#""service":"apache2""#));
            srv.abort();

            match prev_sock {
                Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
                None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
            }
            match prev_cfg_root {
                Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
                None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
            }
        }

        for (k, val) in saved {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_deploy_snapshot_distinguishes_absent_from_eacces_and_preserves_unreadable_files()
    {
        use std::os::unix::fs::PermissionsExt;

        let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("af-deploy-l02-snap-{}", uuid::Uuid::new_v4()));
        let cfg_root = tmp_dir.join("cfg_root");
        let app_dir = cfg_root.join("var/lib/sonarr");
        let avail_dir = cfg_root.join("etc/apache2/sites-available");
        let enabled_dir = cfg_root.join("etc/apache2/sites-enabled");
        fs::create_dir_all(&app_dir).unwrap();
        fs::create_dir_all(&avail_dir).unwrap();
        fs::create_dir_all(&enabled_dir).unwrap();

        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

        let absent_path = avail_dir.join("aetherflow-app-sonarr.conf");
        let secret_unreadable_path = app_dir.join("config.xml");
        let creds_path = app_dir.join("credentials.xml");
        let symlink_path = enabled_dir.join("aetherflow-app-sonarr.conf");

        fs::write(
            &secret_unreadable_path,
            b"<Config><ApiKey>top-secret</ApiKey></Config>\n",
        )
        .unwrap();
        fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();

        fs::write(
            &creds_path,
            b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n",
        )
        .unwrap();
        fs::set_permissions(&creds_path, fs::Permissions::from_mode(0o600)).unwrap();

        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-app-sonarr.conf",
            &symlink_path,
        )
        .unwrap();

        // Snapshot before deploy: absent vs EACCES vs regular 0600 vs symlink.
        assert_eq!(
            read_deploy_snapshot(&absent_path),
            DeploySnapshotPrior::ConfirmedAbsent
        );
        let unreadable_snap = read_deploy_snapshot(&secret_unreadable_path);
        assert!(
            matches!(unreadable_snap, DeploySnapshotPrior::Unreadable { .. }),
            "EACCES file must be Unreadable, got {unreadable_snap:?}"
        );
        assert_eq!(
            read_deploy_snapshot(&creds_path),
            DeploySnapshotPrior::RegularFile {
                bytes: b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n".to_vec(),
                mode: 0o600,
            }
        );
        assert_eq!(
            read_deploy_snapshot(&symlink_path),
            DeploySnapshotPrior::Symlink {
                target: std::path::PathBuf::from("../sites-available/aetherflow-app-sonarr.conf"),
            }
        );

        let snaps = vec![
            DeployFileSnapshot {
                path: absent_path.clone(),
                prior: read_deploy_snapshot(&absent_path),
            },
            DeployFileSnapshot {
                path: secret_unreadable_path.clone(),
                prior: unreadable_snap,
            },
            DeployFileSnapshot {
                path: creds_path.clone(),
                prior: read_deploy_snapshot(&creds_path),
            },
            DeployFileSnapshot {
                path: symlink_path.clone(),
                prior: read_deploy_snapshot(&symlink_path),
            },
        ];

        // Simulate deploy mutating files: creating the previously absent vhost, overwriting creds,
        // replacing symlink with regular file.
        fs::write(&absent_path, b"<VirtualHost *:80>new</VirtualHost>\n").unwrap();
        fs::write(&creds_path, b"<Config><Port>18989</Port></Config>\n").unwrap();
        fs::remove_file(&symlink_path).unwrap();
        fs::write(&symlink_path, b"<VirtualHost *:80>wrong</VirtualHost>\n").unwrap();

        // Rollback when host mutation happened must preserve the unreadable 0600/0000 file,
        // remove the newly created ConfirmedAbsent file, restore 0600 credentials and symlink,
        // and truthfully report incomplete rollback for the unreadable file.
        let report =
            rollback_deploy_files_inner(&snaps, None, None, Some(18989), true, false).await;
        assert!(
            !report.fully_reverted,
            "unreadable pre-deploy file must prevent claiming clean rollback"
        );
        assert!(
            report
                .unrestored_paths
                .iter()
                .any(|p| p == &secret_unreadable_path.display().to_string()),
            "unreadable path must be reported: {:?}",
            report.unrestored_paths
        );

        // Critical: unreadable file was NEVER deleted despite writable parent dir!
        assert!(secret_unreadable_path.exists());
        fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            fs::read(&secret_unreadable_path).unwrap(),
            b"<Config><ApiKey>top-secret</ApiKey></Config>\n"
        );

        // ConfirmedAbsent file was removed, 0600 credentials & symlink restored.
        assert!(!absent_path.exists());
        assert_eq!(
            fs::read(&creds_path).unwrap(),
            b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n"
        );
        assert_eq!(
            fs::metadata(&creds_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(fs::symlink_metadata(&symlink_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&symlink_path).unwrap(),
            std::path::PathBuf::from("../sites-available/aetherflow-app-sonarr.conf")
        );

        // Pre-mutation failure (e.g. STEP 1 DNS error) leaves unreadable snapshot untouched and clean.
        fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();
        let pre_mut_report =
            rollback_deploy_files_inner(&snaps, None, None, None, false, false).await;
        assert!(pre_mut_report.fully_reverted);
        fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();

        match prev_cfg_root {
            Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
            None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_deploy_rollback_surfaces_write_failures_and_keeps_ingress_consistent() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("af-deploy-l02-ing-{}", uuid::Uuid::new_v4()));
        let cfg_root = tmp_dir.join("cfg_root");
        let vhost_dir = cfg_root.join("etc/apache2/sites-available");
        let sonarr_dir = cfg_root.join("var/lib/sonarr");
        fs::create_dir_all(&vhost_dir).unwrap();
        fs::create_dir_all(&sonarr_dir).unwrap();

        let db_file = tmp_dir.join("deploy_l02.sqlite");
        let keys = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"];
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
        for &k in &keys {
            std::env::set_var(k, &db_file);
        }
        af_db::init_db().unwrap();

        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);
        let missing_sock = tmp_dir.join("missing-runner.sock");
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &missing_sock);

        let bp = af_services::get_blueprint("sonarr").expect("sonarr blueprint");
        let prior_ingress = af_models::AppIngressConfig {
            app_name: "sonarr".to_string(),
            listen_port: 8989,
            public_domain: "sonarr.example.test".to_string(),
            external_access_enabled: false,
            tls_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        af_db::set_app_ingress_config(&prior_ingress).unwrap();

        let vhost_file = vhost_dir.join("aetherflow-app-sonarr.conf");
        let cfg_file = sonarr_dir.join("config.xml");
        fs::write(&vhost_file, b"<VirtualHost *:80>8989</VirtualHost>\n").unwrap();
        fs::write(&cfg_file, b"<Config><Port>8989</Port></Config>\n").unwrap();
        let snaps = snapshot_deploy_files(&bp);

        // Simulate STEP 2 writing port 18989 and STEP 3 persisting 18989 to SQLite, then
        // make parent directory read-only (0o555) so rollback write_atomic_nofollow_mode fails (EACCES).
        fs::write(&vhost_file, b"<VirtualHost *:80>18989</VirtualHost>\n").unwrap();
        fs::write(&cfg_file, b"<Config><Port>18989</Port></Config>\n").unwrap();
        let new_ingress = deployment_ingress_config("sonarr", 18989, Some(prior_ingress.clone()));
        af_db::set_app_ingress_config(&new_ingress).unwrap();

        fs::set_permissions(&vhost_dir, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&sonarr_dir, fs::Permissions::from_mode(0o555)).unwrap();

        // Direct rollback_deploy_files must return false (NOT ignore EACCES or mark apache_restored).
        assert!(!rollback_deploy_files(&snaps).await);

        let report = finalize_failed_deploy_rollback(
            &bp,
            "sonarr",
            false,
            DeployStage::IngressPersisted { target_port: 18989 },
            Some(&prior_ingress),
            &snaps,
        )
        .await;
        assert!(!report.fully_reverted);
        assert!(!report.apache_restored);
        assert!(report
            .unrestored_paths
            .iter()
            .any(|p| p == &vhost_file.display().to_string()));
        assert!(report
            .unrestored_paths
            .iter()
            .any(|p| p == &cfg_file.display().to_string()));
        // SQLite ingress MUST remain at 18989 to match un-reverted disk state!
        assert_eq!(
            af_db::get_app_ingress_config("sonarr")
                .unwrap()
                .unwrap()
                .listen_port,
            18989
        );

        // Also verify transmission_stopped=true does NOT start transmission-daemon when rollback fails.
        let tx_report = finalize_failed_deploy_rollback(
            &bp,
            "transmission-daemon",
            true,
            DeployStage::IngressPersisted { target_port: 18989 },
            Some(&prior_ingress),
            &snaps,
        )
        .await;
        assert!(!tx_report.fully_reverted);
        assert!(tx_report.errors.iter().any(
            |e| e.contains("was not restarted because configuration rollback did not complete")
        ));

        // Restore directory permissions; now verify apache reload failure still marks fully_reverted=false
        // and keeps SQLite at 18989, whereas successful reload reverts SQLite to 8989.
        fs::set_permissions(&vhost_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&sonarr_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let sock_path = tmp_dir.join("runner.sock");
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let srv = tokio::spawn(async move {
            // 1st request: fail apache2 reload; 2nd request: succeed apache2 reload.
            for success in [false, true] {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut req_buf = vec![0u8; 4096];
                    let _ = stream.read(&mut req_buf).await;
                    let body = if success {
                        r#"{"success":true,"output":"reloaded","error":""}"#
                    } else {
                        r#"{"success":false,"output":"","error":"apache2 reload failed"}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });

        let fail_reload_report = finalize_failed_deploy_rollback(
            &bp,
            "sonarr",
            false,
            DeployStage::IngressPersisted { target_port: 18989 },
            Some(&prior_ingress),
            &snaps,
        )
        .await;
        assert!(!fail_reload_report.fully_reverted);
        assert_eq!(
            af_db::get_app_ingress_config("sonarr")
                .unwrap()
                .unwrap()
                .listen_port,
            18989
        );

        // Re-mutate files and run successful rollback + apache2 reload -> SQLite reverts to 8989!
        fs::write(&vhost_file, b"<VirtualHost *:80>18989</VirtualHost>\n").unwrap();
        fs::write(&cfg_file, b"<Config><Port>18989</Port></Config>\n").unwrap();
        let ok_report = finalize_failed_deploy_rollback(
            &bp,
            "sonarr",
            false,
            DeployStage::IngressPersisted { target_port: 18989 },
            Some(&prior_ingress),
            &snaps,
        )
        .await;
        assert!(ok_report.fully_reverted, "errors={:?}", ok_report.errors);
        assert_eq!(
            af_db::get_app_ingress_config("sonarr")
                .unwrap()
                .unwrap()
                .listen_port,
            8989
        );
        assert_eq!(
            fs::read(&cfg_file).unwrap(),
            b"<Config><Port>8989</Port></Config>\n"
        );
        srv.abort();

        match prev_sock {
            Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
            None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
        }
        match prev_cfg_root {
            Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
            None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
        }
        for (k, val) in saved {
            match val {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_deploy_rollback_systemd_unit_reverts_and_reports_unprivileged_daemon_reload() {
        let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp_dir =
            std::env::temp_dir().join(format!("af-deploy-l02-unit-{}", uuid::Uuid::new_v4()));
        let cfg_root = tmp_dir.join("cfg_root");
        let unit_dir = cfg_root.join("etc/systemd/system");
        fs::create_dir_all(&unit_dir).unwrap();

        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

        let bp = af_services::get_blueprint("listenarr").expect("listenarr blueprint");
        let unit_path = unit_dir.join("listenarr.service");
        let prior_unit = b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:5050\n";
        fs::write(&unit_path, prior_unit).unwrap();

        let snaps = snapshot_deploy_files(&bp);
        fs::write(
            &unit_path,
            b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:15050\n",
        )
        .unwrap();

        // In fixture mode (is_real_host=false), unit file is reverted without calling host systemctl.
        let fixture_report =
            rollback_deploy_files_inner(&snaps, Some(&bp), None, Some(15050), true, false).await;
        assert!(fixture_report.fully_reverted);
        assert!(fixture_report.systemd_unit_restored);
        assert_eq!(fs::read(&unit_path).unwrap(), prior_unit);

        // When simulating real-host non-root execution without runner /v1/blueprint/apply fallback,
        // reverting a .service unit must surface the missing daemon-reload integration gap.
        if unsafe { libc::geteuid() } != 0 {
            fs::write(
                &unit_path,
                b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:15050\n",
            )
            .unwrap();
            let real_host_report =
                rollback_deploy_files_inner(&snaps, Some(&bp), None, Some(15050), true, true).await;
            assert!(real_host_report.systemd_unit_restored);
            assert!(!real_host_report.fully_reverted);
            assert!(real_host_report
                .errors
                .iter()
                .any(|e| e.contains("systemctl daemon-reload")));
        }

        match prev_cfg_root {
            Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
            None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
        }
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
