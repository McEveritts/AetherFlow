use super::backup_uploads::{finalize_assembled_backup_upload, process_backup_chunk_upload_in_dir};
use super::backups::{
    authorize_backup_password, backup_reauth_password, compute_file_sha256,
    get_optimal_backup_window, is_valid_backup_filename, list_verified_backups_in_dir,
    percent_decode_header_utf8, query_optimal_backup_window_conn, read_verified_backup_checksum,
    safe_backup_path, verify_backup_password, BACKUP_REAUTH,
};
use crate::auth::AuthUser;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::Utc;
use rusqlite::params;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;

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
    finalize_assembled_backup_upload(&dir, clean_base, &first_temp, &final_path, &first_checksum)
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

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_oauth_only_admin_backup_stepup_against_current_schema() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
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

    af_db::init_db().expect("initialize full v28 schema");
    let now = Utc::now().timestamp();
    {
        let conn = af_db::get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);
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
    assert!(!authorize_backup_password(&expired_text_admin, Some(now - 10), &headers, &[]).await);
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
async fn list_verified_backups_distinguishes_missing_dir_from_filesystem_errors() {
    let root = env::temp_dir().join(format!("af-list-backups-err-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    // Missing backup directory returns 200 [].
    let missing_resp = list_verified_backups_in_dir(&root.join("does-not-exist"));
    assert_eq!(missing_resp.status(), StatusCode::OK);
    let missing_body = axum::body::to_bytes(missing_resp.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(missing_body.as_ref(), b"[]");

    // Non-directory path triggers ENOTDIR and must return 500 instead of 200 [].
    let regular_file = root.join("not-a-dir");
    fs::write(&regular_file, b"content").unwrap();
    let err_resp = list_verified_backups_in_dir(&regular_file);
    assert_eq!(err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn get_optimal_backup_window_returns_internal_error_on_db_failure() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    // Missing settings row defaults cleanly to manual.
    let mem = rusqlite::Connection::open_in_memory().unwrap();
    mem.execute_batch(
        "CREATE TABLE settings (id INTEGER PRIMARY KEY, backup_schedule_mode TEXT, backup_next_run_at TEXT);
         CREATE TABLE metrics_history (id INTEGER PRIMARY KEY, timestamp TEXT, cpu_avg REAL, mem_used_gb REAL, mem_total_gb REAL);",
    )
    .unwrap();
    let defaulted = query_optimal_backup_window_conn(&mem).unwrap();
    assert_eq!(defaulted["mode"], "manual");
    assert_eq!(defaulted["running"], false);

    // Real SQLite error (missing settings table) must propagate rather than silently returning 200.
    let broken = rusqlite::Connection::open_in_memory().unwrap();
    assert!(query_optimal_backup_window_conn(&broken).is_err());

    crate::plugins::tests::ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("DROP TABLE settings;").unwrap();
    }
    let resp = get_optimal_backup_window().await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
