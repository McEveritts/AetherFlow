use crate::crypto::{aes_key_candidate_env_files, encrypt_with_key, AES_MASTER_KEY};
use crate::pool::{build_read_pool, migrate};
use crate::*;
use chrono::Utc;
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};
use std::env;
use std::fs;
use std::sync::Mutex;
use std::time::Duration;

pub(crate) static TEST_DB_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[test]
fn bundled_sqlite_includes_wal_security_fix() {
    assert!(
        rusqlite::version_number() >= 3_054_000,
        "bundled SQLite must include the RUSTSEC-2026-0459 WAL fix; found {}",
        rusqlite::version()
    );
}

#[test]
fn sqlite_preserves_checked_unsigned_integer_conversions() {
    let connection = Connection::open_in_memory().unwrap();
    let maximum = connection
        .query_row("SELECT ?1", [i64::MAX], |row| row.get::<_, u64>(0))
        .unwrap();
    assert_eq!(maximum, i64::MAX as u64);
    let offset = connection
        .query_row("SELECT 42", [], |row| row.get::<_, usize>(0))
        .unwrap();
    assert_eq!(offset, 42);
    assert!(connection
        .query_row("SELECT -1", [], |row| row.get::<_, u64>(0))
        .is_err());
}

#[test]
fn revocation_query_distinguishes_absent_revoked_and_database_errors() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let conn = Connection::open_in_memory().unwrap();
    assert!(token_revocation_status_with_conn(&conn, "session").is_err());
    conn.execute_batch(
        "CREATE TABLE revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
    )
    .unwrap();
    assert!(!token_revocation_status_with_conn(&conn, "absent").unwrap());
    for (jti, expiry) in [
        (
            "active",
            (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        ),
        (
            "expired",
            (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        ),
        ("bad-date", "invalid".into()),
    ] {
        conn.execute(
            "INSERT INTO revoked_tokens VALUES (?1, ?2)",
            params![jti, expiry],
        )
        .unwrap();
    }
    assert!(token_revocation_status_with_conn(&conn, "active").unwrap());
    assert!(!token_revocation_status_with_conn(&conn, "expired").unwrap());
    assert!(token_revocation_status_with_conn(&conn, "bad-date").is_err());
    conn.execute_batch("DROP TABLE revoked_tokens;").unwrap();
    assert!(token_revocation_status_with_conn(&conn, "absent").is_err());
}

#[test]
fn bounded_read_pool_works_while_writer_is_held_and_cannot_write() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = std::env::temp_dir().join(format!(
        "af-read-pool-{}-{}.sqlite",
        std::process::id(),
        rand::random::<u64>()
    ));
    let writer_pool = Pool::builder()
        .max_size(1)
        .build(SqliteConnectionManager::file(&path))
        .unwrap();
    let writer = writer_pool.get().unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE example (id INTEGER); INSERT INTO example VALUES (1); BEGIN IMMEDIATE; INSERT INTO example VALUES (2);").unwrap();
    let readers = build_read_pool(path.to_str().unwrap()).unwrap();
    let reader = readers.get().unwrap();
    let count: i64 = reader
        .query_row("SELECT COUNT(*) FROM example", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        count, 1,
        "Reader sees committed WAL snapshot while writer is busy"
    );
    assert!(reader
        .execute("INSERT INTO example VALUES (3)", [])
        .is_err());
    assert_eq!(readers.max_size(), 8);
    writer.execute_batch("ROLLBACK;").unwrap();
    drop(reader);
    drop(readers);
    drop(writer);
    drop(writer_pool);
    let _ = fs::remove_file(path);
}

#[test]
fn test_decrypt_key_requires_master_key_for_ciphertext() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let encrypted = encrypt_with_key("fixture-secret", &[1; 32]).unwrap();
    let previous = AES_MASTER_KEY
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let encrypted_result = decrypt_key(&encrypted);
    let plaintext_result = decrypt_key("local-development-key");
    *AES_MASTER_KEY.write().unwrap_or_else(|e| e.into_inner()) = previous;

    let error = encrypted_result.unwrap_err().to_string();
    assert!(error.contains("AES_MASTER_KEY is required"));
    assert!(!error.contains(&encrypted));
    assert_eq!(plaintext_result.unwrap(), "local-development-key");
}

#[test]
fn test_aes_gcm_roundtrip_and_format() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("AES_MASTER_KEY", "a".repeat(32));
    init_aes_key().unwrap();
    assert!(is_encryption_enabled());

    let encrypted = encrypt_key("my-secret-gemini-key").unwrap();
    assert!(encrypted.starts_with("enc:v1:"));
    let decrypted = decrypt_key(&encrypted).unwrap();
    assert_eq!(decrypted, "my-secret-gemini-key");
}

#[test]
fn test_sqlite_migrations_and_settings_singleton() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();
    let health = db_health_check().unwrap();
    assert_eq!(health["status"], "healthy");

    {
        let conn = get_conn().unwrap();
        let migration_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_versions WHERE version IN (20, 21, 22)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 3);
        let retired_runtime_tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='billing_webhook_cursors'", [], |row| row.get(0)
        ).unwrap();
        assert_eq!(retired_runtime_tables, 0);
        let provenance_column_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('streaming_history') WHERE name = 'provenance'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(provenance_column_count, 1);
        conn.query_row("SELECT COUNT(*) FROM plugins_registry", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    }

    for new_status in ["approved", "rejected"] {
        let action_id = {
            let conn = get_conn().unwrap();
            conn.execute(
                "INSERT INTO pending_actions (source, action, reason) VALUES ('audit', 'test', 'connection regression')",
                [],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let action = resolve_action(action_id, new_status, "audit-admin").unwrap();
        assert_eq!(action.status, new_status);
        assert_eq!(action.resolved_by.as_deref(), Some("audit-admin"));
        assert!(action.resolved_at.is_some());
        assert!(resolve_action(action_id, new_status, "audit-admin").is_err());
    }
}

#[test]
fn test_round3_64hex_aes_key_schema24_and_revoked_lineage_epoch_mfa() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let hex_key: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    let parsed = parse_aes_key_bytes(&hex_key).expect("64-char hex AES key must decode");
    assert_eq!(parsed[0], 0x00);
    assert_eq!(parsed[1], 0x01);
    assert!(parse_aes_key_bytes(&hex_key[..16]).is_err());
    assert!(parse_aes_key_bytes(&"z".repeat(64)).is_err());

    env::set_var("AES_MASTER_KEY", &hex_key);
    init_aes_key().unwrap();
    let ct = encrypt_key("hex-key-secret-value").unwrap();
    assert!(ct.starts_with("enc:v1:"));
    assert_eq!(decrypt_key(&ct).unwrap(), "hex-key-secret-value");

    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();
    let conn = get_conn().unwrap();
    let max_ver: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(max_ver, 24, "MAX(schema_versions.version) must remain 24");

    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (777, 'r3_db_user', 'user')",
        [],
    )
    .unwrap();

    revoke_token_in_tx(&conn, "r3-jti-1", Duration::from_secs(600)).unwrap();
    record_revoked_token_lineage_in_tx(&conn, "r3-jti-1", "r3-family-99", 777).unwrap();
    assert_eq!(
        resolve_revoked_token_family_in_tx(&conn, "r3-jti-1", 777)
            .unwrap()
            .as_deref(),
        Some("r3-family-99")
    );

    store_mfa_challenge_in_tx(&conn, "r3-mfa-tok", 777, 10, Duration::from_secs(300)).unwrap();
    let (_, ver) = begin_mfa_attempt_with_epoch(&conn, "r3-mfa-tok")
        .unwrap()
        .expect("challenge must exist");
    assert_eq!(ver, 10);
    assert!(!consume_mfa_challenge_with_epoch(&conn, "r3-mfa-tok", 777, 11).unwrap());
    assert!(consume_mfa_challenge_with_epoch(&conn, "r3-mfa-tok", 777, 10).unwrap());
}

#[test]
fn test_round7_migrate_legacy_secrets_encrypts_settings_totp_and_streaming() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("AES_MASTER_KEY", "c".repeat(64));
    init_aes_key().unwrap();
    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();

    {
        let conn = get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET gemini_api_key = 'plain-gemini', openai_api_key = 'plain-openai', anthropic_api_key = 'plain-anthropic' WHERE id = 1",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role, totp_secret, totp_enabled) VALUES (888, 'r7_mfa_user', 'admin', 'JBSWY3DPEHPK3PXP', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'JF', 'http://127.0.0.1:8096', 'plain-jf-api-key', 1)",
            [],
        )
        .unwrap();
    }

    migrate_legacy_secrets().expect("migrate_legacy_secrets must succeed");

    let conn = get_conn().unwrap();
    let (gem, oai, ant): (String, String, String) = conn
        .query_row(
            "SELECT gemini_api_key, openai_api_key, anthropic_api_key FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(gem.starts_with("enc:v1:"));
    assert!(oai.starts_with("enc:v1:"));
    assert!(ant.starts_with("enc:v1:"));
    assert_eq!(decrypt_key(&gem).unwrap(), "plain-gemini");
    assert_eq!(decrypt_key(&oai).unwrap(), "plain-openai");
    assert_eq!(decrypt_key(&ant).unwrap(), "plain-anthropic");

    let totp_enc: String = conn
        .query_row("SELECT totp_secret FROM users WHERE id = 888", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(totp_enc.starts_with("enc:v1:"));
    assert_eq!(decrypt_key(&totp_enc).unwrap(), "JBSWY3DPEHPK3PXP");

    let stream_enc: String = conn
        .query_row(
            "SELECT api_key FROM streaming_servers WHERE provider = 'jellyfin'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(stream_enc.starts_with("enc:v1:"));
    assert_eq!(decrypt_key(&stream_enc).unwrap(), "plain-jf-api-key");
}

#[test]
fn test_round8_env_file_aes_fallback_and_rfc3339_prune_expired_data() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let env_path = std::env::temp_dir().join(format!(
        "af_r8_env_file_{}_{}.env",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::write(&env_path, format!("AES_MASTER_KEY={}\n", "e".repeat(64))).unwrap();
    env::remove_var("AES_MASTER_KEY");
    env::set_var("AETHERFLOW_ENV_FILE", &env_path);
    init_aes_key().expect("init_aes_key must load AES_MASTER_KEY from AETHERFLOW_ENV_FILE");
    let ct = encrypt_key("r8-env-secret").unwrap();
    assert!(
        ct.starts_with("enc:v1:"),
        "expected AES-256-GCM ciphertext prefix enc:v1:, got {ct}"
    );
    assert_eq!(decrypt_key(&ct).unwrap(), "r8-env-secret");
    env::remove_var("AETHERFLOW_ENV_FILE");
    let _ = std::fs::remove_file(&env_path);
    env::set_var("AES_MASTER_KEY", "c".repeat(64));
    init_aes_key().unwrap();

    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();
    let now_rfc3339 = Utc::now().to_rfc3339();
    {
        let conn = get_conn().unwrap();
        conn.execute(
            "INSERT INTO login_history (user_id, ip_address, user_agent, created_at) \
             VALUES (1, '10.0.0.1', 'ua-old', '2020-01-01T00:00:00+00:00'), \
                    (1, '10.0.0.2', 'ua-fresh', ?1)",
            params![now_rfc3339],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO metrics_history (cpu_avg, timestamp) \
             VALUES (1.0, '2020-01-01T00:00:00+00:00'), \
                    (2.0, ?1)",
            params![now_rfc3339],
        )
        .unwrap();
    }
    prune_expired_data();
    let conn = get_conn().unwrap();
    let login_rem: Vec<String> = conn
        .prepare("SELECT user_agent FROM login_history")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(login_rem, vec!["ua-fresh".to_string()]);
    let metrics_cnt: i64 = conn
        .query_row("SELECT COUNT(*) FROM metrics_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(metrics_cnt, 1);

    let future_exp = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
    let past_exp = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    conn.execute(
        "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, expires_at, used) \
         VALUES ('live-used-tombstone', 'cid', 1, 'https://app.example/cb', 'openid', ?1, 1), \
                ('expired-used-code', 'cid', 1, 'https://app.example/cb', 'openid', ?2, 1)",
        params![future_exp, past_exp],
    )
    .unwrap();
    drop(conn);
    prune_expired_data();
    let conn = get_conn().unwrap();
    let remaining_codes: Vec<String> = conn
        .prepare("SELECT code FROM oidc_auth_codes")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(remaining_codes, vec!["live-used-tombstone".to_string()]);
}

#[test]
fn test_init_aes_key_requires_key_when_aetherflow_env_production() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let prev_aes = env::var("AES_MASTER_KEY").ok();
    let prev_af_env = env::var("AETHERFLOW_ENV").ok();
    let prev_gin = env::var("GIN_MODE").ok();
    let prev_skip = env::var("AETHERFLOW_SKIP_ENV_FILES").ok();

    env::remove_var("AES_MASTER_KEY");
    env::remove_var("GIN_MODE");
    env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    env::set_var("AETHERFLOW_ENV", "production");

    let err = init_aes_key()
        .expect_err("AETHERFLOW_ENV=production without AES_MASTER_KEY must fail closed");
    assert!(err
        .to_string()
        .contains("AES_MASTER_KEY is required in production"));
    assert!(!err.to_string().contains("GIN_MODE"));

    env::set_var("AETHERFLOW_ENV", "disposable-guest-lifecycle-drill");
    env::set_var("GIN_MODE", "release");
    init_aes_key().expect(
        "legacy GIN_MODE=release must be ignored when AETHERFLOW_ENV is non-production",
    );

    match prev_aes {
        Some(v) => env::set_var("AES_MASTER_KEY", v),
        None => env::remove_var("AES_MASTER_KEY"),
    }
    match prev_af_env {
        Some(v) => env::set_var("AETHERFLOW_ENV", v),
        None => env::remove_var("AETHERFLOW_ENV"),
    }
    match prev_gin {
        Some(v) => env::set_var("GIN_MODE", v),
        None => env::remove_var("GIN_MODE"),
    }
    match prev_skip {
        Some(v) => env::set_var("AETHERFLOW_SKIP_ENV_FILES", v),
        None => env::remove_var("AETHERFLOW_SKIP_ENV_FILES"),
    }
}

#[test]
fn test_aes_key_candidate_env_files_includes_default_fallback() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    struct EnvGuard {
        prev_skip: Option<String>,
        prev_file: Option<String>,
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_skip {
                Some(v) => env::set_var("AETHERFLOW_SKIP_ENV_FILES", v),
                None => env::remove_var("AETHERFLOW_SKIP_ENV_FILES"),
            }
            match &self.prev_file {
                Some(v) => env::set_var("AETHERFLOW_ENV_FILE", v),
                None => env::remove_var("AETHERFLOW_ENV_FILE"),
            }
        }
    }
    let _env_guard = EnvGuard {
        prev_skip: env::var("AETHERFLOW_SKIP_ENV_FILES").ok(),
        prev_file: env::var("AETHERFLOW_ENV_FILE").ok(),
    };

    env::remove_var("AETHERFLOW_SKIP_ENV_FILES");
    env::remove_var("AETHERFLOW_ENV_FILE");
    let default_only = aes_key_candidate_env_files();
    assert_eq!(
        default_only,
        vec![std::path::PathBuf::from("/etc/aetherflow/aetherflow.env")]
    );

    env::set_var("AETHERFLOW_ENV_FILE", "/tmp/custom-af.env");
    let with_explicit = aes_key_candidate_env_files();
    assert_eq!(
        with_explicit,
        vec![
            std::path::PathBuf::from("/tmp/custom-af.env"),
            std::path::PathBuf::from("/etc/aetherflow/aetherflow.env"),
        ]
    );

    env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    assert!(aes_key_candidate_env_files().is_empty());
}

#[test]
fn test_migrate_is_atomic_on_mid_migration_failure() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_versions (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .unwrap();

    let err = migrate(
        &conn,
        99,
        "failing partial migration",
        &[
            "CREATE TABLE atomic_test_table (id INTEGER PRIMARY KEY);",
            "THIS IS NOT VALID SQL;",
        ],
    )
    .expect_err("invalid second statement must fail migration");
    assert!(!err.to_string().is_empty());
    assert!(
        conn.is_autocommit(),
        "connection must not stay in transaction"
    );

    let table_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='atomic_test_table'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        table_exists, 0,
        "first DDL statement must be rolled back when later statement fails"
    );
    let version_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 99",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version_exists, 0);

    // Now apply a valid migration and verify idempotent re-run
    migrate(
        &conn,
        99,
        "valid atomic migration",
        &["CREATE TABLE atomic_test_table (id INTEGER PRIMARY KEY);"],
    )
    .unwrap();
    migrate(
        &conn,
        99,
        "valid atomic migration",
        &["THIS WOULD FAIL IF RE-EXECUTED;"],
    )
    .unwrap();
    let version_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 99",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version_count, 1);
}

#[test]
fn test_system_prompt_default_updated_to_rust_wasm() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();
    let conn = get_conn().unwrap();
    let prompt: String = conn
        .query_row("SELECT system_prompt FROM settings WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(prompt.contains("sovereign Rust + WebAssembly aetherflow-api environment"));
    assert!(!prompt.contains("Next.js"));
}

#[test]
fn test_per_user_broadcast_notification_reads_isolate_users() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    env::set_var("DB_PATH", ":memory:");
    init_db().unwrap();
    let conn = get_conn().unwrap();

    // Seed two broadcast notifications (user_id IS NULL) and one owned per user
    conn.execute(
        "INSERT INTO notifications (id, user_id, level, title, message, read)
         VALUES (1, NULL, 'info', 'Broadcast A', 'Hello all', 0),
                (2, NULL, 'warning', 'Broadcast B', 'Maintenance', 0),
                (3, 1, 'info', 'User 1 private', 'Only 1', 0),
                (4, 2, 'error', 'User 2 private', 'Only 2', 0)",
        [],
    )
    .unwrap();

    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
        3
    );
    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
        3
    );

    // User 1 cannot mark User 2's private notification read
    assert!(!mark_notification_read_for_user_with_conn(&conn, 1, 4).unwrap());
    assert!(!mark_notification_read_for_user_with_conn(&conn, 1, 999).unwrap());

    // User 1 marks Broadcast A (id=1) read: notifications.read MUST stay 0!
    assert!(mark_notification_read_for_user_with_conn(&conn, 1, 1).unwrap());
    let broadcast_global_read: bool = conn
        .query_row("SELECT read FROM notifications WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        !broadcast_global_read,
        "marking broadcast notification read for user 1 must NOT mutate notifications.read"
    );

    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
        2
    );
    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
        3
    );

    let (u1_list, u1_unread) = list_notifications_for_user_with_conn(&conn, 1, 50, 0).unwrap();
    assert_eq!(u1_unread, 2);
    assert_eq!(u1_list.len(), 3);
    let u1_b1 = u1_list.iter().find(|n| n.id == 1).unwrap();
    assert!(u1_b1.read);

    let (u2_list, u2_unread) = list_notifications_for_user_with_conn(&conn, 2, 50, 0).unwrap();
    assert_eq!(u2_unread, 3);
    let u2_b1 = u2_list.iter().find(|n| n.id == 1).unwrap();
    assert!(!u2_b1.read, "Broadcast A must remain unread for user 2");

    // User 1 dismisses all remaining unread (Broadcast B id=2 + private id=3)
    let dismissed_u1 = dismiss_all_notifications_for_user_with_conn(&conn, 1).unwrap();
    assert_eq!(dismissed_u1, 2);
    assert_eq!(
        dismiss_all_notifications_for_user_with_conn(&conn, 1).unwrap(),
        0
    );
    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 1).unwrap(),
        0
    );

    // User 2 still has all 3 unread (both broadcasts + User 2 private)!
    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
        3
    );
    let dismissed_u2 = dismiss_all_notifications_for_user_with_conn(&conn, 2).unwrap();
    assert_eq!(dismissed_u2, 3);
    assert_eq!(
        count_unread_notifications_for_user_with_conn(&conn, 2).unwrap(),
        0
    );
}
