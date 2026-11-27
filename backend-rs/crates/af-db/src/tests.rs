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
    assert_eq!(max_ver, 28, "MAX(schema_versions.version) must be 28");

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
    init_aes_key()
        .expect("legacy GIN_MODE=release must be ignored when AETHERFLOW_ENV is non-production");

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

struct TestDbPathGuard(Option<std::ffi::OsString>);

impl Drop for TestDbPathGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => env::set_var("DB_PATH", value),
            None => env::remove_var("DB_PATH"),
        }
    }
}

fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("prepare PRAGMA table_info");
    stmt.query_map([], |row| row.get::<_, String>(1))
        .expect("query PRAGMA table_info")
        .map(|row| row.expect("read column name"))
        .collect()
}

struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sqlite_object_exists(conn: &Connection, obj_type: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
        params![obj_type, name],
        |r| r.get(0),
    )
    .expect("query sqlite_master")
}

fn assert_no_legacy_cluster_objects(conn: &Connection) {
    for table in [
        "cluster_nodes",
        "cluster_enrollment_tokens",
        "cluster_commands",
    ] {
        assert!(
            !sqlite_object_exists(conn, "table", table),
            "legacy table {table} must not exist after migration 26"
        );
    }
    for index in [
        "idx_cluster_nodes_status",
        "idx_cluster_commands_node_status",
    ] {
        assert!(
            !sqlite_object_exists(conn, "index", index),
            "legacy index {index} must not exist after migration 26"
        );
    }
}

fn assert_db_integrity(conn: &Connection) {
    let mut fk_stmt = conn
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare PRAGMA foreign_key_check");
    let fk_violations: Vec<String> = fk_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("run PRAGMA foreign_key_check")
        .map(|row| row.expect("read foreign_key_check row"))
        .collect();
    assert!(
        fk_violations.is_empty(),
        "database must have zero foreign key violations, found: {fk_violations:?}"
    );

    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .expect("run PRAGMA integrity_check");
    assert_eq!(integrity, "ok", "PRAGMA integrity_check must return ok");
}

fn seed_legacy_master_worker_tables(conn: &Connection) {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS cluster_nodes (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            address TEXT NOT NULL,
            psk_hash TEXT NOT NULL,
            role TEXT DEFAULT 'worker',
            status TEXT DEFAULT 'offline',
            last_heartbeat DATETIME,
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME,
            cpu_usage REAL DEFAULT 0.0,
            ram_usage REAL DEFAULT 0.0,
            disk_usage REAL DEFAULT 0.0,
            peer_cert_sha256 TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);

        CREATE TABLE IF NOT EXISTS cluster_enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_by TEXT
        );

        CREATE TABLE IF NOT EXISTS cluster_commands (
            id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            cmd_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            leased_until INTEGER,
            lease_generation INTEGER NOT NULL DEFAULT 0,
            result_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cluster_commands_node_status
            ON cluster_commands(node_id, status, created_at);

        INSERT INTO cluster_nodes (
            id, hostname, address, psk_hash, role, status,
            last_heartbeat, last_seen, cpu_usage, ram_usage, disk_usage, peer_cert_sha256
        ) VALUES
            ('legacy-node-1', 'worker-1', '10.0.0.5', 'sha256:legacy-hash-1', 'worker', 'online',
             '2026-11-22T12:00:00Z', '2026-11-22T12:00:00Z', 14.5, 41.2, 62.0, 'aabbccdd'),
            ('legacy-node-2', 'worker-2', '10.0.0.6', 'sha256:legacy-hash-2', 'worker', 'offline',
             '2026-11-21T08:30:00Z', '2026-11-21T08:30:00Z', 0.0, 0.0, 0.0, 'eeff0011');

        INSERT INTO cluster_enrollment_tokens (token_hash, created_at, expires_at, consumed_by)
        VALUES
            ('sha256:enroll-active', '2026-11-22T10:00:00Z', 1800000000, NULL),
            ('sha256:enroll-used', '2026-11-20T10:00:00Z', 1799900000, 'legacy-node-1');

        INSERT INTO cluster_commands (
            id, node_id, cmd_type, target, status, leased_until, lease_generation,
            result_message, created_at, updated_at
        ) VALUES
            ('cmd-1', 'legacy-node-1', 'systemctl', 'restart:radarr', 'queued', NULL, 0,
             NULL, '2026-11-22T11:55:00Z', '2026-11-22T11:55:00Z'),
            ('cmd-2', 'legacy-node-1', 'ping', 'health', 'executed', 1795350000, 2,
             'pong', '2026-11-22T11:50:00Z', '2026-11-22T11:50:05Z');
        "#,
    )
    .expect("seed legacy master/worker cluster tables");
}

fn expected_peer_table_columns() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        (
            "peer_identity",
            &["id", "wg_pubkey", "tunnel_ip", "wg_port", "created_at"],
        ),
        (
            "peer_links",
            &[
                "id",
                "name",
                "wg_pubkey",
                "tunnel_ip",
                "endpoint",
                "wg_port",
                "state",
                "peer_version",
                "peer_protocol",
                "capabilities",
                "rtt_ms",
                "last_ok_at",
                "last_error",
                "consecutive_failures",
                "inbound_token_hash",
                "pending_attempt_id",
                "pending_expires_at",
                "created_at",
                "updated_at",
            ],
        ),
        (
            "peer_grants",
            &[
                "id",
                "link_id",
                "run_as_user_id",
                "access",
                "token_hash",
                "created_by",
                "created_at",
                "revoked_at",
            ],
        ),
        (
            "peer_received_grants",
            &[
                "link_id",
                "grant_id",
                "run_as_user_id",
                "access",
                "created_by",
                "created_at",
                "generation",
                "revoked_at",
                "credential_id",
                "updated_at",
            ],
        ),
        (
            "peer_received_grant_cleanups",
            &["link_id", "credential_id", "generation", "updated_at"],
        ),
        (
            "peer_grant_epochs",
            &["link_id", "issuer_generation", "active_op_id", "updated_at"],
        ),
        (
            "peer_pairing_windows",
            &["id", "code_hash", "expires_at", "consumed_at"],
        ),
        (
            "peer_pairing_attempts",
            &[
                "id",
                "window_id",
                "remote_name",
                "remote_pubkey",
                "remote_tunnel_ip",
                "remote_endpoint",
                "source_ip",
                "status",
                "error_code",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "peer_exports",
            &[
                "id",
                "link_id",
                "path",
                "writable",
                "squash_uid",
                "squash_gid",
                "created_at",
            ],
        ),
        (
            "peer_mounts",
            &[
                "id",
                "link_id",
                "remote_path",
                "mount_path",
                "unit_name",
                "writable",
                "purpose",
                "state",
                "last_error",
            ],
        ),
        (
            "transcode_workers",
            &[
                "link_id",
                "enabled",
                "weight",
                "max_jobs",
                "ffmpeg_version",
                "encoders",
                "render_node",
                "parity_ok",
                "parity_error",
            ],
        ),
        (
            "transcode_jobs",
            &[
                "id",
                "link_id",
                "started_at",
                "ended_at",
                "exit_code",
                "request_id",
                "ran_locally",
            ],
        ),
        (
            "transcode_dispatch_settings",
            &["id", "dispatch_policy", "local_max_jobs", "updated_at"],
        ),
    ]
}

#[test]
fn migration_v26_fresh_db_creates_peer_tables_and_omits_legacy_cluster_tables() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _db_path_guard = TestDbPathGuard(env::var_os("DB_PATH"));

    let dir = TempDirGuard(env::temp_dir().join(format!(
        "af-peer-v26-fresh-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir_all(&dir.0).unwrap();
    let db_file = dir.0.join("fresh.sqlite");
    env::set_var("DB_PATH", &db_file);

    init_db().expect("fresh init_db must apply migrations through 28");

    {
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);

        let version_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version_count, 28, "versions 1..=28 must all be recorded");

        let v25_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 25",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v25_desc, "Peer clustering");

        let v26_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 26",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v26_desc, "Remove legacy master/worker clustering");

        let v27_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 27",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v27_desc, "Peer grant direction metadata");

        let v28_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 28",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            v28_desc,
            "Add distributed transcode dispatch policy settings"
        );

        for expected_ver in [5, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM schema_versions WHERE version = ?1",
                    params![expected_ver],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 1,
                "schema_versions must record version {expected_ver} exactly once"
            );
        }

        // Legacy master/worker tables and indexes must never be created on a fresh DB
        assert_no_legacy_cluster_objects(&conn);

        // Unrelated app, auth, and streaming tables remain intact
        for preserved_table in [
            "settings",
            "users",
            "active_sessions",
            "mfa_challenges",
            "revoked_tokens",
            "recovery_codes",
            "oidc_clients",
            "oidc_consents",
            "plugins_registry",
            "streaming_servers",
            "streaming_history",
            "streaming_history_read_revision",
            "mediaflow_queue",
            "app_ingress_configs",
            "pending_actions",
            "admin_audit_log",
            "notifications",
            "notification_reads",
        ] {
            assert!(
                sqlite_object_exists(&conn, "table", preserved_table),
                "table {preserved_table} must exist on fresh v26 DB"
            );
        }

        // Verify exact column layout for all peer clustering & distributed transcode tables
        for (table, expected_cols) in expected_peer_table_columns() {
            let actual = table_columns(&conn, table);
            let expected: Vec<String> = expected_cols.iter().map(|c| (*c).to_string()).collect();
            assert_eq!(actual, expected, "column layout mismatch on table {table}");
        }

        // Verify users.account_type defaults to 'human'
        conn.execute(
            "INSERT INTO users (username, role) VALUES ('fresh-human', 'admin')",
            [],
        )
        .unwrap();
        let account_type: String = conn
            .query_row(
                "SELECT account_type FROM users WHERE username = 'fresh-human'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(account_type, "human");
        assert_db_integrity(&conn);
    }

    // Repeated init_db() must be idempotent and never recreate legacy cluster tables/indexes
    for _ in 0..2 {
        init_db().expect("repeated fresh init_db must succeed");
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);
        assert_no_legacy_cluster_objects(&conn);
        let account_type: String = conn
            .query_row(
                "SELECT account_type FROM users WHERE username = 'fresh-human'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(account_type, "human");
        assert_db_integrity(&conn);
    }
}

#[test]
fn migration_v25_preserves_legacy_v24_rows_and_v26_owns_legacy_deletion() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _db_path_guard = TestDbPathGuard(env::var_os("DB_PATH"));

    let dir = TempDirGuard(env::temp_dir().join(format!(
        "af-peer-v24-to-v26-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir_all(&dir.0).unwrap();

    let prepare_v24_snapshot = |db_file: &std::path::Path| {
        env::set_var("DB_PATH", db_file);
        init_db().unwrap();
        let conn = get_conn().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE IF EXISTS transcode_dispatch_settings;
             DROP TABLE transcode_jobs;
             DROP TABLE transcode_workers;
             DROP TABLE peer_mounts;
             DROP TABLE peer_exports;
             DROP TABLE peer_pairing_attempts;
             DROP TABLE peer_pairing_windows;
             DROP TABLE peer_grant_epochs;
             DROP TABLE IF EXISTS peer_received_grant_cleanups;
             DROP TABLE peer_received_grants;
             DROP TABLE peer_grants;
             DROP TABLE peer_links;
             DROP TABLE peer_identity;
             DELETE FROM schema_versions WHERE version IN (25, 26, 27, 28);
             DROP TABLE users;
             CREATE TABLE users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password_hash TEXT DEFAULT '',
                 google_id TEXT DEFAULT '',
                 email TEXT DEFAULT '',
                 avatar_url TEXT DEFAULT '',
                 role TEXT DEFAULT 'user',
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                 totp_secret TEXT DEFAULT '',
                 totp_enabled BOOLEAN DEFAULT 0,
                 last_totp_step INTEGER NOT NULL DEFAULT -1,
                 sessions_revoked_after INTEGER NOT NULL DEFAULT 0
             );
             INSERT INTO users (id, username, role) VALUES
                 (1, 'legacy-admin', 'admin'),
                 (2, 'legacy-member', 'user');
             INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, family_id)
                 VALUES ('legacy-sess-1', 1, '127.0.0.1', 'af-test', '2099-01-01T00:00:00Z', 'fam-legacy');
             INSERT INTO plugins_registry (plugin_id, enabled)
                 VALUES ('legacy-plugin', 1);
             PRAGMA foreign_keys = ON;",
        )
        .expect("prepare pre-v25 legacy snapshot");
        seed_legacy_master_worker_tables(&conn);

        assert!(
            !table_columns(&conn, "users").contains(&"account_type".to_string()),
            "pre-v25 legacy users table must not yet have account_type"
        );
        let pre_max: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pre_max, 24);
    };

    // Part 1: Stepwise v24 -> v25 (P0 preservation contract) -> v26 (legacy deletion)
    let stepwise_db = dir.0.join("stepwise.sqlite");
    prepare_v24_snapshot(&stepwise_db);

    {
        let conn = get_conn().unwrap();
        // Exercise migration 25 directly to verify P0 preservation contracts still hold
        migrate(
            &conn,
            25,
            "Peer clustering",
            peers::PEER_CLUSTERING_MIGRATION_25_SQL,
        )
        .expect("applying migration 25 directly to v24 snapshot must succeed");

        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 25);

        let legacy_users: Vec<(String, String)> = conn
            .prepare("SELECT username, account_type FROM users ORDER BY id ASC")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            legacy_users,
            vec![
                ("legacy-admin".to_string(), "human".to_string()),
                ("legacy-member".to_string(), "human".to_string()),
            ],
            "migration 25 must preserve existing users with default account_type='human'"
        );

        // Migration 25 itself must NOT delete legacy master/worker tables
        let preserved_cluster: String = conn
            .query_row(
                "SELECT hostname FROM cluster_nodes WHERE id = 'legacy-node-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(preserved_cluster, "worker-1");
        assert!(sqlite_object_exists(
            &conn,
            "table",
            "cluster_enrollment_tokens"
        ));
        assert!(sqlite_object_exists(&conn, "table", "cluster_commands"));
        assert!(sqlite_object_exists(
            &conn,
            "index",
            "idx_cluster_nodes_status"
        ));
        assert!(sqlite_object_exists(
            &conn,
            "index",
            "idx_cluster_commands_node_status"
        ));

        // Seed v25 peer data before migration 26 runs via init_db()
        peers::upsert_peer_identity(
            &conn,
            &peers::PeerIdentity {
                wg_pubkey: "pk-local-restart".to_string(),
                tunnel_ip: "10.231.0.1".to_string(),
                wg_port: 51821,
                created_at: "2026-11-23T05:00:00Z".to_string(),
            },
        )
        .unwrap();
    }

    // Now run init_db(): migration 26 owns legacy-table deletion, migration 27 adds grant direction
    // tables, and migration 28 adds transcode dispatch settings
    init_db().expect("upgrading v25 database to v28 via init_db must succeed");

    for _ in 0..2 {
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);

        let v25_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_versions WHERE version = 25",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v25_rows, 1);
        let v26_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_versions WHERE version = 26",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v26_rows, 1);

        assert_no_legacy_cluster_objects(&conn);

        let identity = peers::get_peer_identity(&conn)
            .unwrap()
            .expect("peer identity must survive migration 26 and restarts");
        assert_eq!(identity.wg_pubkey, "pk-local-restart");

        let legacy_users: Vec<(String, String)> = conn
            .prepare("SELECT username, account_type FROM users ORDER BY id ASC")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            legacy_users,
            vec![
                ("legacy-admin".to_string(), "human".to_string()),
                ("legacy-member".to_string(), "human".to_string()),
            ]
        );

        let preserved_plugin: bool = conn
            .query_row(
                "SELECT enabled FROM plugins_registry WHERE plugin_id = 'legacy-plugin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(preserved_plugin);

        let preserved_session_family: String = conn
            .query_row(
                "SELECT family_id FROM active_sessions WHERE jti = 'legacy-sess-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(preserved_session_family, "fam-legacy");
        assert_db_integrity(&conn);

        drop(conn);
        init_db().expect("repeated restart init_db on v26 database must be idempotent");
    }

    // Part 2: Direct v24 -> v28 upgrade in a single init_db() call
    let direct_db = dir.0.join("direct_v24_to_v28.sqlite");
    prepare_v24_snapshot(&direct_db);
    init_db().expect("direct v24 -> v28 upgrade via init_db must succeed");
    {
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);
        assert_no_legacy_cluster_objects(&conn);
        for (table, _) in expected_peer_table_columns() {
            assert!(
                sqlite_object_exists(&conn, "table", table),
                "peer table {table} must be created during direct v24 -> v26 upgrade"
            );
        }
        let admin_type: String = conn
            .query_row(
                "SELECT account_type FROM users WHERE username = 'legacy-admin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(admin_type, "human");
        assert_db_integrity(&conn);
    }
}

#[test]
fn migration_v26_upgrades_real_v25_legacy_fixture_and_preserves_peer_auth_and_app_data() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _db_path_guard = TestDbPathGuard(env::var_os("DB_PATH"));

    let dir = TempDirGuard(env::temp_dir().join(format!(
        "af-peer-v26-v25-fixture-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir_all(&dir.0).unwrap();
    let db_file = dir.0.join("v25_legacy_fixture.sqlite");
    env::set_var("DB_PATH", &db_file);

    // Bootstrap schema then pin fixture to real migration-25 state (v1..=v25, no v26)
    init_db().unwrap();

    let expected_identity = peers::PeerIdentity {
        wg_pubkey: "pk-server-a-local".to_string(),
        tunnel_ip: "10.231.0.1".to_string(),
        wg_port: 51821,
        created_at: "2026-11-23T06:00:00Z".to_string(),
    };
    let expected_active_link = peers::PeerLink {
        id: "link-media-2".to_string(),
        name: "media-2".to_string(),
        wg_pubkey: "pk-server-b-active".to_string(),
        tunnel_ip: "10.231.0.2".to_string(),
        endpoint: "198.51.100.20".to_string(),
        wg_port: 51821,
        state: "active".to_string(),
        peer_version: Some("4.0.0".to_string()),
        peer_protocol: Some(1),
        capabilities: Some(r#"["links"]"#.to_string()),
        rtt_ms: Some(1.42),
        last_ok_at: Some("2026-11-23T11:59:00Z".to_string()),
        last_error: None,
        consecutive_failures: 0,
        inbound_token_hash: Some("sha256:inbound-token-b".to_string()),
        pending_attempt_id: None,
        pending_expires_at: None,
        created_at: "2026-11-23T06:10:00Z".to_string(),
        updated_at: "2026-11-23T11:59:00Z".to_string(),
    };
    let expected_pending_link = peers::PeerLink {
        id: "link-gpu-3".to_string(),
        name: "gpu-3".to_string(),
        wg_pubkey: "pk-server-c-pending".to_string(),
        tunnel_ip: "10.231.0.3".to_string(),
        endpoint: "198.51.100.30".to_string(),
        wg_port: 51821,
        state: "pending".to_string(),
        peer_version: None,
        peer_protocol: None,
        capabilities: None,
        rtt_ms: None,
        last_ok_at: None,
        last_error: None,
        consecutive_failures: 0,
        inbound_token_hash: Some("sha256:inbound-token-c".to_string()),
        pending_attempt_id: Some("attempt-pending-1".to_string()),
        pending_expires_at: Some(1_800_000_600),
        created_at: "2026-11-23T11:50:00Z".to_string(),
        updated_at: "2026-11-23T11:50:00Z".to_string(),
    };
    let expected_grant = peers::PeerGrant {
        id: "grant-media-2".to_string(),
        link_id: "link-media-2".to_string(),
        run_as_user_id: 10,
        access: peers::AccessMap::read_only_all(),
        token_hash: Some("sha256:grant-token-b".to_string()),
        created_by: "alice".to_string(),
        created_at: "2026-11-23T06:15:00Z".to_string(),
        revoked_at: None,
    };
    let expected_window_open = peers::PairingWindow {
        id: "win-open".to_string(),
        code_hash: "sha256:code-open".to_string(),
        expires_at: 1_800_000_900,
        consumed_at: None,
    };
    let expected_window_used = peers::PairingWindow {
        id: "win-used".to_string(),
        code_hash: "sha256:code-used".to_string(),
        expires_at: 1_800_000_300,
        consumed_at: Some(1_795_340_000),
    };
    let expected_attempt = peers::PairingAttempt {
        id: "attempt-pending-1".to_string(),
        window_id: Some("win-used".to_string()),
        remote_name: Some("gpu-3".to_string()),
        remote_pubkey: Some("pk-server-c-pending".to_string()),
        remote_tunnel_ip: Some("10.231.0.3".to_string()),
        remote_endpoint: Some("198.51.100.30".to_string()),
        source_ip: Some("198.51.100.30".to_string()),
        status: "pending_confirm".to_string(),
        error_code: None,
        expires_at: 1_800_000_600,
        created_at: "2026-11-23T11:50:00Z".to_string(),
    };
    let expected_export = peers::PeerExport {
        id: "exp-movies".to_string(),
        link_id: "link-media-2".to_string(),
        path: "/srv/media/movies".to_string(),
        writable: false,
        squash_uid: Some(1000),
        squash_gid: Some(1000),
        created_at: "2026-11-23T06:20:00Z".to_string(),
    };
    let expected_mount = peers::PeerMount {
        id: "mnt-movies".to_string(),
        link_id: "link-media-2".to_string(),
        remote_path: "/srv/media/movies".to_string(),
        mount_path: "/mnt/af-peers/media-2/movies".to_string(),
        unit_name: "mnt-af\\x2dpeers-media\\x2d2-movies.mount".to_string(),
        writable: false,
        purpose: "media".to_string(),
        state: "mounted".to_string(),
        last_error: None,
    };
    let expected_worker = peers::TranscodeWorker {
        link_id: "link-media-2".to_string(),
        enabled: true,
        weight: 2,
        max_jobs: 4,
        ffmpeg_version: Some("8.1.3-1-trixie".to_string()),
        encoders: Some(r#"["h264_vaapi","hevc_vaapi"]"#.to_string()),
        render_node: Some("/dev/dri/renderD128".to_string()),
        parity_ok: true,
        parity_error: None,
    };
    let expected_job = peers::TranscodeJob {
        id: "job-vaapi-1".to_string(),
        link_id: Some("link-media-2".to_string()),
        started_at: "2026-11-23T11:40:00Z".to_string(),
        ended_at: Some("2026-11-23T11:42:00Z".to_string()),
        exit_code: Some(0),
        request_id: Some("req-transcode-1".to_string()),
        ran_locally: false,
    };

    {
        let conn = get_conn().unwrap();
        conn.execute_batch(
            "DROP TABLE IF EXISTS transcode_dispatch_settings;
             DROP TABLE IF EXISTS peer_grant_epochs;
             DROP TABLE IF EXISTS peer_received_grant_cleanups;
             DROP TABLE IF EXISTS peer_received_grants;
             DELETE FROM schema_versions WHERE version IN (26, 27, 28);",
        )
        .unwrap();
        seed_legacy_master_worker_tables(&conn);

        // Auth & users rows (human + peer run-as + sessions + MFA + OIDC)
        conn.execute_batch(
            r#"
            INSERT INTO users (
                id, username, password_hash, email, role, totp_secret, totp_enabled,
                last_totp_step, sessions_revoked_after, account_type
            ) VALUES
                (1, 'alice', '$argon2id$alice', 'alice@example.test', 'admin',
                 'enc:v1:alice-totp', 1, 42, 1700000000, 'human'),
                (2, 'bob', '$argon2id$bob', 'bob@example.test', 'user',
                 '', 0, -1, 0, 'human'),
                (10, 'peer-media-2', '', '', 'admin',
                 '', 0, -1, 0, 'peer');

            INSERT INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, family_id)
                VALUES ('sess-alice-1', 1, '192.0.2.10', 'af-browser', '2099-01-01T00:00:00Z', 'fam-alice');
            INSERT INTO mfa_challenges (token, user_id, attempts, expires_at, credential_ver)
                VALUES ('mfa-tok-alice', 1, 1, 1899999999, 3);
            INSERT INTO revoked_tokens (jti, expires_at, family_id, user_id)
                VALUES ('revoked-jti-1', '2099-01-01T00:00:00Z', 'fam-old', 1);
            INSERT INTO recovery_codes (user_id, code_hash, used)
                VALUES (1, 'sha256:recovery-1', 0);
            INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris)
                VALUES ('oidc-app-1', 'sha256:client-secret', 'Media Portal', '["https://portal.example/cb"]');
            INSERT INTO oidc_consents (user_id, client_id, scope)
                VALUES (1, 'oidc-app-1', 'openid profile');

            UPDATE settings
               SET setup_completed = 1,
                   base_domain = 'home.example',
                   local_provider = 'ollama',
                   local_model = 'qwen3'
             WHERE id = 1;
            INSERT INTO plugins_registry (plugin_id, enabled, allocated_port, status)
                VALUES ('plugin-alpha', 1, 9101, 'running');
            INSERT INTO streaming_servers (provider, name, url, api_key, enabled, server_id, server_version)
                VALUES ('jellyfin', 'Main JF', 'http://127.0.0.1:8096', 'enc:v1:jf', 1, 'srv-jf-1', '12.4');
            INSERT INTO streaming_history (session_key, provider, server_id, user_name, item_id, item_name, provenance)
                VALUES ('jf-sess-1', 'jellyfin', 'srv-jf-1', 'alice', 'item-1', 'Dune', 'observed_session');
            UPDATE streaming_history_read_revision SET revision = 7 WHERE id = 1;
            INSERT INTO mediaflow_queue (file_path, status, original_codec)
                VALUES ('/srv/media/clip.mkv', 'PENDING_APPROVAL', 'h264');
            INSERT INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled)
                VALUES ('jellyfin', 'jf.home.example', 1, 8096, 1);
            INSERT INTO pending_actions (classification, source, action, reason, status)
                VALUES ('warn', 'system', 'restart:jellyfin', 'upgrade', 'pending');
            INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail)
                VALUES (1, 'alice', 'peer_pair_confirm', 'peer_link', 'link-media-2', 'confirmed');
            INSERT INTO notifications (id, user_id, level, title, message, read)
                VALUES (50, 1, 'info', 'Peer paired', 'media-2 linked', 0);
            INSERT INTO notification_reads (notification_id, user_id)
                VALUES (50, 1);
            "#,
        )
        .expect("seed auth and unrelated app rows");

        // Seed representative P0/P3 peer rows across all 9 peer tables
        peers::upsert_peer_identity(&conn, &expected_identity).unwrap();
        peers::insert_peer_link(&conn, &expected_active_link).unwrap();
        peers::insert_peer_link(&conn, &expected_pending_link).unwrap();
        peers::insert_peer_grant(&conn, &expected_grant).unwrap();
        peers::insert_pairing_window(&conn, &expected_window_open).unwrap();
        peers::insert_pairing_window(&conn, &expected_window_used).unwrap();
        peers::insert_pairing_attempt(&conn, &expected_attempt).unwrap();
        peers::insert_peer_export(&conn, &expected_export).unwrap();
        peers::insert_peer_mount(&conn, &expected_mount).unwrap();
        peers::upsert_transcode_worker(&conn, &expected_worker).unwrap();
        peers::insert_transcode_job(&conn, &expected_job).unwrap();

        // Confirm pre-upgrade fixture truly represents a live migration-25 legacy DB
        let pre_max: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pre_max, 25);
        for (tbl, expected_rows) in [
            ("cluster_nodes", 2i64),
            ("cluster_enrollment_tokens", 2i64),
            ("cluster_commands", 2i64),
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {tbl}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, expected_rows, "fixture must seed rows in {tbl}");
        }
        assert!(sqlite_object_exists(
            &conn,
            "index",
            "idx_cluster_nodes_status"
        ));
        assert!(sqlite_object_exists(
            &conn,
            "index",
            "idx_cluster_commands_node_status"
        ));
    }

    // Upgrade migration-25 fixture -> migration 28, then run two more restarts (repeated init)
    for pass in 0..3 {
        init_db().unwrap_or_else(|e| panic!("init_db pass {pass} failed: {e}"));
        let conn = get_conn().unwrap();

        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);

        let total_versions: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            total_versions, 28,
            "all prior migrations 1..=25 plus 26, 27, and 28 must be preserved"
        );
        let v26_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 26",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v26_desc, "Remove legacy master/worker clustering");
        let v27_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 27",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v27_desc, "Peer grant direction metadata");
        let v28_desc: String = conn
            .query_row(
                "SELECT description FROM schema_versions WHERE version = 28",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            v28_desc,
            "Add distributed transcode dispatch policy settings"
        );

        // All legacy master/worker tables and indexes must be removed
        assert_no_legacy_cluster_objects(&conn);

        // Verify all 9 P0/P3 peer tables and seeded rows survived untouched
        assert_eq!(
            peers::get_peer_identity(&conn).unwrap(),
            Some(expected_identity.clone())
        );
        assert_eq!(
            peers::get_peer_link(&conn, "link-media-2").unwrap(),
            Some(expected_active_link.clone())
        );
        assert_eq!(
            peers::get_peer_link(&conn, "link-gpu-3").unwrap(),
            Some(expected_pending_link.clone())
        );
        assert_eq!(
            peers::get_peer_grant(&conn, "grant-media-2").unwrap(),
            Some(expected_grant.clone())
        );
        assert_eq!(
            peers::get_pairing_window(&conn, "win-open").unwrap(),
            Some(expected_window_open.clone())
        );
        assert_eq!(
            peers::get_pairing_window(&conn, "win-used").unwrap(),
            Some(expected_window_used.clone())
        );
        assert_eq!(
            peers::get_pairing_attempt(&conn, "attempt-pending-1").unwrap(),
            Some(expected_attempt.clone())
        );
        assert_eq!(
            peers::get_peer_export(&conn, "exp-movies").unwrap(),
            Some(expected_export.clone())
        );
        assert_eq!(
            peers::get_peer_mount(&conn, "mnt-movies").unwrap(),
            Some(expected_mount.clone())
        );
        assert_eq!(
            peers::get_transcode_worker(&conn, "link-media-2").unwrap(),
            Some(expected_worker.clone())
        );
        assert_eq!(
            peers::get_transcode_job(&conn, "job-vaapi-1").unwrap(),
            Some(expected_job.clone())
        );

        // Verify auth & users tables survived untouched
        let users_rows: Vec<(i64, String, String, String, i64, i64)> = conn
            .prepare(
                "SELECT id, username, role, account_type, last_totp_step, sessions_revoked_after
                 FROM users ORDER BY id ASC",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            users_rows,
            vec![
                (
                    1,
                    "alice".to_string(),
                    "admin".to_string(),
                    "human".to_string(),
                    42,
                    1_700_000_000,
                ),
                (
                    2,
                    "bob".to_string(),
                    "user".to_string(),
                    "human".to_string(),
                    -1,
                    0,
                ),
                (
                    10,
                    "peer-media-2".to_string(),
                    "admin".to_string(),
                    "peer".to_string(),
                    -1,
                    0,
                ),
            ]
        );

        let session_fam: String = conn
            .query_row(
                "SELECT family_id FROM active_sessions WHERE jti = 'sess-alice-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(session_fam, "fam-alice");
        let mfa_ver: i64 = conn
            .query_row(
                "SELECT credential_ver FROM mfa_challenges WHERE token = 'mfa-tok-alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mfa_ver, 3);
        let revoked_fam: String = conn
            .query_row(
                "SELECT family_id FROM revoked_tokens WHERE jti = 'revoked-jti-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(revoked_fam, "fam-old");
        let recovery_cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = 1 AND code_hash = 'sha256:recovery-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(recovery_cnt, 1);
        let oidc_scope: String = conn
            .query_row(
                "SELECT scope FROM oidc_consents WHERE user_id = 1 AND client_id = 'oidc-app-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(oidc_scope, "openid profile");

        // Verify unrelated app tables & migrations survived untouched
        let (setup_done, base_domain, local_model): (bool, String, String) = conn
            .query_row(
                "SELECT setup_completed, base_domain, local_model FROM settings WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(setup_done);
        assert_eq!(base_domain, "home.example");
        assert_eq!(local_model, "qwen3");

        let plugin_status: String = conn
            .query_row(
                "SELECT status FROM plugins_registry WHERE plugin_id = 'plugin-alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(plugin_status, "running");

        let stream_item: String = conn
            .query_row(
                "SELECT item_name FROM streaming_history WHERE session_key = 'jf-sess-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stream_item, "Dune");

        let read_rev: i64 = conn
            .query_row(
                "SELECT revision FROM streaming_history_read_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(read_rev, 7);

        let mediaflow_status: String = conn
            .query_row(
                "SELECT status FROM mediaflow_queue WHERE file_path = '/srv/media/clip.mkv'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mediaflow_status, "PENDING_APPROVAL");

        let ingress_domain: String = conn
            .query_row(
                "SELECT public_domain FROM app_ingress_configs WHERE app_name = 'jellyfin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ingress_domain, "jf.home.example");

        let pending_cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_actions WHERE action = 'restart:jellyfin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending_cnt, 1);

        let audit_detail: String = conn
            .query_row(
                "SELECT detail FROM admin_audit_log WHERE action = 'peer_pair_confirm'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(audit_detail, "confirmed");

        let notif_read_cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM notification_reads WHERE notification_id = 50 AND user_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(notif_read_cnt, 1);

        assert_db_integrity(&conn);
    }
}

#[test]
fn migration_v26_is_atomic_on_failure_and_handles_partial_legacy_tables() {
    // Part A: Atomicity rollback if the final DROP fails under PRAGMA foreign_keys = ON
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE schema_versions (
             version INTEGER PRIMARY KEY,
             description TEXT NOT NULL,
             applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
         );
         INSERT INTO schema_versions (version, description) VALUES (25, 'Peer clustering');",
    )
    .unwrap();
    seed_legacy_master_worker_tables(&conn);
    conn.execute_batch(
        "CREATE TABLE legacy_fk_blocker (
             id INTEGER PRIMARY KEY,
             node_id TEXT NOT NULL REFERENCES cluster_nodes(id)
         );
         INSERT INTO legacy_fk_blocker (id, node_id) VALUES (1, 'legacy-node-1');",
    )
    .unwrap();

    let err = migrate(
        &conn,
        26,
        "Remove legacy master/worker clustering",
        LEGACY_CLUSTER_REMOVAL_MIGRATION_26_SQL,
    )
    .expect_err("FK reference on cluster_nodes must fail migration 26 and roll back atomically");
    assert!(!err.to_string().is_empty());
    assert!(
        conn.is_autocommit(),
        "connection must return to autocommit after atomic rollback"
    );

    // Earlier drops (cluster_commands, cluster_enrollment_tokens) MUST have rolled back too
    for (table, expected_rows) in [
        ("cluster_commands", 2i64),
        ("cluster_enrollment_tokens", 2i64),
        ("cluster_nodes", 2i64),
    ] {
        assert!(
            sqlite_object_exists(&conn, "table", table),
            "rolled-back migration 26 must retain {table}"
        );
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, expected_rows,
            "rolled-back rows in {table} must stay intact"
        );
    }
    let v26_recorded: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 26",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v26_recorded, 0);

    // Removing the blocker allows migration 26 to commit all three drops cleanly
    conn.execute_batch("DROP TABLE legacy_fk_blocker;").unwrap();
    migrate(
        &conn,
        26,
        "Remove legacy master/worker clustering",
        LEGACY_CLUSTER_REMOVAL_MIGRATION_26_SQL,
    )
    .expect("migration 26 must succeed once FK blocker is removed");
    assert_no_legacy_cluster_objects(&conn);
    let v26_recorded: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 26",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v26_recorded, 1);

    // Part B: Partial legacy DB (only base cluster_nodes existed; cluster_daemon never ran)
    let partial_conn = Connection::open_in_memory().unwrap();
    partial_conn
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE schema_versions (
                 version INTEGER PRIMARY KEY,
                 description TEXT NOT NULL,
                 applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );
             INSERT INTO schema_versions (version, description) VALUES (25, 'Peer clustering');
             CREATE TABLE cluster_nodes (
                 id TEXT PRIMARY KEY,
                 hostname TEXT NOT NULL,
                 address TEXT NOT NULL,
                 psk_hash TEXT NOT NULL,
                 role TEXT DEFAULT 'worker',
                 status TEXT DEFAULT 'offline'
             );
             CREATE INDEX idx_cluster_nodes_status ON cluster_nodes(status);
             INSERT INTO cluster_nodes (id, hostname, address, psk_hash)
                 VALUES ('solo-node', 'worker-solo', '10.0.0.9', 'sha256:solo');",
        )
        .unwrap();
    migrate(
        &partial_conn,
        26,
        "Remove legacy master/worker clustering",
        LEGACY_CLUSTER_REMOVAL_MIGRATION_26_SQL,
    )
    .expect("migration 26 must succeed when only a subset of legacy tables exist");
    assert_no_legacy_cluster_objects(&partial_conn);
    let partial_v26: i64 = partial_conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 26",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(partial_v26, 1);
}

#[test]
fn migration_v27_upgrades_v26_fixture_preserving_existing_grants_and_separating_directions() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _db_path_guard = TestDbPathGuard(env::var_os("DB_PATH"));

    let dir = TempDirGuard(env::temp_dir().join(format!(
        "af-peer-v26-to-v27-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir_all(&dir.0).unwrap();
    let db_file = dir.0.join("v26_fixture.sqlite");
    env::set_var("DB_PATH", &db_file);

    // Bootstrap then step back to v26 state
    init_db().unwrap();
    let seeded_link = peers::PeerLink {
        id: "link-v26".to_string(),
        name: "peer-v26".to_string(),
        wg_pubkey: "pk-peer-v26".to_string(),
        tunnel_ip: "10.231.0.9".to_string(),
        endpoint: "198.51.100.90".to_string(),
        wg_port: 51821,
        state: "active".to_string(),
        peer_version: Some("4.0.0".to_string()),
        peer_protocol: Some(1),
        capabilities: Some(r#"["links"]"#.to_string()),
        rtt_ms: Some(1.1),
        last_ok_at: Some("2026-11-23T12:00:00Z".to_string()),
        last_error: None,
        consecutive_failures: 0,
        inbound_token_hash: Some("sha256:link-v26".to_string()),
        pending_attempt_id: None,
        pending_expires_at: None,
        created_at: "2026-11-23T10:00:00Z".to_string(),
        updated_at: "2026-11-23T12:00:00Z".to_string(),
    };
    let seeded_grant = peers::PeerGrant {
        id: "grant-v26".to_string(),
        link_id: "link-v26".to_string(),
        run_as_user_id: 22,
        access: peers::AccessMap::read_only_all(),
        token_hash: Some("sha256:grant-v26".to_string()),
        created_by: "alice".to_string(),
        created_at: "2026-11-23T10:05:00Z".to_string(),
        revoked_at: None,
    };
    {
        let conn = get_conn().unwrap();
        conn.execute_batch(
            "DROP TABLE IF EXISTS transcode_dispatch_settings;
             DROP TABLE IF EXISTS peer_grant_epochs;
             DROP TABLE IF EXISTS peer_received_grant_cleanups;
             DROP TABLE IF EXISTS peer_received_grants;
             DELETE FROM schema_versions WHERE version IN (27, 28);",
        )
        .unwrap();
        peers::insert_peer_link(&conn, &seeded_link).unwrap();
        peers::insert_peer_grant(&conn, &seeded_grant).unwrap();
        let pre_max: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pre_max, 26);
    }

    init_db().expect("v26 -> v28 upgrade must succeed");
    {
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);
        assert!(sqlite_object_exists(&conn, "table", "peer_received_grants"));
        assert!(sqlite_object_exists(
            &conn,
            "table",
            "peer_received_grant_cleanups"
        ));
        assert!(sqlite_object_exists(&conn, "table", "peer_grant_epochs"));
        assert!(sqlite_object_exists(
            &conn,
            "table",
            "transcode_dispatch_settings"
        ));
        assert_eq!(
            peers::get_peer_link(&conn, "link-v26").unwrap(),
            Some(seeded_link)
        );
        assert_eq!(
            peers::get_active_peer_grant_for_link(&conn, "link-v26").unwrap(),
            Some(seeded_grant)
        );
        assert_eq!(
            peers::get_active_peer_received_grant_for_link(&conn, "link-v26").unwrap(),
            None
        );
        let has_cred_id_col: bool = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(peer_received_grants)")
                .unwrap();
            let found = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .filter_map(Result::ok)
                .any(|c| c == "credential_id");
            found
        };
        assert!(
            has_cred_id_col,
            "migration 27 must provision peer_received_grants.credential_id"
        );
        assert_db_integrity(&conn);
    }

    // Also verify init_db() upgrades an earlier unreleased v27 database lacking `credential_id`
    // and `peer_received_grant_cleanups` while preserving existing canonical rows.
    {
        let conn = get_conn().unwrap();
        conn.execute_batch(
            "DROP TABLE IF EXISTS peer_received_grant_cleanups;
             DROP TABLE peer_received_grants;
             CREATE TABLE peer_received_grants (
                 link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
                 grant_id TEXT NOT NULL,
                 run_as_user_id INTEGER NOT NULL,
                 access TEXT NOT NULL,
                 created_by TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 generation INTEGER NOT NULL DEFAULT 0,
                 revoked_at TEXT,
                 updated_at TEXT NOT NULL
             );
             INSERT INTO peer_received_grants (
                 link_id, grant_id, run_as_user_id, access, created_by, created_at, generation, revoked_at, updated_at
             ) VALUES (
                 'link-v26', 'grant-pre-staged', 22, '{\"services\":\"read\"}', 'alice',
                 '2026-11-23T11:00:00Z', 1, NULL, '2026-11-23T11:00:00Z'
             );",
        )
        .unwrap();
    }
    init_db().expect("re-init must reconcile additive v27 peer_received_grants schema");
    {
        let conn = get_conn().unwrap();
        assert!(sqlite_object_exists(
            &conn,
            "table",
            "peer_received_grant_cleanups"
        ));
        let loaded = peers::get_peer_received_grant(&conn, "link-v26")
            .unwrap()
            .expect("pre-existing received grant row must survive schema invariant upgrade");
        assert_eq!(loaded.grant_id, "grant-pre-staged");
        assert_eq!(loaded.credential_id, None);
        assert_eq!(loaded.effective_credential_id(), "link-v26");
        assert_db_integrity(&conn);
    }
}

#[test]
fn migration_v28_upgrades_v27_fixture_and_persists_transcode_dispatch_settings() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _db_path_guard = TestDbPathGuard(env::var_os("DB_PATH"));

    let dir = TempDirGuard(env::temp_dir().join(format!(
        "af-peer-v27-to-v28-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    fs::create_dir_all(&dir.0).unwrap();
    let db_file = dir.0.join("v27_fixture.sqlite");
    env::set_var("DB_PATH", &db_file);

    // Bootstrap then step back to v27 state
    init_db().unwrap();
    {
        let conn = get_conn().unwrap();
        conn.execute_batch(
            "DROP TABLE IF EXISTS transcode_dispatch_settings;
             DELETE FROM schema_versions WHERE version = 28;",
        )
        .unwrap();
        let pre_max: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pre_max, 27);
        assert!(!sqlite_object_exists(
            &conn,
            "table",
            "transcode_dispatch_settings"
        ));
    }

    init_db().expect("v27 -> v28 upgrade must succeed");
    let expected = peers::TranscodeDispatchSettings {
        dispatch_policy: peers::TranscodeDispatchPolicy::Balanced,
        local_max_jobs: 4,
        updated_at: "2026-11-27T04:30:00Z".to_string(),
    };
    {
        let conn = get_conn().unwrap();
        let max_ver: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_versions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(max_ver, 28);
        assert!(sqlite_object_exists(
            &conn,
            "table",
            "transcode_dispatch_settings"
        ));
        assert_eq!(peers::get_transcode_dispatch_settings(&conn).unwrap(), None);
        peers::upsert_transcode_dispatch_settings(&conn, &expected).unwrap();
        assert_eq!(
            peers::get_transcode_dispatch_settings(&conn).unwrap(),
            Some(expected.clone())
        );
        assert_db_integrity(&conn);
    }

    // Re-running init_db() must be idempotent and retain persisted dispatch settings
    init_db().expect("re-init on v28 DB must succeed");
    {
        let conn = get_conn().unwrap();
        assert_eq!(
            peers::get_transcode_dispatch_settings(&conn).unwrap(),
            Some(expected)
        );
        assert_db_integrity(&conn);
    }
}
