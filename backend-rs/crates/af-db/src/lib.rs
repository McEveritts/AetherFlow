mod audit;
mod auth;
mod crypto;
mod ingress;
mod notifications;
mod pending_actions;
mod pool;
mod retained_ingress;
mod schema;
pub mod streaming;

#[cfg(test)]
mod pending_action_query_tests;
#[cfg(test)]
pub(crate) mod tests;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::auth::TOKEN_BLACKLIST;
use crate::pool::{
    apply_pragmas, build_read_pool, migrate, DB_PATH_RESOLVED, DB_POOL, DB_READ_POOL,
};
use crate::schema::{
    ensure_column, ensure_pending_actions_schema_invariants, ensure_security_schema_invariants,
};

pub use audit::{list_audit_entries, query_audit_log, record_audit, AuditEntry};
pub use auth::{
    begin_mfa_attempt, begin_mfa_attempt_with_epoch, cache_revoked_token, consume_mfa_challenge,
    consume_mfa_challenge_with_epoch, delete_2fa_pending, delete_user_mfa_challenges_in_tx,
    get_2fa_pending, is_token_revoked, record_revoked_token_lineage_in_tx,
    resolve_revoked_token_family_in_tx, revoke_token, revoke_token_in_tx, store_2fa_pending,
    store_mfa_challenge, store_mfa_challenge_in_tx, token_revocation_status,
    token_revocation_status_with_conn, try_consume_session_jti_in_tx, MAX_MFA_ATTEMPTS,
};
pub use crypto::{
    decrypt_key, decrypt_notification_channel_config_str, decrypt_secret_if_needed, encrypt_key,
    encrypt_notification_channel_config_str, encrypt_notification_channel_config_value,
    encrypt_secret_if_configured, init_aes_key, is_encryption_enabled,
    mask_notification_channel_config_str, migrate_legacy_secrets, parse_aes_key_bytes,
    resolve_runtime_aes_key, SECRET_MASK,
};
pub use ingress::{
    cached_base_domain, delete_app_ingress_config, get_all_app_ingress_configs,
    get_app_ingress_config, get_base_domain, has_retained_app_ingress_config,
    invalidate_ingress_cache, matches_cached_ingress_subdomain, maybe_cached_control_plane_host,
    normalize_base_domain, set_app_ingress_and_secondary_port_for_lifecycle,
    set_app_ingress_config, set_app_ingress_config_for_lifecycle, set_base_domain,
};
pub(crate) use ingress::{parse_sqlite_dt, write_app_ingress_config};
pub use notifications::{
    count_unread_notifications_for_user, count_unread_notifications_for_user_with_conn,
    dismiss_all_notifications_for_user, dismiss_all_notifications_for_user_with_conn,
    list_notifications_for_user, list_notifications_for_user_with_conn,
    mark_notification_read_for_user, mark_notification_read_for_user_with_conn,
    UserNotificationRow, LIST_NOTIFICATIONS_FOR_USER_SQL, UNREAD_NOTIFICATIONS_COUNT_FOR_USER_SQL,
};
pub use pending_actions::{
    count_pending_actions, finalize_queued_action_by_id, finalize_queued_action_by_job_unit,
    get_pending_action_by_id, list_pending_actions, list_queued_actions_with_receipts,
    mark_action_executed, mark_action_failed, mark_action_queued, mark_action_unavailable,
    query_pending_actions, queue_action, queue_action_if_not_pending, resolve_action,
    PendingAction, QueueActionOutcome, MAX_PENDING_ACTIONS,
};
pub use pool::{
    db_health_check, db_readiness_check, get_conn, get_db_path, get_read_conn,
    has_unexpired_active_session, prune_expired_active_sessions, prune_expired_data,
    resolve_db_path, try_resolve_db_path, DbConn, PRUNE_METRICS_HISTORY_SQL,
    PRUNE_NOTIFICATION_DELIVERY_LOG_SQL,
};
pub use retained_ingress::{
    archive_app_ingress_config, archive_app_ingress_config_for_lifecycle,
    check_app_ingress_reservation, clear_pending_base_domain_sync,
    get_all_retained_app_ingress_configs, get_pending_base_domain_sync,
    get_reserved_ports_excluding, get_retained_app_ingress_config, list_reserved_ports_excluding,
    list_retained_app_ingress_names, load_lifecycle_ingress, load_lifecycle_secondary_port,
    plan_lifecycle_ingress, reserve_lifecycle_port_in_tx, set_pending_base_domain_sync,
    synchronize_lifecycle_ingress, synchronize_lifecycle_ingress_with_secondary_port,
    update_retained_app_ingress_config_in_tx, PendingBaseDomainSync,
};
pub use schema::{ensure_mediaflow_schema_invariants, ensure_notification_schema_invariants};

// NOTE: `init_db` stays in `lib.rs` so downstream streaming migration tests that inspect
// core schema and migration 19 blocks via `include_str!("../../af-db/src/lib.rs")` continue
// to read the single source of truth.
// No foreign key to users. Cleanup must survive account deletion and restarts.
pub const ACCOUNT_STORAGE_CLEANUP_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS account_storage_cleanup (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        shared INTEGER NOT NULL CHECK (shared IN (0, 1)),
        storage_root TEXT NOT NULL,
        directory TEXT NOT NULL,
        filename TEXT NOT NULL,
        identity TEXT,
        last_error TEXT NOT NULL DEFAULT '',
        UNIQUE (user_id, shared, storage_root, directory, filename)
    );
    CREATE INDEX IF NOT EXISTS idx_account_storage_cleanup_shared
        ON account_storage_cleanup (storage_root, directory, filename) WHERE shared = 1;
";

pub const FILESHARE_PENDING_PUBLISHES_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS fileshare_pending_publishes (
        storage_root TEXT NOT NULL,
        directory TEXT NOT NULL,
        filename TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        new_size_bytes INTEGER NOT NULL CHECK(new_size_bytes >= 0),
        growth_bytes INTEGER NOT NULL CHECK(growth_bytes >= 0),
        previous_user_id INTEGER,
        previous_size_bytes INTEGER CHECK(previous_size_bytes IS NULL OR previous_size_bytes >= 0),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(storage_root, directory, filename)
    );
    CREATE INDEX IF NOT EXISTS idx_fileshare_pending_publishes_user
        ON fileshare_pending_publishes(user_id);
";

pub fn init_db() -> anyhow::Result<()> {
    let db_path = try_resolve_db_path()?;
    if db_path != ":memory:" && !db_path.starts_with("file:") {
        if let Some(parent) = Path::new(&db_path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }

    let manager = if db_path == ":memory:" {
        SqliteConnectionManager::memory()
    } else {
        SqliteConnectionManager::file(&db_path)
    }
    .with_init(|c| {
        apply_pragmas(c);
        Ok(())
    });

    // Constrain pool to 1 writer connection matching Go's `DB.SetMaxOpenConns(1)`
    let pool = Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_secs(5))
        .build(manager)?;
    let conn = pool.get()?;
    apply_pragmas(&conn);

    // Core tables
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            ai_model TEXT DEFAULT 'gemini-4-argon',
            system_prompt TEXT DEFAULT 'You are FlowAI, a highly intelligent infrastructure assistant connected to a sovereign Rust + WebAssembly aetherflow-api environment. Always prioritize safe and performant configurations.',
            language TEXT DEFAULT 'en',
            timezone TEXT DEFAULT 'UTC',
            update_channel TEXT DEFAULT 'stable',
            default_dashboard TEXT DEFAULT 'overview',
            setup_completed BOOLEAN DEFAULT 0,
            gemini_api_key TEXT DEFAULT '',
            openai_api_key TEXT DEFAULT '',
            lm_studio_endpoint TEXT DEFAULT '',
            ollama_endpoint TEXT DEFAULT '',
            anthropic_api_key TEXT DEFAULT '',
            anthropic_endpoint TEXT DEFAULT '',
            local_provider TEXT DEFAULT '',
            local_model TEXT DEFAULT '',
            base_domain TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            google_id TEXT DEFAULT '',
            email TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS cluster_nodes (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            address TEXT NOT NULL,
            psk_hash TEXT NOT NULL,
            role TEXT DEFAULT 'worker',
            status TEXT DEFAULT 'offline',
            last_heartbeat DATETIME,
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS oidc_clients (
            id TEXT PRIMARY KEY,
            client_secret_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (
            app_name TEXT PRIMARY KEY,
            config_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_secondary_ports (
            app_name TEXT NOT NULL,
            port_role TEXT NOT NULL,
            port INTEGER NOT NULL,
            retained INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (app_name, port_role)
        );

        CREATE TABLE IF NOT EXISTS base_domain_sync_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            previous_base_domain TEXT NOT NULL DEFAULT '',
            target_base_domain TEXT NOT NULL DEFAULT '',
            source_domains_json TEXT NOT NULL DEFAULT '[]',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS oidc_auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            code_challenge TEXT DEFAULT '',
            code_challenge_method TEXT DEFAULT '',
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            expires_at DATETIME NOT NULL,
            revoked BOOLEAN DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS oidc_device_codes (
            device_code TEXT PRIMARY KEY,
            user_code TEXT NOT NULL,
            client_id TEXT NOT NULL,
            scope TEXT DEFAULT 'openid profile email',
            user_id INTEGER,
            expires_at DATETIME NOT NULL,
            status TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS log_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_source TEXT NOT NULL,
            log_line TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            note TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            level TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notification_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            condition_type TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            level TEXT DEFAULT 'warning',
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            config TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            billing_provider TEXT DEFAULT '',
            billing_external_id TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS quota_rollbacks (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            username TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS fileshare_objects (
            storage_root TEXT NOT NULL,
            directory TEXT NOT NULL,
            filename TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id),
            size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
            PRIMARY KEY(storage_root, directory, filename)
        );
        CREATE INDEX IF NOT EXISTS idx_fileshare_objects_user ON fileshare_objects(user_id);

        CREATE TABLE IF NOT EXISTS billing_webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_type TEXT DEFAULT '',
            username TEXT DEFAULT '',
            quota_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'received',
            error TEXT DEFAULT '',
            payload TEXT NOT NULL,
            processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(provider, event_id)
        );

        CREATE TABLE IF NOT EXISTS app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT DEFAULT '',
            latest_version TEXT DEFAULT '',
            update_available BOOLEAN DEFAULT 0,
            update_url TEXT DEFAULT '',
            checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_error TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS media_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            title TEXT DEFAULT '',
            year TEXT DEFAULT '',
            language TEXT DEFAULT '',
            quality TEXT DEFAULT '',
            subtitles_json TEXT DEFAULT '[]',
            enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_avg REAL DEFAULT 0,
            mem_used_gb REAL DEFAULT 0,
            mem_total_gb REAL DEFAULT 0,
            disk_read_bps REAL DEFAULT 0,
            disk_write_bps REAL DEFAULT 0,
            net_rx_bytes INTEGER DEFAULT 0,
            net_tx_bytes INTEGER DEFAULT 0,
            load_avg_1 REAL DEFAULT 0,
            active_conns INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS schema_versions (
            version INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;

    // All 19 versioned migrations matching `backend/db/db.go`
    migrate(
        &conn,
        1,
        "Add setup_completed to settings",
        &["ALTER TABLE settings ADD COLUMN setup_completed BOOLEAN DEFAULT 0;"],
    )?;
    migrate(
        &conn,
        2,
        "Add gemini_api_key to settings",
        &["ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        3,
        "Add password_hash to users",
        &["ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        4,
        "Add backup scheduling columns to settings",
        &[
            "ALTER TABLE settings ADD COLUMN backup_schedule_mode TEXT DEFAULT 'manual';",
            "ALTER TABLE settings ADD COLUMN backup_optimal_window TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        5,
        "v3.1.0 Gold — performance indexes",
        &[
            "CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, read);",
            "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_login_history_created ON login_history(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_client ON oidc_auth_codes(client_id);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_refresh_client ON oidc_refresh_tokens(client_id);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);",
            "CREATE INDEX IF NOT EXISTS idx_billing_provider_event ON billing_webhook_events(provider, event_id);",
            "CREATE INDEX IF NOT EXISTS idx_log_bookmarks_user ON log_bookmarks(user_id);",
        ],
    )?;
    migrate(
        &conn,
        6,
        "Persist smart backup next run time",
        &["ALTER TABLE settings ADD COLUMN backup_next_run_at TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        7,
        "Add OIDC consent persistence",
        &[
            r#"CREATE TABLE IF NOT EXISTS oidc_consents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, client_id)
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_oidc_consents_user_client ON oidc_consents(user_id, client_id);",
        ],
    )?;
    migrate(
        &conn,
        8,
        "Add active sessions table for session tracking",
        &[
            r#"CREATE TABLE IF NOT EXISTS active_sessions (
                jti TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                expires_at DATETIME NOT NULL,
                last_active DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_active_sessions_expires ON active_sessions(expires_at);",
        ],
    )?;
    migrate(
        &conn,
        9,
        "Add pending_actions table for approval gates",
        &[
            r#"CREATE TABLE IF NOT EXISTS pending_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                classification TEXT NOT NULL DEFAULT 'warn',
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                resolved_by TEXT,
                execution_log TEXT
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);",
        ],
    )?;
    migrate(
        &conn,
        10,
        "Add notification_delivery_log for delivery tracking",
        &[
            r#"CREATE TABLE IF NOT EXISTS notification_delivery_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                channel_type TEXT NOT NULL,
                notification_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_delivery_log_channel ON notification_delivery_log(channel_id);",
            "CREATE INDEX IF NOT EXISTS idx_delivery_log_status ON notification_delivery_log(status);",
        ],
    )?;
    migrate(
        &conn,
        11,
        "Add admin audit trail for accountability",
        &[
            r#"CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                target_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_audit_log_user ON admin_audit_log(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON admin_audit_log(action);",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON admin_audit_log(created_at);",
        ],
    )?;
    migrate(
        &conn,
        12,
        "Add OpenAI and Local AI provider config",
        &[
            "ALTER TABLE settings ADD COLUMN openai_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN lm_studio_endpoint TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN ollama_endpoint TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        13,
        "Add Anthropic API provider config",
        &[
            "ALTER TABLE settings ADD COLUMN anthropic_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN anthropic_endpoint TEXT DEFAULT '';",
        ],
    )?;
    migrate(
        &conn,
        14,
        "Add TOTP 2FA columns to users",
        &[
            "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';",
            "ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;",
        ],
    )?;
    migrate(
        &conn,
        15,
        "Add recovery_codes table for 2FA backup codes",
        &[r#"CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );"#],
    )?;
    migrate(
        &conn,
        16,
        "Add mediaflow queue for hwaccel transcoding",
        &[
            r#"CREATE TABLE IF NOT EXISTS mediaflow_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                original_codec TEXT DEFAULT '',
                original_size INTEGER DEFAULT 0,
                new_codec TEXT DEFAULT '',
                new_size INTEGER DEFAULT 0,
                error_log TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_mediaflow_status ON mediaflow_queue(status);",
        ],
    )?;
    migrate(
        &conn,
        17,
        "Add app_ingress_configs table for persistent ingress routing",
        &[
            r#"CREATE TABLE IF NOT EXISTS app_ingress_configs (
                app_name TEXT PRIMARY KEY,
                public_domain TEXT DEFAULT '',
                external_access_enabled BOOLEAN DEFAULT 0,
                listen_port INTEGER DEFAULT 0,
                tls_enabled BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ingress_configs_app_name ON app_ingress_configs(app_name);",
        ],
    )?;
    migrate(
        &conn,
        18,
        "Add base_domain to settings for automatic app subdomain provisioning",
        &["ALTER TABLE settings ADD COLUMN base_domain TEXT DEFAULT '';"],
    )?;
    migrate(
        &conn,
        19,
        "Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables",
        &[
            r#"CREATE TABLE IF NOT EXISTS streaming_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL DEFAULT 'Jellyfin',
                url TEXT NOT NULL DEFAULT 'http://127.0.0.1:8096',
                api_key TEXT NOT NULL DEFAULT '',
                enabled BOOLEAN DEFAULT 1,
                server_id TEXT DEFAULT '',
                server_version TEXT DEFAULT '',
                last_connected_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            r#"CREATE TABLE IF NOT EXISTS streaming_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT UNIQUE NOT NULL,
                provider TEXT NOT NULL DEFAULT 'jellyfin',
                server_name TEXT NOT NULL DEFAULT 'Jellyfin',
                user_id TEXT NOT NULL DEFAULT '',
                user_name TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                device_name TEXT NOT NULL DEFAULT '',
                device_id TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                item_id TEXT NOT NULL DEFAULT '',
                item_name TEXT NOT NULL DEFAULT '',
                item_type TEXT NOT NULL DEFAULT 'Movie',
                series_name TEXT NOT NULL DEFAULT '',
                series_id TEXT NOT NULL DEFAULT '',
                season_number INTEGER DEFAULT 0,
                episode_number INTEGER DEFAULT 0,
                production_year INTEGER DEFAULT 0,
                play_method TEXT NOT NULL DEFAULT 'DirectPlay',
                container TEXT NOT NULL DEFAULT '',
                video_codec TEXT NOT NULL DEFAULT '',
                video_resolution TEXT NOT NULL DEFAULT '',
                audio_codec TEXT NOT NULL DEFAULT '',
                audio_channels INTEGER DEFAULT 0,
                subtitle_codec TEXT NOT NULL DEFAULT '',
                hw_accel TEXT NOT NULL DEFAULT '',
                transcode_reasons TEXT NOT NULL DEFAULT '',
                bitrate_bps INTEGER DEFAULT 0,
                duration_secs INTEGER DEFAULT 0,
                watched_secs INTEGER DEFAULT 0,
                data_used_bytes INTEGER DEFAULT 0,
                completion_pct REAL DEFAULT 0,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at DATETIME,
                is_active BOOLEAN DEFAULT 0
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_provider ON streaming_history(provider);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_started ON streaming_history(started_at);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_last_seen ON streaming_history(last_seen_at DESC, id DESC);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_user ON streaming_history(user_name);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_item ON streaming_history(item_id);",
            "CREATE INDEX IF NOT EXISTS idx_streaming_history_active ON streaming_history(provider, is_active);",
            r#"CREATE TABLE IF NOT EXISTS streaming_bandwidth_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                provider TEXT NOT NULL DEFAULT 'jellyfin',
                active_streams INTEGER DEFAULT 0,
                direct_play_count INTEGER DEFAULT 0,
                direct_stream_count INTEGER DEFAULT 0,
                transcode_count INTEGER DEFAULT 0,
                total_bitrate_bps INTEGER DEFAULT 0,
                bytes_delta INTEGER DEFAULT 0
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_streaming_bw_timestamp ON streaming_bandwidth_samples(timestamp);",
        ],
    )?;

    streaming::migrate_history(&conn, &db_path)?;
    migrate(
        &conn,
        21,
        "Add plugins_registry table for Rust plugin platform lifecycle state",
        &[
            r#"CREATE TABLE IF NOT EXISTS plugins_registry (
                plugin_id TEXT PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT 0,
                allocated_port INTEGER NOT NULL DEFAULT 0,
                token_epoch INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'stopped',
                last_health_at DATETIME,
                last_error TEXT NOT NULL DEFAULT '',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
            "CREATE INDEX IF NOT EXISTS idx_plugins_registry_enabled ON plugins_registry(enabled);",
        ],
    )?;

    migrate(&conn, 22, "Persist MFA replay guards and OIDC nonces", &[
        "ALTER TABLE users ADD COLUMN last_totp_step INTEGER NOT NULL DEFAULT -1;",
        "ALTER TABLE oidc_auth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';",
        "CREATE TABLE IF NOT EXISTS mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);",
        "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expiry ON mfa_challenges(expires_at);",
        "CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
    ])?;

    let security_migration: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_versions WHERE version = 22",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        security_migration == 1,
        "Security schema migration v22 failed"
    );

    // Singleton settings row & model normalization
    migrate(
        &conn,
        23,
        "Persist installed local AI model and runtime separately",
        &[
            "ALTER TABLE settings ADD COLUMN local_provider TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN local_model TEXT DEFAULT '';",
        ],
    )?;
    let local_settings_migration: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_versions WHERE version = 23",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        local_settings_migration == 1,
        "Local AI settings migration v23 failed"
    );

    ensure_security_schema_invariants(&conn)?;
    ensure_notification_schema_invariants(&conn)?;
    ensure_pending_actions_schema_invariants(&conn)?;
    // Streaming owns version 24. Reconcile MediaFlow independently of that epoch.
    ensure_mediaflow_schema_invariants(&conn)?;
    conn.execute_batch(ACCOUNT_STORAGE_CLEANUP_SCHEMA)?;
    conn.execute_batch(FILESHARE_PENDING_PUBLISHES_SCHEMA)?;
    ensure_column(
        &conn,
        "base_domain_sync_state",
        "source_domains_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;

    let _ = conn.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)", []);
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'gemini-4-argon' WHERE id = 1 AND ai_model IN ('gemini-3.8-flash', 'gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-3.1-pro-preview', 'gemini-3-flash-preview', 'gemini-3.1-flash-lite-preview', 'gemini-3-pro-image-preview', 'gemini-3.1-flash-image-preview')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'gpt-6.1-sol' WHERE id = 1 AND ai_model IN ('gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-5.4', 'gpt-5.4-mini')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-opus-5-5' WHERE id = 1 AND ai_model IN ('claude-opus', 'claude-opus-4.5', 'claude-opus-4.6', 'claude-4-5-opus')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-sonnet-5-5' WHERE id = 1 AND ai_model IN ('claude-sonnet-4.5', 'claude-sonnet-4.6', 'claude-4-6-sonnet')",
        [],
    );
    let _ = conn.execute(
        "UPDATE settings SET ai_model = 'claude-haiku-5-5' WHERE id = 1 AND ai_model IN ('claude-4-6-haiku')",
        [],
    );

    let _ = conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);
         CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
    );

    let env_domain = env::var("AETHERFLOW_BASE_DOMAIN")
        .or_else(|_| env::var("AETHERFLOW_DOMAIN"))
        .map(|dom| normalize_base_domain(&dom))
        .unwrap_or_default();
    if !env_domain.is_empty() {
        let _ = conn.execute(
            "UPDATE settings SET base_domain = ?1 WHERE id = 1 AND COALESCE(base_domain, '') = ''",
            params![env_domain],
        );
    }

    drop(conn);
    let read_pool = if db_path == ":memory:" || db_path.contains("mode=memory") {
        None
    } else {
        Some(build_read_pool(&db_path)?)
    };
    *DB_PATH_RESOLVED.write().unwrap_or_else(|e| e.into_inner()) = db_path.clone();
    *DB_POOL.write().unwrap_or_else(|e| e.into_inner()) = Some(pool);
    *DB_READ_POOL.write().unwrap_or_else(|e| e.into_inner()) = read_pool;
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        map.clear();
    }
    invalidate_ingress_cache();
    get_base_domain();

    tracing::info!(path = %db_path, "SQLite WAL database connected");
    Ok(())
}
