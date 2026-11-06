mod retained_ingress;
pub use retained_ingress::{
    archive_app_ingress_config, archive_app_ingress_config_for_lifecycle,
    get_retained_app_ingress_config, load_lifecycle_ingress, synchronize_lifecycle_ingress,
};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use af_models::AppIngressConfig;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::RngCore;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod streaming;

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM Secret Encryption (`backend/api/crypto.go`)
// ─────────────────────────────────────────────────────────────────────────────

const CIPHERTEXT_PREFIX: &str = "enc:v1:";

static AES_MASTER_KEY: Lazy<RwLock<Option<[u8; 32]>>> = Lazy::new(|| RwLock::new(None));

/// Initializes the AES-256-GCM master key from `AES_MASTER_KEY` (32 raw bytes or Base64).
pub fn init_aes_key() -> anyhow::Result<()> {
    let raw = env::var("AES_MASTER_KEY").unwrap_or_default();
    if raw.is_empty() {
        let mode = env::var("GIN_MODE").unwrap_or_default();
        if mode == "release" {
            anyhow::bail!(
                "FATAL: AES_MASTER_KEY is required in production (GIN_MODE=release). \
                 Set a 32-byte key (raw or base64-encoded) to enable API key encryption."
            );
        }
        tracing::info!(
            "WARNING: AES_MASTER_KEY not set. API key encryption is disabled (dev/test mode only)."
        );
        if let Ok(mut guard) = AES_MASTER_KEY.write() {
            *guard = None;
        }
        return Ok(());
    }

    let key_bytes: [u8; 32] = if let Ok(decoded) = BASE64_STD.decode(&raw) {
        if decoded.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            arr
        } else if raw.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(raw.as_bytes());
            arr
        } else {
            anyhow::bail!(
                "FATAL: AES_MASTER_KEY must be exactly 32 bytes (AES-256). Got {} bytes.",
                raw.len()
            );
        }
    } else if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw.as_bytes());
        arr
    } else {
        anyhow::bail!(
            "FATAL: AES_MASTER_KEY must be exactly 32 bytes (AES-256). Got {} raw bytes.",
            raw.len()
        );
    };

    if let Ok(mut guard) = AES_MASTER_KEY.write() {
        *guard = Some(key_bytes);
    }
    tracing::info!("AES-256-GCM encryption key loaded successfully.");
    Ok(())
}

pub fn is_encryption_enabled() -> bool {
    AES_MASTER_KEY.read().map(|g| g.is_some()).unwrap_or(false)
}

/// Encrypts plaintext using AES-256-GCM with a 12-byte random nonce, returning
/// `"enc:v1:<base64(nonce || ciphertext)>"` — byte-for-byte compatible with Go's `EncryptKey`.
pub fn encrypt_key(plaintext: &str) -> anyhow::Result<String> {
    let key_opt = *AES_MASTER_KEY.read().unwrap();
    let Some(key) = key_opt else {
        return Ok(plaintext.to_string());
    };

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("aes cipher creation failed: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("gcm encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(format!(
        "{}{}",
        CIPHERTEXT_PREFIX,
        BASE64_STD.encode(combined)
    ))
}

/// Decrypts a versioned `"enc:v1:<base64>"` string produced by Go or Rust.
pub fn decrypt_key(encoded: &str) -> anyhow::Result<String> {
    let key_opt = *AES_MASTER_KEY.read().unwrap();
    let Some(key) = key_opt else {
        return Ok(encoded.to_string());
    };

    if let Some(payload) = encoded.strip_prefix(CIPHERTEXT_PREFIX) {
        let data = BASE64_STD
            .decode(payload)
            .map_err(|e| anyhow::anyhow!("versioned ciphertext base64 decode failed: {}", e))?;
        if data.len() < 12 {
            anyhow::bail!("ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("aes cipher creation failed: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("gcm decryption failed: {}", e))?;
        return String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("invalid utf8: {}", e));
    }

    anyhow::bail!("ciphertext tampered or missing required version prefix")
}

/// Migrates any plaintext `gemini_api_key` in `settings` to `enc:v1:` format.
pub fn migrate_legacy_secrets() -> anyhow::Result<()> {
    if !is_encryption_enabled() {
        return Ok(());
    }
    let conn = get_conn()?;
    let api_key: String = conn
        .query_row(
            "SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_default();

    if !api_key.is_empty() && !api_key.starts_with(CIPHERTEXT_PREFIX) {
        let enc = encrypt_key(&api_key)?;
        conn.execute(
            "UPDATE settings SET gemini_api_key = ?1 WHERE id = 1",
            params![enc],
        )?;
        tracing::info!("[crypto] Successfully migrated legacy gemini_api_key to enc:v1: format");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Connection Pool, WAL PRAGMAs & Schema Migrations (`backend/db/db.go`)
// ─────────────────────────────────────────────────────────────────────────────

static DB_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
static DB_READ_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
static DB_PATH_RESOLVED: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

pub fn try_resolve_db_path() -> anyhow::Result<String> {
    let default_fallback = env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|exe_dir| exe_dir.join("data/aetherflow.sqlite"))
        })
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aetherflow.sqlite".to_string());

    let resolved = af_models::try_resolve_active_db_path_from_env(None, &default_fallback)
        .map_err(|err| anyhow::anyhow!(err))?;
    let resolved_str = resolved.to_string_lossy().into_owned();
    if resolved_str != ":memory:" && !resolved_str.starts_with("file:") {
        if let Some(parent) = resolved.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }
    Ok(resolved_str)
}

pub fn resolve_db_path() -> String {
    let default_fallback = env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|exe_dir| exe_dir.join("data/aetherflow.sqlite"))
        })
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aetherflow.sqlite".to_string());

    let resolved = af_models::resolve_active_db_path_from_env(None, &default_fallback);
    let resolved_str = resolved.to_string_lossy().into_owned();
    if resolved_str != ":memory:" && !resolved_str.starts_with("file:") {
        if let Some(parent) = resolved.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
    }
    resolved_str
}

pub fn get_db_path() -> String {
    let current = DB_PATH_RESOLVED.read().unwrap().clone();
    if !current.is_empty() {
        return current;
    }
    resolve_db_path()
}

pub fn get_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_POOL
        .read()
        .unwrap()
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Database pool not initialized"))?;
    pool.get()
        .map_err(|e| anyhow::anyhow!("Failed to acquire SQLite connection: {}", e))
}

/// Bounded, read-only WAL connections. The writer remains a pool of one.
/// Private in-memory test databases must use their original connection.
pub fn get_read_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_READ_POOL.read().unwrap().clone();
    match pool {
        Some(pool) => pool.get().map_err(Into::into),
        None => get_conn(),
    }
}

fn build_read_pool(db_path: &str) -> anyhow::Result<Pool<SqliteConnectionManager>> {
    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
        .with_init(|conn| {
            conn.busy_timeout(Duration::from_secs(5))?;
            conn.execute_batch(
                "PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA cache_size=-8000;",
            )
        });
    Ok(Pool::builder()
        .max_size(4)
        .min_idle(Some(1))
        .connection_timeout(Duration::from_secs(5))
        .build(manager)?)
}

fn apply_pragmas(conn: &Connection) {
    let pragmas = [
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA busy_timeout=5000;",
        "PRAGMA cache_size=-64000;",
        "PRAGMA foreign_keys=ON;",
        "PRAGMA temp_store=MEMORY;",
        "PRAGMA mmap_size=268435456;",
    ];
    for p in pragmas {
        if let Err(e) = conn.execute_batch(p) {
            tracing::warn!(pragma = p, error = %e, "PRAGMA execution warning");
        }
    }
}

fn migrate(conn: &Connection, version: i32, description: &str, stmts: &[&str]) {
    let count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if count > 0 {
        return;
    }

    for stmt in stmts {
        if let Err(err) = conn.execute_batch(stmt) {
            let msg = err.to_string();
            if msg.contains("duplicate column name") {
                tracing::info!(version, "migration already applied (duplicate column)");
                continue;
            }
            tracing::error!(version, error = %msg, "migration failed");
            return;
        }
    }

    let _ = conn.execute(
        "INSERT INTO schema_versions (version, description) VALUES (?1, ?2)",
        params![version, description],
    );
    tracing::info!(version, description, "migration applied");
}

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

    // Core tables (`backend/db/db.go`)
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            ai_model TEXT DEFAULT 'gemini-4-argon',
            system_prompt TEXT DEFAULT 'You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.',
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
    );
    migrate(
        &conn,
        2,
        "Add gemini_api_key to settings",
        &["ALTER TABLE settings ADD COLUMN gemini_api_key TEXT DEFAULT '';"],
    );
    migrate(
        &conn,
        3,
        "Add password_hash to users",
        &["ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT '';"],
    );
    migrate(
        &conn,
        4,
        "Add backup scheduling columns to settings",
        &[
            "ALTER TABLE settings ADD COLUMN backup_schedule_mode TEXT DEFAULT 'manual';",
            "ALTER TABLE settings ADD COLUMN backup_optimal_window TEXT DEFAULT '';",
        ],
    );
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
            "CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
            "CREATE INDEX IF NOT EXISTS idx_oidc_device_codes_expires ON oidc_device_codes(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_cluster_nodes_status ON cluster_nodes(status);",
            "CREATE INDEX IF NOT EXISTS idx_billing_provider_event ON billing_webhook_events(provider, event_id);",
            "CREATE INDEX IF NOT EXISTS idx_log_bookmarks_user ON log_bookmarks(user_id);",
        ],
    );
    migrate(
        &conn,
        6,
        "Persist smart backup next run time",
        &["ALTER TABLE settings ADD COLUMN backup_next_run_at TEXT DEFAULT '';"],
    );
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
    );
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
    );
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
    );
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
    );
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
    );
    migrate(
        &conn,
        12,
        "Add OpenAI and Local AI provider config",
        &[
            "ALTER TABLE settings ADD COLUMN openai_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN lm_studio_endpoint TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN ollama_endpoint TEXT DEFAULT '';",
        ],
    );
    migrate(
        &conn,
        13,
        "Add Anthropic API provider config",
        &[
            "ALTER TABLE settings ADD COLUMN anthropic_api_key TEXT DEFAULT '';",
            "ALTER TABLE settings ADD COLUMN anthropic_endpoint TEXT DEFAULT '';",
        ],
    );
    migrate(
        &conn,
        14,
        "Add TOTP 2FA columns to users",
        &[
            "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';",
            "ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;",
        ],
    );
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
    );
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
    );
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
    );
    migrate(
        &conn,
        18,
        "Add base_domain to settings for automatic app subdomain provisioning",
        &["ALTER TABLE settings ADD COLUMN base_domain TEXT DEFAULT '';"],
    );
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
    );

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
    );

    migrate(&conn, 22, "Persist MFA replay guards and OIDC nonces", &[
        "ALTER TABLE users ADD COLUMN last_totp_step INTEGER NOT NULL DEFAULT -1;",
        "ALTER TABLE oidc_auth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';",
        "CREATE TABLE IF NOT EXISTS mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);",
        "CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expiry ON mfa_challenges(expires_at);",
        "CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
    ]);

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
    );
    let local_settings_migration: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_versions WHERE version = 23",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        local_settings_migration == 1,
        "Local AI settings migration v23 failed"
    );

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
    *DB_PATH_RESOLVED.write().unwrap() = db_path.clone();
    *DB_POOL.write().unwrap() = Some(pool);
    *DB_READ_POOL.write().unwrap() = read_pool;
    invalidate_ingress_cache();

    tracing::info!(path = %db_path, "SQLite WAL database connected");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check & Data Pruning (`backend/db/db.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub fn db_health_check() -> anyhow::Result<serde_json::Value> {
    let start = Instant::now();
    let conn = get_conn()?;
    let _one: i32 = conn.query_row("SELECT 1", [], |row| row.get(0))?;
    let latency_ms = start.elapsed().as_millis() as i64;

    let tables = [
        "users",
        "active_sessions",
        "oidc_clients",
        "notifications",
        "metrics_history",
    ];
    let mut counts = HashMap::new();
    for tbl in tables {
        let query_sql = format!("SELECT COUNT(*) FROM {}", tbl);
        if let Ok(cnt) = conn.query_row(&query_sql, [], |row| row.get::<_, i64>(0)) {
            counts.insert(tbl.to_string(), cnt);
        }
    }

    let wal_pages: i64 = conn
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| row.get(0))
        .unwrap_or(0);

    Ok(serde_json::json!({
        "status": "healthy",
        "latency_ms": latency_ms,
        "table_counts": counts,
        "wal_pages": wal_pages,
    }))
}

pub fn prune_expired_data() {
    let Ok(conn) = get_conn() else {
        return;
    };
    let now = Utc::now().to_rfc3339();
    let param_queries = [
        "DELETE FROM oidc_auth_codes WHERE expires_at < ?1 OR used = 1",
        "DELETE FROM oidc_device_codes WHERE expires_at < ?1",
        "DELETE FROM oidc_refresh_tokens WHERE expires_at < ?1 OR revoked = 1",
        "DELETE FROM active_sessions WHERE expires_at < ?1",
    ];
    for query_sql in param_queries {
        let _ = conn.execute(query_sql, params![now]);
    }
    let _ = conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![Utc::now().timestamp()],
    );

    let static_queries = [
        "DELETE FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
        "DELETE FROM login_history WHERE created_at < datetime('now', '-90 days')",
        "DELETE FROM streaming_bandwidth_samples WHERE timestamp < datetime('now', '-90 days')",
    ];
    for query_sql in static_queries {
        let _ = conn.execute(query_sql, []);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// App Ingress Configs & Base Domain (`backend/db/db.go`)
// ─────────────────────────────────────────────────────────────────────────────

struct IngressCache {
    generation: u64,
    configs: Option<Vec<AppIngressConfig>>,
    configs_at: Option<Instant>,
    base_domain: String,
    base_domain_at: Option<Instant>,
}

static INGRESS_CACHE: Lazy<RwLock<IngressCache>> = Lazy::new(|| {
    RwLock::new(IngressCache {
        generation: 0,
        configs: None,
        configs_at: None,
        base_domain: String::new(),
        base_domain_at: None,
    })
});

const INGRESS_CACHE_TTL: Duration = Duration::from_secs(5);

pub fn invalidate_ingress_cache() {
    if let Ok(mut guard) = INGRESS_CACHE.write() {
        guard.generation = guard.generation.wrapping_add(1);
        guard.configs = None;
        guard.configs_at = None;
        guard.base_domain.clear();
        guard.base_domain_at = None;
    }
}

pub fn normalize_base_domain(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host.to_string();
    }
    if let Some((host, _)) = s.split_once(':') {
        s = host.to_string();
    }
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    s = s.trim_matches('.').to_string();
    if s.is_empty()
        || s == "localhost"
        || s == "aether.local"
        || s.ends_with(".local")
        || !s.contains('.')
    {
        return String::new();
    }
    s
}

pub fn get_base_domain() -> String {
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let Some(at) = guard.base_domain_at {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return guard.base_domain.clone();
            }
        }
    }
    let domain = get_conn()
        .ok()
        .and_then(|c| {
            c.query_row(
                "SELECT COALESCE(base_domain, '') FROM settings WHERE id = 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .map(|d| normalize_base_domain(&d))
        .unwrap_or_default();

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        guard.base_domain = domain.clone();
        guard.base_domain_at = Some(Instant::now());
    }
    domain
}

pub fn set_base_domain(domain: &str) -> anyhow::Result<()> {
    let norm = normalize_base_domain(domain);
    let conn = get_conn()?;
    conn.execute(
        "UPDATE settings SET base_domain = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![norm],
    )?;
    invalidate_ingress_cache();
    Ok(())
}

fn parse_sqlite_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|ndt| ndt.and_utc())
        })
        .unwrap_or_else(|_| Utc::now())
}

pub fn get_all_app_ingress_configs() -> anyhow::Result<Vec<AppIngressConfig>> {
    let generation = INGRESS_CACHE.read().map(|guard| guard.generation).unwrap_or(0);
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let (Some(ref cfgs), Some(at)) = (&guard.configs, guard.configs_at) {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return Ok(cfgs.clone());
            }
        }
    }

    let conn = get_conn()?;
    let mut stmt = conn.prepare(
        "SELECT app_name, public_domain, external_access_enabled, listen_port, tls_enabled, \
         COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '') \
         FROM app_ingress_configs ORDER BY app_name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let created_raw: String = r.get(5)?;
        let updated_raw: String = r.get(6)?;
        Ok(AppIngressConfig {
            app_name: r.get(0)?,
            public_domain: r.get(1)?,
            external_access_enabled: r.get(2)?,
            listen_port: r.get(3)?,
            tls_enabled: r.get(4)?,
            created_at: parse_sqlite_dt(&created_raw),
            updated_at: parse_sqlite_dt(&updated_raw),
        })
    })?;

    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        if guard.generation == generation {
            guard.configs = Some(result.clone());
            guard.configs_at = Some(Instant::now());
        }
    }
    Ok(result)
}

pub fn get_app_ingress_config(app_name: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    let all = get_all_app_ingress_configs()?;
    Ok(all.into_iter().find(|c| c.app_name == app_name))
}

pub fn set_app_ingress_config(cfg: &AppIngressConfig) -> anyhow::Result<()> {
    let mut conn = get_conn()?;
    retained_ingress::set_config(&mut conn, cfg, None)?;
    invalidate_ingress_cache();
    Ok(())
}

pub fn set_app_ingress_config_for_lifecycle(
    cfg: &AppIngressConfig,
    job_id: &str,
    action: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(action, "install" | "update"),
        "Invalid ingress lifecycle action"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "Ingress lifecycle job identity is required"
    );
    let mut conn = get_conn()?;
    retained_ingress::set_config(&mut conn, cfg, Some((job_id, action)))?;
    invalidate_ingress_cache();
    Ok(())
}

fn write_app_ingress_config(conn: &Connection, cfg: &AppIngressConfig) -> anyhow::Result<()> {
    conn.execute(
        r#"
        INSERT INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
        ON CONFLICT(app_name) DO UPDATE SET
            public_domain = excluded.public_domain,
            external_access_enabled = excluded.external_access_enabled,
            listen_port = CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE app_ingress_configs.listen_port END,
            tls_enabled = excluded.tls_enabled,
            updated_at = CURRENT_TIMESTAMP
        "#,
        params![
            cfg.app_name,
            cfg.public_domain,
            cfg.external_access_enabled,
            cfg.listen_port,
            cfg.tls_enabled,
        ],
    )?;
    Ok(())
}

pub fn delete_app_ingress_config(app_name: &str) -> anyhow::Result<()> {
    let conn = get_conn()?;
    conn.execute(
        "DELETE FROM app_ingress_configs WHERE app_name = ?1",
        params![app_name],
    )?;
    invalidate_ingress_cache();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Audit Trail (`backend/db/audit.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub fn record_audit(
    user_id: i64,
    username: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: &str,
    ip_address: &str,
    user_agent: &str,
) {
    if let Ok(conn) = get_conn() {
        let _ = conn.execute(
            "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                user_id,
                username,
                action,
                target_type,
                target_id,
                detail,
                ip_address,
                user_agent
            ],
        );
    }
}

pub fn query_audit_log(
    mut limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    if limit <= 0 || limit > 200 {
        limit = 50;
    }
    let conn = get_conn()?;
    let mut where_sql = String::from("WHERE 1=1");
    let mut bind_vals: Vec<String> = Vec::new();
    if !action.is_empty() {
        bind_vals.push(action.to_string());
        where_sql.push_str(&format!(" AND action = ?{}", bind_vals.len()));
    }
    if !username.is_empty() {
        bind_vals.push(username.to_string());
        where_sql.push_str(&format!(" AND username = ?{}", bind_vals.len()));
    }

    let count_sql = format!("SELECT COUNT(*) FROM admin_audit_log {}", where_sql);
    let total: i64 = match bind_vals.len() {
        0 => conn.query_row(&count_sql, [], |r| r.get(0))?,
        1 => conn.query_row(&count_sql, params![bind_vals[0]], |r| r.get(0))?,
        _ => conn.query_row(&count_sql, params![bind_vals[0], bind_vals[1]], |r| {
            r.get(0)
        })?,
    };

    let list_sql = format!(
        "SELECT id, user_id, username, action, target_type, target_id, detail, ip_address, user_agent, COALESCE(CAST(created_at AS TEXT), '') \
         FROM admin_audit_log {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_sql,
        limit,
        offset.max(0)
    );

    let mut stmt = conn.prepare(&list_sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<AuditEntry> {
        Ok(AuditEntry {
            id: r.get(0)?,
            user_id: r.get(1)?,
            username: r.get(2)?,
            action: r.get(3)?,
            target_type: r.get(4)?,
            target_id: r.get(5)?,
            detail: r.get(6)?,
            ip_address: r.get(7)?,
            user_agent: r.get(8)?,
            created_at: r.get(9)?,
        })
    };

    let mut entries = Vec::new();
    match bind_vals.len() {
        0 => {
            for row in stmt.query_map([], map_row)? {
                entries.push(row?);
            }
        }
        1 => {
            for row in stmt.query_map(params![bind_vals[0]], map_row)? {
                entries.push(row?);
            }
        }
        _ => {
            for row in stmt.query_map(params![bind_vals[0], bind_vals[1]], map_row)? {
                entries.push(row?);
            }
        }
    }

    Ok((entries, total))
}

// ─────────────────────────────────────────────────────────────────────────────
// Action Approval Gates (`backend/db/action_gates.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PendingAction {
    pub id: i64,
    pub classification: String,
    pub source: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_log: Option<String>,
}

pub fn queue_action(classification: &str, source: &str, action: &str, reason: &str) -> (i64, bool) {
    if classification == "safe" {
        return (0, false);
    }
    let Ok(conn) = get_conn() else {
        return (0, true);
    };
    match conn.execute(
        "INSERT INTO pending_actions (classification, source, action, reason, status) VALUES (?1, ?2, ?3, ?4, 'pending')",
        params![classification, source, action, reason],
    ) {
        Ok(_) => (conn.last_insert_rowid(), true),
        Err(_) => (0, true),
    }
}

pub fn mark_action_executed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'executed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn mark_action_failed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'failed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn list_audit_entries(
    limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    query_audit_log(limit, offset, action, username)
}

pub fn list_pending_actions(mut limit: i64, offset: i64) -> anyhow::Result<Vec<PendingAction>> {
    if limit <= 0 {
        limit = 50;
    } else if limit > 500 {
        limit = 500;
    }
    let conn = get_conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), resolved_at, resolved_by, execution_log \
         FROM pending_actions ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt.query_map(params![limit, offset.max(0)], |r| {
        Ok(PendingAction {
            id: r.get(0)?,
            classification: r.get(1)?,
            source: r.get(2)?,
            action: r.get(3)?,
            reason: r.get(4)?,
            status: r.get(5)?,
            created_at: r.get(6)?,
            resolved_at: r.get(7).ok().flatten(),
            resolved_by: r.get(8).ok().flatten(),
            execution_log: r.get(9).ok().flatten(),
        })
    })?;
    let mut actions = Vec::new();
    for r in rows {
        actions.push(r?);
    }
    Ok(actions)
}

pub fn get_pending_action_by_id(action_id: i64) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_conn()?;
    get_pending_action_by_id_with_connection(&conn, action_id)
}

fn get_pending_action_by_id_with_connection(
    conn: &Connection,
    action_id: i64,
) -> anyhow::Result<Option<PendingAction>> {
    let mut stmt = conn.prepare(
        "SELECT id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), resolved_at, resolved_by, execution_log \
         FROM pending_actions WHERE id = ?1",
    )?;
    let res = stmt.query_row(params![action_id], |r| {
        Ok(PendingAction {
            id: r.get(0)?,
            classification: r.get(1)?,
            source: r.get(2)?,
            action: r.get(3)?,
            reason: r.get(4)?,
            status: r.get(5)?,
            created_at: r.get(6)?,
            resolved_at: r.get(7).ok().flatten(),
            resolved_by: r.get(8).ok().flatten(),
            execution_log: r.get(9).ok().flatten(),
        })
    });
    match res {
        Ok(action) => Ok(Some(action)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn resolve_action(
    action_id: i64,
    new_status: &str,
    resolved_by: &str,
) -> anyhow::Result<PendingAction> {
    let conn = get_conn()?;
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, resolved_by = ?3 WHERE id = ?4 AND status = 'pending'",
        params![new_status, now, resolved_by, action_id],
    )?;
    if changed == 0 {
        anyhow::bail!("Action not found or already resolved");
    }
    get_pending_action_by_id_with_connection(&conn, action_id)?
        .ok_or_else(|| anyhow::anyhow!("Action disappeared after resolve"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Revocation, 2FA Pending & MFA Challenge Store (`backend/db/redis.go`)
// ─────────────────────────────────────────────────────────────────────────────

static TOKEN_BLACKLIST: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PENDING_2FA_CACHE: Lazy<Mutex<HashMap<i64, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn ensure_revoked_tokens_table(conn: &Connection) -> bool {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);",
    )
    .is_ok()
}

pub fn revoke_token(jti: &str, ttl: Duration) {
    if jti.is_empty() {
        return;
    }
    // Refresh still accepts a token for 7200s after exp, and exp itself is 900s.
    let ttl = ttl.max(Duration::from_secs(8100));
    let exp = Instant::now() + ttl;
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        map.retain(|_, v| *v > Instant::now());
        map.insert(jti.to_string(), exp);
    }
    if let Ok(conn) = get_conn() {
        if !ensure_revoked_tokens_table(&conn) {
            let _ = conn.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti]);
            return;
        }
        let exp_rfc3339 =
            (Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)",
            params![jti, exp_rfc3339],
        );
        let _ = conn.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti]);
        let _ = conn.execute(
            "DELETE FROM revoked_tokens WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        );
    }
}

/// Errors are distinct from a confirmed revocation so rotation grace cannot mask a DB failure.
pub fn token_revocation_status(jti: &str) -> anyhow::Result<bool> {
    if jti.is_empty() {
        return Ok(true);
    }
    if let Ok(mut map) = TOKEN_BLACKLIST.lock() {
        if let Some(&exp) = map.get(jti) {
            if exp > Instant::now() {
                return Ok(true);
            }
            map.remove(jti);
        }
    }
    let conn = get_read_conn()?;
    token_revocation_status_with_conn(&conn, jti)
}

fn token_revocation_status_with_conn(conn: &Connection, jti: &str) -> anyhow::Result<bool> {
    let expiry: Option<String> = conn
        .query_row(
            "SELECT expires_at FROM revoked_tokens WHERE jti = ?1",
            params![jti],
            |r| r.get(0),
        )
        .optional()?;
    match expiry {
        None => Ok(false),
        Some(expiry) => Ok(DateTime::parse_from_rfc3339(&expiry)?.with_timezone(&Utc) > Utc::now()),
    }
}

pub fn is_token_revoked(jti: &str) -> bool {
    token_revocation_status(jti).unwrap_or(true)
}

pub fn store_2fa_pending(user_id: i64, secret: &str, ttl: Duration) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        map.insert(user_id, (secret.to_string(), Instant::now() + ttl));
    }
}

pub fn get_2fa_pending(user_id: i64) -> Option<String> {
    let mut map = PENDING_2FA_CACHE.lock().ok()?;
    if let Some((secret, exp)) = map.get(&user_id) {
        if *exp > Instant::now() {
            return Some(secret.clone());
        }
        map.remove(&user_id);
    }
    None
}

pub fn delete_2fa_pending(user_id: i64) {
    if let Ok(mut map) = PENDING_2FA_CACHE.lock() {
        map.remove(&user_id);
    }
}

pub const MAX_MFA_ATTEMPTS: i64 = 5;

pub fn store_mfa_challenge(token: &str, user_id: i64, ttl: Duration) -> anyhow::Result<()> {
    let conn = get_conn()?;
    let now = Utc::now().timestamp();
    conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now],
    )?;
    conn.execute(
        "INSERT INTO mfa_challenges (token, user_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, user_id, now + ttl.as_secs().min(300) as i64],
    )?;
    Ok(())
}

/// Call within the same write transaction as factor verification and consumption.
/// Failed verification must commit this attempt; successful consumption must commit with the factor.
pub fn begin_mfa_attempt(conn: &Connection, token: &str) -> anyhow::Result<Option<i64>> {
    Ok(conn.query_row(
        "UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token = ?1 AND attempts < ?2 AND expires_at > ?3 RETURNING user_id",
        params![token, MAX_MFA_ATTEMPTS, Utc::now().timestamp()], |r| r.get(0),
    ).optional()?)
}

pub fn consume_mfa_challenge(conn: &Connection, token: &str, user_id: i64) -> anyhow::Result<bool> {
    let consumed: Option<i64> = conn.query_row(
        "DELETE FROM mfa_challenges WHERE token = ?1 AND user_id = ?2 AND attempts <= ?3 AND expires_at > ?4 RETURNING user_id",
        params![token, user_id, MAX_MFA_ATTEMPTS, Utc::now().timestamp()], |r| r.get(0),
    ).optional()?;
    Ok(consumed == Some(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_query_distinguishes_absent_revoked_and_database_errors() {
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
        assert_eq!(readers.max_size(), 4);
        writer.execute_batch("ROLLBACK;").unwrap();
        drop(reader);
        drop(readers);
        drop(writer);
        drop(writer_pool);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_aes_gcm_roundtrip_and_format() {
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
}
