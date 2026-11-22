use chrono::Utc;
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::RwLock;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// SQLite Connection Pool, WAL PRAGMAs & Schema Migrations
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) static DB_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
pub(crate) static DB_READ_POOL: Lazy<RwLock<Option<Pool<SqliteConnectionManager>>>> =
    Lazy::new(|| RwLock::new(None));
pub(crate) static DB_PATH_RESOLVED: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

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
    let current = DB_PATH_RESOLVED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if !current.is_empty() {
        return current;
    }
    resolve_db_path()
}

pub fn get_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_POOL
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Database pool not initialized"))?;
    pool.get()
        .map_err(|e| anyhow::anyhow!("Failed to acquire SQLite connection: {}", e))
}

/// Bounded, read-only WAL connections. The writer remains a pool of one.
/// Private in-memory test databases must use their original connection.
pub fn get_read_conn() -> anyhow::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
    let pool = DB_READ_POOL
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match pool {
        Some(pool) => pool.get().map_err(Into::into),
        None => get_conn(),
    }
}

pub(crate) fn build_read_pool(db_path: &str) -> anyhow::Result<Pool<SqliteConnectionManager>> {
    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
        .with_init(|conn| {
            conn.busy_timeout(Duration::from_millis(750))?;
            conn.execute_batch(
                "PRAGMA query_only=ON; PRAGMA foreign_keys=ON; PRAGMA cache_size=-8000;",
            )
        });
    Ok(Pool::builder()
        .max_size(8)
        .min_idle(Some(1))
        .connection_timeout(Duration::from_secs(2))
        .build(manager)?)
}

pub(crate) fn apply_pragmas(conn: &Connection) {
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

pub(crate) fn run_atomic_migration_tx<F, R>(conn: &Connection, f: F) -> anyhow::Result<R>
where
    F: FnOnce(&Connection) -> anyhow::Result<R>,
{
    if conn.is_autocommit() {
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    } else {
        conn.execute_batch("SAVEPOINT af_migrate;")?;
        match f(conn) {
            Ok(out) => {
                conn.execute_batch("RELEASE SAVEPOINT af_migrate;")?;
                Ok(out)
            }
            Err(err) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT af_migrate; RELEASE SAVEPOINT af_migrate;",
                );
                Err(err)
            }
        }
    }
}

pub(crate) fn migrate(
    conn: &Connection,
    version: i32,
    description: &str,
    stmts: &[&str],
) -> anyhow::Result<()> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let count: i32 = tx_conn.query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        if count > 0 {
            return Ok(());
        }

        for stmt in stmts {
            if let Err(err) = tx_conn.execute_batch(stmt) {
                let msg = err.to_string().to_ascii_lowercase();
                if msg.contains("duplicate column name") || msg.contains("already exists") {
                    tracing::info!(version, "migration DDL already applied");
                    continue;
                }
                tracing::error!(version, error = %err, "migration failed");
                return Err(err.into());
            }
        }

        tx_conn.execute(
            "INSERT INTO schema_versions (version, description) VALUES (?1, ?2)",
            params![version, description],
        )?;
        tracing::info!(version, description, "migration applied");
        Ok(())
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check & Data Pruning
// ─────────────────────────────────────────────────────────────────────────────

pub fn db_readiness_check() -> anyhow::Result<i64> {
    let start = Instant::now();
    let conn = get_read_conn()?;
    let _: Option<i32> = conn
        .query_row("SELECT 1 FROM users LIMIT 1", [], |row| row.get(0))
        .optional()?;
    Ok(start.elapsed().as_millis() as i64)
}

pub fn db_health_check() -> anyhow::Result<serde_json::Value> {
    let start = Instant::now();
    let conn = get_read_conn()?;
    let _: Option<i32> = conn
        .query_row("SELECT 1 FROM users LIMIT 1", [], |row| row.get(0))
        .optional()?;
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

    // A WAL frame occupies its database page plus a 24-byte frame header.
    // Measuring the file avoids a checkpoint on the writer connection.
    let path: String = conn.query_row("PRAGMA database_list", [], |row| row.get(2))?;
    let page_size: u64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let wal_pages = if path.is_empty() {
        0
    } else {
        match fs::metadata(format!("{path}-wal")) {
            Ok(wal) => wal.len().saturating_sub(32) / (page_size + 24),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        }
    };

    Ok(serde_json::json!({
        "status": "healthy",
        "latency_ms": latency_ms,
        "table_counts": counts,
        "wal_pages": wal_pages,
    }))
}

pub const PRUNE_METRICS_HISTORY_SQL: &str =
    "DELETE FROM metrics_history WHERE julianday(timestamp) < julianday('now', '-90 days')";

pub fn has_unexpired_active_session(
    conn: &Connection,
    jti: &str,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE jti = ?1 AND user_id = ?2 AND unixepoch(expires_at, 'auto') > ?3)",
        params![jti, user_id, now],
        |row| row.get(0),
    )
}

pub fn prune_expired_active_sessions(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM active_sessions WHERE unixepoch(expires_at, 'auto') <= ?1",
        params![now],
    )
}

pub const PRUNE_NOTIFICATION_DELIVERY_LOG_SQL: &str =
    "DELETE FROM notification_delivery_log WHERE status IN ('delivered', 'failed', 'uncertain') AND replace(CAST(created_at AS TEXT), 'T', ' ') < datetime('now', '-90 days')";

pub fn prune_expired_data() {
    let Ok(conn) = get_conn() else {
        return;
    };
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let param_queries = [
        // Retain used = 1 authorization-code tombstones until expires_at for RFC 6749 §4.1.2 reuse detection.
        "DELETE FROM oidc_auth_codes WHERE expires_at < ?1",
        "DELETE FROM oidc_device_codes WHERE expires_at < ?1",
        "DELETE FROM oidc_refresh_tokens WHERE expires_at < ?1",
    ];
    for query_sql in param_queries {
        let _ = conn.execute(query_sql, params![now_rfc3339]);
    }
    let _ = prune_expired_active_sessions(&conn, now.timestamp());
    let _ = conn.execute(
        "DELETE FROM mfa_challenges WHERE expires_at <= ?1",
        params![now.timestamp()],
    );

    let static_queries = [
        "DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND TRIM(expires_at) != '' AND datetime(expires_at) IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        PRUNE_METRICS_HISTORY_SQL,
        "DELETE FROM login_history WHERE replace(CAST(created_at AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
        "DELETE FROM streaming_bandwidth_samples WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
        PRUNE_NOTIFICATION_DELIVERY_LOG_SQL,
    ];
    for query_sql in static_queries {
        let _ = conn.execute(query_sql, []);
    }
}
