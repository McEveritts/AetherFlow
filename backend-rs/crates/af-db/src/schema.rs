use rusqlite::{params, Connection, OptionalExtension};

use crate::pool::run_atomic_migration_tx;

pub(crate) fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    column_ddl: &str,
) -> anyhow::Result<()> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name.eq_ignore_ascii_case(column));
    if !exists {
        let alter = format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, column_ddl);
        conn.execute(&alter, [])?;
    }
    Ok(())
}

pub(crate) fn ensure_security_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    ensure_column(
        conn,
        "users",
        "sessions_revoked_after",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "active_sessions",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "oidc_refresh_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "mfa_challenges",
        "credential_ver",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "revoked_tokens",
        "family_id",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        conn,
        "revoked_tokens",
        "user_id",
        "INTEGER NOT NULL DEFAULT 0",
    )?;

    let existing_index_sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_oidc_device_codes_user_code'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let needs_unique_index = match existing_index_sql {
        Some(sql) => !sql.to_ascii_uppercase().contains("UNIQUE"),
        None => true,
    };
    if needs_unique_index {
        conn.execute_batch(
            "DELETE FROM oidc_device_codes
             WHERE rowid NOT IN (
                 SELECT MAX(rowid) FROM oidc_device_codes GROUP BY user_code
             );
             DROP INDEX IF EXISTS idx_oidc_device_codes_user_code;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_device_codes_user_code ON oidc_device_codes(user_code);",
        )?;
    }
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_sessions_family ON active_sessions(family_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mediaflow_file_path ON mediaflow_queue(file_path)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_oidc_refresh_family ON oidc_refresh_tokens(family_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_revoked_tokens_family ON revoked_tokens(family_id)",
        [],
    )?;
    Ok(())
}

pub fn ensure_notification_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    run_atomic_migration_tx(conn, |tx_conn| {
        tx_conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notification_reads (
                notification_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (notification_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_notification_reads_user_notification
                ON notification_reads(user_id, notification_id);",
        )?;

        let has_table = |name: &str| -> rusqlite::Result<bool> {
            tx_conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                params![name],
                |r| r.get(0),
            )
        };

        if has_table("notification_rules")? {
            ensure_column(
                tx_conn,
                "notification_rules",
                "last_triggered_at",
                "INTEGER",
            )?;
        }

        if has_table("notification_delivery_log")? {
            ensure_column(
                tx_conn,
                "notification_delivery_log",
                "next_attempt_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            ensure_column(
                tx_conn,
                "notification_delivery_log",
                "claim_token",
                "TEXT NOT NULL DEFAULT ''",
            )?;
            ensure_column(
                tx_conn,
                "notification_delivery_log",
                "lease_until",
                "INTEGER",
            )?;
            ensure_column(
                tx_conn,
                "notification_delivery_log",
                "updated_at",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
            tx_conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_delivery_log_notification
                    ON notification_delivery_log(notification_id);
                 CREATE INDEX IF NOT EXISTS idx_delivery_log_due
                    ON notification_delivery_log(status, next_attempt_at, lease_until);
                 CREATE INDEX IF NOT EXISTS idx_delivery_log_channel_id_desc
                    ON notification_delivery_log(channel_id, id DESC);",
            )?;
        }
        Ok(())
    })
}

pub(crate) fn ensure_pending_actions_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    ensure_column(conn, "pending_actions", "job_unit", "TEXT")?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pending_actions_job_unit ON pending_actions(job_unit)",
        [],
    )?;
    Ok(())
}

pub fn ensure_mediaflow_schema_invariants(conn: &Connection) -> anyhow::Result<()> {
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mediaflow_queue')",
        [],
        |r| r.get(0),
    )?;
    if !table_exists {
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS mediaflow_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                original_codec TEXT DEFAULT '',
                original_size INTEGER DEFAULT 0,
                new_codec TEXT DEFAULT '',
                new_size INTEGER DEFAULT 0,
                error_log TEXT DEFAULT '',
                source_dev INTEGER,
                source_ino INTEGER,
                source_size INTEGER,
                source_mtime_sec INTEGER,
                source_mtime_nsec INTEGER,
                source_fingerprint TEXT NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
        )?;
    }

    let has_table_unique: bool = {
        let mut stmt = conn.prepare("PRAGMA index_list(mediaflow_queue)")?;
        let mut found = false;
        let rows = stmt.query_map([], |row| {
            let unique: i64 = row.get(2)?;
            let origin: String = row.get(3)?;
            let partial: i64 = row.get(4)?;
            Ok((unique, origin, partial))
        })?;
        for item in rows.flatten() {
            if item.0 == 1 && (item.1 == "u" || item.2 == 0) {
                found = true;
                break;
            }
        }
        found
    };

    if has_table_unique {
        run_atomic_migration_tx(conn, |tx_conn| {
            let existing_cols: std::collections::HashSet<String> = {
                let mut stmt = tx_conn.prepare("PRAGMA table_info(mediaflow_queue)")?;
                let cols = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(Result::ok)
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                cols
            };
            let opt_col = |name: &str, fallback: &str| -> String {
                if existing_cols.contains(name) {
                    name.to_string()
                } else {
                    fallback.to_string()
                }
            };
            let select_sql = format!(
                "INSERT INTO mediaflow_queue_v2 (
                    id, file_path, status, original_codec, original_size,
                    new_codec, new_size, error_log,
                    source_dev, source_ino, source_size,
                    source_mtime_sec, source_mtime_nsec, source_fingerprint,
                    created_at, updated_at
                )
                SELECT
                    id, file_path, status, original_codec, original_size,
                    new_codec, new_size, error_log,
                    {}, {}, {}, {}, {}, {},
                    created_at, updated_at
                FROM mediaflow_queue;",
                opt_col("source_dev", "NULL"),
                opt_col("source_ino", "NULL"),
                opt_col("source_size", "NULL"),
                opt_col("source_mtime_sec", "NULL"),
                opt_col("source_mtime_nsec", "NULL"),
                opt_col("source_fingerprint", "''"),
            );
            tx_conn.execute_batch(
                r#"DROP TABLE IF EXISTS mediaflow_queue_v2;
                CREATE TABLE mediaflow_queue_v2 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING_APPROVAL',
                    original_codec TEXT DEFAULT '',
                    original_size INTEGER DEFAULT 0,
                    new_codec TEXT DEFAULT '',
                    new_size INTEGER DEFAULT 0,
                    error_log TEXT DEFAULT '',
                    source_dev INTEGER,
                    source_ino INTEGER,
                    source_size INTEGER,
                    source_mtime_sec INTEGER,
                    source_mtime_nsec INTEGER,
                    source_fingerprint TEXT NOT NULL DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );"#,
            )?;
            tx_conn.execute_batch(&select_sql)?;
            tx_conn.execute_batch(
                "DROP TABLE mediaflow_queue;
                 ALTER TABLE mediaflow_queue_v2 RENAME TO mediaflow_queue;",
            )?;
            Ok(())
        })?;
    }

    ensure_column(conn, "mediaflow_queue", "source_dev", "INTEGER")?;
    ensure_column(conn, "mediaflow_queue", "source_ino", "INTEGER")?;
    ensure_column(conn, "mediaflow_queue", "source_size", "INTEGER")?;
    ensure_column(conn, "mediaflow_queue", "source_mtime_sec", "INTEGER")?;
    ensure_column(conn, "mediaflow_queue", "source_mtime_nsec", "INTEGER")?;
    ensure_column(
        conn,
        "mediaflow_queue",
        "source_fingerprint",
        "TEXT NOT NULL DEFAULT ''",
    )?;

    // Deduplicate any pre-existing duplicate active rows before creating the partial unique index.
    conn.execute(
        "UPDATE mediaflow_queue
         SET status = 'SUPERSEDED',
             error_log = CASE
                 WHEN COALESCE(error_log, '') = '' THEN 'Superseded duplicate active queue entry during schema migration'
                 ELSE error_log
             END,
             updated_at = CURRENT_TIMESTAMP
         WHERE status IN ('PENDING_APPROVAL', 'APPROVED', 'PROCESSING')
           AND id NOT IN (
               SELECT MAX(id)
               FROM mediaflow_queue
               WHERE status IN ('PENDING_APPROVAL', 'APPROVED', 'PROCESSING')
               GROUP BY file_path
           )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mediaflow_status ON mediaflow_queue(status)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mediaflow_file_path ON mediaflow_queue(file_path)",
        [],
    )?;
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_mediaflow_active_file_path ON mediaflow_queue(file_path) WHERE status IN ('PENDING_APPROVAL', 'APPROVED', 'PROCESSING')",
        [],
    )?;
    Ok(())
}
