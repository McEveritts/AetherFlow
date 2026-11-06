use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::{Path, PathBuf};

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;

pub fn verified_backup(conn: &Connection, db_path: &str) -> anyhow::Result<Option<PathBuf>> {
    if db_path == ":memory:" || (db_path.starts_with("file:") && db_path.contains("mode=memory")) {
        return Ok(None);
    }
    anyhow::ensure!(!db_path.starts_with("file:"), "File URI backup requires an explicit native database path");
    let parent = Path::new(db_path).parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let directory = parent.join(format!("streaming-backup-{}-{}", std::process::id(), Utc::now().timestamp_nanos_opt().unwrap_or_default()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let backup = directory.join("before-migration.sqlite");
    let result = (|| -> anyhow::Result<()> {
        conn.execute("VACUUM main INTO ?1", [backup.to_string_lossy().as_ref()])?;
        let verification = Connection::open_with_flags(&backup, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String = verification.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        anyhow::ensure!(integrity == "ok", "Streaming database backup failed integrity verification");
        let original: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| row.get(0))?;
        let copied: i64 = verification.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| row.get(0))?;
        anyhow::ensure!(original == copied, "Streaming backup count changed during verification; retry while collection is quiescent");
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(Some(backup))
}

pub fn migrate_history(conn: &Connection, db_path: &str) -> anyhow::Result<()> {
    let applied: Option<i64> = conn.query_row("SELECT version FROM schema_versions WHERE version = 20", [], |row| row.get(0)).optional()?;
    if applied.is_some() {
        return migrate_read_epoch(conn);
    }
    let backup = verified_backup(conn, db_path)?;
    if let Some(path) = backup {
        tracing::info!(backup = %path.display(), "Verified backup before streaming history migration");
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> anyhow::Result<()> {
        conn.execute_batch(include_str!("migrations/020_streaming_history.sql"))?;
        conn.execute("INSERT INTO schema_versions(version, description) VALUES(20, 'Canonical streaming provenance, query indexes and evidence')", [])?;
        conn.execute_batch("COMMIT")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    result?;
    migrate_read_epoch(conn)
}

fn migrate_read_epoch(conn: &Connection) -> anyhow::Result<()> {
    const DESCRIPTION: &str = "Streaming historical read epoch; destructive revision retained";
    let transaction = conn.unchecked_transaction()?;
    transaction.execute("DELETE FROM schema_versions WHERE version=21 AND description=?1", [DESCRIPTION])?;
    let existing: Option<String> = transaction.query_row("SELECT description FROM schema_versions WHERE version=24", [], |row| row.get(0)).optional()?;
    if let Some(description) = existing {
        anyhow::ensure!(description == DESCRIPTION, "Streaming read-epoch migration version24 collision: {description}");
        transaction.commit()?;
        return Ok(());
    }
    transaction.execute_batch(include_str!("migrations/024_streaming_read_epoch.sql"))?;
    for (table, label) in [("streaming_user_links", "links"), ("streaming_history_labels", "labels")] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            transaction.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS streaming_read_{label}_{} AFTER {operation} ON {table} BEGIN UPDATE streaming_history_read_revision SET revision=revision+1 WHERE id=1; END;", operation.to_ascii_lowercase()))?;
        }
    }
    transaction.execute("INSERT INTO schema_versions(version,description) VALUES(24,?1)", [DESCRIPTION])?;
    transaction.commit()?;
    Ok(())
}
