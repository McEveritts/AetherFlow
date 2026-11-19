use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;

const MAX_RETAINED_STREAMING_BACKUPS: usize = 2;
static STREAMING_BACKUP_SEQ: AtomicU64 = AtomicU64::new(0);

fn parse_backup_dir_sort_key(name: &str) -> u128 {
    // Format: streaming-backup-<pid>-<nanos>[-<seq>]
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() >= 4 {
        let nanos = parts[3].parse::<u128>().unwrap_or(0);
        let seq = parts
            .get(4)
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        (nanos << 16) | (seq & 0xffff)
    } else {
        0
    }
}

fn prune_old_streaming_backups(parent: &Path, keep_current: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let mut backups: Vec<(bool, u128, std::time::SystemTime, String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("streaming-backup-") {
            continue;
        }
        if !path.join("before-migration.sqlite").is_file() {
            continue;
        }
        let is_current = path == keep_current;
        let sort_key = parse_backup_dir_sort_key(name);
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        backups.push((is_current, sort_key, mtime, name.to_string(), path));
    }
    if backups.len() <= MAX_RETAINED_STREAMING_BACKUPS {
        return;
    }
    backups.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| b.3.cmp(&a.3))
    });
    for (_, _, _, _, stale_dir) in backups.into_iter().skip(MAX_RETAINED_STREAMING_BACKUPS) {
        let _ = std::fs::remove_dir_all(stale_dir);
    }
}

pub fn verified_backup(conn: &Connection, db_path: &str) -> anyhow::Result<Option<PathBuf>> {
    if db_path == ":memory:" || (db_path.starts_with("file:") && db_path.contains("mode=memory")) {
        return Ok(None);
    }
    anyhow::ensure!(
        !db_path.starts_with("file:"),
        "File URI backup requires an explicit native database path"
    );
    let parent = Path::new(db_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let seq = STREAMING_BACKUP_SEQ.fetch_add(1, Ordering::Relaxed);
    let directory = parent.join(format!(
        "streaming-backup-{}-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        seq
    ));
    struct BackupDirGuard {
        path: Option<PathBuf>,
    }
    impl Drop for BackupDirGuard {
        fn drop(&mut self) {
            if let Some(dir) = self.path.take() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let mut dir_guard = BackupDirGuard {
        path: Some(directory.clone()),
    };
    let backup = directory.join("before-migration.sqlite");
    let result = (|| -> anyhow::Result<()> {
        conn.execute("VACUUM main INTO ?1", [backup.to_string_lossy().as_ref()])?;
        let verification = Connection::open_with_flags(&backup, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String =
            verification.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        anyhow::ensure!(
            integrity == "ok",
            "Streaming database backup failed integrity verification"
        );
        let original: i64 =
            conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
                row.get(0)
            })?;
        let copied: i64 =
            verification.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
                row.get(0)
            })?;
        anyhow::ensure!(original == copied, "Streaming backup count changed during verification; retry while collection is quiescent");
        Ok(())
    })();
    result?;
    dir_guard.path = None;
    prune_old_streaming_backups(parent, &directory);
    Ok(Some(backup))
}

pub fn migrate_history(conn: &Connection, db_path: &str) -> anyhow::Result<()> {
    let applied: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_versions WHERE version = 20",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let policies_table_exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'streaming_tracking_policies'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if applied.is_some() && policies_table_exists.is_some() {
        return migrate_read_epoch(conn);
    }
    let backup = verified_backup(conn, db_path)?;
    if let Some(path) = backup {
        tracing::info!(backup = %path.display(), "Verified backup before streaming history migration");
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> anyhow::Result<()> {
        conn.execute_batch(include_str!("migrations/020_streaming_history.sql"))?;
        conn.execute(
            "INSERT OR REPLACE INTO schema_versions(version, description) VALUES(20, 'Canonical streaming provenance, query indexes and evidence')",
            [],
        )?;
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
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM schema_versions WHERE version=21 AND description=?1",
        [DESCRIPTION],
    )?;
    let existing: Option<String> = transaction
        .query_row(
            "SELECT description FROM schema_versions WHERE version=24",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(description) = existing {
        anyhow::ensure!(
            description == DESCRIPTION,
            "Streaming read-epoch migration version24 collision: {description}"
        );
        transaction.commit()?;
        return Ok(());
    }
    transaction.execute_batch(include_str!("migrations/024_streaming_read_epoch.sql"))?;
    for (table, label) in [
        ("streaming_user_links", "links"),
        ("streaming_history_labels", "labels"),
    ] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            transaction.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS streaming_read_{label}_{} AFTER {operation} ON {table} BEGIN UPDATE streaming_history_read_revision SET revision=revision+1 WHERE id=1; END;", operation.to_ascii_lowercase()))?;
        }
    }
    transaction.execute(
        "INSERT INTO schema_versions(version,description) VALUES(24,?1)",
        [DESCRIPTION],
    )?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod backup_prune_tests {
    use super::*;

    #[test]
    fn verified_backup_prunes_older_directories_retaining_two_newest() {
        let root =
            std::env::temp_dir().join(format!("af-stream-bkp-prune-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).unwrap();
        let db_file = root.join("aetherflow.sqlite");
        let conn = Connection::open(&db_file).unwrap();
        conn.execute_batch(
            "CREATE TABLE streaming_history (id INTEGER PRIMARY KEY AUTOINCREMENT, item_name TEXT);",
        )
        .unwrap();

        let mut created = Vec::new();
        for idx in 0..4 {
            conn.execute(
                "INSERT INTO streaming_history (item_name) VALUES (?1)",
                [format!("item-{idx}")],
            )
            .unwrap();
            let bkp = verified_backup(&conn, db_file.to_str().unwrap())
                .unwrap()
                .unwrap();
            created.push(bkp.parent().unwrap().to_path_buf());
        }

        let remaining: Vec<PathBuf> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("streaming-backup-"))
            })
            .collect();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&created[2]));
        assert!(remaining.contains(&created[3]));

        drop(conn);
        let _ = std::fs::remove_dir_all(&root);
    }
}
