use super::*;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "af_db_streaming_test_{}_{}_{}",
            prefix,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn db_file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn extract_raw_strings(mut src: &str) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(pos) = src.find("r#\"") {
        let after_start = &src[pos + 3..];
        let end = after_start
            .find("\"#")
            .expect("unterminated raw string literal in lib.rs");
        out.push(after_start[..end].to_string());
        src = &after_start[end + 2..];
    }
    out
}

fn extract_quoted_ddl_statements(block: &str, prefix: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let stripped = trimmed.strip_prefix('"')?;
            let sql = stripped.strip_suffix("\",")?;
            if sql.starts_with(prefix) {
                Some(sql.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn apply_actual_migration_19_from_lib_source(conn: &Connection) {
    let lib_src = include_str!("lib.rs");

    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .expect("enable foreign_keys");

    // Extract core table block from init_db() in lib.rs (includes users, schema_versions, etc.)
    let core_marker = "CREATE TABLE IF NOT EXISTS settings (";
    let core_idx = lib_src
        .find(core_marker)
        .expect("core tables marker in lib.rs");
    let before_core = &lib_src[..core_idx];
    let raw_start = before_core
        .rfind("r#\"")
        .expect("raw string start before core tables");
    let raw_body = &lib_src[raw_start + 3..];
    let raw_end = raw_body
        .find("\"#")
        .expect("raw string end for core tables");
    let core_ddl = &raw_body[..raw_end];
    conn.execute_batch(core_ddl)
        .expect("execute core tables DDL from lib.rs");

    // Extract migration 19 block from lib.rs
    let m19_marker =
        "\"Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables\"";
    let m19_start = lib_src
        .find(m19_marker)
        .expect("migration 19 marker in lib.rs");
    let m19_tail = &lib_src[m19_start..];
    let m19_end = m19_tail
        .find("streaming::migrate_history")
        .expect("migrate_history call after migration 19 in lib.rs");
    let m19_block = &m19_tail[..m19_end];

    let raw_tables = extract_raw_strings(m19_block);
    assert_eq!(
        raw_tables.len(),
        3,
        "migration 19 must define 3 raw table DDL strings (streaming_servers, streaming_history, streaming_bandwidth_samples)"
    );
    for ddl in &raw_tables {
        conn.execute_batch(ddl)
            .expect("execute migration 19 table DDL");
    }

    let index_stmts = extract_quoted_ddl_statements(m19_block, "CREATE INDEX");
    assert_eq!(
        index_stmts.len(),
        7,
        "migration 19 must define 7 CREATE INDEX statements"
    );
    for idx_sql in &index_stmts {
        conn.execute_batch(idx_sql)
            .expect("execute migration 19 index DDL");
    }

    conn.execute(
        "INSERT OR IGNORE INTO schema_versions (version, description) VALUES (19, 'Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables')",
        [],
    )
    .expect("record schema version 19");
}

#[test]
fn migration_v20_preserves_v19_legacy_records_as_unverified_and_sets_defaults() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    apply_actual_migration_19_from_lib_source(&conn);

    // Seed legacy v19 records: one with standard SQLite timestamp, one with empty started_at
    conn.execute(
        r#"
        INSERT INTO streaming_history (
            session_key, provider, server_name, user_id, user_name,
            client_name, device_name, device_id, ip_address,
            item_id, item_name, item_type, series_name,
            play_method, duration_secs, watched_secs, data_used_bytes,
            started_at, last_seen_at, ended_at, is_active
        ) VALUES
        (
            'legacy:sess:1', 'jellyfin', 'Main Vault', 'u-legacy-1', 'alice',
            'Jellyfin Web', 'Firefox', 'dev-1', '10.0.0.10',
            'item-101', 'Arrival', 'Movie', '',
            'DirectPlay', 6960, 3600, 1073741824,
            '2026-03-15 20:00:00', '2026-03-15 21:00:00', '2026-03-15 21:00:00', 0
        ),
        (
            'legacy:sess:2', 'jellyfin', 'Main Vault', 'u-legacy-2', 'bob',
            'Infuse', 'Apple TV', 'dev-2', '10.0.0.11',
            'item-102', 'Severance S01E01', 'Episode', 'Severance',
            'Transcode', 3300, 1200, 524288000,
            '', '2026-03-16 21:00:00', NULL, 0
        )
        "#,
        [],
    )
    .expect("insert v19 legacy rows");

    migrate_history(&conn, ":memory:").expect("migrate_history v20");

    let v20_recorded: Option<String> = conn
        .query_row(
            "SELECT description FROM schema_versions WHERE version = 20",
            [],
            |r| r.get(0),
        )
        .optional()
        .expect("query schema_versions");
    assert_eq!(
        v20_recorded.as_deref(),
        Some("Canonical streaming provenance, query indexes and evidence")
    );

    // Verify row 1 (dated legacy record)
    let row1: (String, String, Option<String>, String, String, String, Option<i64>, i64, i64, i64) = conn
        .query_row(
            "SELECT provenance, server_id, source_event_id, timestamp_certainty, byte_accuracy, policy_status, event_unix, event_missing, watched_secs, data_used_bytes FROM streaming_history WHERE session_key = 'legacy:sess:1'",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .expect("read migrated row 1");

    assert_eq!(row1.0, "legacy_unverified");
    assert_eq!(row1.1, "");
    assert_eq!(row1.2, None);
    assert_eq!(row1.3, "legacy_unverified");
    assert_eq!(row1.4, "legacy_unverified");
    assert_eq!(row1.5, "included");
    assert_eq!(row1.6, Some(1_773_604_800)); // 2026-03-15T20:00:00Z
    assert_eq!(row1.7, 0);
    assert_eq!(row1.8, 3600);
    assert_eq!(row1.9, 1_073_741_824);

    // Verify row 2 (undated legacy record with empty started_at)
    let row2: (String, String, String, String, Option<i64>, i64) = conn
        .query_row(
            "SELECT provenance, timestamp_certainty, byte_accuracy, policy_status, event_unix, event_missing FROM streaming_history WHERE session_key = 'legacy:sess:2'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .expect("read migrated row 2");

    assert_eq!(row2.0, "legacy_unverified");
    assert_eq!(row2.1, "legacy_unverified");
    assert_eq!(row2.2, "legacy_unverified");
    assert_eq!(row2.3, "included");
    assert_eq!(row2.4, None);
    assert_eq!(row2.5, 1);

    // Verify revision and tracking policies singleton rows initialized
    let rev: i64 = conn
        .query_row("SELECT revision FROM streaming_history_revision WHERE id = 1", [], |r| r.get(0))
        .expect("revision singleton");
    assert_eq!(rev, 0);

    let policy: (i64, String, String, i64) = conn
        .query_row(
            "SELECT minimum_watch_secs, excluded_users, excluded_libraries, reconnect_window_secs FROM streaming_tracking_policies WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("policy singleton");
    assert_eq!(policy, (0, "[]".to_string(), "[]".to_string(), 0));

    // Verify revision triggers fire on update/delete of history, policies, links, and labels
    conn.execute("INSERT INTO users (id, username) VALUES (1, 'alice')", [])
        .expect("insert user");
    conn.execute(
        "INSERT INTO streaming_user_links (af_user_id, provider, server_id, provider_user_id) VALUES (1, 'jellyfin', 'srv-1', 'u-legacy-1')",
        [],
    )
    .expect("insert link");
    let rev_after_link: i64 = conn
        .query_row("SELECT revision FROM streaming_history_revision WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rev_after_link, 1);

    conn.execute(
        "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (1, 'genre', 'Sci-Fi', 'Sci-Fi')",
        [],
    )
    .expect("insert label");
    let rev_after_label: i64 = conn
        .query_row("SELECT revision FROM streaming_history_revision WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rev_after_label, 2);

    conn.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs = 60 WHERE id = 1",
        [],
    )
    .expect("update policy");
    let rev_after_policy: i64 = conn
        .query_row("SELECT revision FROM streaming_history_revision WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rev_after_policy, 3);
}

#[test]
fn migration_v20_is_idempotent_across_repeated_invocations() {
    let dir = TempTestDir::new("idempotent");
    let db_path = dir.db_file("aetherflow.sqlite");
    let db_path_str = db_path.to_string_lossy().to_string();

    let conn = Connection::open(&db_path).expect("open disk db");
    apply_actual_migration_19_from_lib_source(&conn);

    conn.execute(
        "INSERT INTO streaming_history (session_key, provider, user_id, user_name, item_id, item_name) VALUES ('s1', 'jellyfin', 'u1', 'user1', 'i1', 'Movie 1')",
        [],
    )
    .expect("insert row");

    migrate_history(&conn, &db_path_str).expect("first migrate_history");

    let backups_after_first: Vec<_> = fs::read_dir(&dir.path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("streaming-backup-"))
        .collect();
    assert_eq!(
        backups_after_first.len(),
        1,
        "first migration must create exactly 1 backup directory"
    );

    // Mutate state slightly and re-run migrate_history
    conn.execute(
        "UPDATE streaming_history SET watched_secs = 500 WHERE session_key = 's1'",
        [],
    )
    .expect("update history row");

    migrate_history(&conn, &db_path_str).expect("second migrate_history should be no-op");
    migrate_history(&conn, &db_path_str).expect("third migrate_history should be no-op");

    let backups_after_repeat: Vec<_> = fs::read_dir(&dir.path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("streaming-backup-"))
        .collect();
    assert_eq!(
        backups_after_repeat.len(),
        1,
        "subsequent migrate_history calls must short-circuit before creating extra backups"
    );

    let v20_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM schema_versions WHERE version = 20",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v20_count, 1);

    let rev: i64 = conn
        .query_row(
            "SELECT revision FROM streaming_history_revision WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rev, 1, "revision incremented once by update, untouched by idempotent re-runs");
}

#[test]
fn verified_backup_removes_unverified_files_on_failure() {
    let directory = TempTestDir::new("backup_failure");
    let db_path = directory.db_file("invalid.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)").unwrap();
    assert!(verified_backup(&conn, db_path.to_str().unwrap()).is_err());
    assert!(!fs::read_dir(&directory.path).unwrap().filter_map(Result::ok).any(|entry| entry.file_name().to_string_lossy().starts_with("streaming-backup-")));
}

#[test]
fn migration_v20_rolls_back_atomically_on_schema_failure() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    apply_actual_migration_19_from_lib_source(&conn);

    conn.execute(
        "INSERT INTO streaming_history (session_key, provider, user_id, user_name, item_id, item_name) VALUES ('pre-fail', 'jellyfin', 'u1', 'alice', 'm1', 'Dune')",
        [],
    )
    .expect("seed v19 row");

    // Pre-create a conflicting table that 020_streaming_history.sql attempts to CREATE TABLE (without IF NOT EXISTS)
    // Midway through 020_streaming_history.sql, `CREATE TABLE streaming_history_labels` will fail after ALTER TABLE statements have executed inside the transaction.
    conn.execute_batch("CREATE TABLE streaming_history_labels (conflict_col INTEGER);")
        .expect("create conflicting table");

    let err = migrate_history(&conn, ":memory:").expect_err("migration should fail on schema conflict");
    assert!(
        err.to_string().contains("streaming_history_labels"),
        "expected failure mentioning conflicting table, got: {err}"
    );

    // Ensure transaction was rolled back (connection is not stuck in an open transaction)
    assert!(
        conn.is_autocommit(),
        "connection must return to autocommit mode after rollback"
    );

    // Verify schema_versions does not have version 20
    let v20_exists: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_versions WHERE version = 20",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(v20_exists, None);

    // Verify the earlier ALTER TABLE statements on streaming_history were rolled back
    let mut stmt = conn
        .prepare("PRAGMA table_info(streaming_history)")
        .unwrap();
    let columns: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        !columns.contains(&"provenance".to_string()),
        "ALTER TABLE ADD COLUMN provenance must be rolled back on mid-migration failure"
    );
    assert!(
        !columns.contains(&"event_unix".to_string()),
        "ALTER TABLE ADD COLUMN event_unix must be rolled back on mid-migration failure"
    );

    // Verify streaming_history_revision table was also rolled back
    let rev_table_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='streaming_history_revision'",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(rev_table_exists, None);

    // Verify pre-existing v19 data is still intact
    let preserved_item: String = conn
        .query_row(
            "SELECT item_name FROM streaming_history WHERE session_key = 'pre-fail'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(preserved_item, "Dune");
}

#[test]
fn verified_backup_enforces_private_permissions_and_disk_restore_consistency() {
    let dir = TempTestDir::new("backup_restore");
    let db_path = dir.db_file("live.sqlite");
    let db_path_str = db_path.to_string_lossy().to_string();

    // 1. Memory and URI path handling
    let mem_conn = Connection::open_in_memory().unwrap();
    assert_eq!(
        verified_backup(&mem_conn, ":memory:").unwrap(),
        None,
        ":memory: should skip file backup"
    );
    assert_eq!(
        verified_backup(&mem_conn, "file:memdb?mode=memory&cache=shared").unwrap(),
        None,
        "mode=memory URI should skip file backup"
    );
    let uri_err = verified_backup(&mem_conn, "file:/tmp/some.sqlite")
        .expect_err("non-memory file: URI must be rejected");
    assert!(uri_err
        .to_string()
        .contains("File URI backup requires an explicit native database path"));

    // 2. Disk DB with v19 schema and realistic legacy records
    let conn = Connection::open(&db_path).expect("open live disk db");
    apply_actual_migration_19_from_lib_source(&conn);

    for i in 1..=25 {
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_name, user_id, user_name, item_id, item_name, watched_secs, data_used_bytes, started_at)
             VALUES (?1, 'jellyfin', 'Vault', ?2, ?3, ?4, ?5, ?6, ?7, '2026-04-01 18:30:00')",
            params![
                format!("sess-{i}"),
                format!("user-{}", i % 3),
                format!("User {}", i % 3),
                format!("item-{i}"),
                format!("Title {i}"),
                i * 120,
                i * 1024 * 1024
            ],
        )
        .expect("seed v19 disk row");
    }

    // Run migrate_history on disk DB, which creates the verified backup first
    migrate_history(&conn, &db_path_str).expect("migrate_history on disk db");

    // Locate the backup directory created alongside live.sqlite
    let backup_dirs: Vec<PathBuf> = fs::read_dir(&dir.path)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with("streaming-backup-"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(backup_dirs.len(), 1, "expected 1 backup directory");
    let backup_dir = &backup_dirs[0];
    let backup_file = backup_dir.join("before-migration.sqlite");
    assert!(backup_file.is_file(), "before-migration.sqlite must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(backup_dir)
            .expect("backup dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "backup directory must have private 0700 permissions, got {:o}",
            mode
        );
    }

    // Verify backup is a pre-v20 snapshot (v19 only) and passes integrity_check
    let bkp_conn =
        Connection::open_with_flags(&backup_file, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let integrity: String = bkp_conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let bkp_v20: Option<i64> = bkp_conn
        .query_row(
            "SELECT version FROM schema_versions WHERE version = 20",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(
        bkp_v20, None,
        "backup must capture state strictly before migration 20"
    );
    drop(bkp_conn);

    // Simulate post-migration disaster on live DB (corrupt/delete rows), then restore from backup
    conn.execute("DELETE FROM streaming_history", []).unwrap();
    drop(conn);

    let restored_path = dir.db_file("restored.sqlite");
    fs::copy(&backup_file, &restored_path).expect("restore backup to disk");

    let restored_conn = Connection::open(&restored_path).expect("open restored db");
    let restored_count: i64 = restored_conn
        .query_row("SELECT COUNT(*) FROM streaming_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(restored_count, 25);

    // Re-running migration 20 on the restored backup must cleanly produce identical v20 state
    migrate_history(&restored_conn, &restored_path.to_string_lossy())
        .expect("migrate restored backup to v20");

    let migrated_unverified_count: i64 = restored_conn
        .query_row(
            "SELECT COUNT(*) FROM streaming_history WHERE provenance = 'legacy_unverified' AND timestamp_certainty = 'legacy_unverified' AND byte_accuracy = 'legacy_unverified' AND event_unix = 1775068200 AND event_missing = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(migrated_unverified_count, 25);
}
