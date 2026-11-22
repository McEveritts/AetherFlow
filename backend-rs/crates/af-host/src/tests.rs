mod backup_and_snapshot;
mod hardening_and_maintenance;
mod security_and_provenance;
mod staged_restore;

use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};

/// RAII temporary directory guard under `std::env::temp_dir()` for isolated unit tests.
struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "af-host-test-{}-{}-{}",
            prefix,
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create isolated temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_sample_wal_database(db_path: &Path) {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA user_version = 42;
         CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT NOT NULL);
         INSERT INTO settings (id, base_domain) VALUES (1, 'seedbox.example.test');
         CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
         INSERT INTO users (id, username) VALUES (1, 'admin'), (2, 'operator');",
    )
    .unwrap();
}
