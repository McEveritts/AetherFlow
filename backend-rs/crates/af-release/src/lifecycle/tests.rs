use super::*;
use crate::{ReleaseCommand, ReleaseConfig, ReleaseLockGuard};
use rusqlite::Connection;
use std::path::PathBuf;
use std::time::Duration;

mod lease_jobs_tests;
mod redaction_tests;
mod version_tests;

pub(super) fn fixture() -> (PathBuf, ReleaseConfig, PathBuf, Connection) {
    let root = std::env::temp_dir().join(format!("af-owner-{}", uuid::Uuid::new_v4()));
    let cfg = ReleaseConfig::for_root(&root);
    let database = crate::config::try_resolve_db_path(&cfg, None).unwrap().path;
    std::fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    initialize_schema(&conn).unwrap();
    (root, cfg, database, conn)
}

pub(super) fn insert(conn: &Connection, owner: &str) {
    conn.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at,owner_id,service_units)
        VALUES ('fixture','job','update','updating','now',?1,'[\"fixture.service\",\"fixture.timer\"]')", [owner]).unwrap();
}

pub(super) fn state(conn: &Connection) -> String {
    conn.query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
        row.get(0)
    })
    .unwrap()
}

pub(super) fn admission(cfg: &ReleaseConfig) -> crate::ReleaseResult<()> {
    let path = crate::ensure_interoperable_maintenance_lock_file(cfg)?;
    let _guard = ReleaseLockGuard::acquire(path, Duration::ZERO)?;
    crate::admin::ensure_no_active_package_lifecycle_jobs(cfg, ReleaseCommand::Deploy)
}
