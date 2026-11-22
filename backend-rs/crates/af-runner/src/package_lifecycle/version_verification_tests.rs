use super::backend::LifecycleBackend;
use super::coordinator::CoordinatedOperation;
use super::recovery_storage::{
    prepare_runtime_snapshot_backup_root_with_policy, RecoveryStoragePolicy,
};
use super::runtime_snapshot::force_remove_backup_tree;
use super::runtime_targets::candidate_runtime_targets;
use super::version_probe::validate_systemd_unit_runtime_evidence;
use super::*;
use af_models::{Package, PackageRunnerRequest};
use anyhow::Result;
use futures::future::BoxFuture;
use rusqlite::Connection;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

mod redaction_and_receipts;
mod rollback_gating;
mod rollback_transitions;
mod runtime_snapshots;
mod version_probing;

static ENV_TEST_MUTEX: once_cell::sync::Lazy<std::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

fn test_fixture() -> (PathBuf, PathBuf, Connection, Package) {
    let root = std::env::temp_dir().join(format!("af-coordinator-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let path = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;
        CREATE TABLE settings(id INTEGER PRIMARY KEY,base_domain TEXT);
        INSERT INTO settings VALUES(1,'default.example.test');
        CREATE TABLE app_updates(package_name TEXT PRIMARY KEY);
        INSERT INTO app_updates VALUES('syncthing');
        CREATE TABLE app_ingress_configs(app_name TEXT PRIMARY KEY,public_domain TEXT,
            external_access_enabled BOOLEAN,listen_port INTEGER,tls_enabled BOOLEAN,
            created_at TEXT,updated_at TEXT);
        INSERT INTO app_ingress_configs VALUES('syncthing','custom.example.test',1,18384,0,'now','now');").unwrap();
    let package = Package {
        name: "syncthing".into(),
        service_name: "syncthing".into(),
        service_type: "systemd".into(),
        default_port: 8384,
        ..Default::default()
    };
    (root, path, conn, package)
}
