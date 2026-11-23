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

struct ScopedEnvVars {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ScopedEnvVars {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn save_once(&mut self, key: &'static str) {
        if !self.saved.iter().any(|(existing, _)| *existing == key) {
            self.saved.push((key, std::env::var_os(key)));
        }
    }

    fn set<V: AsRef<std::ffi::OsStr>>(&mut self, key: &'static str, value: V) {
        self.save_once(key);
        std::env::set_var(key, value);
    }

    fn remove(&mut self, key: &'static str) {
        self.save_once(key);
        std::env::remove_var(key);
    }
}

impl Drop for ScopedEnvVars {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(val) => std::env::set_var(key, val),
                None => std::env::remove_var(key),
            }
        }
    }
}

struct RollbackHookGuard;

impl RollbackHookGuard {
    fn set<F>(hook: F) -> Self
    where
        F: Fn(&[FileSnapshot]) + Send + Sync + 'static,
    {
        *super::TEST_ROLLBACK_HOOK
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(Box::new(hook));
        Self
    }
}

impl Drop for RollbackHookGuard {
    fn drop(&mut self) {
        *super::TEST_ROLLBACK_HOOK
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = None;
    }
}

struct CertifyFailHookGuard;

impl CertifyFailHookGuard {
    fn set<F>(hook: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        *super::TEST_CERTIFY_FAIL_HOOK
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some(Box::new(hook));
        Self
    }
}

impl Drop for CertifyFailHookGuard {
    fn drop(&mut self) {
        *super::TEST_CERTIFY_FAIL_HOOK
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = None;
    }
}

struct InjectWaitidEpermGuard;

impl InjectWaitidEpermGuard {
    fn enable() -> Self {
        super::INJECT_WAITID_EPERM.store(true, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for InjectWaitidEpermGuard {
    fn drop(&mut self) {
        super::INJECT_WAITID_EPERM.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn run_in_isolated_subprocess(test_name: &str, child_env: &str) -> bool {
    if std::env::var_os(child_env).is_some() {
        return false;
    }
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test_name, "--nocapture"])
        .env(child_env, "1");
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_INSTALL_ROOT",
        "AETHERFLOW_RECOVERY_ROOT",
        "AF_RECOVERY_ROOT",
        "AETHERFLOW_PACKAGES_CONFIG",
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "AF_PACKAGES_CONFIG",
        "AF_PACKAGE_AUTOMATION_CONFIG",
        "AETHERFLOW_MAX_SNAPSHOT_BYTES",
        "AETHERFLOW_TEST_FORCE_DISK_FULL",
    ] {
        cmd.env_remove(key);
    }
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("1 passed; 0 failed"),
        "isolated subprocess test `{test_name}` failed (status={}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status
    );
    true
}

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
