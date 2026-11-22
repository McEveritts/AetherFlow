use super::admitted_snapshots::spawn_worker;
use super::backend::LifecycleBackend;
use super::coordinator::CoordinatedOperation;
use af_models::{Package, PackageRunnerRequest};
use af_release::lifecycle;
use anyhow::Result;
use futures::future::BoxFuture;
use rusqlite::Connection;
use tokio::sync::mpsc;

mod coordination;
mod policies_and_rollback;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct FakeBackend {
    calls: Mutex<Vec<String>>,
    fail_script: bool,
    script_error_message: Option<String>,
    fail_stop: bool,
    fail_restore: bool,
    runtime_port: i32,
    started: Option<Arc<tokio::sync::Notify>>,
    release: Option<Arc<tokio::sync::Notify>>,
    conflict_database: Option<PathBuf>,
    root: Option<PathBuf>,
    inactive_after_start: bool,
    inactive_after_certification: bool,
    active_count: Mutex<usize>,
    active_oneshots: Vec<String>,
}

impl LifecycleBackend for FakeBackend {
    fn runtime_port(&self, _: &str) -> i32 {
        self.runtime_port
    }
    fn available_port(&self, _: i32) -> bool {
        true
    }
    fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        let mut count = self.active_count.lock().unwrap();
        *count += 1;
        let current_count = *count;
        let calls = self.calls.lock().unwrap();
        let last_stop = calls.iter().rposition(|c| c == &format!("stop {unit}"));
        let last_start = calls.iter().rposition(|c| c == &format!("start {unit}"));
        let is_active = match (last_stop, last_start) {
            (Some(s), Some(st)) if s > st => false,
            (Some(_), Some(_)) => {
                if self.inactive_after_start {
                    false
                } else {
                    !(self.inactive_after_certification && current_count == 3)
                }
            }
            (Some(_), None) => false,
            (None, Some(_)) => !self.inactive_after_start,
            (None, None) => {
                if matches!(unit, "recyclarr" | "scrutiny-collector") {
                    self.active_oneshots.iter().any(|u| u == unit)
                } else {
                    true
                }
            }
        };
        Box::pin(async move { Ok(is_active) })
    }
    fn control<'a>(
        &'a self,
        unit: &'a str,
        action: &'a str,
        _: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(format!("{action} {unit}"));
            if action == "stop" && self.fail_stop {
                anyhow::bail!("simulated ambiguous stop failure");
            }
            if action == "start" && self.fail_restore {
                anyhow::bail!("simulated restore failure");
            }
            if let Some(path) = &self.conflict_database {
                let mut conn = Connection::open(path)?;
                assert!(lifecycle::admit_job(
                    &mut conn,
                    "competitor",
                    "foreign",
                    "update",
                    "now",
                    &["syncthing".into()]
                )
                .is_err());
            }
            Ok(())
        })
    }
    fn script<'a>(
        &'a self,
        request: &'a PackageRunnerRequest,
        sender: &'a mpsc::Sender<String>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(format!(
                "script {} port={} purge={}",
                request.action, request.app_port, request.delete_data
            ));
            if let Some(started) = &self.started {
                started.notify_one();
            }
            if let Some(release) = &self.release {
                release.notified().await;
            }
            let _ = sender.try_send("[PROGRESS:100] Installer finished\n".into());
            if let Some(target) = &request.expected_target_version {
                if let Some(root) = &self.root {
                    let vfile = root.join("var/lib/syncthing/.af-version");
                    let _ = std::fs::create_dir_all(vfile.parent().unwrap());
                    let _ = std::fs::write(vfile, target);
                    let bin = root.join("usr/bin/syncthing");
                    let _ = std::fs::create_dir_all(bin.parent().unwrap());
                    let _ =
                        std::fs::write(&bin, format!("#!/bin/sh\necho \"syncthing {target}\"\n"));
                    let dpkg_ver = target.trim_start_matches(['v', 'V']);
                    let dpkg_shim = root.join("usr/bin/dpkg-query");
                    let _ = std::fs::write(
                        &dpkg_shim,
                        format!("#!/bin/sh\necho \"installed {dpkg_ver}\"\n"),
                    );
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
                        let _ = std::fs::set_permissions(
                            &dpkg_shim,
                            std::fs::Permissions::from_mode(0o755),
                        );
                    }
                }
            }
            if let Some(msg) = &self.script_error_message {
                anyhow::bail!("{msg}");
            }
            if self.fail_script {
                anyhow::bail!("simulated script failure secret-do-not-persist");
            }
            Ok(())
        })
    }
}

fn fixture() -> (PathBuf, PathBuf, Connection, Package) {
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

fn request(action: &str) -> PackageRunnerRequest {
    PackageRunnerRequest {
        package_id: "syncthing".into(),
        action: action.into(),
        script_name: format!("{action}package-syncthing"),
        expected_target_version: if action == "update" {
            Some("v1.23.4".into())
        } else {
            None
        },
        ..Default::default()
    }
}

fn persisted(conn: &Connection) -> (String, String, String) {
    conn.query_row("SELECT job_id,status,failure_category FROM package_lifecycle_jobs WHERE package_id='syncthing'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()
}
