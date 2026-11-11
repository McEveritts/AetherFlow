use af_models::{Package, PackageRunnerRequest, SystemctlRequest};
use af_release::lifecycle::{self, OwnerLease};
use anyhow::{Context, Result};
use futures::{future::BoxFuture, StreamExt};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, time::Duration};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use tokio::sync::mpsc;

pub const JOB_MARKER: &str = "__RUNNER_JOB__:";
pub const RECEIPT_MARKER: &str = "__RUNNER_LIFECYCLE__:";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LifecycleReceipt {
    pub job_id: String,
    pub package_id: String,
    pub action: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub app_port: i32,
}

pub fn package_service_units(package: &str) -> Result<Vec<String>> {
    let package = package_definition(package)?;
    let primary = if package.service_name.is_empty() {
        package.name.clone()
    } else {
        package.service_name
    };
    Ok(
        lifecycle::package_resources(&primary, &package.sandbox_service_ids)
            .into_iter()
            .collect(),
    )
}

fn catalog_source(variable: &str, filename: &str, embedded: &str) -> Result<String> {
    let mut env_paths = Vec::new();
    if let Ok(path) = std::env::var(variable) {
        env_paths.push(path);
    }
    if let Some(short_var) = variable.strip_prefix("AETHERFLOW_") {
        let alt = format!("AF_{}", short_var);
        if let Ok(path) = std::env::var(&alt) {
            env_paths.push(path);
        }
    }
    for path in env_paths {
        if !path.trim().is_empty() {
            return Ok(std::fs::read_to_string(path.trim())?);
        }
    }
    let mut candidates = vec![
        Path::new("/opt/AetherFlow/current/config").join(filename),
        Path::new("/opt/AetherFlow/current/backend/config").join(filename),
        Path::new("config").join(filename),
        Path::new("../config").join(filename),
        Path::new("/opt/AetherFlow/config").join(filename),
        Path::new("backend/config").join(filename),
        Path::new("../backend/config").join(filename),
        Path::new("/opt/AetherFlow/backend/config").join(filename),
    ];
    if let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_owned))
    {
        candidates.insert(2, directory.join("config").join(filename));
    }
    for path in candidates {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Ok(std::fs::read_to_string(path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(embedded.into())
}

fn package_definition(name: &str) -> Result<Package> {
    let packages: Vec<Package> = serde_json::from_str(&catalog_source(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        crate::EMBEDDED_PACKAGES_JSON,
    )?)?;
    let automation: std::collections::HashMap<String, af_models::PackageAutomation> =
        serde_json::from_str(&catalog_source(
            "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
            "package_automation.json",
            crate::EMBEDDED_AUTOMATION_JSON,
        )?)?;
    let mut names = std::collections::HashSet::new();
    for package in &packages {
        anyhow::ensure!(
            !package.name.trim().is_empty() && names.insert(package.name.to_ascii_lowercase()),
            "Package catalog has duplicate or empty identities"
        );
    }
    let mut package = packages
        .into_iter()
        .find(|package| package.name == name)
        .context("Package catalog entry is unavailable")?;
    if let Some(automation) = automation.get(name) {
        package.update_source = automation.update_source.clone();
        package.require_download_sha256 = automation.require_download_sha256;
        package.update_repo = automation.update_repo.clone();
        package.update_repo_url = automation.update_repo_url.clone();
        package.update_package = automation.update_package.clone();
        package.update_channel = automation.update_channel.clone();
        package.version_command = automation.version_command.clone();
        package.version_regex = automation.version_regex.clone();
        package.sandbox_profile = automation.sandbox_profile.clone();
        package.sandbox_read_write = automation.sandbox_read_write.clone();
        package.sandbox_service_ids = automation.sandbox_service_ids.clone();
    }
    Ok(package)
}

pub fn execute_coordinated_package_stream(
    request: PackageRunnerRequest,
) -> impl futures::Stream<Item = std::io::Result<String>> + Send {
    async_stream::stream! {
        if !request.lifecycle_job_id.is_empty() {
            let stream = crate::execute_package_request_stream(request);
            tokio::pin!(stream);
            while let Some(line) = stream.next().await { yield line; }
            return;
        }
        let mut receiver = spawn_worker(request, |request, sender| async move {
            run_direct(request, &sender).await
        });
        while let Some(line) = receiver.recv().await { yield Ok(line); }
    }
}

fn spawn_worker<Run, RunFuture>(request: PackageRunnerRequest, run: Run) -> mpsc::Receiver<String>
where
    Run: FnOnce(PackageRunnerRequest, mpsc::Sender<String>) -> RunFuture + Send + 'static,
    RunFuture: std::future::Future<Output = Result<LifecycleReceipt>> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(128);
    tokio::spawn(async move {
        let result = run(request, sender.clone()).await;
        match result {
            Ok(receipt) => match serde_json::to_string(&receipt) {
                Ok(json) => {
                    let _ = sender.send(format!("{RECEIPT_MARKER}{json}\n")).await;
                }
                Err(_) => {
                    let _ = sender
                        .send(
                            "__RUNNER_EXIT_ERROR__:Lifecycle receipt serialization failed\n".into(),
                        )
                        .await;
                }
            },
            Err(error) => {
                tracing::error!(error = %error, "Direct package lifecycle could not confirm completion");
                let sanitized_err = sanitize_lifecycle_field(&error.to_string());
                let _ = sender
                    .send(format!(
                        "__RUNNER_EXIT_ERROR__:Lifecycle completion could not be confirmed: {}; inspect durable package status before retrying\n",
                        sanitized_err
                    ))
                    .await;
            }
        }
    });
    receiver
}

#[cfg(test)]
mod tests {
    use super::*;
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
                    } else if self.inactive_after_certification && current_count == 3 {
                        false
                    } else {
                        true
                    }
                }
                (Some(_), None) => false,
                (None, Some(_)) => {
                    if self.inactive_after_start {
                        false
                    } else {
                        true
                    }
                }
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
                        let _ = std::fs::write(&bin, format!("#!/bin/sh\necho \"syncthing {target}\"\n"));
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
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

    #[tokio::test]
    async fn direct_remove_reinstall_and_explicit_purge_share_durable_ingress_callbacks() {
        let (root, path, conn, package) = fixture();
        let backend = FakeBackend::default();
        let (sender, _receiver) = mpsc::channel(32);
        let mut remove = CoordinatedOperation::admit(
            conn,
            request("remove"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        let terminal = remove.execute(&backend, &sender).await.unwrap();
        assert_eq!(terminal.status, "completed");
        assert_eq!(persisted(&remove.conn).0, terminal.job_id);
        assert_eq!(
            remove
                .conn
                .query_row("SELECT COUNT(*) FROM app_updates", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            remove
                .conn
                .query_row("SELECT COUNT(*) FROM app_ingress_configs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let retained = af_db::load_lifecycle_ingress(&remove.conn, "syncthing")
            .unwrap()
            .unwrap();
        assert_eq!(retained.public_domain, "custom.example.test");
        assert!(!retained.tls_enabled);
        drop(remove);
        let mut install = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("install"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        assert_eq!(
            install.execute(&backend, &sender).await.unwrap().app_port,
            18384
        );
        assert_eq!(
            install
                .conn
                .query_row("SELECT listen_port FROM app_ingress_configs", [], |row| row
                    .get::<_, i32>(0))
                .unwrap(),
            18384
        );
        drop(install);
        let mut purge = request("remove");
        purge.delete_data = true;
        let mut purge = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            purge,
            package,
            vec!["syncthing".into()],
        )
        .unwrap();
        assert_eq!(
            purge.execute(&backend, &sender).await.unwrap().status,
            "completed"
        );
        assert!(af_db::load_lifecycle_ingress(&purge.conn, "syncthing")
            .unwrap()
            .is_none());
        assert_eq!(
            *backend.calls.lock().unwrap(),
            vec![
                "script remove port=0 purge=false",
                "script install port=18384 purge=false",
                "script remove port=0 purge=true"
            ]
        );
        drop(purge);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn update_retains_custom_port_and_reservation_until_timer_and_service_restore() {
        let (root, path, conn, package) = fixture();
        let backend = FakeBackend {
            conflict_database: Some(path),
            root: Some(root.clone()),
            ..Default::default()
        };
        let (sender, _receiver) = mpsc::channel(32);
        let mut operation = CoordinatedOperation::admit(
            conn,
            request("update"),
            package,
            vec![
                "syncthing".into(),
                "syncthing.timer".into(),
                "recyclarr".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            operation.execute(&backend, &sender).await.unwrap().status,
            "completed"
        );
        assert_eq!(
            *backend.calls.lock().unwrap(),
            vec![
                "stop syncthing.timer",
                "stop syncthing",
                "script update port=18384 purge=false",
                "start syncthing",
                "start syncthing.timer"
            ]
        );
        drop(operation);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn required_callback_and_script_failures_never_become_completed_receipts() {
        for failure in [
            "retention",
            "installer",
            "service_restore",
            "invalid_port",
            "stop",
        ] {
            let (root, _, conn, package) = fixture();
            if failure == "retention" {
                conn.execute_batch("DROP TABLE app_updates").unwrap();
            }
            let backend = FakeBackend {
                fail_script: failure == "installer",
                fail_stop: failure == "stop",
                fail_restore: failure == "service_restore",
                runtime_port: if failure == "invalid_port" { 70000 } else { 0 },
                ..Default::default()
            };
            let (sender, _receiver) = mpsc::channel(32);
            let action = if failure == "retention" {
                "remove"
            } else {
                "update"
            };
            let mut operation = CoordinatedOperation::admit(
                conn,
                request(action),
                package,
                vec!["syncthing".into()],
            )
            .unwrap();
            let receipt = operation.execute(&backend, &sender).await.unwrap();
            assert_eq!(receipt.status, "failed", "{failure}");
            let (_, status, category) = persisted(&operation.conn);
            assert_eq!(status, "failed");
            assert_eq!(
                category,
                if matches!(failure, "invalid_port" | "stop") {
                    "preparation"
                } else {
                    failure
                }
            );
            if failure == "retention" {
                assert_eq!(
                    operation
                        .conn
                        .query_row("SELECT COUNT(*) FROM app_ingress_configs", [], |row| row
                            .get::<_, i64>(0))
                        .unwrap(),
                    1
                );
            }
            if failure == "installer" {
                assert!(backend
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|call| call == "start syncthing"));
                let stored = std::fs::read(operation.conn.path().unwrap()).unwrap();
                assert!(!String::from_utf8_lossy(&stored).contains("secret-do-not-persist"));
            }
            if failure == "invalid_port" {
                assert!(backend.calls.lock().unwrap().is_empty());
            }
            if failure == "stop" {
                assert_eq!(
                    *backend.calls.lock().unwrap(),
                    vec!["stop syncthing", "stop syncthing"]
                );
            }
            drop(operation);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn stream_disconnect_does_not_drop_worker_owner_or_required_callbacks() {
        let (root, path, conn, package) = fixture();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let backend = FakeBackend {
            started: Some(started.clone()),
            release: Some(release.clone()),
            ..Default::default()
        };
        let operation =
            CoordinatedOperation::admit(conn, request("remove"), package, vec!["syncthing".into()])
                .unwrap();
        let identity = operation.request.lifecycle_job_id.clone();
        let (finished, done) = tokio::sync::oneshot::channel();
        let receiver = spawn_worker(request("remove"), move |_, sender| async move {
            let mut operation = operation;
            let result = operation.execute(&backend, &sender).await;
            let _ = finished.send(());
            result
        });
        started.notified().await;
        drop(receiver);
        let conn = Connection::open(&path).unwrap();
        lifecycle::reconcile_jobs(&conn, &path).unwrap();
        assert_eq!(persisted(&conn).1, "uninstalling");
        release.notify_one();
        done.await.unwrap();
        assert_eq!(persisted(&conn), (identity, "completed".into(), "".into()));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM retained_app_ingress_configs",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn dropped_coordinator_is_interrupted_only_after_maintenance_lock_is_available() {
        let (root, path, conn, package) = fixture();
        let operation =
            CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
                .unwrap();
        let identity = operation.request.lifecycle_job_id.clone();
        let guard = crate::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        drop(operation);
        assert!(crate::acquire_lifecycle_admission_lock(Some(&root)).is_err());
        let conn = Connection::open(&path).unwrap();
        assert_eq!(persisted(&conn).1, "updating");
        drop(guard);
        let _admission = crate::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        lifecycle::reconcile_jobs(&conn, &path).unwrap();
        assert_eq!(persisted(&conn).1, "interrupted");
        assert!(lifecycle::finish_job(&conn, "syncthing", &identity, "update", true, "").is_err());
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn in_place_reinstall_pre_stops_active_units_and_restores_on_completion_and_failure() {
        let (root, path, conn, mut package) = fixture();
        let lock_path = root.join("install/.syncthing.lock");
        std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        std::fs::write(&lock_path, "installed\n").unwrap();
        package.lock_file = lock_path.to_string_lossy().into_owned();

        // 1. In-place reinstall (action="install" with lock_file present on disk) pre-stops active units
        // and starts them in reverse order after the installer script completes.
        let backend = FakeBackend::default();
        let (sender, _receiver) = mpsc::channel(32);
        let mut reinstall = CoordinatedOperation::admit(
            conn,
            request("install"),
            package.clone(),
            vec!["syncthing".into(), "syncthing.timer".into()],
        )
        .unwrap();
        let receipt = reinstall.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "completed");
        assert_eq!(
            *backend.calls.lock().unwrap(),
            vec![
                "stop syncthing.timer",
                "stop syncthing",
                "script install port=18384 purge=false",
                "start syncthing",
                "start syncthing.timer",
            ]
        );
        drop(reinstall);

        // 2. Failed in-place reinstall still restores pre-stopped units in reverse order.
        let fail_backend = FakeBackend {
            fail_script: true,
            ..Default::default()
        };
        let mut failed_reinstall = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("install"),
            package,
            vec!["syncthing".into(), "syncthing.timer".into()],
        )
        .unwrap();
        let fail_receipt = failed_reinstall
            .execute(&fail_backend, &sender)
            .await
            .unwrap();
        assert_eq!(fail_receipt.status, "failed");
        assert_eq!(
            *fail_backend.calls.lock().unwrap(),
            vec![
                "stop syncthing.timer",
                "stop syncthing",
                "script install port=18384 purge=false",
                "stop syncthing.timer",
                "stop syncthing",
                "start syncthing",
                "start syncthing.timer",
            ]
        );
        drop(failed_reinstall);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn afmp003_stopped_or_retained_application_port_is_never_stolen_by_another_application() {
        let (root, path, mut conn, mut package) = fixture();
        // Reset syncthing's own saved config from fixture so we test fresh port allocation for a second app
        conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
        // Persist port 8384 for stopped application `radarr` and retain port 17000 for removed application `sonarr`
        conn.execute(
            "INSERT INTO app_ingress_configs(app_name,public_domain,external_access_enabled,listen_port,tls_enabled)
             VALUES ('radarr','',0,8384,0)",
            [],
        )
        .unwrap();
        af_db::synchronize_lifecycle_ingress(
            &mut conn,
            "sonarr",
            "remove",
            "",
            0,
            false,
            "",
        )
        .ok();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO retained_app_ingress_configs(app_name, config_json) VALUES ('sonarr', ?1)",
            [serde_json::to_string(&af_models::AppIngressConfig {
                app_name: "sonarr".into(),
                listen_port: 17000,
                ..Default::default()
            })
            .unwrap()],
        )
        .unwrap();

        package.default_port = 8384;
        let backend = FakeBackend::default();

        // Explicit request for a port owned by stopped `radarr` (8384) or retained `sonarr` (17000) must be rejected at admission
        let mut steal_req = request("install");
        steal_req.app_port = 8384;
        assert!(
            CoordinatedOperation::admit(
                Connection::open(&path).unwrap(),
                steal_req,
                package.clone(),
                vec!["syncthing".into()],
            )
            .is_err(),
            "admit must reject explicit app_port owned by stopped radarr"
        );

        // Automatic port resolution for `syncthing` (default_port = 8384) must skip 8384 (owned by radarr)
        // and skip 17000 (retained by sonarr), allocating 17001 instead!
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            request("install"),
            package,
            vec!["syncthing".into()],
        )
        .unwrap();
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "completed");
        assert_eq!(receipt.app_port, 17001);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn afmp_sol_003_symlinked_sonarr_config_fails_closed_without_recording_port() {
        let (root, _path, conn, _package) = fixture();
        conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
        let sonarr_dir = root.join("var/lib/sonarr");
        std::fs::create_dir_all(&sonarr_dir).unwrap();
        let target_cfg = root.join("var/lib/sonarr-target-config.xml");
        std::fs::write(&target_cfg, "<Config><Port>8989</Port></Config>\n").unwrap();
        std::os::unix::fs::symlink(&target_cfg, sonarr_dir.join("config.xml")).unwrap();

        let package = Package {
            name: "sonarr".into(),
            service_name: "sonarr".into(),
            service_type: "systemd".into(),
            default_port: 8989,
            ..Default::default()
        };
        let mut req = PackageRunnerRequest {
            package_id: "sonarr".into(),
            action: "install".into(),
            script_name: "installpackage-sonarr".into(),
            app_port: 18989,
            ..Default::default()
        };
        let backend = FakeBackend::default();
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            std::mem::take(&mut req),
            package,
            vec!["sonarr".into()],
        )
        .unwrap();
        let exec_res = op.execute(&backend, &sender).await;
        assert!(exec_res.is_err(), "Execute must fail closed at preflight when blueprint target is a symlink");
        let (status, category): (String, String) = op
            .conn
            .query_row(
                "SELECT status, failure_category FROM package_lifecycle_jobs WHERE package_id='sonarr'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(category, "preflight");
        assert!(
            af_db::load_lifecycle_ingress(&op.conn, "sonarr")
                .unwrap()
                .is_none(),
            "app_ingress_configs must not record port 18989 when config.xml mutation fails"
        );
        assert_eq!(
            std::fs::read_to_string(&target_cfg).unwrap(),
            "<Config><Port>8989</Port></Config>\n"
        );
        drop(op);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn incomplete_rollback_refuses_to_restart_pre_stopped_units() {
        let (root, _path, conn, package) = fixture();
        let backend = FakeBackend {
            script_error_message: Some(
                "step failed; incomplete rollback: recovery backup preserved at /var/lib/syncthing.bak"
                    .into(),
            ),
            ..Default::default()
        };
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            request("update"),
            package,
            vec!["syncthing".into(), "syncthing.timer".into()],
        )
        .unwrap();
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");
        let calls = backend.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                "stop syncthing.timer",
                "stop syncthing",
                "script update port=18384 purge=false",
                "stop syncthing.timer",
                "stop syncthing",
            ],
            "pre-stopped units must NOT be restarted after incomplete rollback"
        );
        let (_, status, category) = persisted(&op.conn);
        assert_eq!(status, "failed");
        assert_eq!(category, "service_restore");
        drop(op);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn update_rejects_missing_or_invalid_target_version_at_admission() {
        let (root, _path, conn, package) = fixture();
        let mut req = request("update");
        req.expected_target_version = None;
        assert!(
            CoordinatedOperation::admit(
                conn,
                req,
                package.clone(),
                vec!["syncthing".into()]
            )
            .is_err(),
            "admission must reject update request with missing target version"
        );

        let (_r2, _p2, conn2, _pkg2) = fixture();
        let mut req2 = request("update");
        req2.expected_target_version = Some("invalid target with spaces".into());
        assert!(
            CoordinatedOperation::admit(
                conn2,
                req2,
                package,
                vec!["syncthing".into()]
            )
            .is_err(),
            "admission must reject update request with invalid target version"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn update_fails_target_verification_when_live_probe_fails_or_mismatches() {
        let (root, _path, conn, package) = fixture();
        // Backend does not write target version to .af-version, so live probe will find nothing!
        let backend = FakeBackend::default();
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            request("update"),
            package,
            vec!["syncthing".into()],
        )
        .unwrap();
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");
        let (_, status, category) = persisted(&op.conn);
        assert_eq!(status, "failed");
        assert_eq!(category, "target_verification");
        drop(op);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_service_restart_inactive_unit_triggers_receipt_and_blueprint_rollback() {
        let (root, _path, conn, package) = fixture();
        let receipt_file = root.join("var/lib/syncthing/.af-version");
        std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
        std::fs::write(&receipt_file, b"v1.22.0").unwrap();

        let backend = FakeBackend {
            root: Some(root.clone()),
            inactive_after_start: true,
            ..Default::default()
        };
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            request("update"),
            package,
            vec!["syncthing".into()],
        )
        .unwrap();

        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        let (status, category, diag): (String, String, Option<String>) = op
            .conn
            .query_row(
                "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(category, "service_restore");
        assert!(
            diag.as_deref().unwrap_or("").contains("not active after start"),
            "Diagnostic summary must detail unit inactive after start: {:?}",
            diag
        );

        // Candidate receipt MUST have been rolled back to v1.22.0, NOT the installer's v1.23.4
        let restored_content = std::fs::read_to_string(&receipt_file).unwrap();
        assert_eq!(
            restored_content, "v1.22.0",
            "Receipt must be restored to pre-operation version on restart failure"
        );

        drop(op);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_service_unit_exiting_during_certification_triggers_receipt_rollback() {
        let (root, _path, conn, package) = fixture();
        let receipt_file = root.join("var/lib/syncthing/.af-version");
        std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
        std::fs::write(&receipt_file, b"v1.22.0").unwrap();

        let backend = FakeBackend {
            root: Some(root.clone()),
            inactive_after_certification: true,
            ..Default::default()
        };
        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            request("update"),
            package,
            vec!["syncthing".into()],
        )
        .unwrap();

        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        let (status, category, diag): (String, String, Option<String>) = op
            .conn
            .query_row(
                "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(category, "service_restore");
        assert!(
            diag.as_deref().unwrap_or("").contains("exited or became inactive during certification"),
            "Diagnostic summary must report post-certification unit exit: {:?}",
            diag
        );

        // Receipt rolled back to v1.22.0
        let restored_content = std::fs::read_to_string(&receipt_file).unwrap();
        assert_eq!(restored_content, "v1.22.0");

        drop(op);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_blueprint_config_rollback_on_target_certification_failure() {
        let (root, _path, conn, _package) = fixture();
        let sonarr_package = Package {
            name: "sonarr".into(),
            service_name: "sonarr".into(),
            service_type: "systemd".into(),
            default_port: 8989,
            ..Default::default()
        };
        let config_file = root.join("var/lib/sonarr/config.xml");
        std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        std::fs::write(&config_file, b"<Config><Port>8989</Port><ApiKey>PRE_OP_KEY</ApiKey></Config>\n").unwrap();

        let receipt_file = root.join("var/lib/sonarr/.af-version");
        std::fs::write(&receipt_file, b"2.0.0\n").unwrap();

        let req = PackageRunnerRequest {
            package_id: "sonarr".into(),
            action: "update".into(),
            script_name: "updatepackage-sonarr".into(),
            expected_target_version: Some("3.0.0".into()),
            app_port: 8989,
            ..Default::default()
        };

        struct BlueprintMutationBackend {
            root: PathBuf,
            config_file: PathBuf,
            receipt_file: PathBuf,
            stopped: Arc<std::sync::Mutex<bool>>,
        }
        impl LifecycleBackend for BlueprintMutationBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8989 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let s = *self.stopped.lock().unwrap();
                Box::pin(async move { Ok(s) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                if action == "stop" {
                    *self.stopped.lock().unwrap() = true;
                } else if action == "start" {
                    *self.stopped.lock().unwrap() = false;
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    // Installer mutates blueprint config and writes receipt that mismatches target
                    std::fs::write(&self.config_file, b"<Config><Port>8989</Port><ApiKey>MODIFIED_KEY</ApiKey></Config>\n").unwrap();
                    std::fs::write(&self.receipt_file, b"2.5.0\n").unwrap();
                    let bin = self.root.join("usr/bin/sonarr");
                    let _ = std::fs::create_dir_all(bin.parent().unwrap());
                    let _ = std::fs::write(&bin, b"#!/bin/sh\necho \"sonarr 2.5.0\"\n");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
                    }
                    Ok(())
                })
            }
        }

        let backend = BlueprintMutationBackend {
            root: root.clone(),
            config_file: config_file.clone(),
            receipt_file: receipt_file.clone(),
            stopped: Arc::new(std::sync::Mutex::new(false)),
        };

        let (sender, _receiver) = mpsc::channel(32);
        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            sonarr_package,
            vec!["sonarr".into()],
        )
        .unwrap();

        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        let (status, category): (String, String) = op
            .conn
            .query_row(
                "SELECT status, failure_category FROM package_lifecycle_jobs WHERE package_id='sonarr'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(category, "target_verification");

        // The blueprint config file MUST have been rolled back to PRE_OP_KEY!
        let rolled_back_config = std::fs::read_to_string(&config_file).unwrap();
        assert!(
            rolled_back_config.contains("PRE_OP_KEY"),
            "Blueprint config must be rolled back on certification failure, got: {}",
            rolled_back_config
        );
        assert!(
            !rolled_back_config.contains("MODIFIED_KEY"),
            "Modified blueprint config must not persist after certification failure"
        );

        // The receipt MUST have been rolled back to 2.0.0!
        let rolled_back_receipt = std::fs::read_to_string(&receipt_file).unwrap();
        assert_eq!(rolled_back_receipt.trim(), "2.0.0");

        drop(op);
        let _ = std::fs::remove_dir_all(root);
    }
}

async fn run_direct(
    request: PackageRunnerRequest,
    sender: &mpsc::Sender<String>,
) -> Result<LifecycleReceipt> {
    let package = package_definition(&request.package_id)?;
    let units = package_service_units(&request.package_id)?;
    let environment = crate::PackageExecutionEnv::default();
    let root = environment.fs_root.as_deref();
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let cfg = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    let guard = crate::acquire_package_maintenance_guard(
        root,
        lifecycle::ReservationTarget::Package(&request.package_id),
        "",
        Some(&request.action),
    )
    .await?;
    if request.action == "update" {
        anyhow::ensure!(
            !package.lock_file.is_empty()
                && environment.resolve_path(&package.lock_file)?.is_file(),
            "Package must be installed before it can be updated"
        );
    }
    let conn = Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let mut operation = CoordinatedOperation::admit(conn, request, package, units)?;
    drop(guard);
    let identity = serde_json::json!({
        "job_id": operation.request.lifecycle_job_id,
        "package_id": operation.request.package_id,
        "action": operation.request.action,
    });
    let _ = sender.send(format!("{JOB_MARKER}{identity}\n")).await;
    operation.execute(&HostBackend, sender).await
}

trait LifecycleBackend: Send + Sync {
    fn runtime_port(&self, package: &str) -> i32;
    fn available_port(&self, port: i32) -> bool;
    fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>>;
    fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(!self.active(unit).await?) })
    }
    fn control<'a>(
        &'a self,
        unit: &'a str,
        action: &'a str,
        identity: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
    fn script<'a>(
        &'a self,
        request: &'a PackageRunnerRequest,
        sender: &'a mpsc::Sender<String>,
    ) -> BoxFuture<'a, Result<()>>;
}

struct HostBackend;

impl LifecycleBackend for HostBackend {
    fn runtime_port(&self, package: &str) -> i32 {
        crate::extract_app_runtime_meta_local(package).configured_port
    }

    fn available_port(&self, port: i32) -> bool {
        (1024..=65535).contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok()
    }

    fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let mut child = tokio::process::Command::new("systemctl")
                .args(["show", "--property=ActiveState", "--value", "--", unit])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut stdout = child
                .stdout
                .take()
                .context("Application status pipe missing")?
                .take(65);
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                stdout.read_to_end(&mut bytes).await?;
                child.wait().await
            })
            .await;
            let status = match read {
                Ok(Ok(status)) => status,
                error => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    anyhow::bail!("Cannot confirm application service state: {error:?}");
                }
            };
            anyhow::ensure!(
                status.success() && bytes.len() < 65,
                "Cannot inspect application service state"
            );
            let status = String::from_utf8(bytes)?;
            parse_systemd_active_state(&status)
        })
    }

    fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let output = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new("systemctl")
                    .args(["is-active", "--", unit])
                    .output(),
            )
            .await;
            let output = match output {
                Ok(Ok(out)) => out,
                error => {
                    anyhow::bail!("Cannot confirm application service state: {error:?}");
                }
            };
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let status = stdout_str.trim();
            if !status.is_empty() {
                if let Ok(quiesced) = parse_systemd_quiesced_state(status) {
                    return Ok(quiesced);
                }
            }
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stderr_lower = stderr_str.to_ascii_lowercase();
            if status.is_empty()
                && (stderr_lower.contains("not found")
                    || stderr_lower.contains("not-found")
                    || stderr_lower.contains("not loaded")
                    || stderr_lower.contains("could not be found")
                    || stderr_lower.contains("no such file"))
            {
                if let Ok(Ok(show_out)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::process::Command::new("systemctl")
                        .args(["show", "--property=LoadState,ActiveState", "--value", "--", unit])
                        .output(),
                )
                .await
                {
                    if show_out.status.success() {
                        let text = String::from_utf8_lossy(&show_out.stdout);
                        let lines: Vec<&str> = text.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
                        if (lines.get(0) == Some(&"not-found") || text.contains("LoadState=not-found"))
                            && (lines.get(1) == Some(&"inactive") || text.contains("ActiveState=inactive"))
                        {
                            return Ok(true);
                        }
                    }
                }
            }
            parse_systemd_quiesced_state(status)
        })
    }

    fn control<'a>(
        &'a self,
        unit: &'a str,
        action: &'a str,
        identity: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (_, axum::Json(response)) = crate::handle_systemctl(axum::Json(SystemctlRequest {
                action: action.into(),
                service: unit.into(),
                lifecycle_job_id: identity.into(),
            }))
            .await;
            if !response.success {
                if action == "stop" {
                    if let Ok(Ok(output)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::process::Command::new("systemctl")
                            .args(["show", "--property=LoadState,ActiveState,SubState", "--value", "--", unit])
                            .output(),
                    )
                    .await
                    {
                        if output.status.success() {
                            let text = String::from_utf8_lossy(&output.stdout);
                            let lines: Vec<&str> = text.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
                            if lines.len() >= 2
                                && (lines[0] == "not-found" || text.contains("LoadState=not-found"))
                                && (lines[1] == "inactive" || text.contains("ActiveState=inactive"))
                                && (lines.len() < 3 || lines[2] == "dead" || text.contains("SubState=dead"))
                            {
                                return Ok(());
                            }
                        }
                    }
                }
                anyhow::bail!(
                    "Application service {action} failed: {}",
                    response.error
                );
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
            let stream = crate::execute_package_request_stream(request.clone());
            tokio::pin!(stream);
            let mut error = None;
            while let Some(line) = stream.next().await {
                let line = line?;
                if let Some(reason) = line.trim().strip_prefix("__RUNNER_EXIT_ERROR__:") {
                    error = Some(reason.to_owned());
                } else {
                    let line = if line.trim().starts_with(JOB_MARKER)
                        || line.trim().starts_with(RECEIPT_MARKER)
                    {
                        format!("[LOG] {line}")
                    } else {
                        line
                    };
                    let _ = sender.try_send(line);
                }
            }
            if let Some(error) = error {
                anyhow::bail!("{error}");
            }
            Ok(())
        })
    }
}

struct CoordinatedOperation {
    conn: Connection,
    request: PackageRunnerRequest,
    package: Package,
    units: Vec<String>,
    started_at: String,
    _owner: OwnerLease,
}

impl CoordinatedOperation {
    fn admit(
        mut conn: Connection,
        mut request: PackageRunnerRequest,
        package: Package,
        mut units: Vec<String>,
    ) -> Result<Self> {
        anyhow::ensure!(
            request.lifecycle_job_id.is_empty(),
            "Direct lifecycle cannot adopt a foreign identity"
        );
        anyhow::ensure!(
            !request.delete_data || request.action == "remove",
            "Purge requires removal"
        );
        conn.busy_timeout(Duration::from_secs(5))?;
        lifecycle::initialize_schema(&conn)?;
        if request.action != "remove" {
            let candidate_port = if request.app_port > 0 {
                Some(request.app_port)
            } else {
                af_db::load_lifecycle_ingress(&conn, &request.package_id)?
                    .map(|cfg| cfg.listen_port)
                    .filter(|p| *p > 0)
            };
            if let Some(port) = candidate_port {
                let reserved = af_db::list_reserved_ports_excluding(&conn, &request.package_id)?;
                anyhow::ensure!(
                    !reserved.contains(&port),
                    "Listen port {} is already reserved by another application",
                    port
                );
                if let Some(res) = lifecycle::port_resource(port) {
                    if !units.contains(&res) {
                        units.push(res);
                    }
                }
            }
        }
        request.lifecycle_job_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now().to_rfc3339();
        if request.action == "update" {
            let valid = request
                .expected_target_version
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && af_release::lifecycle::validate_target_version(s))
                .is_some();
            if !valid {
                anyhow::bail!("Cannot start update: expected_target_version is missing, empty, or invalid");
            }
        }
        if let Some(ref target) = request.expected_target_version {
            let trimmed = target.trim();
            if trimmed.is_empty() || !af_release::lifecycle::validate_target_version(trimmed) {
                anyhow::bail!(
                    "Cannot start {}: expected_target_version '{}' is invalid",
                    request.action,
                    target
                );
            }
        }
        let owner = lifecycle::admit_job_with_target(
            &mut conn,
            &request.package_id,
            &request.lifecycle_job_id,
            &request.action,
            &started_at,
            &units,
            request.expected_target_version.as_deref(),
        )?;
        Ok(Self {
            conn,
            request,
            package,
            units,
            started_at,
            _owner: owner,
        })
    }

    fn is_installed_on_disk(&self) -> bool {
        let trimmed = self.package.lock_file.trim();
        if trimmed.is_empty() {
            return false;
        }
        let env_cfg = crate::PackageExecutionEnv::default();
        let resolved = match &env_cfg.fs_root {
            Some(root) => root.join(trimmed.trim_start_matches(['/', '\\'])),
            None => Path::new(trimmed).to_path_buf(),
        };
        std::fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.is_file())
    }

    fn resolve_port(&self, backend: &impl LifecycleBackend) -> Result<i32> {
        if self.request.action == "remove" {
            return Ok(0);
        }
        let reserved = af_db::list_reserved_ports_excluding(&self.conn, &self.request.package_id)?;
        let ingress = af_db::load_lifecycle_ingress(&self.conn, &self.request.package_id)?;
        let saved = ingress
            .as_ref()
            .map(|config| config.listen_port)
            .unwrap_or(0);
        if self.request.action == "update" {
            let runtime = backend.runtime_port(&self.request.package_id);
            if runtime > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&runtime),
                    "Native application listen port is invalid"
                );
                anyhow::ensure!(
                    !reserved.contains(&runtime),
                    "Listen port {} is already reserved by another application",
                    runtime
                );
                return Ok(runtime);
            }
            if saved > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&saved),
                    "Persisted listen port is invalid"
                );
                anyhow::ensure!(
                    !reserved.contains(&saved),
                    "Listen port {} is already reserved by another application",
                    saved
                );
                return Ok(saved);
            }
            anyhow::ensure!(
                self.package.default_port <= 0,
                "Existing application listen port is unavailable"
            );
            return Ok(0);
        }
        if self.request.app_port > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&self.request.app_port),
                "Requested listen port is invalid"
            );
            anyhow::ensure!(
                !reserved.contains(&self.request.app_port),
                "Listen port {} is already reserved by another application",
                self.request.app_port
            );
            return Ok(self.request.app_port);
        }
        if saved > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&saved),
                "Persisted listen port is invalid"
            );
            anyhow::ensure!(
                !reserved.contains(&saved),
                "Listen port {} is already reserved by another application",
                saved
            );
            return Ok(saved);
        }
        if self.is_installed_on_disk() {
            let runtime = backend.runtime_port(&self.request.package_id);
            if runtime > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&runtime),
                    "Native application listen port is invalid"
                );
                if !reserved.contains(&runtime) {
                    return Ok(runtime);
                }
            }
        }
        let default = self.package.default_port;
        if default <= 0 {
            return Ok(0);
        }
        if !reserved.contains(&default) && backend.available_port(default) {
            return Ok(default);
        }
        anyhow::ensure!(
            !matches!(self.request.package_id.as_str(), "plex" | "calibreweb"),
            "Fixed application port is unavailable"
        );
        (17000..=19999)
            .find(|port| !reserved.contains(port) && backend.available_port(*port))
            .context("No application listen port is available")
    }

    fn update_units(&self) -> Vec<String> {
        let is_in_place_reinstall = self.request.action == "reinstall"
            || (self.request.action == "install" && self.is_installed_on_disk());
        if (self.request.action != "update" && !is_in_place_reinstall)
            || self.package.service_type == "pm2"
            || matches!(
                self.package.name.as_str(),
                "nextcloud" | "rutorrent" | "organizr" | "maintainerr"
            )
        {
            return Vec::new();
        }
        let root = crate::PackageExecutionEnv::default().fs_root;
        let rclone = root
            .as_deref()
            .unwrap_or(Path::new("/"))
            .join("etc/rclone/rclone.conf");
        let configured = self.units.iter().any(|unit| unit == "rclone-vfs")
            && std::fs::read_to_string(rclone).is_ok_and(|text| {
                text.lines()
                    .any(|line| line.trim().eq_ignore_ascii_case("[remote]"))
            });
        let mut units: Vec<_> = self
            .units
            .iter()
            .filter(|unit| {
                !unit.starts_with("port:")
                    && !matches!(unit.as_str(), "recyclarr" | "scrutiny-collector")
                    && (unit.as_str() != "rclone-vfs" || configured)
            })
            .cloned()
            .collect();
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        units
    }

    fn rollback_quiesce_units(&self) -> Vec<String> {
        if !matches!(self.request.action.as_str(), "install" | "update" | "reinstall")
            || self.package.service_type == "pm2"
            || matches!(
                self.package.name.as_str(),
                "nextcloud" | "rutorrent" | "organizr" | "maintainerr"
            )
        {
            return Vec::new();
        }
        let mut units: Vec<_> = self
            .units
            .iter()
            .filter(|unit| !unit.starts_with("port:"))
            .cloned()
            .collect();
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        units
    }
}

pub(crate) fn parse_systemd_active_state(status: &str) -> Result<bool> {
    match status.trim() {
        "active" => Ok(true),
        "inactive" | "failed" | "activating" | "deactivating" | "reloading" => Ok(false),
        _ => anyhow::bail!("Application service state is unknown"),
    }
}

pub(crate) fn parse_systemd_quiesced_state(status: &str) -> Result<bool> {
    match status.trim() {
        "inactive" | "failed" => Ok(true),
        "active" | "reloading" | "activating" | "deactivating" => Ok(false),
        _ => anyhow::bail!("Application service state is unknown"),
    }
}

pub fn is_incomplete_rollback_error(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("incomplete rollback")
        || lower.contains("incomplete-rollback")
        || lower.contains("incomplete_rollback")
        || lower.contains("incomplete recovery")
        || lower.contains("recovery backup preserved")
        || lower.contains("failed to stop")
}

fn quote_closes_outer_span(after: Option<u8>, include_colon: bool) -> bool {
    match after {
        None => true,
        Some(n) if n.is_ascii_whitespace() => true,
        Some(n) if matches!(n, b'"' | b'\'' | b',' | b'}' | b']' | b';' | b'&') => true,
        Some(b':') if include_colon => true,
        _ => false,
    }
}

/// Scan a `{...}` / `[...]` container. `Some(end)` is the index just past a
/// container that closed on this line (or ran to EOF). `None` means a newline
/// arrived before the opener closed, so the caller must leave the opener in
/// place for the multiline container redactor.
fn consume_balanced_container(bytes: &[u8], start: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let open = bytes[start];
    stack.push(if open == b'{' { b'}' } else { b']' });
    let mut j = start + 1;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\r' || c == b'\n' {
            return None;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        if c == b'\\' {
            j += 1;
            if j < bytes.len() && bytes[j] != b'\r' && bytes[j] != b'\n' {
                j += 1;
            }
            continue;
        }
        if c == b'"' || c == b'\'' {
            quote = Some(c);
            j += 1;
            continue;
        }
        if c == b'{' || c == b'[' {
            stack.push(if c == b'{' { b'}' } else { b']' });
            j += 1;
            continue;
        }
        if c == b'}' || c == b']' {
            if stack.last().copied() == Some(c) {
                stack.pop();
                j += 1;
                if stack.is_empty() {
                    return Some(j);
                }
                continue;
            }
            return None;
        }
        j += 1;
    }
    Some(j)
}

fn consume_plain_quoted(bytes: &[u8], quote_idx: usize) -> usize {
    let q = bytes[quote_idx];
    let mut j = quote_idx + 1;
    let mut bs = 0usize;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'\\' {
            bs += 1;
            j += 1;
            continue;
        }
        if c == q && bs % 2 == 0 {
            return j + 1;
        }
        bs = 0;
        j += 1;
    }
    bytes.len()
}

const REDACTED_URL_SHIELD: &str = "]AFURLKEEP";
const REDACTED_URL_SHIELD_LOWER: &str = "]afurlkeep";

fn shield_redacted_urls(input: &str) -> String {
    // `[REDACTED_URL]` is shaped like a JSON array, so the persisted container
    // redactor would collapse it to `[REDACTED]`. Rewrite it to `[REDACTED]`
    // plus a suffix that starts with `]`, which that scanner treats as a
    // terminator, and put the original marker back at the end.
    static MARKER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\[REDACTED_(?:URL|url)\]").unwrap()
    });
    MARKER_RE.replace_all(input, |captures: &regex::Captures| {
        let marker = captures.get(0).unwrap();
        let suffix = &input[marker.end()..];
        let standalone = match suffix.chars().next() {
            None => true,
            Some(quote @ ('\'' | '"')) => !suffix[quote.len_utf8()..].contains(quote),
            Some(next) => next.is_whitespace() || matches!(next, ',' | '}' | ']' | ';' | '&'),
        };
        if !standalone {
            "[REDACTED]".to_string()
        } else if marker.as_str() == "[REDACTED_URL]" {
            format!("[REDACTED]{REDACTED_URL_SHIELD}")
        } else {
            format!("[REDACTED]{REDACTED_URL_SHIELD_LOWER}")
        }
    }).into_owned()
}

fn unshield_redacted_urls(input: &str) -> String {
    input
        .replace(
            &format!("[REDACTED]{REDACTED_URL_SHIELD}"),
            "[REDACTED_URL]",
        )
        .replace(
            &format!("[REDACTED]{REDACTED_URL_SHIELD_LOWER}"),
            "[REDACTED_url]",
        )
}

fn starts_with_url_shield(s: &str) -> bool {
    s.starts_with(REDACTED_URL_SHIELD) || s.starts_with(REDACTED_URL_SHIELD_LOWER)
}

/// Length of a secret scalar starting at `s`.
///
/// The span is one shell/JSON token made of adjacent unquoted, backslash-escaped,
/// `$'...'` / `$"..."`, quoted, escaped-quoted, and balanced `{...}` / `[...]`
/// segments. `allow_comma_list` keeps internal commas (`password=part1,part2`)
/// while leaving a trailing separator comma in place. A finished `[REDACTED]`
/// marker stays put when the next quote closes an enclosing string, and a glued
/// suffix (`[REDACTED]SENTINEL`, `[REDACTED]"secret"`) is consumed with it.
fn consume_secret_scalar_value(s: &str, allow_comma_list: bool) -> usize {
    if s.starts_with("[REDACTED_URL]") || s.starts_with("[REDACTED_url]") {
        return "[REDACTED_URL]".len();
    }

    let bytes = s.as_bytes();
    let mut i = 0usize;
    if s.starts_with("[REDACTED]") {
        i = "[REDACTED]".len();
        if i >= bytes.len() {
            return i;
        }
        if starts_with_url_shield(&s[i..]) {
            return i;
        }
        let bs0 = bytes[i..].iter().take_while(|b| **b == b'\\').count();
        if i + bs0 < bytes.len() && matches!(bytes[i + bs0], b'"' | b'\'') {
            let after = bytes.get(i + bs0 + 1).copied();
            // `"[REDACTED]",` and `[REDACTED]\" https://...` close an enclosing
            // string. `[REDACTED]"secret"` / `[REDACTED]\"secret\"` do not.
            if quote_closes_outer_span(after, false) && (!after.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, i + bs0, bs0)) {
                return i;
            }
        } else if bytes[i].is_ascii_whitespace()
            || matches!(bytes[i], b';' | b'}' | b']' | b'&')
            || (bytes[i] == b',' && !allow_comma_list)
        {
            return i;
        }
    }

    while i < bytes.len() {
        if bytes[i] == b'\r' || bytes[i] == b'\n' || starts_with_url_shield(&s[i..]) {
            break;
        }

        let mut as_unescaped_quote = false;
        if bytes[i] == b'$' && matches!(bytes.get(i + 1), Some(b'\'' | b'"')) {
            i += 1;
            as_unescaped_quote = true;
        } else if bytes[i] == b'\\' {
            let bs = bytes[i..].iter().take_while(|b| **b == b'\\').count();
            let nxt = bytes.get(i + bs).copied();
            if matches!(nxt, Some(b'"' | b'\'')) {
                let q = nxt.unwrap();
                let q_idx = i + bs;
                let after_q = bytes.get(q_idx + 1).copied();
                if i > 0 && quote_closes_outer_span(after_q, false) && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, q_idx, bs)) {
                    break;
                }
                let mut j = q_idx + 1;
                let mut inner_bs = 0usize;
                let mut stop_outer = false;
                while j < bytes.len() {
                    let c = bytes[j];
                    if c == b'\\' {
                        inner_bs += 1;
                        j += 1;
                        continue;
                    }
                    if c == q {
                        if inner_bs == 0 {
                            i = j;
                            stop_outer = true;
                            break;
                        }
                        if inner_bs == bs || (inner_bs % 2 == 1 && escaped_quote_closes_payload(bytes, j))
                        {
                            i = j + 1;
                            if escaped_quote_closes_payload(bytes, j) {
                                stop_outer = true;
                            }
                            break;
                        }
                    }
                    inner_bs = 0;
                    j += 1;
                }
                if j >= bytes.len() && i < q_idx {
                    i = bytes.len();
                    break;
                }
                if stop_outer {
                    break;
                }
                continue;
            } else if matches!(nxt, Some(b'u' | b'U')) {
                i += bs + 1;
                continue;
            } else if let Some(nc) = nxt {
                if nc != b'\r' && nc != b'\n' {
                    i += bs + 1;
                    continue;
                }
                i += bs;
                break;
            } else {
                i += bs;
                break;
            }
        } else if matches!(bytes[i], b'"' | b'\'') {
            as_unescaped_quote = true;
        }

        if as_unescaped_quote {
            let q = bytes[i];
            if i > 0 {
                let after_q = bytes.get(i + 1).copied();
                if quote_closes_outer_span(after_q, true) && (!after_q.is_some_and(|next| next.is_ascii_whitespace()) || !af_release::lifecycle::has_matching_secret_quote(bytes, i, 0)) {
                    break;
                }
            }
            let end = consume_plain_quoted(bytes, i);
            if end <= i {
                break;
            }
            i = end;
            if i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n') {
                break;
            }
            if i > 0 && bytes.get(i.saturating_sub(1)).copied() != Some(q) && i < bytes.len() {
                break;
            }
            continue;
        }

        if bytes[i] == b'{' || bytes[i] == b'[' {
            match consume_balanced_container(bytes, i) {
                Some(end) if end > i => {
                    i = end;
                    continue;
                }
                _ => break,
            }
        }

        if bytes[i].is_ascii_whitespace() || matches!(bytes[i], b';' | b'}' | b']' | b'&') {
            break;
        }
        if bytes[i] == b',' {
            if !allow_comma_list {
                break;
            }
            let next = bytes.get(i + 1).copied();
            let trailing_separator = match next {
                None => true,
                Some(n) => {
                    n.is_ascii_whitespace()
                        || matches!(n, b';' | b'"' | b'\'' | b'}' | b']' | b'&' | b',')
                }
            };
            if trailing_separator {
                break;
            }
        }
        if bytes[i] < 0x80 {
            i += 1;
        } else {
            let width = s[i..].chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
            i += width;
        }
    }
    i
}

fn escaped_quote_closes_payload(bytes: &[u8], quote_idx: usize) -> bool {
    let next = bytes.get(quote_idx + 1).copied();
    next.is_none()
        || matches!(
            next,
            Some(b'"' | b'\'' | b',' | b'}' | b']' | b'\r' | b'\n' | b' ')
        )
}

fn redact_prefixed_secrets(text: &str, prefix_re: &regex::Regex, allow_comma_list: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while cursor < text.len() {
        let slice = &text[cursor..];
        let Some(mat) = prefix_re.find(slice) else {
            out.push_str(slice);
            break;
        };
        if mat.end() == 0 {
            out.push_str(slice);
            break;
        }
        out.push_str(&slice[..mat.end()]);
        let value_off = cursor + mat.end();
        if af_release::lifecycle::is_complete_redacted_header(&slice[mat.start()..mat.end()], &text[value_off..]) {
            cursor = value_off;
            continue;
        }
        let n = consume_secret_scalar_value(&text[value_off..], allow_comma_list);
        if n == 0 {
            // An unclosed `{` / `[` at the value start belongs to the multiline
            // container redactor. Advancing past the prefix leaves that text intact.
            cursor = value_off;
            continue;
        }
        let consumed = &text[value_off..value_off + n];
        if consumed == "[REDACTED]" || consumed.eq_ignore_ascii_case("[REDACTED_URL]") {
            out.push_str(consumed);
        } else {
            out.push_str("[REDACTED]");
        }
        cursor = value_off + n;
    }
    out
}

fn redact_scalar_cli_and_curl_secrets(text: &str) -> String {
    static CURL_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)(?:^|[^A-Za-z0-9])(?:--user(?:\s+|=)|-u\s*)"#).unwrap()
    });
    static CLI_FLAG_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)(?:^|[^A-Za-z0-9])(--(?:password|passwd|api-key|apikey|cookies|cookie|secret|token|session|webhook|pwd|pass))(?:\s+|=)"#,
        )
        .unwrap()
    });
    let with_curl = redact_prefixed_secrets(text, &CURL_PREFIX_RE, true);
    let with_kv = redact_prefixed_secrets(&with_curl, &af_release::lifecycle::SENSITIVE_ASSIGNMENT_PREFIX_RE, true);
    redact_prefixed_secrets(&with_kv, &CLI_FLAG_PREFIX_RE, true)
}

fn find_closing_header_quote(val: &str, pre: &str) -> Option<usize> {
    af_release::lifecycle::find_closing_header_quote(val, pre)
}

pub fn sanitize_lifecycle_field(raw: &str) -> String {
    let normalized = af_release::lifecycle::normalize_unicode_escaped_sensitive_keys(raw);
    let shielded = shield_redacted_urls(&normalized);
    let raw = shielded.as_str();
    static HTTP_HEADER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?im)(?P<pre>\\*["'])?\b(?P<hdr>Set-Cookie|Cookie|Proxy-Authorization|X-Api-Key|X-Auth-Token|Authorization)\s*:\s*(?P<val>[^\r\n]+)"#
        ).unwrap()
    });
    static SENSITIVE_JSON_NESTED_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)("[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|bearer|cookie|session|webhook|passphrase|rclone_pass|jwt_secret)[\w.-]*"\s*:\s*)(\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#
        ).unwrap()
    });
    static SENSITIVE_RAW_NESTED_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?i)(["']?[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|bearer|cookie|session|webhook|passphrase|rclone_pass|jwt_secret)[\w.-]*["']?\s*[:=]\s*)(\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#
        ).unwrap()
    });
    static BEARER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"#).unwrap()
    });
    static BASIC_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r#"(?i)\bBasic\s+[A-Za-z0-9+/=]+"#).unwrap()
    });

    let sanitize_http_headers = |text: &str| -> String {
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        while cursor < text.len() {
            let slice = &text[cursor..];
            let Some(caps) = HTTP_HEADER_RE.captures(slice) else {
                out.push_str(slice);
                break;
            };
            let full = caps.get(0).unwrap();
            let pre = caps.name("pre").map(|m| m.as_str()).unwrap_or("");
            let hdr = caps.name("hdr").map(|m| m.as_str()).unwrap_or("");
            let val_match = caps.name("val").unwrap();
            let val = val_match.as_str();
            out.push_str(&slice[..full.start()]);
            if !pre.is_empty() {
                if let Some(close_idx) = find_closing_header_quote(val, pre) {
                    let close_len = if val[close_idx..].starts_with(pre) {
                        pre.len()
                    } else {
                        1
                    };
                    out.push_str(&format!(
                        "{pre}{hdr}: [REDACTED]{}",
                        &val[close_idx..close_idx + close_len]
                    ));
                    cursor += val_match.start() + close_idx + close_len;
                    continue;
                }
                out.push_str(&format!("{pre}{hdr}: [REDACTED]"));
            } else {
                out.push_str(&format!("{hdr}: [REDACTED]"));
            }
            cursor += full.end();
        }
        out
    };

    let sanitize_nested = |text: &str| -> String {
        let s = SENSITIVE_JSON_NESTED_RE.replace_all(text, |caps: &regex::Captures| {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if redacted_container_value(val) {
                format!("{prefix}{val}")
            } else {
                format!("{prefix}\"[REDACTED]\"")
            }
        });
        SENSITIVE_RAW_NESTED_RE.replace_all(&s, |caps: &regex::Captures| {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if redacted_container_value(val) {
                format!("{prefix}{val}")
            } else {
                format!("{prefix}[REDACTED]")
            }
        }).into_owned()
    };

    let s_headers = sanitize_http_headers(raw);
    // The local scanner runs first so a shell escape (`\ `, `\;`, `$'...'`,
    // concatenated quotes) is consumed as one token. The persisted scanner
    // stops at the first unescaped space or separator and would otherwise
    // leave the remainder of that token behind. It still runs next so nested
    // containers and URL credentials are redacted, then the local scanner
    // runs again for any leaked `[REDACTED]...` suffix.
    let s_local = redact_scalar_cli_and_curl_secrets(&s_headers);
    let s_persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(&s_local);
    let s3 = redact_scalar_cli_and_curl_secrets(&s_persisted);
    let s3_nested = sanitize_nested(&s3);
    let s4 = redact_scalar_cli_and_curl_secrets(&s3_nested);
    let s5 = BEARER_RE.replace_all(&s4, "Bearer [REDACTED]");
    let s6 = BASIC_RE.replace_all(&s5, "Basic [REDACTED]");
    unshield_redacted_urls(&sanitize_http_headers(&s6))
}

fn redacted_container_value(val: &str) -> bool {
    matches!(
        val,
        "[REDACTED]"
            | "\"[REDACTED]\""
            | "[REDACTED_URL]"
            | "[REDACTED_url]"
            | "\"[REDACTED_URL]\""
            | "\"[REDACTED_url]\""
    ) || val.eq_ignore_ascii_case("[REDACTED_URL]")
        || val.eq_ignore_ascii_case("\"[REDACTED_URL]\"")
}

impl CoordinatedOperation {
    fn effective_fs_root(&self) -> Option<std::path::PathBuf> {
        if let Some(root) = crate::PackageExecutionEnv::default().fs_root {
            return Some(root);
        }
        self.conn.path().map(Path::new).and_then(|p| {
            p.ancestors().find_map(|anc| {
                let rel = p.strip_prefix(anc).ok()?;
                if anc != Path::new("/")
                    && (rel == Path::new("var/lib/aetherflow/aetherflow.sqlite")
                        || rel == Path::new("var/lib/aetherflow/aetherflow.db")
                        || rel == Path::new("etc/aetherflow/aetherflow.db"))
                {
                    Some(anc.to_path_buf())
                } else {
                    None
                }
            })
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn restore_and_restart_units(
        backend: &impl LifecycleBackend,
        lifecycle_job_id: &str,
        package_id: &str,
        quiesce_units: &[String],
        restart_units: &[String],
        receipt_snapshots: &[FileSnapshot],
        blueprint_snapshots: &[FileSnapshot],
        receipt_restore_error: &mut Option<String>,
        restart_failures: &mut Vec<String>,
        incomplete_rollback: bool,
        quiesce_first: bool,
    ) {
        Self::restore_and_restart_units_with_runtime(
            backend,
            lifecycle_job_id,
            package_id,
            quiesce_units,
            restart_units,
            receipt_snapshots,
            blueprint_snapshots,
            receipt_restore_error,
            restart_failures,
            incomplete_rollback,
            quiesce_first,
            None,
        )
        .await
    }

    pub(crate) async fn restore_and_restart_units_with_runtime(
        backend: &impl LifecycleBackend,
        lifecycle_job_id: &str,
        package_id: &str,
        quiesce_units: &[String],
        restart_units: &[String],
        receipt_snapshots: &[FileSnapshot],
        blueprint_snapshots: &[FileSnapshot],
        receipt_restore_error: &mut Option<String>,
        restart_failures: &mut Vec<String>,
        incomplete_rollback: bool,
        quiesce_first: bool,
        mut runtime_snapshot: Option<&mut PackageRuntimeSnapshot>,
    ) {
        if incomplete_rollback {
            if let Some(snapshot) = runtime_snapshot.as_deref_mut() {
                snapshot.preserve_on_drop = true;
            }
        }
        let mut quiesce_failed = false;
        if quiesce_first {
            let mut seen = std::collections::HashSet::new();
            for unit in quiesce_units.iter().chain(restart_units.iter()) {
                if !seen.insert(unit.as_str()) {
                    continue;
                }
                match backend.control(unit, "stop", lifecycle_job_id).await {
                    Ok(()) => match backend.quiescent(unit).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::error!(unit, "Unit is still active after stop before restoration");
                            quiesce_failed = true;
                            restart_failures.push(format!("{unit}: still active after stop before restoration"));
                        }
                        Err(error) => {
                            tracing::error!(unit, error = %error, "Failed to verify quiescence before restoration");
                            quiesce_failed = true;
                            restart_failures.push(format!("{unit}: failed to verify quiescence before restoration: {error}"));
                        }
                    },
                    Err(error) => {
                        let err_str = error.to_string();
                        let err_lower = err_str.to_ascii_lowercase();
                        let is_absent_err = err_lower.contains("not loaded")
                            || err_lower.contains("not-found")
                            || err_lower.contains("no such file")
                            || err_lower.contains("exit status: 5")
                            || err_lower.contains("exit code 5");
                        if is_absent_err && matches!(backend.quiescent(unit).await, Ok(true)) {
                            tracing::info!(unit, "Absent unit not loaded during stop before restoration, confirmed quiescent");
                        } else {
                            tracing::error!(unit, error = %error, "Failed to quiesce unit before state restoration");
                            quiesce_failed = true;
                            restart_failures.push(format!("{unit}: stop before restoration failed: {error}"));
                        }
                    }
                }
            }
        }

        if quiesce_failed {
            if let Some(snapshot) = runtime_snapshot.as_deref_mut() {
                snapshot.preserve_on_drop = true;
            }
            let msg = "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)".to_string();
            if let Some(ref mut existing) = receipt_restore_error {
                existing.push_str(&format!("; {}", msg));
            } else {
                *receipt_restore_error = Some(msg);
            }
            return;
        }

        let mut snapshot_restore_failed = false;
        if let Err(restore_err) = rollback_operation_state_with_runtime(
            receipt_snapshots,
            blueprint_snapshots,
            if incomplete_rollback { None } else { runtime_snapshot },
        ) {
            tracing::error!(
                package = %package_id,
                error = %restore_err,
                "Failed to restore candidate receipts, blueprints, and package runtime"
            );
            snapshot_restore_failed = true;
            if let Some(ref mut existing) = receipt_restore_error {
                existing.push_str(&format!("; {}", restore_err));
            } else {
                *receipt_restore_error = Some(restore_err);
            }
        }

        if incomplete_rollback || snapshot_restore_failed {
            if !restart_units.is_empty() {
                if incomplete_rollback {
                    tracing::error!(
                        package = %package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push("Refusing to restart pre-stopped service after incomplete rollback".to_string());
                }
                if snapshot_restore_failed {
                    tracing::error!(
                        package = %package_id,
                        "Refusing to restart pre-stopped service after snapshot restoration failure"
                    );
                    restart_failures.push("Refusing to restart pre-stopped service after snapshot restoration failure".to_string());
                }
            }
        } else {
            restart_failures.clear();
            for unit in restart_units.iter().rev() {
                if let Err(error) = backend
                    .control(unit, "start", lifecycle_job_id)
                    .await
                {
                    tracing::error!(unit, error = %error, "Application service restoration failed");
                    restart_failures.push(format!("Application service start for unit '{unit}' failed: {error}"));
                } else {
                    match backend.active(unit).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let msg = format!("Application service unit '{unit}' is not active after start");
                            tracing::error!(unit, "{}", msg);
                            restart_failures.push(msg);
                        }
                        Err(error) => {
                            let msg = format!("Cannot confirm application service state for unit '{unit}' after start: {error}");
                            tracing::error!(unit, error = %error, "Cannot confirm application service state");
                            restart_failures.push(msg);
                        }
                    }
                }
            }
        }
    }

    async fn execute(
        &mut self,
        backend: &impl LifecycleBackend,
        sender: &mpsc::Sender<String>,
    ) -> Result<LifecycleReceipt> {
        let rollback_quiesce_units = self.rollback_quiesce_units();
        let mut pre_op_env = crate::PackageExecutionEnv::default();
        if pre_op_env.fs_root.is_none() {
            pre_op_env.fs_root = self.effective_fs_root();
        }
        let receipt_snapshots = match snapshot_candidate_receipts_with_env(&self.request.package_id, &pre_op_env) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!("Failed to snapshot candidate receipts before execution: {}", snap_err);
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight candidate receipt snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self.request.expected_target_version.as_deref().map(sanitize_lifecycle_field);
                let mut finish_res = Ok(());
                for _ in 0..3 {
                    finish_res = lifecycle::finish_job_with_diagnostics(
                        &self.conn,
                        &self.request.package_id,
                        &self.request.lifecycle_job_id,
                        &self.request.action,
                        false,
                        lifecycle::LifecycleJobDiagnostics {
                            failure_category: "preflight",
                            failed_stage: Some("preflight_receipt_snapshot"),
                            exit_code: Some(1),
                            sanitized_summary: Some(&sanitized_err),
                            expected_target_version: sanitized_expected.as_deref(),
                            ..Default::default()
                        },
                    );
                    if finish_res.is_ok() {
                        break;
                    }
                }
                if let Err(ref finish_err) = finish_res {
                    anyhow::bail!("{err_msg}; completion error: {finish_err}");
                }
                anyhow::bail!("{err_msg}");
            }
        };
        let blueprint_snapshots = match snapshot_blueprint_targets(&self.request.package_id, &pre_op_env) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!("Failed to snapshot blueprint targets before execution: {}", snap_err);
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight blueprint target snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self.request.expected_target_version.as_deref().map(sanitize_lifecycle_field);
                let mut finish_res = Ok(());
                for _ in 0..3 {
                    finish_res = lifecycle::finish_job_with_diagnostics(
                        &self.conn,
                        &self.request.package_id,
                        &self.request.lifecycle_job_id,
                        &self.request.action,
                        false,
                        lifecycle::LifecycleJobDiagnostics {
                            failure_category: "preflight",
                            failed_stage: Some("preflight_receipt_snapshot"),
                            exit_code: Some(1),
                            sanitized_summary: Some(&sanitized_err),
                            expected_target_version: sanitized_expected.as_deref(),
                            ..Default::default()
                        },
                    );
                    if finish_res.is_ok() {
                        break;
                    }
                }
                if let Err(ref finish_err) = finish_res {
                    anyhow::bail!("{err_msg}; completion error: {finish_err}");
                }
                anyhow::bail!("{err_msg}");
            }
        };

        let mut stopped = Vec::new();
        let mut failure = "preparation";
        let mut runtime_snapshot: Option<PackageRuntimeSnapshot> = None;
        let all_controllable_units = self.update_units();
        let should_quiesce_oneshots_pre_op = self.is_installed_on_disk()
            || matches!(self.request.action.as_str(), "update" | "reinstall");
        let mut execution: Result<()> = async {
            self.request.app_port = self.resolve_port(backend)?;
            if let Some(res) = lifecycle::port_resource(self.request.app_port) {
                if !self.units.contains(&res) {
                    self.units.push(res);
                    let normalized: Vec<_> =
                        lifecycle::package_resources(&self.request.package_id, &self.units)
                            .into_iter()
                            .collect();
                    self.conn.execute(
                        "UPDATE package_lifecycle_jobs SET service_units=?1 WHERE package_id=?2 AND job_id=?3",
                        rusqlite::params![
                            serde_json::to_string(&normalized)?,
                            self.request.package_id,
                            self.request.lifecycle_job_id,
                        ],
                    )?;
                }
            }
            for unit in &all_controllable_units {
                if !backend.quiescent(unit).await? {
                    stopped.push(unit.clone());
                    backend
                        .control(unit, "stop", &self.request.lifecycle_job_id)
                        .await?;
                }
            }
            if should_quiesce_oneshots_pre_op {
                for unit in &rollback_quiesce_units {
                    if matches!(unit.as_str(), "recyclarr" | "scrutiny-collector")
                        && !backend.quiescent(unit).await?
                    {
                        backend
                            .control(unit, "stop", &self.request.lifecycle_job_id)
                            .await?;
                    }
                }
            }
            if matches!(self.request.action.as_str(), "install" | "reinstall" | "update") {
                runtime_snapshot = Some(
                    PackageRuntimeSnapshot::capture(&self.request.package_id, &rollback_quiesce_units, &pre_op_env, false)
                        .map_err(|e| anyhow::anyhow!("Failed to snapshot package runtime before execution: {e}"))?,
                );
            }
            failure = "installer";
            backend.script(&self.request, sender).await?;
            Ok(())
        }
        .await;
        let incomplete_rollback = execution
            .as_ref()
            .err()
            .is_some_and(|err| is_incomplete_rollback_error(&err.to_string()));
        let mut restart_failures: Vec<String> = Vec::new();
        let mut restore_failed;
        let mut receipt_restore_error: Option<String> = None;
        let lifecycle_job_id = self.request.lifecycle_job_id.clone();
        let package_id = self.request.package_id.clone();

        if execution.is_err() {
            let quiesce_units = if failure == "preparation" {
                &stopped
            } else {
                &rollback_quiesce_units
            };
            Self::restore_and_restart_units_with_runtime(
                backend,
                &lifecycle_job_id,
                &package_id,
                quiesce_units,
                &stopped,
                &receipt_snapshots,
                &blueprint_snapshots,
                &mut receipt_restore_error,
                &mut restart_failures,
                incomplete_rollback,
                true,
                runtime_snapshot.as_mut(),
            )
            .await;
            restore_failed = !restart_failures.is_empty();
        } else {
            if incomplete_rollback {
                if !stopped.is_empty() {
                    tracing::error!(
                        package = %self.request.package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push("Refusing to restart pre-stopped service after incomplete rollback".to_string());
                }
            } else {
                for unit in stopped.iter().rev() {
                    if let Err(error) = backend
                        .control(unit, "start", &self.request.lifecycle_job_id)
                        .await
                    {
                        tracing::error!(unit, error = %error, "Application service restoration failed");
                        restart_failures.push(format!("Application service start for unit '{unit}' failed: {error}"));
                    } else {
                        match backend.active(unit).await {
                            Ok(true) => {}
                            Ok(false) => {
                                let msg = format!("Application service unit '{unit}' is not active after start");
                                tracing::error!(unit, "{}", msg);
                                restart_failures.push(msg);
                            }
                            Err(error) => {
                                let msg = format!("Cannot confirm application service state for unit '{unit}' after start: {error}");
                                tracing::error!(unit, error = %error, "Cannot confirm application service state");
                                restart_failures.push(msg);
                            }
                        }
                    }
                }
            }
            restore_failed = !restart_failures.is_empty();
            if restore_failed {
                let initial_failures = restart_failures.clone();
                let mut restore_restart_failures = Vec::new();
                Self::restore_and_restart_units_with_runtime(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restore_restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.as_mut(),
                )
                .await;
                restart_failures = initial_failures;
                restart_failures.extend(restore_restart_failures);
                restore_failed = true;
            }
        }

        // Target certification BEFORE post-install ingress synchronization & configuration commit
        let mut target_match_failed = false;
        let mut achieved_ver: Option<String> = None;
        if execution.is_ok() && !restore_failed && self.request.expected_target_version.is_some() && self.request.action != "remove" {
            let target = self.request.expected_target_version.as_deref().unwrap();
            let mut env_cfg = crate::PackageExecutionEnv::default();
            if env_cfg.fs_root.is_none() {
                env_cfg.fs_root = self.effective_fs_root();
            }
            achieved_ver = resolve_verified_installed_version(&self.request.package_id, &env_cfg);
            let matches = achieved_ver
                .as_deref()
                .map(|ach| af_release::lifecycle::versions_match_target(ach, target))
                .unwrap_or(false);
            if !matches {
                target_match_failed = true;
                failure = "target_verification";
                #[cfg(test)]
                {
                    if let Some(hook) = TEST_CERTIFY_FAIL_HOOK.lock().unwrap().as_ref() {
                        hook(&package_id);
                    }
                }
                // Rollback / restore previous candidate receipts and blueprints while quiesced so uncertified version is not retained
                Self::restore_and_restart_units_with_runtime(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.as_mut(),
                )
                .await;
                if !restart_failures.is_empty() {
                    restore_failed = true;
                }
            }
        }

        // Re-check service units right after target certification to ensure none exited during certification
        if execution.is_ok() && !restore_failed && !target_match_failed && !incomplete_rollback {
            for unit in &stopped {
                match backend.active(unit).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let msg = format!("Application service unit '{unit}' exited or became inactive during certification");
                        tracing::error!(unit, "{}", msg);
                        restart_failures.push(msg);
                    }
                    Err(error) => {
                        let msg = format!("Cannot confirm application service state for unit '{unit}' after certification: {error}");
                        tracing::error!(unit, error = %error, "Cannot confirm application service state");
                        restart_failures.push(msg);
                    }
                }
            }
            if !restart_failures.is_empty() {
                restore_failed = true;
                let primary_failures = restart_failures.clone();
                let mut restore_restart_failures = Vec::new();
                Self::restore_and_restart_units_with_runtime(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restore_restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.as_mut(),
                )
                .await;
                restart_failures = primary_failures;
                restart_failures.extend(restore_restart_failures);
            }
        }

        // Post-install ingress synchronization & blueprint app config only AFTER certification succeeds
        if execution.is_ok() && !restore_failed && !target_match_failed {
            let post_commit: Result<()> = async {
                failure = if self.request.action == "remove" {
                    "retention"
                } else {
                    "configuration"
                };
                if self.request.action != "remove" && (1024..=65535).contains(&self.request.app_port) {
                    let fs_root = self.effective_fs_root();
                    crate::package_executor::try_apply_runner_blueprint_app_config(
                        fs_root.as_deref(),
                        &self.request.package_id,
                        self.request.app_port,
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                let base: Option<String> = self
                    .conn
                    .query_row(
                        "SELECT COALESCE(base_domain,'') FROM settings WHERE id=1",
                        [],
                        |row| row.get(0),
                    )
                    .optional()?;
                af_db::synchronize_lifecycle_ingress(
                    &mut self.conn,
                    &self.request.package_id,
                    &self.request.action,
                    &self.request.lifecycle_job_id,
                    self.request.app_port,
                    self.request.delete_data,
                    base.as_deref().unwrap_or(""),
                )?;
                Ok(())
            }
            .await;
            if let Err(error) = post_commit {
                execution = Err(error);
                Self::restore_and_restart_units_with_runtime(
                    backend,
                    &lifecycle_job_id,
                    &package_id,
                    &rollback_quiesce_units,
                    &stopped,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    &mut receipt_restore_error,
                    &mut restart_failures,
                    incomplete_rollback,
                    true,
                    runtime_snapshot.as_mut(),
                )
                .await;
                if !restart_failures.is_empty() {
                    restore_failed = true;
                }
            }
        }

        let success = execution.is_ok() && !restore_failed && !target_match_failed;
        if let Err(error) = &execution {
            tracing::error!(package = %self.request.package_id, error = %error, "Required lifecycle phase failed");
        }
        if restore_failed {
            failure = if execution.is_err() && failure == "configuration" {
                "configuration_and_service_restore"
            } else if incomplete_rollback || execution.is_ok() {
                "service_restore"
            } else {
                failure
            };
        } else if target_match_failed {
            failure = "target_verification";
        }
        let diag_summary = if target_match_failed {
            let mut msg = format!(
                "Target certification failed after installer execution (runtime state may be partially committed): expected {}, achieved {}",
                self.request.expected_target_version.as_deref().unwrap_or(""),
                achieved_ver.as_deref().unwrap_or("none")
            );
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else if !restart_failures.is_empty() {
            let mut msg = format!(
                "Application service restoration failed: {}",
                restart_failures.join("; ")
            );
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else if let Err(ref exec_err) = execution {
            let mut msg = format!("Execution failed in {} phase: {}", failure, exec_err);
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            Some(msg)
        } else if let Some(ref r_err) = receipt_restore_error {
            Some(format!("Receipt restoration error: {}", r_err))
        } else {
            None
        };
        let sanitized_diag_summary = diag_summary.as_deref().map(sanitize_lifecycle_field);
        let sanitized_expected = self.request.expected_target_version.as_deref().map(sanitize_lifecycle_field);
        let sanitized_achieved = achieved_ver.as_deref().map(sanitize_lifecycle_field);
        lifecycle::finish_job_with_diagnostics(
            &self.conn,
            &self.request.package_id,
            &self.request.lifecycle_job_id,
            &self.request.action,
            success,
            lifecycle::LifecycleJobDiagnostics {
                failure_category: failure,
                failed_stage: if target_match_failed {
                    Some("target_certification_after_install_commit")
                } else if restore_failed {
                    Some("service_restoration")
                } else if execution.is_err() {
                    Some(failure)
                } else if receipt_restore_error.is_some() {
                    Some("rollback")
                } else {
                    None
                },
                exit_code: if target_match_failed
                    || restore_failed
                    || execution.is_err()
                    || receipt_restore_error.is_some()
                {
                    Some(1)
                } else {
                    None
                },
                sanitized_summary: sanitized_diag_summary.as_deref().or(if target_match_failed {
                    Some("Post-execution installed version did not match expected target")
                } else if restore_failed {
                    Some("Service restart verification failed")
                } else if execution.is_err() {
                    Some("Lifecycle execution failed")
                } else if receipt_restore_error.is_some() {
                    Some("Receipt restoration failed")
                } else {
                    None
                }),
                expected_target_version: sanitized_expected.as_deref(),
                achieved_version: sanitized_achieved.as_deref(),
                ..Default::default()
            },
        )?;
        let finished_at = self.conn.query_row(
            "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
            rusqlite::params![self.request.package_id, self.request.lifecycle_job_id],
            |row| row.get(0),
        )?;
        Ok(LifecycleReceipt {
            job_id: self.request.lifecycle_job_id.clone(),
            package_id: self.request.package_id.clone(),
            action: self.request.action.clone(),
            status: if success { "completed" } else { "failed" }.into(),
            started_at: self.started_at.clone(),
            finished_at,
            app_port: self.request.app_port,
        })
    }
}

const MERGED_USR_ALIASES: &[&str] = &["bin", "sbin", "lib", "lib32", "lib64", "libx32"];

/// Debian/Ubuntu merged-`/usr` aliases (`<root>/lib` -> `usr/lib`) are real
/// directory ancestors. Any other symlink target stays prohibited.
fn is_trusted_merged_usr_symlink(dir_path: &Path, fs_root: Option<&Path>) -> bool {
    let base_root = fs_root.unwrap_or_else(|| Path::new("/"));
    let alias = MERGED_USR_ALIASES.iter().copied().find(|alias| {
        dir_path.components().eq(base_root.join(alias).components())
    });
    let Some(alias) = alias else {
        return false;
    };
    let Ok(meta) = std::fs::symlink_metadata(dir_path) else {
        return false;
    };
    if !meta.file_type().is_symlink() {
        return false;
    }
    let Ok(target) = std::fs::read_link(dir_path) else {
        return false;
    };
    let target_str = target.to_string_lossy();
    let expected_rel = format!("usr/{alias}");
    let expected_abs = format!("/usr/{alias}");
    if target_str != expected_rel && target_str != expected_abs {
        return false;
    }
    let usr_alias = base_root.join("usr").join(alias);
    match std::fs::symlink_metadata(&usr_alias) {
        Ok(usr_meta) => usr_meta.is_dir() && !usr_meta.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn verify_no_symlink_ancestors_with_root(path: &Path, fs_root: Option<&Path>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component);
            if current.as_os_str() == "/" {
                continue;
            }
            match std::fs::symlink_metadata(&current) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        if is_trusted_merged_usr_symlink(&current, fs_root) {
                            continue;
                        }
                        return Err(format!(
                            "Ancestor directory {} is a symlink (symlink traversal prohibited)",
                            current.display()
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    break;
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to check ancestor directory {}: {}",
                        current.display(),
                        e
                    ));
                }
            }
        }
    }
    Ok(())
}

fn verify_no_symlink_ancestors(path: &Path) -> Result<(), String> {
    verify_no_symlink_ancestors_with_root(path, None)
}

pub fn candidate_version_marker_paths(package_id: &str) -> Result<Vec<PathBuf>, String> {
    candidate_version_marker_paths_with_env(package_id, &crate::PackageExecutionEnv::default())
}

pub fn candidate_version_marker_paths_with_env(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    if let Some(recipe) = crate::package_executor::get_declarative_recipe(package_id) {
        if let Some(vf) = crate::package_executor::recipe_version_file_logical_path(&recipe) {
            let p = env_cfg
                .resolve_path(&vf)
                .map_err(|e| format!("Failed to resolve version file logical path {}: {}", vf, e))?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && package_id.eq_ignore_ascii_case("filebot") {
            let candidate = "/opt/filebot-node/.af-version";
            let p = env_cfg
                .resolve_path(candidate)
                .map_err(|e| format!("Failed to resolve candidate receipt path {}: {}", candidate, e))?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [package_id, &package_id.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = env_cfg
                .resolve_path(&candidate)
                .map_err(|e| format!("Failed to resolve candidate receipt path {}: {}", candidate, e))?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if package_id.eq_ignore_ascii_case("piped") {
        for extra in ["/opt/piped/.af-components.json", "/var/lib/piped/.af-components.json"] {
            let p = env_cfg
                .resolve_path(extra)
                .map_err(|e| format!("Failed to resolve extra receipt path {}: {}", extra, e))?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFileState {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub type SnapshotFileEntry = SnapshotFileState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub state: Option<SnapshotFileState>,
}

impl FileSnapshot {
    pub fn absent(path: PathBuf) -> Self {
        Self { path, state: None }
    }

    pub fn present(path: PathBuf, bytes: Vec<u8>, mode: u32, uid: u32, gid: u32) -> Self {
        Self {
            path,
            state: Some(SnapshotFileState {
                bytes,
                mode,
                uid,
                gid,
            }),
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        self.state.as_ref().map(|s| s.bytes.as_slice())
    }
}

impl From<(PathBuf, Option<SnapshotFileState>)> for FileSnapshot {
    fn from((path, state): (PathBuf, Option<SnapshotFileState>)) -> Self {
        Self { path, state }
    }
}

impl From<(PathBuf, Option<Vec<u8>>)> for FileSnapshot {
    fn from((path, opt_bytes): (PathBuf, Option<Vec<u8>>)) -> Self {
        Self {
            path,
            state: opt_bytes.map(|bytes| SnapshotFileState {
                bytes,
                mode: 0o644,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            }),
        }
    }
}

pub fn snapshot_blueprint_targets(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<FileSnapshot>, String> {
    let mut snaps = Vec::new();
    let paths = crate::package_executor::collect_blueprint_target_paths(package_id, env_cfg.fs_root.as_deref());
    for path in paths {
        verify_no_symlink_ancestors_with_root(&path, env_cfg.fs_root.as_deref())?;
        let state = read_file_entry_bounded_nofollow(&path, 1024 * 1024)?;
        snaps.push(FileSnapshot { path, state });
    }
    Ok(snaps)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTargetKind {
    Directory,
    FileOrSymlink,
}

#[derive(Debug)]
pub enum RuntimeSnapshotEntry {
    Absent {
        target_path: PathBuf,
        kind: RuntimeTargetKind,
    },
    File {
        target_path: PathBuf,
        backup_path: PathBuf,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Symlink {
        target_path: PathBuf,
        link_target: PathBuf,
    },
    Directory {
        target_path: PathBuf,
        backup_path: PathBuf,
        mode: u32,
        uid: u32,
        gid: u32,
    },
}

#[derive(Debug)]
pub struct PackageRuntimeSnapshot {
    pub package_id: String,
    pub backup_root: PathBuf,
    pub entries: Vec<RuntimeSnapshotEntry>,
    pub embedded_receipts: Vec<FileSnapshot>,
    pub preserve_on_drop: bool,
    pub fs_root: Option<PathBuf>,
}

fn force_remove_backup_tree(path: &Path) {
    if std::fs::remove_dir_all(path).is_ok() {
        return;
    }
    #[cfg(unix)]
    {
        fn grant_owner_rwx(dir: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::symlink_metadata(dir) else {
                return;
            };
            if meta.file_type().is_dir() {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        grant_owner_rwx(&entry.path());
                    }
                }
            }
        }
        grant_owner_rwx(path);
        let _ = std::fs::remove_dir_all(path);
    }
}

impl Drop for PackageRuntimeSnapshot {
    fn drop(&mut self) {
        if !self.preserve_on_drop {
            force_remove_backup_tree(&self.backup_root);
        }
    }
}

pub fn is_receipt_file_name(name: &str) -> bool {
    matches!(name, ".af-version" | ".af-components.json")
}

fn is_protected_root(path: &Path) -> bool {
    let p = path.to_string_lossy();
    let norm = p.trim_end_matches('/');
    if matches!(
        norm,
        "" | "/"
            | "/opt"
            | "/var"
            | "/var/lib"
            | "/var/www"
            | "/var/www/html"
            | "/etc"
            | "/usr"
            | "/usr/bin"
            | "/usr/lib"
            | "/lib"
            | "/lib/systemd"
            | "/lib/systemd/system"
            | "/usr/lib/systemd"
            | "/usr/lib/systemd/system"
            | "/usr/share"
            | "/usr/sbin"
            | "/usr/libexec"
            | "/usr/local"
            | "/usr/local/bin"
            | "/usr/local/sbin"
            | "/usr/local/share"
            | "/usr/local/lib"
            | "/sbin"
            | "/etc/systemd"
            | "/etc/systemd/system"
            | "/etc/default"
            | "/install"
    ) {
        return true;
    }
    let comp_count = path.components().count();
    if comp_count <= 1 {
        return true;
    }
    false
}

fn copy_range_sparse(
    src_file: &mut std::fs::File,
    dst_file: &mut std::fs::File,
    start: u64,
    end: u64,
) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    src_file.seek(SeekFrom::Start(start))?;
    dst_file.seek(SeekFrom::Start(start))?;
    let mut remaining = end.saturating_sub(start);
    let mut buf = [0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = src_file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().all(|&b| b == 0) {
            dst_file.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst_file.write_all(&buf[..n])?;
        }
        remaining = remaining.saturating_sub(n as u64);
    }
    dst_file.flush()?;
    Ok(())
}

fn copy_file_preserving_sparse_and_meta(
    src: &Path,
    dst: &Path,
    meta: &std::fs::Metadata,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(parent) = dst.parent() {
            if let Ok(c_parent) = std::ffi::CString::new(parent.as_os_str().as_bytes()) {
                let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::statvfs(c_parent.as_ptr(), &mut vfs) } == 0 {
                    let needed_bytes = meta.blocks().saturating_mul(512);
                    let avail_bytes = (vfs.f_bavail as u64).saturating_mul(vfs.f_frsize as u64);
                    if avail_bytes > 0 && needed_bytes > avail_bytes {
                        return Err(format!(
                            "Insufficient disk space to snapshot {}: need {} bytes, available {} bytes",
                            src.display(),
                            needed_bytes,
                            avail_bytes
                        ));
                    }
                }
            }
        }
    }

    #[cfg(test)]
    {
        if std::env::var("AETHERFLOW_TEST_FORCE_DISK_FULL").is_ok() {
            return Err(format!(
                "Insufficient disk space to snapshot {}: need 1000000000 bytes, available 0 bytes",
                src.display()
            ));
        }
    }

    let mut dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| format!("Failed to create {}: {}", dst.display(), e))?;

    let mut src_file = match std::fs::File::open(src) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            return Err(format!("Failed to open {}: {}", src.display(), e));
        }
    };

    #[cfg(target_os = "linux")]
    let reflink_ok = {
        use std::os::unix::io::AsRawFd;
        let src_fd = src_file.as_raw_fd();
        let dst_fd = dst_file.as_raw_fd();
        unsafe { libc::ioctl(dst_fd, 0x40049409 as libc::c_ulong, src_fd) == 0 }
    };
    #[cfg(not(target_os = "linux"))]
    let reflink_ok = false;

    if !reflink_ok {
        let len = meta.len();
        if let Err(e) = dst_file.set_len(len) {
            let _ = std::fs::remove_file(dst);
            return Err(format!("Failed to set len on {}: {}", dst.display(), e));
        }

        #[cfg(target_os = "linux")]
        if len > 0 {
            use std::os::unix::io::AsRawFd;
            let src_fd = src_file.as_raw_fd();
            let mut offset: u64 = 0;
            let mut seek_data_supported = true;

            while offset < len {
                let data_start = unsafe { libc::lseek(src_fd, offset as libc::off_t, libc::SEEK_DATA) };
                if data_start < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENXIO) {
                        break;
                    } else {
                        seek_data_supported = false;
                        break;
                    }
                }
                let data_start = data_start as u64;
                if data_start >= len {
                    break;
                }
                let next_hole = unsafe { libc::lseek(src_fd, data_start as libc::off_t, libc::SEEK_HOLE) };
                let extent_end = if next_hole < 0 {
                    len
                } else {
                    (next_hole as u64).min(len)
                };
                if extent_end <= data_start {
                    break;
                }

                if let Err(e) = copy_range_sparse(&mut src_file, &mut dst_file, data_start, extent_end) {
                    let _ = std::fs::remove_file(dst);
                    return Err(format!("Failed to copy range in {}: {}", src.display(), e));
                }

                offset = extent_end;
            }

            if !seek_data_supported {
                if let Err(e) = copy_range_sparse(&mut src_file, &mut dst_file, 0, len) {
                    let _ = std::fs::remove_file(dst);
                    return Err(format!("Failed to copy file {}: {}", src.display(), e));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        if len > 0 {
            if let Err(e) = copy_range_sparse(&mut src_file, &mut dst_file, 0, len) {
                let _ = std::fs::remove_file(dst);
                return Err(format!("Failed to copy file {}: {}", src.display(), e));
            }
        }
    }

    drop(src_file);
    drop(dst_file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(meta.mode()));
        unsafe {
            if libc::geteuid() == 0 {
                if let Ok(c_path) = std::ffi::CString::new(dst.as_os_str().as_bytes()) {
                    libc::chown(c_path.as_ptr(), meta.uid(), meta.gid());
                }
            }
        }
    }

    Ok(())
}

fn copy_live_receipts_to_stage(live_dir: &Path, stage_dir: &Path) -> Result<(), String> {
    if !live_dir.is_dir() {
        return Ok(());
    }
    fn walk(curr_live: &Path, rel_path: &Path, stage_root: &Path) -> Result<(), String> {
        let entries = match std::fs::read_dir(curr_live) {
            Ok(e) => e,
            Err(_) => return Ok(()),
        };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            let child_live = curr_live.join(&fname);
            let child_rel = rel_path.join(&fname);
            if let Ok(meta) = std::fs::symlink_metadata(&child_live) {
                if meta.is_dir() {
                    walk(&child_live, &child_rel, stage_root)?;
                } else if meta.is_file() && is_receipt_file_name(&name_str) {
                    let stage_file = stage_root.join(&child_rel);
                    if let Some(p) = stage_file.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    let _ = std::fs::copy(&child_live, &stage_file);
                }
            }
        }
        Ok(())
    }
    walk(live_dir, Path::new(""), stage_dir)
}

fn remove_untracked_receipt_files(dir: &Path, embedded: &[FileSnapshot]) {
    fn walk(curr: &Path, embedded: &[FileSnapshot]) {
        let entries = match std::fs::read_dir(curr) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if meta.is_dir() {
                    walk(&p, embedded);
                } else if meta.is_file() && is_receipt_file_name(&name_str) {
                    if !embedded.iter().any(|snap| snap.path == p) {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
        }
    }
    walk(dir, embedded);
}

fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    root: &Path,
    mut embedded_receipts: Option<&mut Vec<FileSnapshot>>,
    _ignore_permission_denied: bool,
    fs_root: Option<&Path>,
) -> Result<(), String> {
    // PermissionDenied is never skipped. A partial directory backup would
    // delete unread files such as mode 000 databases on restore.
    let src_meta = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(e) => return Err(format!("Failed to stat {}: {}", src.display(), e)),
    };
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("Failed to create dir {}: {}", dst.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o700));
    }
    let read_res = std::fs::read_dir(src);
    let entries = match read_res {
        Ok(e) => e,
        Err(e) => return Err(format!("Failed to read dir {}: {}", src.display(), e)),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(format!("Failed to read entry in {}: {}", src.display(), e)),
        };
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with(".af-backup.") || name_str.contains(".af-backup.") {
            continue;
        }
        let child_src = entry.path();
        let child_dst = dst.join(&file_name);
        let meta = match std::fs::symlink_metadata(&child_src) {
            Ok(m) => m,
            Err(e) => return Err(format!("Failed to stat {}: {}", child_src.display(), e)),
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = match std::fs::read_link(&child_src) {
                Ok(t) => t,
                Err(e) => return Err(format!("Failed to read symlink {}: {}", child_src.display(), e)),
            };
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &child_dst)
                    .map_err(|e| format!("Failed to create symlink {}: {}", child_dst.display(), e))?;
            }
        } else if ft.is_dir() {
            let receipts_sub = match embedded_receipts {
                Some(ref mut r) => Some(&mut **r),
                None => None,
            };
            copy_dir_recursive(&child_src, &child_dst, root, receipts_sub, _ignore_permission_denied, fs_root)?;
        } else if ft.is_file() {
            if let Some(ref mut receipts) = embedded_receipts {
                if is_receipt_file_name(&name_str) {
                    verify_no_symlink_ancestors_with_root(&child_src, fs_root)?;
                    let state = read_file_entry_bounded_nofollow(&child_src, 1024 * 1024)?;
                    receipts.push(FileSnapshot { path: child_src, state });
                    continue;
                }
            }
            if let Err(e) = copy_file_preserving_sparse_and_meta(&child_src, &child_dst, &meta) {
                return Err(format!("Failed to copy file {}: {}", child_src.display(), e));
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(src_meta.mode()));
        unsafe {
            if libc::geteuid() == 0 {
                if let Ok(c_path) = std::ffi::CString::new(dst.as_os_str().as_bytes()) {
                    libc::chown(c_path.as_ptr(), src_meta.uid(), src_meta.gid());
                }
            }
        }
    }
    Ok(())
}

fn candidate_runtime_targets(
    package_id: &str,
    units: &[String],
    env_cfg: &crate::PackageExecutionEnv,
) -> Vec<(PathBuf, RuntimeTargetKind)> {
    let resolve = |p: &str| -> PathBuf {
        let mut logical = p.to_string();
        for alias in MERGED_USR_ALIASES {
            let prefix = format!("/{alias}/");
            if logical.starts_with(&prefix) {
                let alias_path = match env_cfg.fs_root.as_ref() {
                    Some(root) => root.join(alias),
                    None => PathBuf::from(format!("/{alias}")),
                };
                if is_trusted_merged_usr_symlink(&alias_path, env_cfg.fs_root.as_deref()) {
                    logical = format!("/usr{logical}");
                }
                break;
            }
        }
        if let Some(ref root) = env_cfg.fs_root {
            let rel = logical.trim_start_matches(['/', '\\']);
            root.join(rel)
        } else {
            PathBuf::from(logical)
        }
    };

    let pkg = package_id.trim();
    let pkg_lower = pkg.to_ascii_lowercase();

    let mut dir_candidates: Vec<String> = vec![
        format!("/opt/{pkg}"),
        format!("/opt/{pkg_lower}"),
        format!("/etc/{pkg}"),
        format!("/etc/{pkg_lower}"),
        format!("/var/lib/{pkg}"),
        format!("/var/lib/{pkg_lower}"),
        format!("/usr/share/{pkg}"),
        format!("/usr/share/{pkg_lower}"),
        format!("/usr/lib/{pkg}"),
        format!("/usr/lib/{pkg_lower}"),
        format!("/usr/libexec/{pkg}"),
        format!("/usr/libexec/{pkg_lower}"),
        format!("/usr/local/share/{pkg}"),
        format!("/usr/local/share/{pkg_lower}"),
    ];

    match pkg_lower.as_str() {
        "adguardhome" => dir_candidates.push("/opt/AdGuardHome".into()),
        "bazarr" => dir_candidates.push("/opt/Bazarr".into()),
        "calibreweb" => {
            dir_candidates.extend([
                "/opt/calibre-web".into(),
                "/var/lib/calibre-web".into(),
                "/var/lib/calibre-library".into(),
            ]);
        }
        "duplicati" => dir_candidates.push("/usr/lib/duplicati".into()),
        "emby" => {
            dir_candidates.extend([
                "/opt/emby-server".into(),
                "/etc/emby-server".into(),
                "/usr/lib/emby-server".into(),
                "/usr/share/emby-server".into(),
                "/var/lib/emby-server".into(),
            ]);
        }
        "filebot" => {
            dir_candidates.extend([
                "/opt/filebot".into(),
                "/opt/filebot-node".into(),
            ]);
        }
        "jackett" => dir_candidates.push("/opt/Jackett".into()),
        "jellyfin" => dir_candidates.push("/usr/lib/jellyfin".into()),
        "grafana" => dir_candidates.push("/usr/share/grafana-server".into()),
        "kasmvnc" => {
            dir_candidates.extend([
                "/usr/lib/kasmvnc".into(),
                "/usr/lib/kasmvncserver".into(),
                "/usr/share/kasmvnc".into(),
                "/usr/share/kasmvncserver".into(),
            ]);
        }
        "kavita" => dir_candidates.push("/opt/Kavita".into()),
        "librespeed" => dir_candidates.push("/var/www/librespeed".into()),
        "lidarr" => dir_candidates.push("/opt/Lidarr".into()),
        "listenarr" => dir_candidates.push("/opt/Listenarr".into()),
        "maintainerr" => dir_candidates.push("/etc/systemd/system/af-maintainerr.service.d".into()),
        "netdata" => dir_candidates.push("/usr/lib/netdata".into()),
        "nextcloud" => {
            dir_candidates.extend([
                "/var/www/nextcloud".into(),
                "/var/www/html/nextcloud".into(),
            ]);
        }
        "ombi" => {
            dir_candidates.extend([
                "/opt/Ombi".into(),
                "/etc/Ombi".into(),
            ]);
        }
        "organizr" => dir_candidates.push("/var/www/organizr".into()),
        "paperless-ngx" => {
            dir_candidates.extend([
                "/opt/paperless".into(),
                "/var/lib/paperless".into(),
            ]);
        }
        "pihole" => {
            dir_candidates.extend([
                "/etc/.pihole".into(),
                "/var/www/html/admin".into(),
                "/var/www/html/pihole".into(),
            ]);
        }
        "piped" => {
            dir_candidates.extend([
                "/opt/piped".into(),
                "/opt/piped-backend".into(),
                "/opt/piped-proxy".into(),
            ]);
        }
        "plex" => {
            dir_candidates.extend([
                "/usr/lib/plexmediaserver".into(),
                "/usr/share/plexmediaserver".into(),
                "/var/lib/plexmediaserver".into(),
                "/etc/plexmediaserver".into(),
            ]);
        }
        "prowlarr" => dir_candidates.push("/opt/Prowlarr".into()),
        "qbittorrent" => dir_candidates.push("/usr/lib/qbittorrent".into()),
        "quassel" => dir_candidates.push("/usr/lib/quassel".into()),
        "radarr" => dir_candidates.push("/opt/Radarr".into()),
        "readarr" => dir_candidates.push("/opt/Readarr".into()),
        "rutorrent" => dir_candidates.push("/var/www/rutorrent".into()),
        "sabnzbd" => dir_candidates.push("/opt/SABnzbd".into()),
        "sonarr" => {
            dir_candidates.extend([
                "/opt/Sonarr".into(),
                "/opt/NzbDrone".into(),
            ]);
        }
        "tautulli" => {
            dir_candidates.extend([
                "/opt/Tautulli".into(),
                "/opt/plexpy".into(),
            ]);
        }
        "transmission" => {
            dir_candidates.extend([
                "/etc/transmission-daemon".into(),
                "/usr/lib/transmission".into(),
                "/var/lib/transmission-daemon".into(),
            ]);
        }
        "prometheus" => dir_candidates.push("/usr/share/prometheus-node-exporter".into()),
        "uptimekuma" => dir_candidates.push("/opt/uptime-kuma".into()),
        "wireguard" => dir_candidates.push("/usr/share/wireguard-tools".into()),
        "x2go" => dir_candidates.push("/usr/lib/x2go".into()),
        "xrdp" => dir_candidates.push("/usr/lib/xrdp".into()),
        "znc" => dir_candidates.push("/usr/lib/znc".into()),
        _ => {}
    }

    let mut all_units: Vec<String> = units.to_vec();
    match pkg_lower.as_str() {
        "deluge" => all_units.extend(["deluged.service".into(), "deluge-web.service".into()]),
        "dispatcharr" => all_units.extend(["dispatcharr-celery.service".into(), "dispatcharr-celerybeat.service".into()]),
        "emby" => all_units.push("emby-server.service".into()),
        "grafana" => all_units.push("grafana-server.service".into()),
        "homeassistant" => all_units.push("home-assistant@homeassistant.service".into()),
        "invidious" => all_units.extend(["af-invidious.service".into(), "af-invidious-companion.service".into()]),
        "kasmvnc" => all_units.push("af-kasmvnc.service".into()),
        "maintainerr" => all_units.push("af-maintainerr.service".into()),
        "mcvnc" => all_units.push("af-mcvnc.service".into()),
        "novnc" => all_units.push("novnc-xvnc.service".into()),
        "palate" => all_units.push("af-palate.service".into()),
        "paperless-ngx" => all_units.extend(["paperless-webserver.service".into(), "paperless-worker.service".into(), "paperless-scheduler.service".into()]),
        "pihole" => all_units.push("pihole-FTL.service".into()),
        "piped" => all_units.extend(["af-piped.service".into(), "af-piped-api.service".into(), "af-piped-proxy.service".into(), "piped-backend.service".into(), "piped-proxy.service".into()]),
        "plex" => all_units.push("plexmediaserver.service".into()),
        "prometheus" => all_units.extend(["node_exporter.service".into(), "prometheus-node-exporter.service".into()]),
        "quassel" => all_units.push("quasselcore.service".into()),
        "rclone" => all_units.push("rclone-vfs.service".into()),
        "recyclarr" => all_units.extend(["recyclarr.service".into(), "recyclarr.timer".into()]),
        "scrutiny" => all_units.extend(["scrutiny-collector.service".into(), "scrutiny-collector.timer".into()]),
        "tailscale" => all_units.push("tailscaled.service".into()),
        "transmission" => all_units.push("transmission-daemon.service".into()),
        "uptimekuma" => all_units.push("uptime-kuma.service".into()),
        "wireguard" => all_units.push("wg-quick@wg0.service".into()),
        "x2go" => all_units.push("x2goserver.service".into()),
        "xrdp" => all_units.push("xrdp-sesman.service".into()),
        _ => {}
    }

    let mut file_candidates: Vec<String> = vec![
        format!("/usr/local/bin/{pkg}"),
        format!("/usr/local/bin/{pkg_lower}"),
        format!("/usr/bin/{pkg}"),
        format!("/usr/bin/{pkg_lower}"),
        format!("/usr/sbin/{pkg}"),
        format!("/usr/sbin/{pkg_lower}"),
        format!("/usr/local/sbin/{pkg}"),
        format!("/usr/local/sbin/{pkg_lower}"),
        format!("/etc/systemd/system/{pkg}.service"),
        format!("/etc/systemd/system/{pkg_lower}.service"),
        format!("/lib/systemd/system/{pkg_lower}.service"),
        format!("/usr/lib/systemd/system/{pkg_lower}.service"),
        format!("/etc/systemd/system/{pkg}.timer"),
        format!("/etc/systemd/system/{pkg_lower}.timer"),
        format!("/etc/default/{pkg}"),
        format!("/etc/default/{pkg_lower}"),
        format!("/install/.{pkg_lower}.lock"),
    ];

    for unit in all_units {
        let u = unit.trim();
        if u.is_empty() || u.starts_with("port:") {
            continue;
        }
        let unit_file = if u.contains('.') {
            u.to_string()
        } else {
            format!("{u}.service")
        };
        file_candidates.push(format!("/etc/systemd/system/{unit_file}"));
        file_candidates.push(format!("/lib/systemd/system/{unit_file}"));
        file_candidates.push(format!("/usr/lib/systemd/system/{unit_file}"));
    }

    match pkg_lower.as_str() {
        "autobrr" => file_candidates.push("/usr/local/bin/autobrrctl".into()),
        "deluge" => file_candidates.extend([
            "/etc/default/deluged".into(),
            "/usr/bin/deluged".into(),
            "/usr/bin/deluge-web".into(),
            "/usr/bin/deluge-console".into(),
        ]),
        "duplicati" => file_candidates.push("/usr/bin/duplicati-server".into()),
        "emby" => file_candidates.extend([
            "/etc/emby-server.conf".into(),
            "/usr/bin/emby-server".into(),
        ]),
        "fail2ban" => file_candidates.extend([
            "/usr/bin/fail2ban-server".into(),
            "/usr/bin/fail2ban-client".into(),
        ]),
        "grafana" => file_candidates.extend([
            "/usr/bin/grafana-server".into(),
            "/usr/bin/grafana-cli".into(),
            "/usr/sbin/grafana-server".into(),
        ]),
        "kasmvnc" => file_candidates.extend([
            "/usr/local/bin/af-kasmvnc-start".into(),
            "/usr/bin/kasmvncserver".into(),
            "/usr/bin/kasmvncpasswd".into(),
            "/usr/bin/Xkasmvnc".into(),
            "/usr/bin/Xvnc".into(),
            "/usr/bin/vncserver".into(),
        ]),
        "maintainerr" => file_candidates.push("/usr/local/bin/af-systemd-sandbox".into()),
        "netdata" => file_candidates.extend([
            "/usr/sbin/netdata".into(),
            "/usr/local/sbin/netdata".into(),
        ]),
        "novnc" => file_candidates.extend([
            "/usr/local/bin/af-novnc-start".into(),
            "/usr/local/bin/af-novnc-xvnc-start".into(),
            "/usr/bin/Xtigervnc".into(),
            "/usr/bin/tigervncserver".into(),
            "/usr/bin/websockify".into(),
            "/usr/bin/x11vnc".into(),
        ]),
        "nzbget" => file_candidates.push("/etc/nzbget.conf".into()),
        "paperless-ngx" => file_candidates.push("/etc/paperless.conf".into()),
        "pihole" => file_candidates.push("/usr/bin/pihole-FTL".into()),
        "plex" => file_candidates.extend([
            "/etc/default/plexmediaserver".into(),
            "/usr/bin/plexmediaserver".into(),
        ]),
        "prometheus" => file_candidates.extend([
            "/usr/local/bin/promtool".into(),
            "/usr/local/bin/node_exporter".into(),
            "/usr/bin/promtool".into(),
            "/usr/bin/prometheus-node-exporter".into(),
        ]),
        "qbittorrent" => file_candidates.push("/usr/bin/qbittorrent-nox".into()),
        "quassel" => file_candidates.extend([
            "/etc/default/quasselcore".into(),
            "/usr/bin/quasselcore".into(),
        ]),
        "sabnzbd" => file_candidates.push("/etc/default/sabnzbdplus".into()),
        "tailscale" => file_candidates.extend([
            "/etc/default/tailscaled".into(),
            "/usr/sbin/tailscaled".into(),
        ]),
        "transmission" => file_candidates.extend([
            "/usr/bin/transmission-daemon".into(),
            "/usr/bin/transmission-remote".into(),
        ]),
        "wireguard" => file_candidates.extend([
            "/usr/bin/wg".into(),
            "/usr/bin/wg-quick".into(),
        ]),
        "x2go" => file_candidates.extend([
            "/usr/bin/x2goruncommand".into(),
            "/usr/bin/x2gostartagent".into(),
            "/usr/sbin/x2gocleansessions".into(),
        ]),
        "xrdp" => file_candidates.extend([
            "/usr/sbin/xrdp".into(),
            "/usr/sbin/xrdp-sesman".into(),
        ]),
        _ => {}
    }

    if let Some(recipe) = crate::package_executor::get_declarative_recipe(pkg) {
        for step in recipe.install_steps.iter().chain(recipe.update_steps.iter()) {
            match step {
                crate::package_executor::DeclarativeStep::WriteTemplateFile { path, .. } => {
                    file_candidates.push(path.clone());
                }
                crate::package_executor::DeclarativeStep::WriteSystemdUnit { unit_name, .. } => {
                    let u = unit_name.trim();
                    let unit_file = if u.contains('.') {
                        u.to_string()
                    } else {
                        format!("{u}.service")
                    };
                    file_candidates.push(format!("/etc/systemd/system/{unit_file}"));
                    file_candidates.push(format!("/lib/systemd/system/{unit_file}"));
                    file_candidates.push(format!("/usr/lib/systemd/system/{unit_file}"));
                }
                crate::package_executor::DeclarativeStep::DownloadBinary { dest_path, .. } => {
                    file_candidates.push(dest_path.clone());
                }
                crate::package_executor::DeclarativeStep::DownloadAndExtractTarGz { dest_dir, extract_binaries, .. } => {
                    let clean = dest_dir.trim_end_matches('/');
                    for b in extract_binaries {
                        file_candidates.push(format!("{clean}/{b}"));
                    }
                }
                crate::package_executor::DeclarativeStep::GenerateSelfSignedTlsCert { cert_path, key_out_path, .. } => {
                    file_candidates.push(cert_path.clone());
                    if let Some(ref k) = key_out_path {
                        file_candidates.push(k.clone());
                    }
                }
                crate::package_executor::DeclarativeStep::MergeIniSettings { path, .. } => {
                    file_candidates.push(path.clone());
                }
                _ => {}
            }
        }
    }

    let bp_paths = crate::package_executor::collect_blueprint_target_paths(pkg, env_cfg.fs_root.as_deref());

    let mut dir_targets: Vec<PathBuf> = Vec::new();
    for d in dir_candidates {
        let p = resolve(&d);
        if !dir_targets.contains(&p) {
            dir_targets.push(p);
        }
    }

    let mut file_targets: Vec<PathBuf> = Vec::new();
    for f in file_candidates {
        let p = resolve(&f);
        if dir_targets.iter().any(|d| p == *d || p.starts_with(d)) {
            continue;
        }
        if !file_targets.contains(&p) {
            file_targets.push(p);
        }
    }

    for p in bp_paths {
        if dir_targets.iter().any(|d| p == *d || p.starts_with(d)) {
            continue;
        }
        if !file_targets.contains(&p) {
            file_targets.push(p);
        }
    }

    let mut targets = Vec::new();
    for d in dir_targets {
        targets.push((d, RuntimeTargetKind::Directory));
    }
    for f in file_targets {
        targets.push((f, RuntimeTargetKind::FileOrSymlink));
    }
    targets
}

#[derive(Debug)]
enum StagedRuntimeItem {
    File {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
    Symlink {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
    Directory {
        target_path: PathBuf,
        stage_path: PathBuf,
    },
}

#[derive(Debug)]
struct CommittedSwap {
    target_path: PathBuf,
    old_path: Option<PathBuf>,
}

fn cleanup_staged_items(items: &[StagedRuntimeItem]) {
    for item in items {
        match item {
            StagedRuntimeItem::File { stage_path, .. }
            | StagedRuntimeItem::Symlink { stage_path, .. } => {
                let _ = std::fs::remove_file(stage_path);
            }
            StagedRuntimeItem::Directory { stage_path, .. } => {
                let _ = std::fs::remove_dir_all(stage_path);
            }
        }
    }
}

impl PackageRuntimeSnapshot {
    pub fn capture(
        package_id: &str,
        units: &[String],
        env_cfg: &crate::PackageExecutionEnv,
        _ignore_permission_denied: bool,
    ) -> Result<Self, String> {
        let safe_pkg: String = package_id
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let folder_name = format!(".af-rt-snap-{}-{}", safe_pkg, uuid::Uuid::new_v4());
        let mut parent_candidates: Vec<PathBuf> = Vec::new();
        if !env_cfg.temp_dir.as_os_str().is_empty() {
            parent_candidates.push(env_cfg.temp_dir.clone());
        }
        let var_tmp = Path::new("/var/tmp");
        if var_tmp.is_dir() && !parent_candidates.iter().any(|p| p == var_tmp) {
            parent_candidates.push(var_tmp.to_path_buf());
        }
        let sys_tmp = std::env::temp_dir();
        if !parent_candidates.iter().any(|p| p == &sys_tmp) {
            parent_candidates.push(sys_tmp);
        }
        let mut created_root = None;
        let mut last_create_err = String::new();
        for parent in parent_candidates {
            let candidate = parent.join(&folder_name);
            match std::fs::create_dir_all(&candidate) {
                Ok(()) => {
                    created_root = Some(candidate);
                    break;
                }
                Err(e) => {
                    last_create_err = format!("Failed to create backup root {}: {}", candidate.display(), e);
                }
            }
        }
        let backup_root = created_root.ok_or(last_create_err)?;
        // `backup_root` exists before any target is copied. If a later target
        // fails, `PackageRuntimeSnapshot` is never built, so its Drop cannot
        // remove the directory. Disarm the guard only after `Self` owns it.
        struct CaptureBackupGuard {
            path: PathBuf,
            armed: bool,
        }
        impl Drop for CaptureBackupGuard {
            fn drop(&mut self) {
                if self.armed {
                    force_remove_backup_tree(&self.path);
                }
            }
        }
        let mut backup_guard = CaptureBackupGuard {
            path: backup_root.clone(),
            armed: true,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&backup_root, std::fs::Permissions::from_mode(0o700));
        }

        let targets = candidate_runtime_targets(package_id, units, env_cfg);
        let mut entries = Vec::new();
        let mut embedded_receipts = Vec::new();

        for (idx, (target_path, kind)) in targets.into_iter().enumerate() {
            verify_no_symlink_ancestors_with_root(&target_path, env_cfg.fs_root.as_deref())?;
            match std::fs::symlink_metadata(&target_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    entries.push(RuntimeSnapshotEntry::Absent { target_path, kind });
                }
                Err(e) => {
                    return Err(format!("Failed to read metadata for {}: {}", target_path.display(), e));
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    let link_target = std::fs::read_link(&target_path)
                        .map_err(|e| format!("Failed to read link {}: {}", target_path.display(), e))?;
                    entries.push(RuntimeSnapshotEntry::Symlink { target_path, link_target });
                }
                Ok(meta) if meta.is_file() => {
                    let file_name = target_path.file_name().unwrap_or_default().to_string_lossy();
                    if is_receipt_file_name(&file_name) {
                        verify_no_symlink_ancestors_with_root(&target_path, env_cfg.fs_root.as_deref())?;
                        let state = read_file_entry_bounded_nofollow(&target_path, 1024 * 1024)?;
                        embedded_receipts.push(FileSnapshot { path: target_path.clone(), state });
                        continue;
                    }
                    let backup_path = backup_root.join(format!("entry_{idx}"));
                    copy_file_preserving_sparse_and_meta(&target_path, &backup_path, &meta)?;
                    #[cfg(unix)]
                    let (mode, uid, gid) = {
                        use std::os::unix::fs::MetadataExt;
                        (meta.mode(), meta.uid(), meta.gid())
                    };
                    #[cfg(not(unix))]
                    let (mode, uid, gid) = (0o644, 0, 0);
                    entries.push(RuntimeSnapshotEntry::File { target_path, backup_path, mode, uid, gid });
                }
                Ok(meta) if meta.is_dir() => {
                    let backup_path = backup_root.join(format!("entry_{idx}"));
                    copy_dir_recursive(
                        &target_path,
                        &backup_path,
                        &target_path,
                        Some(&mut embedded_receipts),
                        _ignore_permission_denied,
                        env_cfg.fs_root.as_deref(),
                    )?;
                    #[cfg(unix)]
                    let (mode, uid, gid) = {
                        use std::os::unix::fs::MetadataExt;
                        (meta.mode(), meta.uid(), meta.gid())
                    };
                    #[cfg(not(unix))]
                    let (mode, uid, gid) = (0o755, 0, 0);
                    entries.push(RuntimeSnapshotEntry::Directory {
                        target_path,
                        backup_path,
                        mode,
                        uid,
                        gid,
                    });
                }
                _ => {}
            }
        }

        backup_guard.armed = false;
        Ok(Self {
            package_id: package_id.to_string(),
            backup_root,
            entries,
            embedded_receipts,
            preserve_on_drop: false,
            fs_root: env_cfg.fs_root.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<(), String> {
        // Phase 1 (Preflight & Stage — zero live mutations!)
        let mut staged_items: Vec<StagedRuntimeItem> = Vec::new();

        for entry in &self.entries {
            let entry_target = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. } => target_path,
                RuntimeSnapshotEntry::File { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Symlink { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            if let Err(e) = verify_no_symlink_ancestors_with_root(entry_target, self.fs_root.as_deref()) {
                cleanup_staged_items(&staged_items);
                self.preserve_on_drop = true;
                return Err(e);
            }
            for ancestor in entry_target.ancestors().skip(1) {
                if ancestor.as_os_str().is_empty() {
                    continue;
                }
                match std::fs::symlink_metadata(ancestor) {
                    Ok(meta) => {
                        let trusted_merged_usr = meta.file_type().is_symlink()
                            && is_trusted_merged_usr_symlink(ancestor, self.fs_root.as_deref());
                        if !trusted_merged_usr && !meta.is_dir() {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!(
                                "Runtime target path {} ancestor {} is not a directory",
                                entry_target.display(),
                                ancestor.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!("Failed to stat ancestor {}: {}", ancestor.display(), e));
                    }
                }
            }
            match entry {
                RuntimeSnapshotEntry::Absent { target_path, kind } => {
                    match std::fs::symlink_metadata(target_path) {
                        Ok(meta) => {
                            if *kind == RuntimeTargetKind::Directory && !meta.is_dir() {
                                cleanup_staged_items(&staged_items);
                                self.preserve_on_drop = true;
                                return Err(format!(
                                    "Runtime directory path {} blocked by non-directory entry (ENOTDIR)",
                                    target_path.display()
                                ));
                            }
                            if is_protected_root(target_path) {
                                cleanup_staged_items(&staged_items);
                                self.preserve_on_drop = true;
                                return Err(format!(
                                    "Refusing to delete protected root directory: {}",
                                    target_path.display()
                                ));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!("Failed to stat {}: {}", target_path.display(), e));
                        }
                    }
                }
                RuntimeSnapshotEntry::File { target_path, backup_path, mode, uid, gid } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let stage = parent.join(format!(".af-rt-file-{}", uuid::Uuid::new_v4()));
                    let meta = std::fs::metadata(backup_path).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to stat backup file {}: {}", backup_path.display(), e)
                    })?;
                    if let Err(e) = copy_file_preserving_sparse_and_meta(backup_path, &stage, &meta) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!("Failed to stage restored file {}: {}", stage.display(), e));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(*mode));
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) = std::ffi::CString::new(stage.as_os_str().as_bytes()) {
                                    libc::chown(c_path.as_ptr(), *uid, *gid);
                                }
                            }
                        }
                    }
                    staged_items.push(StagedRuntimeItem::File {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
                RuntimeSnapshotEntry::Symlink { target_path, link_target } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let stage = parent.join(format!(".af-rt-sym-{}", uuid::Uuid::new_v4()));
                    #[cfg(unix)]
                    {
                        if let Err(e) = std::os::unix::fs::symlink(link_target, &stage) {
                            cleanup_staged_items(&staged_items);
                            self.preserve_on_drop = true;
                            return Err(format!("Failed to create symlink {}: {}", stage.display(), e));
                        }
                    }
                    staged_items.push(StagedRuntimeItem::Symlink {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
                RuntimeSnapshotEntry::Directory { target_path, backup_path, mode, uid, gid } => {
                    let parent = target_path.parent().ok_or_else(|| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Target path {} has no parent", target_path.display())
                    })?;
                    std::fs::create_dir_all(parent).map_err(|e| {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        format!("Failed to create parent dir {}: {}", parent.display(), e)
                    })?;
                    let name = target_path.file_name().unwrap_or_default().to_string_lossy();
                    let stage = parent.join(format!(".{}.af-rt-stage-{}", name, uuid::Uuid::new_v4()));
                    if let Err(e) = copy_dir_recursive(backup_path, &stage, backup_path, None, false, self.fs_root.as_deref()) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!("Failed to stage restored directory {}: {}", stage.display(), e));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(*mode));
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) = std::ffi::CString::new(stage.as_os_str().as_bytes()) {
                                    libc::chown(c_path.as_ptr(), *uid, *gid);
                                }
                            }
                        }
                    }
                    if let Err(e) = copy_live_receipts_to_stage(target_path, &stage) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!("Failed to preserve live receipts into stage {}: {}", stage.display(), e));
                    }
                    staged_items.push(StagedRuntimeItem::Directory {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
            }
        }

        // Phase 2 (Commit Runtime Swaps & Absent Removals)
        let mut committed_swaps: Vec<CommittedSwap> = Vec::new();
        let mut swap_err: Option<String> = None;

        for item in staged_items {
            let (target_path, stage_path, is_dir) = match item {
                StagedRuntimeItem::File { target_path, stage_path } => (target_path, stage_path, false),
                StagedRuntimeItem::Symlink { target_path, stage_path } => (target_path, stage_path, false),
                StagedRuntimeItem::Directory { target_path, stage_path } => (target_path, stage_path, true),
            };
            let parent = match target_path.parent() {
                Some(p) => p,
                None => {
                    let _ = if is_dir { std::fs::remove_dir_all(&stage_path) } else { std::fs::remove_file(&stage_path) };
                    swap_err = Some(format!("Target {} has no parent", target_path.display()));
                    break;
                }
            };
            let name = target_path.file_name().unwrap_or_default().to_string_lossy();
            let old_path = parent.join(format!(".{}.af-rt-old-{}", name, uuid::Uuid::new_v4()));
            let had_target = std::fs::symlink_metadata(&target_path).is_ok();
            if had_target {
                if let Err(e) = std::fs::rename(&target_path, &old_path) {
                    let _ = if is_dir { std::fs::remove_dir_all(&stage_path) } else { std::fs::remove_file(&stage_path) };
                    swap_err = Some(format!("Failed to move old {} to {}: {}", target_path.display(), old_path.display(), e));
                    break;
                }
            }
            if let Err(e) = std::fs::rename(&stage_path, &target_path) {
                if had_target {
                    let _ = std::fs::rename(&old_path, &target_path);
                }
                let _ = if is_dir { std::fs::remove_dir_all(&stage_path) } else { std::fs::remove_file(&stage_path) };
                swap_err = Some(format!("Failed to move stage {} to {}: {}", stage_path.display(), target_path.display(), e));
                break;
            }
            committed_swaps.push(CommittedSwap {
                target_path,
                old_path: if had_target { Some(old_path) } else { None },
            });
        }

        if let Some(err) = swap_err {
            for swap in committed_swaps.into_iter().rev() {
                let _ = if swap.target_path.is_dir() {
                    std::fs::remove_dir_all(&swap.target_path)
                } else {
                    std::fs::remove_file(&swap.target_path)
                };
                if let Some(old) = swap.old_path {
                    let _ = std::fs::rename(&old, &swap.target_path);
                }
            }
            self.preserve_on_drop = true;
            return Err(err);
        }

        let mut absent_parked: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut absent_err: Option<String> = None;
        for entry in &self.entries {
            if let RuntimeSnapshotEntry::Absent { target_path, .. } = entry {
                match std::fs::symlink_metadata(target_path) {
                    Ok(meta) => {
                        if let Some(parent) = target_path.parent() {
                            let name = target_path.file_name().unwrap_or_default().to_string_lossy();
                            let parked = parent.join(format!(".{}.af-rt-abs-{}", name, uuid::Uuid::new_v4()));
                            if std::fs::rename(target_path, &parked).is_ok() {
                                absent_parked.push((target_path.clone(), parked));
                                continue;
                            }
                        }
                        let rem_res = if meta.is_dir() {
                            std::fs::remove_dir_all(target_path)
                        } else {
                            std::fs::remove_file(target_path)
                        };
                        if let Err(e) = rem_res {
                            absent_err = Some(format!(
                                "Failed to remove absent runtime target {}: {}",
                                target_path.display(),
                                e
                            ));
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        absent_err = Some(format!(
                            "Failed to stat absent runtime target {}: {}",
                            target_path.display(),
                            e
                        ));
                        break;
                    }
                }
            }
        }

        if let Some(err) = absent_err {
            for (orig, parked) in absent_parked.into_iter().rev() {
                let _ = std::fs::rename(&parked, &orig);
            }
            for swap in committed_swaps.into_iter().rev() {
                let _ = if swap.target_path.is_dir() {
                    std::fs::remove_dir_all(&swap.target_path)
                } else {
                    std::fs::remove_file(&swap.target_path)
                };
                if let Some(old) = swap.old_path {
                    let _ = std::fs::rename(&old, &swap.target_path);
                }
            }
            self.preserve_on_drop = true;
            return Err(err);
        }

        for (_, parked) in absent_parked {
            if let Ok(meta) = std::fs::symlink_metadata(&parked) {
                if meta.is_dir() {
                    let _ = std::fs::remove_dir_all(&parked);
                } else {
                    let _ = std::fs::remove_file(&parked);
                }
            }
        }

        for swap in committed_swaps {
            if let Some(old) = swap.old_path {
                let _ = if old.is_dir() {
                    std::fs::remove_dir_all(&old)
                } else {
                    std::fs::remove_file(&old)
                };
            }
        }

        // Clean up <target_path>.af-backup.* sibling directories
        for entry in &self.entries {
            let target_path = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. } => target_path,
                RuntimeSnapshotEntry::File { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Symlink { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            if let (Some(parent), Some(fname)) = (target_path.parent(), target_path.file_name()) {
                let prefix = format!("{}.af-backup.", fname.to_string_lossy());
                if let Ok(dir_entries) = std::fs::read_dir(parent) {
                    for de in dir_entries.flatten() {
                        let name = de.file_name().to_string_lossy().to_string();
                        if name.starts_with(&prefix) {
                            let owner_file = de.path().join(".af-archive-owner");
                            if let Ok(owner) = std::fs::read_to_string(&owner_file) {
                                if owner.trim() == self.package_id {
                                    let _ = std::fs::remove_dir_all(de.path());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 3 (Commit Embedded Receipts — ONLY reached after 100% of runtime targets succeeded!)
        for entry in &self.entries {
            if let RuntimeSnapshotEntry::Directory { target_path, .. } = entry {
                remove_untracked_receipt_files(target_path, &self.embedded_receipts);
            }
        }
        restore_candidate_receipts(&self.embedded_receipts)?;

        Ok(())
    }
}

#[cfg(test)]
pub static TEST_ROLLBACK_HOOK: once_cell::sync::Lazy<std::sync::Mutex<Option<Box<dyn Fn(&[FileSnapshot]) + Send + Sync>>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub static TEST_CERTIFY_FAIL_HOOK: once_cell::sync::Lazy<std::sync::Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

pub fn rollback_operation_state(
    receipt_snapshots: &[FileSnapshot],
    blueprint_snapshots: &[FileSnapshot],
) -> Result<(), String> {
    rollback_operation_state_with_runtime(receipt_snapshots, blueprint_snapshots, None)
}

pub fn rollback_operation_state_with_runtime(
    receipt_snapshots: &[FileSnapshot],
    blueprint_snapshots: &[FileSnapshot],
    mut runtime_snapshot: Option<&mut PackageRuntimeSnapshot>,
) -> Result<(), String> {
    #[cfg(test)]
    {
        if let Some(hook) = TEST_ROLLBACK_HOOK.lock().unwrap().as_ref() {
            hook(receipt_snapshots);
        }
    }
    if let Some(ref mut rt) = runtime_snapshot {
        rt.restore()?;
    }
    restore_candidate_receipts(blueprint_snapshots)?;
    restore_candidate_receipts(receipt_snapshots)?;
    Ok(())
}

pub fn snapshot_candidate_receipts(
    package_id: &str,
) -> Result<Vec<FileSnapshot>, String> {
    snapshot_candidate_receipts_with_env(package_id, &crate::PackageExecutionEnv::default())
}

#[derive(Debug)]
pub struct StepwiseDirError {
    pub message: String,
    pub raw_os_error: Option<i32>,
}

impl std::fmt::Display for StepwiseDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for StepwiseDirError {}

impl StepwiseDirError {
    pub fn is_not_found(&self) -> bool {
        self.raw_os_error == Some(libc::ENOENT)
    }
}

pub fn open_dir_nofollow_stepwise_inner_ext(
    dir_path: &Path,
    create_missing: bool,
) -> Result<Option<std::os::fd::OwnedFd>, StepwiseDirError> {
    use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};
    use std::ffi::CString;
    use std::path::Component;

    if !dir_path.is_absolute() {
        return Err(StepwiseDirError {
            message: format!("Directory path must be absolute: {}", dir_path.display()),
            raw_os_error: Some(libc::EINVAL),
        });
    }

    let root_raw = unsafe {
        libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if root_raw < 0 {
        let err = std::io::Error::last_os_error();
        return Err(StepwiseDirError {
            message: format!("Failed to open root directory /: {}", err),
            raw_os_error: err.raw_os_error(),
        });
    }
    let mut curr_fd = unsafe { OwnedFd::from_raw_fd(root_raw) };

    for comp in dir_path.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(part) => {
                let part_bytes = part.to_string_lossy().into_owned();
                let part_cstr = match CString::new(part_bytes) {
                    Ok(c) => c,
                    Err(e) => return Err(StepwiseDirError {
                        message: format!("CString error: {}", e),
                        raw_os_error: Some(libc::EINVAL),
                    }),
                };
                let mut next_raw = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_raw < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOENT) {
                        if create_missing {
                            let mk_rc = unsafe {
                                libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755)
                            };
                            if mk_rc != 0 {
                                let mk_err = std::io::Error::last_os_error();
                                if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                    return Err(StepwiseDirError {
                                        message: format!(
                                            "Failed to create directory component {:?} in {}: {}",
                                            part,
                                            dir_path.display(),
                                            mk_err
                                        ),
                                        raw_os_error: mk_err.raw_os_error(),
                                    });
                                }
                            }
                            next_raw = unsafe {
                                libc::openat(
                                    curr_fd.as_raw_fd(),
                                    part_cstr.as_ptr(),
                                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                                )
                            };
                            if next_raw < 0 {
                                let retry_err = std::io::Error::last_os_error();
                                return Err(StepwiseDirError {
                                    message: format!(
                                        "Failed to open directory component {:?} after creation in {}: {}",
                                        part,
                                        dir_path.display(),
                                        retry_err
                                    ),
                                    raw_os_error: retry_err.raw_os_error(),
                                });
                            }
                        } else {
                            return Ok(None);
                        }
                    } else {
                        let msg = format!(
                            "Failed to open directory component {:?} in {}: {}",
                            part,
                            dir_path.display(),
                            err
                        );
                        return Err(StepwiseDirError {
                            message: msg,
                            raw_os_error: err.raw_os_error(),
                        });
                    }
                }
                curr_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(StepwiseDirError {
                    message: format!("Parent directory traversal '..' forbidden: {}", dir_path.display()),
                    raw_os_error: Some(libc::EPERM),
                });
            }
            Component::Prefix(_) => {
                return Err(StepwiseDirError {
                    message: format!("Prefix path component forbidden: {}", dir_path.display()),
                    raw_os_error: Some(libc::EINVAL),
                });
            }
        }
    }

    Ok(Some(curr_fd))
}

pub fn open_dir_nofollow_stepwise_inner(dir_path: &Path) -> Result<std::os::fd::OwnedFd, StepwiseDirError> {
    match open_dir_nofollow_stepwise_inner_ext(dir_path, false)? {
        Some(fd) => Ok(fd),
        None => Err(StepwiseDirError {
            message: format!("Directory not found: {}", dir_path.display()),
            raw_os_error: Some(libc::ENOENT),
        }),
    }
}

pub fn open_dir_nofollow_stepwise_ext(
    dir_path: &Path,
    create_missing: bool,
) -> Result<Option<std::os::fd::OwnedFd>, String> {
    open_dir_nofollow_stepwise_inner_ext(dir_path, create_missing).map_err(|e| e.to_string())
}

pub fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    open_dir_nofollow_stepwise_inner(dir_path).map_err(|e| e.to_string())
}

pub fn read_file_entry_bounded_nofollow(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<SnapshotFileState>, String> {
    use std::os::fd::{FromRawFd, OwnedFd, AsRawFd};
    use std::ffi::CString;
    use std::io::Read;

    let parent = match path.parent() {
        Some(p) => p,
        None => return Err(format!("Receipt path has no parent: {}", path.display())),
    };
    let file_name = match path.file_name() {
        Some(f) => f.to_string_lossy().into_owned(),
        None => return Err(format!("Receipt path has no filename: {}", path.display())),
    };

    let dir_fd = match open_dir_nofollow_stepwise_inner(parent) {
        Ok(fd) => fd,
        Err(e) if e.is_not_found() => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };

    let file_cstr = CString::new(file_name.as_bytes()).map_err(|e| format!("CString error: {}", e))?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(dir_fd.as_raw_fd(), file_cstr.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
    };
    if stat_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("fstatat failed on receipt {}: {}", path.display(), err));
    }

    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "Receipt path {} is a symlink or non-regular file",
            path.display()
        ));
    }
    if st.st_size > max_bytes as libc::off_t {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let file_raw = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            file_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_raw < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("openat failed on receipt {}: {}", path.display(), err));
    }
    let file_fd = unsafe { OwnedFd::from_raw_fd(file_raw) };

    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_rc = unsafe { libc::fstat(file_fd.as_raw_fd(), &mut fst) };
    if fstat_rc != 0 {
        return Err(format!("fstat failed on receipt {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    if (fst.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "Receipt path {} is not a regular file after opening",
            path.display()
        ));
    }
    if fst.st_dev != st.st_dev || fst.st_ino != st.st_ino {
        return Err(format!("Inode or device changed for receipt {}", path.display()));
    }
    if fst.st_size > max_bytes as libc::off_t {
        return Err(format!("Receipt path {} exceeds {} byte limit", path.display(), max_bytes));
    }

    let mut std_file = std::fs::File::from(file_fd);
    let mut buf = Vec::new();
    std_file
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read receipt {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!("Receipt path {} exceeds {} byte limit during read", path.display(), max_bytes));
    }

    let mode = (fst.st_mode & 0o7777) as u32;
    let uid = fst.st_uid;
    let gid = fst.st_gid;

    Ok(Some(SnapshotFileState {
        bytes: buf,
        mode,
        uid,
        gid,
    }))
}

pub fn read_receipt_bounded_nofollow(path: &Path) -> Result<Option<Vec<u8>>, String> {
    read_file_entry_bounded_nofollow(path, 512 * 1024).map(|opt| opt.map(|s| s.bytes))
}

pub fn snapshot_candidate_receipts_with_env(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<Vec<FileSnapshot>, String> {
    let paths = candidate_version_marker_paths_with_env(package_id, env_cfg)?;
    let mut snapshots = Vec::new();
    for path in paths {
        verify_no_symlink_ancestors(&path)?;
        let state = read_file_entry_bounded_nofollow(&path, 512 * 1024)?;
        snapshots.push(FileSnapshot { path, state });
    }
    Ok(snapshots)
}

pub fn restore_candidate_receipts(
    snapshots: &[FileSnapshot],
) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let mut errors = Vec::new();

    for snap in snapshots {
        let path = &snap.path;
        let prior_state = &snap.state;

        if let Err(e) = verify_no_symlink_ancestors(path) {
            errors.push(e);
            continue;
        }

        let parent = match path.parent() {
            Some(p) => p,
            None => {
                errors.push(format!("Invalid receipt path with no parent: {}", path.display()));
                continue;
            }
        };

        let dir = match open_dir_nofollow_stepwise_ext(parent, prior_state.is_some()) {
            Ok(Some(fd)) => fd,
            Ok(None) => {
                // ENOENT when prior_state.is_none() and create_missing is false
                continue;
            }
            Err(e) => {
                errors.push(format!("Failed to open directory stepwise {}: {}", parent.display(), e));
                continue;
            }
        };
        let dir_fd = dir.as_raw_fd();

        let file_name = match path.file_name() {
            Some(f) => f.to_string_lossy().to_string(),
            None => {
                errors.push(format!("Receipt path has no file name: {}", path.display()));
                continue;
            }
        };
        let file_cstr = match CString::new(file_name.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("CString error: {}", e));
                continue;
            }
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_rc = unsafe {
            libc::fstatat(dir_fd, file_cstr.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
        };
        if stat_rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            if prior_state.is_some() {
                errors.push(format!(
                    "Refusing to overwrite directory at receipt path {}",
                    path.display()
                ));
                continue;
            }
        }

        if let Some(entry) = prior_state {
            let tmp_name = format!(".af-receipt-tmp-{}-{}", std::process::id(), uuid::Uuid::new_v4());
            let tmp_cstr = match CString::new(tmp_name.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("CString error: {}", e));
                    continue;
                }
            };

            // Create temporary file with mode 0o600 so it is never world-readable even briefly before fchmod/fchown
            let fd = unsafe {
                libc::openat(
                    dir_fd,
                    tmp_cstr.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                errors.push(format!(
                    "Failed to create temporary file for receipt restoration {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let mut written = 0;
            let mut write_err: Option<std::io::Error> = None;
            while written < entry.bytes.len() {
                let n = unsafe {
                    libc::write(
                        fd,
                        entry.bytes[written..].as_ptr() as *const libc::c_void,
                        entry.bytes.len() - written,
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    write_err = Some(err);
                    break;
                }
                written += n as usize;
            }

            if let Some(err) = write_err {
                unsafe {
                    libc::close(fd);
                    libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                };
                errors.push(format!(
                    "Failed to write receipt bytes to {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            // Restore original ownership via fchown
            let current_uid = unsafe { libc::geteuid() };
            let current_gid = unsafe { libc::getegid() };
            if current_uid == 0 || entry.uid != current_uid || entry.gid != current_gid {
                let chown_rc = unsafe { libc::fchown(fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
                if chown_rc != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe {
                        libc::close(fd);
                        libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                    };
                    errors.push(format!(
                        "Failed to restore ownership (uid={}, gid={}) on {}: {}",
                        entry.uid, entry.gid, path.display(), err
                    ));
                    continue;
                }
            }

            // Restore original permissions via fchmod AFTER fchown (since fchown can clear special bits)
            let target_mode = (entry.mode & 0o7777) as libc::mode_t;
            let chmod_rc = unsafe { libc::fchmod(fd, target_mode) };
            if chmod_rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                    libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                };
                errors.push(format!(
                    "Failed to restore permissions ({:#o}) on {}: {}",
                    target_mode, path.display(), err
                ));
                continue;
            }

            let sync_rc = unsafe { libc::fsync(fd) };
            let close_rc = unsafe { libc::close(fd) };

            if sync_rc != 0 || close_rc != 0 {
                unsafe { libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to fsync or close receipt fd for {}",
                    path.display()
                ));
                continue;
            }

            let rename_rc = unsafe {
                libc::renameat(dir_fd, tmp_cstr.as_ptr(), dir_fd, file_cstr.as_ptr())
            };
            if rename_rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to atomically rename receipt {} into place: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        } else {
            let unlink_rc = unsafe { libc::unlinkat(dir_fd, file_cstr.as_ptr(), 0) };
            if unlink_rc != 0 {
                let err = std::io::Error::last_os_error();
                let raw_err = err.raw_os_error();
                if raw_err == Some(libc::EISDIR) || raw_err == Some(libc::EPERM) {
                    let rmdir_rc = unsafe { libc::unlinkat(dir_fd, file_cstr.as_ptr(), libc::AT_REMOVEDIR) };
                    if rmdir_rc != 0 {
                        let rmdir_err = std::io::Error::last_os_error();
                        if rmdir_err.raw_os_error() != Some(libc::ENOENT) {
                            errors.push(format!("Failed to remove directory at receipt path {}: {}", path.display(), rmdir_err));
                        }
                    }
                } else if raw_err != Some(libc::ENOENT) {
                    errors.push(format!("Failed to unlink receipt {}: {}", path.display(), err));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}

fn spawn_bounded_pipe_reader<R>(
    pipe: Option<R>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tx: std::sync::mpsc::SyncSender<Vec<u8>>,
)
where
    R: std::io::Read + std::os::unix::io::AsRawFd + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        const MAX_PROBE_OUTPUT_BYTES: usize = 65536;
        if let Some(pipe) = pipe {
            #[cfg(unix)]
            {
                use std::sync::atomic::Ordering;
                let fd = pipe.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                    if flags >= 0 {
                        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
                let mut scratch = [0u8; 4096];
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                };
                loop {
                    if stop.load(Ordering::Relaxed) {
                        loop {
                            let n = unsafe {
                                libc::read(fd, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len())
                            };
                            if n > 0 {
                                let to_take = (MAX_PROBE_OUTPUT_BYTES - buf.len()).min(n as usize);
                                if to_take > 0 {
                                    buf.extend_from_slice(&scratch[..to_take]);
                                }
                            } else {
                                break;
                            }
                        }
                        break;
                    }

                    let ret = unsafe { libc::poll(&mut pfd, 1, 25) };
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        break;
                    }
                    if ret > 0 {
                        let mut eof = false;
                        loop {
                            let n = unsafe {
                                libc::read(fd, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len())
                            };
                            if n > 0 {
                                let to_take = (MAX_PROBE_OUTPUT_BYTES - buf.len()).min(n as usize);
                                if to_take > 0 {
                                    buf.extend_from_slice(&scratch[..to_take]);
                                }
                            } else if n == 0 {
                                eof = true;
                                break;
                            } else {
                                let err = std::io::Error::last_os_error();
                                if err.raw_os_error() == Some(libc::EAGAIN)
                                    || err.raw_os_error() == Some(libc::EWOULDBLOCK)
                                {
                                    break;
                                }
                                if err.raw_os_error() == Some(libc::EINTR) {
                                    continue;
                                }
                                eof = true;
                                break;
                            }
                        }
                        if eof || (pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0) {
                            break;
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                use std::io::Read;
                let mut pipe = pipe;
                let _ = pipe.by_ref().take(MAX_PROBE_OUTPUT_BYTES as u64).read_to_end(&mut buf);
            }
        }
        let _ = tx.send(buf);
    });
}

#[cfg(test)]
pub static INJECT_WAITID_EPERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
pub(crate) fn is_process_zombie_linux(pid: i32) -> bool {
    let stat_path = format!("/proc/{}/stat", pid);
    if let Ok(contents) = std::fs::read_to_string(&stat_path) {
        if let Some(idx) = contents.rfind(')') {
            let rest = contents[idx + 1..].trim_start();
            if let Some(ch) = rest.chars().next() {
                return ch == 'Z';
            }
        }
    }
    false
}

pub fn run_bounded_probe_command_cancellable<F>(
    cmd: &mut std::process::Command,
    timeout: Duration,
    mut is_cancelled: F,
) -> Result<std::process::Output, String>
where
    F: FnMut() -> bool,
{
    use std::process::Stdio;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn probe command: {}", e))?;
    #[cfg(unix)]
    let pgid = child.id() as i32;

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stop_reading = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (stdout_tx, stdout_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let (stderr_tx, stderr_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);

    spawn_bounded_pipe_reader(stdout_pipe, stop_reading.clone(), stdout_tx);
    spawn_bounded_pipe_reader(stderr_pipe, stop_reading.clone(), stderr_tx);

    let start = std::time::Instant::now();
    let mut exit_status = None;
    let mut child_exited = false;
    let poll_interval = Duration::from_millis(15);

    while start.elapsed() < timeout {
        if is_cancelled() {
            #[cfg(unix)]
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
                libc::kill(pgid, libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
            let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
            return Err("probe command cancelled".to_string());
        }

        #[cfg(unix)]
        {
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waitid_res = {
                #[cfg(test)]
                if INJECT_WAITID_EPERM.load(std::sync::atomic::Ordering::SeqCst) {
                    -1
                } else {
                    unsafe {
                        libc::waitid(
                            libc::P_PID,
                            pgid as libc::id_t,
                            &mut siginfo,
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                        )
                    }
                }
                #[cfg(not(test))]
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pgid as libc::id_t,
                        &mut siginfo,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                }
            };
            let waitid_pid = unsafe { siginfo.si_pid() };
            if waitid_res == 0 && waitid_pid == pgid {
                child_exited = true;
                break;
            } else if waitid_res != 0 {
                let errno = if waitid_res == -1 {
                    #[cfg(test)]
                    if INJECT_WAITID_EPERM.load(std::sync::atomic::Ordering::SeqCst) {
                        libc::EPERM
                    } else {
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                    }
                    #[cfg(not(test))]
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                };
                if errno == libc::EINTR {
                    std::thread::sleep(poll_interval);
                    continue;
                }

                #[cfg(target_os = "linux")]
                {
                    if is_process_zombie_linux(pgid) {
                        // Leader exited but is still an unreaped zombie holding the PID/PGID.
                        // Kill all descendant processes in the process group BEFORE reaping the leader!
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        match child.wait() {
                            Ok(status) => {
                                exit_status = Some(status);
                                child_exited = true;
                                break;
                            }
                            Err(e) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                                let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                                return Err(format!("error waiting for probe child: {}", e));
                            }
                        }
                    } else if !std::path::Path::new("/proc").exists() {
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        match child.wait() {
                            Ok(status) => {
                                exit_status = Some(status);
                                child_exited = true;
                                break;
                            }
                            Err(e) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                                let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                                return Err(format!("error waiting for probe child: {}", e));
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                    match child.wait() {
                        Ok(status) => {
                            exit_status = Some(status);
                            child_exited = true;
                            break;
                        }
                        Err(e) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                            let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                            let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                            return Err(format!("error waiting for probe child: {}", e));
                        }
                    }
                }
            }
            std::thread::sleep(poll_interval);
        }
        #[cfg(not(unix))]
        {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    child_exited = true;
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = stdout_rx.recv_timeout(Duration::from_millis(100));
                    let _ = stderr_rx.recv_timeout(Duration::from_millis(100));
                    return Err(format!("error waiting for probe child: {}", e));
                }
            }
        }
    }

    let timed_out = !child_exited;
    let status = if timed_out {
        #[cfg(unix)]
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
            libc::kill(pgid, libc::SIGKILL);
        }
        let _ = child.kill();
        child.wait().map_err(|e| format!("failed waiting for child after kill: {}", e))?
    } else {
        #[cfg(unix)]
        if exit_status.is_none() {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        match exit_status {
            Some(s) => s,
            None => child.wait().map_err(|e| format!("failed waiting for child: {}", e))?,
        }
    };

    stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);

    let stdout = stdout_rx.recv_timeout(Duration::from_millis(100)).unwrap_or_default();
    let stderr = stderr_rx.recv_timeout(Duration::from_millis(100)).unwrap_or_default();

    if timed_out {
        return Err(format!("probe command timed out after {:?}", timeout));
    }

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

pub fn run_bounded_probe_command(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    run_bounded_probe_command_cancellable(cmd, timeout, || false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveRuntimeProbeOutcome {
    Verified(String),
    Failed(String),
    NotConfigured,
}

pub use LiveRuntimeProbeOutcome::Verified as Confirmed;

pub fn has_prerelease_or_build(token: &str) -> bool {
    if let Some(pos) = token.find(|c: char| c == '-' || c == '+') {
        token[pos + 1..].chars().any(|c| c.is_ascii_alphanumeric() || c == '-')
    } else {
        false
    }
}

pub fn has_prerelease_or_build_with_alnum(token: &str) -> bool {
    has_prerelease_or_build(token)
}

pub fn trim_version_token(raw_token: &str) -> &str {
    let mut s = raw_token.trim();
    loop {
        let trimmed_punct = s.trim_end_matches(['.', ',', ';', ':', ')', ']', '"', '\'']);
        if trimmed_punct.len() < s.len() {
            s = trimmed_punct;
            continue;
        }
        if s.ends_with('+') {
            s = s.trim_end_matches('+');
            continue;
        }
        if s.ends_with('-') && !has_prerelease_or_build(s) {
            s = s.trim_end_matches('-');
            continue;
        }
        break;
    }
    s
}

pub fn extract_version_token(raw: &str) -> String {
    static DOTTED_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
    });
    static DEFAULT_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
    });
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(caps) = DOTTED_VERSION_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return trim_version_token(m.as_str()).to_string();
        }
    }
    for line in trimmed.lines() {
        let line_trim = line.trim();
        if let Some(caps) = DOTTED_VERSION_RE.captures(line_trim) {
            if let Some(m) = caps.get(1) {
                return trim_version_token(m.as_str()).to_string();
            }
        }
    }
    if let Some(caps) = DEFAULT_VERSION_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return trim_version_token(m.as_str()).to_string();
        }
        if let Some(m) = caps.get(0) {
            return trim_version_token(m.as_str()).to_string();
        }
    }
    trim_version_token(trimmed).to_string()
}

pub fn probe_live_runtime_version(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> LiveRuntimeProbeOutcome {
    // 0. 3-repo live git probe for piped: check frontend, backend, and proxy sub-repos
    if package_id.eq_ignore_ascii_case("piped") {
        let find_git_dir = |primary_sub: &str, fallback_sub: &str| -> Option<std::path::PathBuf> {
            if let Ok(p) = env_cfg.resolve_path(primary_sub) {
                let git = p.join(".git");
                if git.exists() {
                    return Some(git);
                }
            }
            if let Ok(p) = env_cfg.resolve_path(fallback_sub) {
                let git = p.join(".git");
                if git.exists() {
                    return Some(git);
                }
            }
            None
        };

        let fe_dir = find_git_dir("/opt/piped/frontend", "/opt/piped");
        let be_dir = find_git_dir("/opt/piped/backend", "/opt/piped-backend");
        let pr_dir = find_git_dir("/opt/piped/proxy", "/opt/piped-proxy");

        let any_exists = fe_dir.is_some() || be_dir.is_some() || pr_dir.is_some();
        if any_exists {
            if let (Some(fe), Some(be), Some(pr)) = (fe_dir, be_dir, pr_dir) {
                let rev_parse = |git_dir: &std::path::Path| -> Option<String> {
                    let mut cmd = std::process::Command::new("git");
                    cmd.args(["--git-dir", &git_dir.to_string_lossy(), "rev-parse", "HEAD"]);
                    let out = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)).ok()?;
                    if out.status.success() {
                        let hash = String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase();
                        if !hash.is_empty() {
                            return Some(hash);
                        }
                    }
                    None
                };
                if let (Some(fe_hash), Some(be_hash), Some(pr_hash)) = (
                    rev_parse(&fe),
                    rev_parse(&be),
                    rev_parse(&pr),
                ) {
                    return LiveRuntimeProbeOutcome::Verified(format!(
                        "frontend:{fe_hash},backend:{be_hash},proxy:{pr_hash}"
                    ));
                } else {
                    return LiveRuntimeProbeOutcome::Failed(
                        "Piped git rev-parse HEAD failed for one or more sub-repos".into(),
                    );
                }
            } else {
                return LiveRuntimeProbeOutcome::Failed(
                    "Piped partial git checkouts detected: expected frontend, backend, and proxy".into(),
                );
            }
        } else {
            return LiveRuntimeProbeOutcome::Failed(
                "Piped git repositories missing: expected frontend, backend, and proxy in /opt/piped".into(),
            );
        }
    }

    // 1. version_command from package definition
    let pkg = match package_definition(package_id) {
        Ok(pkg) => pkg,
        Err(e) => {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Failed to load package definition for live probe: {}",
                e
            ));
        }
    };


    let is_cat_receipt = pkg.version_command.len() == 2
        && pkg.version_command[0] == "cat"
        && pkg.version_command[1].ends_with("/.af-version");

    if !pkg.version_command.is_empty() && !is_cat_receipt {
        let prog = &pkg.version_command[0];
        let args = &pkg.version_command[1..];
        let prog_to_run = if let Ok(resolved_prog) = env_cfg.resolve_path(prog) {
            if resolved_prog.exists() {
                resolved_prog.to_string_lossy().to_string()
            } else {
                prog.clone()
            }
        } else if let Some(root) = &env_cfg.fs_root {
            let mut found = None;
            for bin_dir in ["usr/bin", "usr/local/bin", "bin"] {
                let candidate = root.join(bin_dir).join(prog);
                if candidate.exists() {
                    found = Some(candidate.to_string_lossy().to_string());
                    break;
                }
            }
            found.unwrap_or_else(|| prog.clone())
        } else {
            prog.clone()
        };

        let mut cmd = std::process::Command::new(&prog_to_run);
        cmd.args(args);
        if let Some(ref root) = env_cfg.fs_root {
            cmd.env("AETHERFLOW_FS_ROOT", root);
        }

        match run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
            Ok(output) => {
                if output.status.success() {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let mut extracted = if !pkg.version_regex.is_empty() {
                        if let Ok(re) = regex::Regex::new(&pkg.version_regex) {
                            re.captures(&combined)
                                .and_then(|cap| {
                                    cap.get(1)
                                        .or_else(|| cap.get(0))
                                        .map(|m| m.as_str().trim().to_string())
                                })
                                .unwrap_or_default()
                        } else {
                            extract_version_token(combined.lines().next().unwrap_or("").trim())
                        }
                    } else {
                        extract_version_token(combined.lines().next().unwrap_or("").trim())
                    };
                    if let Some(stripped) = extracted.strip_prefix('v').or_else(|| extracted.strip_prefix('V')) {
                        if stripped.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                            extracted = stripped.to_string();
                        }
                    }
                    if !extracted.is_empty() {
                        return LiveRuntimeProbeOutcome::Verified(extracted);
                    } else {
                        return LiveRuntimeProbeOutcome::Failed(
                            "Version command produced no output matching regex".into(),
                        );
                    }
                } else {
                    return LiveRuntimeProbeOutcome::Failed(format!(
                        "Version command exited with status: {}",
                        output.status
                    ));
                }
            }
            Err(e) => {
                return LiveRuntimeProbeOutcome::Failed(format!(
                    "Failed to execute version command '{}': {}",
                    prog_to_run, e
                ));
            }
        }
    }

    // 2. Live git `rev-parse HEAD` in `/opt/<pkg>/source` or `/opt/<pkg>` (e.g. invidious, git packages)
    if !package_id.eq_ignore_ascii_case("piped") {
        let is_git_package = pkg.update_source.eq_ignore_ascii_case("git_tags")
            || pkg.update_source.eq_ignore_ascii_case("git")
            || !pkg.update_repo_url.is_empty();

        let mut candidates = Vec::new();
        for dir_cand in [
            format!("/opt/{}/source", package_id),
            format!("/opt/{}/source", package_id.to_lowercase()),
            format!("/opt/{}", package_id),
            format!("/opt/{}", package_id.to_lowercase()),
        ] {
            if let Ok(resolved) = env_cfg.resolve_path(&dir_cand) {
                let git = resolved.join(".git");
                if git.exists() && !candidates.contains(&resolved) {
                    candidates.push(resolved);
                }
            }
        }
        if let Some(opt_dir) = candidates.into_iter().next() {
            let mut cmd = std::process::Command::new("git");
            cmd.arg("-C").arg(&opt_dir).args(["rev-parse", "HEAD"]);
            match run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                Ok(output) if output.status.success() => {
                    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !hash.is_empty() {
                        return LiveRuntimeProbeOutcome::Verified(hash);
                    } else {
                        return LiveRuntimeProbeOutcome::Failed("Git rev-parse returned empty hash".into());
                    }
                }
                Ok(output) => {
                    return LiveRuntimeProbeOutcome::Failed(format!(
                        "Git rev-parse exited with status: {}",
                        output.status
                    ));
                }
                Err(e) => {
                    return LiveRuntimeProbeOutcome::Failed(format!("Failed to run git rev-parse: {}", e));
                }
            }
        } else if is_git_package {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Package '{}' has git update source, but no valid git checkout exists in /opt",
                package_id
            ));
        }
    }

    // 3. Binary or dpkg version
    let is_apt = pkg.update_source.eq_ignore_ascii_case("apt");

    let mut pkg_names = Vec::new();
    if !pkg.update_package.is_empty() {
        pkg_names.push(pkg.update_package.clone());
    }
    pkg_names.push(package_id.to_string());
    pkg_names.push(pkg.name.clone());
    pkg_names.push(pkg.service_name.clone());

    for name in &pkg_names {
        if name.is_empty() {
            continue;
        }
        let mut cmd = std::process::Command::new("dpkg-query");
        cmd.args(["-W", "-f=${Version}\n", name]);
        if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
            if output.status.success() {
                let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ver.is_empty() {
                    return LiveRuntimeProbeOutcome::Verified(ver);
                }
            }
        }
    }

    // If dpkg-query didn't find the package, check if an executable binary exists on disk
    let mut candidate_progs = Vec::new();
    if !pkg.update_package.is_empty() {
        candidate_progs.push(pkg.update_package.clone());
    }
    candidate_progs.push(package_id.to_string());
    candidate_progs.push(pkg.name.clone());

    for prog_cand in &candidate_progs {
        let bin_path = if let Some(root) = &env_cfg.fs_root {
            let mut found = None;
            for dir in ["usr/bin", "usr/local/bin", "bin", "opt"] {
                let p = root.join(dir).join(prog_cand);
                if p.is_file() {
                    found = Some(p);
                    break;
                }
            }
            found
        } else {
            let mut found = None;
            for dir in ["/usr/bin", "/usr/local/bin", "/bin"] {
                let p = Path::new(dir).join(prog_cand);
                if p.is_file() {
                    found = Some(p);
                    break;
                }
            }
            found
        };

        if let Some(bin) = bin_path {
            let mut cmd = std::process::Command::new(&bin);
            cmd.arg("--version");
            if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                if output.status.success() {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let re = regex::Regex::new(
                        r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:[0-9]+:)?[0-9]+\.[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z.+~_-]+)?(?:-[0-9A-Za-z.+~_-]+)?(?:\+[0-9A-Za-z.+~_-]+)?|\b[0-9a-f]{7,40}\b)"
                    ).unwrap();
                    if let Some(cap) = re.captures(&combined) {
                        if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                            let extracted = trim_version_token(m.as_str()).to_string();
                            if !extracted.is_empty() {
                                return LiveRuntimeProbeOutcome::Verified(extracted);
                            }
                        }
                    }
                }
            }
        }
    }

    if is_apt {
        return LiveRuntimeProbeOutcome::Failed(format!(
            "Package '{}' is configured with apt update_source, but dpkg-query failed to resolve its version",
            package_id
        ));
    }

    LiveRuntimeProbeOutcome::NotConfigured
}

pub fn read_af_version_receipt(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Option<String> {
    if let Some(recipe) = crate::package_executor::get_declarative_recipe(package_id) {
        if let Some(vf) = crate::package_executor::recipe_version_file_logical_path(&recipe) {
            if let Ok(p) = env_cfg.resolve_path(&vf) {
                if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                    if let Ok(raw) = String::from_utf8(bytes) {
                        let t = raw.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
        }
    }
    if package_id.eq_ignore_ascii_case("filebot") {
        for candidate in [
            "/opt/filebot-node/.af-version",
            "/var/lib/filebot/.af-version",
            "/etc/filebot/.af-version",
        ] {
            if let Ok(p) = env_cfg.resolve_path(candidate) {
                if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                    if let Ok(raw) = String::from_utf8(bytes) {
                        let t = raw.trim().to_string();
                        if !t.is_empty() {
                            return Some(t);
                        }
                    }
                }
            }
        }
        return None;
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        let candidate = format!("{}/{}/.af-version", prefix, package_id);
        if let Ok(p) = env_cfg.resolve_path(&candidate) {
            if let Ok(Some(bytes)) = read_receipt_bounded_nofollow(&p) {
                if let Ok(raw) = String::from_utf8(bytes) {
                    let t = raw.trim().to_string();
                    if !t.is_empty() {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

fn is_regular_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o111) != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        Err(_) => false,
    }
}

fn tokenize_systemd_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' && !in_single {
            escaped = true;
        } else if ch == '\'' && !in_double {
            in_single = !in_single;
        } else if ch == '"' && !in_single {
            in_double = !in_double;
        } else if ch.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn validate_systemd_unit_runtime_evidence(
    content: &str,
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> bool {
    let mut working_dir: Option<PathBuf> = None;
    let mut exec_commands: Vec<String> = Vec::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_string();
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            if key == "WorkingDirectory" {
                if current_section == "Service" {
                    let v = val.trim().trim_matches('"').trim_matches('\'');
                    if !v.is_empty() {
                        working_dir = Some(PathBuf::from(v));
                    }
                }
                continue;
            }
            if key == "ExecStart" {
                if current_section != "Service" {
                    // ExecStart outside [Service] is invalid in systemd service units. Fail closed immediately.
                    return false;
                }
                let rhs = val.trim();
                if rhs.is_empty() {
                    exec_commands.clear();
                } else {
                    exec_commands.push(rhs.to_string());
                }
                continue;
            }
        }
    }

    if exec_commands.is_empty() {
        return false;
    }

    for cmd in &exec_commands {
        let mut s = cmd.as_str().trim_start();
        while let Some(stripped) = s.strip_prefix(|c| matches!(c, '-' | '@' | '+' | '!' | ':')) {
            s = stripped.trim_start();
        }
        if s.is_empty() {
            return false;
        }
        let tokens = tokenize_systemd_command(s);
        if tokens.is_empty() {
            return false;
        }
        let exec_bin = &tokens[0];
        let resolved_bin = if exec_bin.starts_with('/') {
            let p_cand = env_cfg.resolve_path(exec_bin).ok();
            if let Some(ref p) = p_cand {
                if is_regular_executable(p) {
                    p_cand
                } else if is_regular_executable(Path::new(exec_bin)) {
                    Some(PathBuf::from(exec_bin))
                } else {
                    None
                }
            } else if is_regular_executable(Path::new(exec_bin)) {
                Some(PathBuf::from(exec_bin))
            } else {
                None
            }
        } else {
            let mut found = None;
            for dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
                let full = format!("{}/{}", dir, exec_bin);
                if let Ok(p) = env_cfg.resolve_path(&full) {
                    if is_regular_executable(&p) {
                        found = Some(p);
                        break;
                    }
                }
                if is_regular_executable(Path::new(&full)) {
                    found = Some(PathBuf::from(full));
                    break;
                }
            }
            found
        };

        let Some(bin_path) = resolved_bin else {
            return false;
        };
        if !is_regular_executable(&bin_path) {
            return false;
        }

        let bin_name = Path::new(exec_bin)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(exec_bin)
            .to_ascii_lowercase();

        let is_interpreter = matches!(
            bin_name.as_str(),
            "sh" | "bash" | "dash" | "zsh" | "env" | "python" | "python2" | "python3"
                | "node" | "nodejs" | "java" | "ruby" | "perl" | "php" | "dotnet"
        );

        if is_interpreter {
            let mut script_found = false;
            let mut has_c_flag = false;
            let mut c_command = None;

            let mut idx = 1;
            while idx < tokens.len() {
                let arg = &tokens[idx];
                if arg == "-c" {
                    has_c_flag = true;
                    if idx + 1 < tokens.len() {
                        c_command = Some(&tokens[idx + 1]);
                        idx += 2;
                        continue;
                    }
                } else if arg == "-jar" || arg == "-m" {
                    if idx + 1 < tokens.len() {
                        let target = &tokens[idx + 1];
                        let cand = if target.starts_with('/') {
                            env_cfg.resolve_path(target).ok()
                        } else if let Some(ref wd) = working_dir {
                            wd.join(target).to_str().and_then(|s| env_cfg.resolve_path(s).ok())
                        } else {
                            None
                        };
                        if let Some(target_p) = cand {
                            if !std::fs::symlink_metadata(&target_p)
                                .map(|m| m.file_type().is_file())
                                .unwrap_or(false)
                            {
                                return false;
                            }
                            script_found = true;
                        } else {
                            return false;
                        }
                        idx += 2;
                        continue;
                    }
                } else if !arg.starts_with('-') {
                    let cand = if arg.starts_with('/') {
                        env_cfg.resolve_path(arg).ok()
                    } else if let Some(ref wd) = working_dir {
                        wd.join(arg).to_str().and_then(|s| env_cfg.resolve_path(s).ok())
                    } else {
                        None
                    };
                    if let Some(target_p) = cand {
                        if !std::fs::symlink_metadata(&target_p)
                            .map(|m| m.file_type().is_file())
                            .unwrap_or(false)
                        {
                            return false;
                        }
                        script_found = true;
                        break;
                    }
                }
                idx += 1;
            }

            if !script_found {
                if has_c_flag {
                    let mut found_file = false;
                    if let Some(cmd_str) = c_command {
                        let c_tokens = tokenize_systemd_command(cmd_str);
                        for tok in &c_tokens {
                            if tok.starts_with('/') {
                                if let Ok(tp) = env_cfg.resolve_path(tok) {
                                    if std::fs::symlink_metadata(&tp)
                                        .map(|m| m.file_type().is_file())
                                        .unwrap_or(false)
                                    {
                                        found_file = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !found_file {
                        let mut app_has_exec = false;
                        for cand_dir in [
                            format!("/opt/{}", package_id),
                            format!("/opt/{}", package_id.to_lowercase()),
                        ] {
                            if let Ok(ap) = env_cfg.resolve_path(&cand_dir) {
                                if ap.is_dir() {
                                    if let Ok(entries) = std::fs::read_dir(&ap) {
                                        for entry in entries.flatten() {
                                            if is_regular_executable(&entry.path()) {
                                                app_has_exec = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if app_has_exec {
                                break;
                            }
                        }
                        if !app_has_exec {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
        }
    }

    true
}

fn is_executable_regular_file(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                (meta.permissions().mode() & 0o111) != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        Err(_) => false,
    }
}

pub fn has_independent_runtime_evidence(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> bool {
    let lower_id = package_id.to_lowercase();

    // 1. Installed systemd unit file for the package's systemd services or <pkg>.service
    let mut unit_candidates = vec![
        format!("{}.service", package_id),
        format!("{}.service", lower_id),
    ];
    if let Ok(units) = package_service_units(package_id) {
        for u in units {
            let u_name = if u.ends_with(".service") { u } else { format!("{}.service", u) };
            if !unit_candidates.contains(&u_name) {
                unit_candidates.push(u_name);
            }
        }
    }
    for unit in &unit_candidates {
        for prefix in ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"] {
            let unit_path = format!("{}/{}", prefix, unit);
            if let Ok(p) = env_cfg.resolve_path(&unit_path) {
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.is_file() {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            if validate_systemd_unit_runtime_evidence(&content, package_id, env_cfg) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Executable regular file at /usr/local/bin/<pkg>, /usr/bin/<pkg>, /bin/<pkg>, or inside /opt/<pkg>
    for prog in [package_id, &lower_id] {
        for dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
            let bin_path = format!("{}/{}", dir, prog);
            if let Ok(p) = env_cfg.resolve_path(&bin_path) {
                if is_executable_regular_file(&p) {
                    return true;
                }
            }
        }
    }

    // Scan /opt/<pkg> and /opt/<lower_id> for executable regular files (excluding .af-*, *.lock, *.tmp, *.log, *.pid, *.bak)
    for opt_name in [package_id, &lower_id] {
        for opt_sub in [
            format!("/opt/{}", opt_name),
            format!("/opt/{}/bin", opt_name),
            format!("/opt/{}/current", opt_name),
            format!("/opt/{}/current/bin", opt_name),
        ] {
            if let Ok(p) = env_cfg.resolve_path(&opt_sub) {
                if p.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(&p) {
                        for entry in entries.flatten() {
                            let fname = entry.file_name();
                            let fname_str = fname.to_string_lossy();
                            if fname_str.starts_with(".af-")
                                || fname_str.ends_with(".lock")
                                || fname_str.ends_with(".tmp")
                                || fname_str.ends_with(".log")
                                || fname_str.ends_with(".pid")
                                || fname_str.ends_with(".bak")
                            {
                                continue;
                            }
                            if is_executable_regular_file(&entry.path()) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. When apt_package is configured, verified dpkg-query "install ok installed" status
    if let Ok(pkg) = package_definition(package_id) {
        if pkg.update_source.eq_ignore_ascii_case("apt") || !pkg.update_package.is_empty() {
            let apt_name = if !pkg.update_package.is_empty() {
                &pkg.update_package
            } else {
                package_id
            };
            let mut cmd = std::process::Command::new("dpkg-query");
            cmd.args(["-W", "-f=${Status}\n", apt_name]);
            if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                if output.status.success() {
                    let out = String::from_utf8_lossy(&output.stdout);
                    if out.trim() == "install ok installed" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn resolve_verified_installed_version(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Option<String> {
    resolve_verified_installed_version_with_prober(
        package_id,
        env_cfg,
        probe_live_runtime_version,
        read_af_version_receipt,
    )
}

pub fn resolve_verified_installed_version_with_prober<FProbe, FReceipt>(
    package_id: &str,
    env_cfg: &crate::PackageExecutionEnv,
    probe_fn: FProbe,
    receipt_fn: FReceipt,
) -> Option<String>
where
    FProbe: Fn(&str, &crate::PackageExecutionEnv) -> LiveRuntimeProbeOutcome,
    FReceipt: Fn(&str, &crate::PackageExecutionEnv) -> Option<String>,
{
    let live_outcome = probe_fn(package_id, env_cfg);
    let receipt_opt = receipt_fn(package_id, env_cfg);

    match live_outcome {
        LiveRuntimeProbeOutcome::Failed(reason) => {
            tracing::warn!(
                package = %package_id,
                reason = %reason,
                "Configured live runtime probe failed; refusing to certify installed version"
            );
            None
        }
        LiveRuntimeProbeOutcome::Verified(live_ver) => {
            if let Some(receipt_ver) = receipt_opt {
                if !af_release::lifecycle::versions_match_target(&receipt_ver, &live_ver)
                    && !af_release::lifecycle::versions_match_target(&live_ver, &receipt_ver)
                {
                    tracing::warn!(
                        package = %package_id,
                        live = %live_ver,
                        receipt = %receipt_ver,
                        "Live runtime probe disagrees with .af-version receipt; treating as stale receipt"
                    );
                    None
                } else {
                    Some(live_ver)
                }
            } else {
                Some(live_ver)
            }
        }
        LiveRuntimeProbeOutcome::NotConfigured => {
            // Only use .af-version alone when package has independent app-specific runtime evidence on disk
            if let Some(receipt_ver) = receipt_opt {
                if has_independent_runtime_evidence(package_id, env_cfg) {
                    Some(receipt_ver)
                } else {
                    tracing::warn!(
                        package = %package_id,
                        receipt = %receipt_ver,
                        "Refusing to certify package version based on receipt alone: no independent runtime evidence found on disk"
                    );
                    None
                }
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod version_verification_tests {
    use super::*;
    use std::sync::Arc;

    static ENV_TEST_MUTEX: once_cell::sync::Lazy<std::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

    #[test]
    fn test_stale_af_version_receipt_against_older_live_runtime_fails_certification() {
        let env_cfg = crate::PackageExecutionEnv::default();
        let target = "2.5.0";

        // Scenario 1: Stale .af-version receipt was written with "2.5.0" (matching target),
        // but the live runtime probe still returns older "2.4.0".
        // Certification MUST fail because live runtime and receipt disagree.
        let live_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
            LiveRuntimeProbeOutcome::Verified("2.4.0".to_string())
        };
        let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());

        let resolved = resolve_verified_installed_version_with_prober(
            "sonarr",
            &env_cfg,
            live_probe,
            receipt_probe,
        );
        assert_eq!(
            resolved, None,
            "Disagreement between live probe (2.4.0) and receipt (2.5.0) must reject receipt as stale"
        );

        let matches_target = resolved
            .as_deref()
            .map(|ver| af_release::lifecycle::versions_match_target(ver, target))
            .unwrap_or(false);
        assert!(!matches_target, "Certification must fail on stale receipt!");

        // Scenario 2: Live git rev-parse HEAD returns older commit while receipt claims new commit
        let live_git = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
            LiveRuntimeProbeOutcome::Verified("1111111111111111".to_string())
        };
        let receipt_git = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2222222222222222".to_string());
        let resolved_git = resolve_verified_installed_version_with_prober(
            "lidarr",
            &env_cfg,
            live_git,
            receipt_git,
        );
        assert_eq!(
            resolved_git, None,
            "Disagreement between live git commit and receipt must reject certification"
        );

        // Scenario 3: When live probe and receipt agree on "2.5.0", certification passes
        let live_ok = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
            LiveRuntimeProbeOutcome::Verified("2.5.0".to_string())
        };
        let receipt_ok = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
        let resolved_ok = resolve_verified_installed_version_with_prober(
            "sonarr",
            &env_cfg,
            live_ok,
            receipt_ok,
        );
        assert_eq!(resolved_ok, Some("2.5.0".to_string()));
        assert!(af_release::lifecycle::versions_match_target(resolved_ok.as_deref().unwrap(), target));

        // Scenario 4: When no live runtime probe is available, .af-version alone is rejected without independent runtime evidence, and accepted with evidence
        let live_none = |_pkg: &str, _env: &crate::PackageExecutionEnv| LiveRuntimeProbeOutcome::NotConfigured;
        let receipt_only = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
        let resolved_none = resolve_verified_installed_version_with_prober(
            "custompkg",
            &env_cfg,
            live_none,
            receipt_only,
        );
        assert_eq!(resolved_none, None, "Without independent runtime evidence on disk, receipt-only certification must be rejected");

        let temp_dir_sc4 = std::env::temp_dir().join(format!("af-test-sc4-evidence-{}", uuid::Uuid::new_v4()));
        let mut env_cfg_sc4 = crate::PackageExecutionEnv::default();
        env_cfg_sc4.fs_root = Some(temp_dir_sc4.clone());
        let payload_file = temp_dir_sc4.join("opt/custompkg/app.bin");
        std::fs::create_dir_all(payload_file.parent().unwrap()).unwrap();
        std::fs::write(&payload_file, b"runtime-payload").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&payload_file, std::fs::Permissions::from_mode(0o755));
        }

        let resolved_with_evidence = resolve_verified_installed_version_with_prober(
            "custompkg",
            &env_cfg_sc4,
            live_none,
            receipt_only,
        );
        assert_eq!(resolved_with_evidence, Some("2.5.0".to_string()), "With independent runtime evidence on disk, receipt is accepted");
        let _ = std::fs::remove_dir_all(&temp_dir_sc4);

        // Scenario 5: Configured live probe fails -> certification MUST fail even if .af-version matches target
        let live_failed = |_pkg: &str, _env: &crate::PackageExecutionEnv| {
            LiveRuntimeProbeOutcome::Failed("Probe timeout or binary missing".to_string())
        };
        let receipt_matches = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("2.5.0".to_string());
        let resolved_failed = resolve_verified_installed_version_with_prober(
            "invidious",
            &env_cfg,
            live_failed,
            receipt_matches,
        );
        assert_eq!(
            resolved_failed, None,
            "Failed live probe must fail-closed and NEVER fall back to receipt"
        );
    }

    #[test]
    fn test_piped_live_probe_three_components() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-piped-runner-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let init_repo = |dir: &Path| -> String {
            std::fs::create_dir_all(dir).unwrap();
            let _ = std::process::Command::new("git").args(["init", "-b", "main"]).current_dir(dir).output();
            let _ = std::process::Command::new("git").args(["config", "user.email", "t@e.com"]).current_dir(dir).output();
            let _ = std::process::Command::new("git").args(["config", "user.name", "T"]).current_dir(dir).output();
            std::fs::write(dir.join("f"), "c").unwrap();
            let _ = std::process::Command::new("git").args(["add", "f"]).current_dir(dir).output();
            let _ = std::process::Command::new("git").args(["commit", "-m", "init"]).current_dir(dir).output();
            let out = std::process::Command::new("git").args(["rev-parse", "HEAD"]).current_dir(dir).output().unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase()
        };

        let fe = init_repo(&temp_dir.join("opt/piped/frontend"));
        let be = init_repo(&temp_dir.join("opt/piped/backend"));
        let pr = init_repo(&temp_dir.join("opt/piped/proxy"));

        let live = probe_live_runtime_version("piped", &env_cfg);
        assert_eq!(live, LiveRuntimeProbeOutcome::Verified(format!("frontend:{fe},backend:{be},proxy:{pr}")));

        let receipt_path = temp_dir.join("opt/piped/.af-version");
        std::fs::write(&receipt_path, format!("frontend:{fe},backend:{be},proxy:{pr}")).unwrap();
        let verified = resolve_verified_installed_version("piped", &env_cfg);
        assert_eq!(verified, Some(format!("frontend:{fe},backend:{be},proxy:{pr}")));

        // Mismatched receipt
        std::fs::write(&receipt_path, format!("frontend:{fe},backend:0000000000000000000000000000000000000000,proxy:{pr}")).unwrap();
        let verified_mismatch = resolve_verified_installed_version("piped", &env_cfg);
        assert_eq!(verified_mismatch, None);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_direct_runner_extract_version_token_from_rclone_output() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-rclone-version-token-{}", uuid::Uuid::new_v4()));
        let bin_dir = temp_dir.join("usr/local/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Create a mock rclone script that prints prose like "rclone v1.75.2\n- os/version: linux"
        let script_path = bin_dir.join("rclone");
        std::fs::write(
            &script_path,
            "#!/bin/sh\necho 'rclone v1.75.2'\necho '- os/version: linux'\n",
        ).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        // Keep the production regex, but execute the fixture rather than the
        // catalog's shell command, which names the host's /usr/bin/rclone.
        let packages_path = temp_dir.join("packages.json");
        std::fs::write(&packages_path, crate::EMBEDDED_PACKAGES_JSON).unwrap();
        let mut automation: serde_json::Value =
            serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
        automation["rclone"]["version_command"] =
            serde_json::json!(["/usr/local/bin/rclone", "version"]);
        let automation_path = temp_dir.join("package_automation.json");
        std::fs::write(&automation_path, serde_json::to_vec(&automation).unwrap()).unwrap();
        let previous_packages = std::env::var_os("AETHERFLOW_PACKAGES_CONFIG");
        let previous_automation = std::env::var_os("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &packages_path);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation_path);

        // Probe live runtime version for "rclone"
        let outcome = probe_live_runtime_version("rclone", &env_cfg);
        for (key, previous) in [
            ("AETHERFLOW_PACKAGES_CONFIG", previous_packages),
            ("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", previous_automation),
        ] {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        assert_eq!(
            outcome,
            LiveRuntimeProbeOutcome::Verified("1.75.2".to_string()),
            "probe_live_runtime_version must extract bare token '1.75.2' from 'rclone v1.75.2'"
        );

        // Also test receipt matching target "1.75.2"
        let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("1.75.2".to_string());
        let certified = resolve_verified_installed_version_with_prober(
            "rclone",
            &env_cfg,
            |_pkg, _env| outcome.clone(),
            receipt_probe,
        );
        assert_eq!(certified, Some("1.75.2".to_string()));
        assert!(af_release::lifecycle::versions_match_target(certified.as_deref().unwrap(), "1.75.2"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_catalog_loading_failure_fails_closed_without_certifying_af_version() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-catalog-fail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let malformed_cfg = temp_dir.join("bad_packages.json");
        std::fs::write(&malformed_cfg, "{ this is not valid json }").unwrap();

        // Point AF_PACKAGES_CONFIG to the malformed file
        std::env::set_var("AF_PACKAGES_CONFIG", &malformed_cfg);

        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        // Probe live runtime version: must return Failed(...)
        let outcome = probe_live_runtime_version("sonarr", &env_cfg);
        match &outcome {
            LiveRuntimeProbeOutcome::Failed(reason) => {
                assert!(
                    reason.contains("Failed to load package definition"),
                    "Expected failure reason about package definition, got: {}",
                    reason
                );
            }
            other => panic!("Expected LiveRuntimeProbeOutcome::Failed, got: {:?}", other),
        }

        // Even if .af-version receipt is present with target version "3.0.0", certification MUST fail (return None)
        let receipt_probe = |_pkg: &str, _env: &crate::PackageExecutionEnv| Some("3.0.0".to_string());
        let certified = resolve_verified_installed_version_with_prober(
            "sonarr",
            &env_cfg,
            |_pkg, _env| outcome.clone(),
            receipt_probe,
        );
        assert_eq!(certified, None, "Catalog failure must fail closed and refuse to certify .af-version");

        std::env::remove_var("AF_PACKAGES_CONFIG");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_probe_live_runtime_version_descendant_pipe_drain_does_not_hang() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-pipe-drain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut packages: Vec<serde_json::Value> = serde_json::from_str(crate::EMBEDDED_PACKAGES_JSON).unwrap();
        packages.push(serde_json::json!({
            "name": "probe-pipe-test",
            "label": "Probe Pipe Test",
            "description": "Test package",
            "lock_file": "/install/.probe-pipe-test.lock",
            "category": "Test",
            "service_type": "systemd",
            "service_name": "probe-pipe-test"
        }));
        let pkg_path = temp_dir.join("packages.json");
        std::fs::write(&pkg_path, serde_json::to_string(&packages).unwrap()).unwrap();

        let mut automation: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
        automation.insert(
            "probe-pipe-test".to_string(),
            serde_json::json!({
                "version_command": ["sh", "-c", "echo 1.75.2; sleep 30 &"]
            }),
        );
        let auto_path = temp_dir.join("package_automation.json");
        std::fs::write(&auto_path, serde_json::to_string(&automation).unwrap()).unwrap();

        std::env::set_var("AF_PACKAGES_CONFIG", &pkg_path);
        std::env::set_var("AF_PACKAGE_AUTOMATION_CONFIG", &auto_path);

        let env_cfg = crate::PackageExecutionEnv::default();
        let start = std::time::Instant::now();
        let outcome = probe_live_runtime_version("probe-pipe-test", &env_cfg);
        let elapsed = start.elapsed();

        std::env::remove_var("AF_PACKAGES_CONFIG");
        std::env::remove_var("AF_PACKAGE_AUTOMATION_CONFIG");
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "probe_live_runtime_version took {:?}, expected < 2s without hanging on descendant",
            elapsed
        );
        assert_eq!(
            outcome,
            Confirmed("1.75.2".to_string()),
            "probe_live_runtime_version must return Confirmed(\"1.75.2\")"
        );
    }

    #[test]
    fn test_preserve_complete_prerelease_and_build_identities() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
        // 1. extract_version_token preserves complete identities
        let old_token = extract_version_token("my-tool 1.0.0+build--old (x86_64-linux)");
        let new_token = extract_version_token("my-tool 1.0.0+build--new (x86_64-linux)");
        let debug_token = extract_version_token("my-tool 1.0.0+Debug (x86_64-linux)");
        let alpha_token = extract_version_token("my-tool 1.0.0-alpha--1 (x86_64-linux)");
        let debian_epoch = extract_version_token("Package: 2:1.18.2-1ubuntu1 (amd64)");
        let tilde_rc = extract_version_token("my-tool 1.0.0~rc1-1");

        assert_eq!(old_token, "1.0.0+build--old");
        assert_eq!(new_token, "1.0.0+build--new");
        assert_eq!(debug_token, "1.0.0+Debug");
        assert_eq!(alpha_token, "1.0.0-alpha--1");
        assert_eq!(debian_epoch, "2:1.18.2-1ubuntu1");
        assert_eq!(tilde_rc, "1.0.0~rc1-1");

        assert_ne!(old_token, new_token, "1.0.0+build--old and 1.0.0+build--new must not collapse");
        assert_ne!(debug_token, "1.0.0", "1.0.0+Debug must retain build metadata");
        assert_ne!(old_token, "1.0.0+build", "1.0.0+build--old must not be truncated at --");

        // 2. Generic binary-probe fallback in probe_live_runtime_version
        let temp_dir = std::env::temp_dir().join(format!("af-test-build-meta-{}", uuid::Uuid::new_v4()));
        let bin_dir = temp_dir.join("usr/local/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        let mut packages: Vec<serde_json::Value> = serde_json::from_str(crate::EMBEDDED_PACKAGES_JSON).unwrap();
        packages.push(serde_json::json!({
            "name": "buildmetaapp",
            "label": "Build Meta App",
            "description": "Test package",
            "lock_file": "/install/.buildmetaapp.lock",
            "category": "Test",
            "service_type": "systemd",
            "service_name": "buildmetaapp"
        }));
        let pkg_path = temp_dir.join("packages.json");
        std::fs::write(&pkg_path, serde_json::to_string(&packages).unwrap()).unwrap();
        std::env::set_var("AF_PACKAGES_CONFIG", &pkg_path);

        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        for (ver, expected) in [
            ("1.0.0+build--old", "1.0.0+build--old"),
            ("1.0.0+build--new", "1.0.0+build--new"),
            ("1.0.0+Debug", "1.0.0+Debug"),
        ] {
            let prog_path = bin_dir.join("buildmetaapp");
            std::fs::write(
                &prog_path,
                format!("#!/bin/sh\necho 'buildmetaapp {}'\n", ver),
            ).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&prog_path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }

            let outcome = probe_live_runtime_version("buildmetaapp", &env_cfg);
            assert_eq!(
                outcome,
                LiveRuntimeProbeOutcome::Verified(expected.to_string()),
                "Generic binary probe must preserve complete version '{}'",
                ver
            );
        }

        std::env::remove_var("AF_PACKAGES_CONFIG");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_snapshot_and_restore_on_failed_certification() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-receipt-snap-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        // Setup pre-existing receipt at /opt/mockpkg/.af-version
        let pre_existing = temp_dir.join("opt/mockpkg/.af-version");
        std::fs::create_dir_all(pre_existing.parent().unwrap()).unwrap();
        std::fs::write(&pre_existing, b"1.0.0\n").unwrap();

        // Snapshot candidate receipts before operation
        let snapshots = snapshot_candidate_receipts_with_env("mockpkg", &env_cfg).unwrap();
        assert!(!snapshots.is_empty(), "Must find candidate paths");

        // Verify pre-existing receipt has Some(b"1.0.0\n")
        let pre_snap = snapshots.iter().find(|s| s.path == pre_existing).expect("pre-existing must be tracked");
        assert_eq!(pre_snap.bytes(), Some(b"1.0.0\n".as_slice()));

        // Verify non-existent candidate path (e.g. /var/lib/mockpkg/.af-version) has None
        let var_lib_path = temp_dir.join("var/lib/mockpkg/.af-version");
        let non_exist_snap = snapshots.iter().find(|s| s.path == var_lib_path).expect("var/lib candidate must be tracked");
        assert_eq!(non_exist_snap.state, None);

        // Mutate pre-existing receipt (installer writes new version)
        std::fs::write(&pre_existing, b"2.0.0-uncertified\n").unwrap();

        // Also write a newly created receipt at var/lib
        std::fs::create_dir_all(var_lib_path.parent().unwrap()).unwrap();
        std::fs::write(&var_lib_path, b"2.0.0-uncertified\n").unwrap();

        // Target certification fails -> restore candidate receipts!
        let restore_res = restore_candidate_receipts(&snapshots);
        assert!(restore_res.is_ok(), "Restoration must succeed: {:?}", restore_res);

        // Pre-existing receipt must be rolled back to 1.0.0
        assert_eq!(std::fs::read(&pre_existing).unwrap(), b"1.0.0\n");

        // Newly created receipt at var/lib must be completely removed
        assert!(!var_lib_path.exists(), "Newly created receipt must be removed after failed certification");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_run_bounded_probe_command_kills_descendants_and_times_out() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "sleep 30"]);

        let start = std::time::Instant::now();
        let res = run_bounded_probe_command(&mut cmd, Duration::from_millis(150));
        let elapsed = start.elapsed();

        assert!(res.is_err(), "Hanging command must time out");
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("timed out"), "Error must mention timeout: {}", err_msg);
        assert!(
            elapsed < Duration::from_secs(2),
            "Command timeout took {:?}, expected < 2s",
            elapsed
        );

        let mut echo_cmd = std::process::Command::new("echo");
        echo_cmd.arg("hello-probe");
        let echo_res = run_bounded_probe_command(&mut echo_cmd, Duration::from_secs(2));
        assert!(echo_res.is_ok());
        let output = echo_res.unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello-probe");
    }

    #[test]
    fn test_restore_candidate_receipts_symlink_swap_does_not_modify_victim() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-symlink-restore-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let receipt_path = temp_dir.join("opt/vulnpkg/.af-version");
        std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
        std::fs::write(&receipt_path, b"1.0.0\n").unwrap();

        // Snapshot original receipt (1.0.0)
        let snapshots = snapshot_candidate_receipts_with_env("vulnpkg", &env_cfg).unwrap();

        // Attacker creates a victim file outside
        let victim_file = temp_dir.join("victim_file.txt");
        std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

        // Attacker replaces .af-version with a symlink pointing to victim_file
        std::fs::remove_file(&receipt_path).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

        // Now restore candidate receipts!
        let restore_res = restore_candidate_receipts(&snapshots);
        assert!(restore_res.is_ok(), "Restoration must succeed: {:?}", restore_res);

        // Victim file MUST NOT have been modified!
        assert_eq!(std::fs::read(&victim_file).unwrap(), b"VICTIM_INTACT_CONTENT");

        // .af-version MUST now be a regular file with b"1.0.0\n", NOT a symlink!
        let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
        assert!(!meta.file_type().is_symlink(), ".af-version must not be a symlink after restoration");
        assert!(meta.file_type().is_file(), ".af-version must be a regular file");
        assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0\n");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_snapshot_symlink_or_fifo_fails_closed_and_marks_job_failed() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-symlink-snap-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let receipt_path = temp_dir.join("opt/symlinkpkg/.af-version");
        std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
        let target_file = temp_dir.join("target.txt");
        std::fs::write(&target_file, b"target").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target_file, &receipt_path).unwrap();

        // 1. snapshot_candidate_receipts_with_env must fail closed with Err
        let snap_res = snapshot_candidate_receipts_with_env("symlinkpkg", &env_cfg);
        assert!(snap_res.is_err(), "Snapshotting a symlink must fail closed: {:?}", snap_res);
        let err_msg = snap_res.unwrap_err();
        assert!(err_msg.to_ascii_lowercase().contains("symlink"), "Error must mention symlink: {}", err_msg);

        // Also verify FIFO fails closed with non-regular file error
        #[cfg(unix)]
        {
            let fifo_path = temp_dir.join("opt/fifopkg/.af-version");
            std::fs::create_dir_all(fifo_path.parent().unwrap()).unwrap();
            let fifo_cstr = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
            let _ = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o644) };
            let fifo_snap = snapshot_candidate_receipts_with_env("fifopkg", &env_cfg);
            assert!(fifo_snap.is_err(), "Snapshotting a FIFO must fail closed");
            let fifo_err = fifo_snap.unwrap_err();
            assert!(
                fifo_err.contains("non-regular file") || fifo_err.contains("symlink"),
                "FIFO error must mention non-regular file: {}",
                fifo_err
            );
        }

        // 2. CoordinatedOperation::execute must mark job as terminal "failed"
        let db_path = temp_dir.join("var/lib/aetherflow/aetherflow.sqlite");
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE settings(id INTEGER PRIMARY KEY,base_domain TEXT);
            INSERT INTO settings VALUES(1,'default.example.test');
            CREATE TABLE app_updates(package_name TEXT PRIMARY KEY);
            CREATE TABLE app_ingress_configs(app_name TEXT PRIMARY KEY,public_domain TEXT,
                external_access_enabled BOOLEAN,listen_port INTEGER,tls_enabled BOOLEAN,
                created_at TEXT,updated_at TEXT);").unwrap();

        let req = PackageRunnerRequest {
            package_id: "symlinkpkg".to_string(),
            action: "install".to_string(),
            script_name: "installpackage-symlinkpkg".to_string(),
            app_port: 8080,
            delete_data: false,
            expected_target_version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let package = Package {
            name: "symlinkpkg".into(),
            service_name: "symlinkpkg".into(),
            service_type: "systemd".into(),
            default_port: 8080,
            ..Default::default()
        };

        struct DummyBackend;
        impl LifecycleBackend for DummyBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(false) })
            }
            fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let mut coord = CoordinatedOperation::admit(conn, req, package, vec!["symlinkpkg".into()]).unwrap();
        let (tx, _rx) = mpsc::channel(10);
        let exec_res = coord.execute(&DummyBackend, &tx).await;
        assert!(exec_res.is_err(), "Execute must fail due to symlink receipt snapshot");

        let (status, failure_category, failed_stage): (String, Option<String>, Option<String>) = coord.conn.query_row(
            "SELECT status, failure_category, failed_stage FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
            rusqlite::params![coord.request.package_id, coord.request.lifecycle_job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();

        assert_eq!(status, "failed", "Job status must be terminal 'failed'");
        assert_eq!(failure_category.as_deref(), Some("preflight"), "failure_category must be preflight");
        assert_eq!(failed_stage.as_deref(), Some("preflight_receipt_snapshot"), "failed_stage must be preflight_receipt_snapshot");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_has_independent_runtime_evidence_rejects_only_lockfile() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-lock-evidence-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        // Create directory /opt/lockpkg with only .af-version and anything.lock
        let opt_dir = temp_dir.join("opt/lockpkg");
        std::fs::create_dir_all(&opt_dir).unwrap();
        std::fs::write(opt_dir.join(".af-version"), b"1.0.0\n").unwrap();
        std::fs::write(opt_dir.join("anything.lock"), b"lockfile").unwrap();
        std::fs::write(opt_dir.join("install.log"), b"logs").unwrap();
        std::fs::write(opt_dir.join("data.tmp"), b"temporary").unwrap();

        let has_evidence = has_independent_runtime_evidence("lockpkg", &env_cfg);
        assert!(
            !has_evidence,
            "has_independent_runtime_evidence must reject directory containing only .af-version, anything.lock, and data files"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_extract_version_token_preserves_trailing_hyphens_in_prerelease_and_build() {
        assert_eq!(extract_version_token("tool 1.0.0+build- (linux)"), "1.0.0+build-");
        assert_eq!(extract_version_token("tool 1.0.0+build-- (linux)"), "1.0.0+build--");
        assert_eq!(extract_version_token("tool 1.0.0-alpha- (linux)"), "1.0.0-alpha-");
        assert_eq!(extract_version_token("tool 1.0.0-alpha-- (linux)"), "1.0.0-alpha--");
        assert_eq!(extract_version_token("tool 1.0.0-- (linux)"), "1.0.0--");
        assert_eq!(extract_version_token("tool 1.0.0+-- (linux)"), "1.0.0+--");
        assert_eq!(extract_version_token("tool 1.0.0+- (linux)"), "1.0.0+-");

        // Dangling trailing hyphen without identifier must be trimmed
        assert_eq!(extract_version_token("tool 1.0.0- (linux)"), "1.0.0");
        assert_eq!(extract_version_token("tool 1.0.0+ (linux)"), "1.0.0");

        // Trailing punctuation should be trimmed while preserving valid hyphens
        assert_eq!(extract_version_token("tool 1.0.0+build-."), "1.0.0+build-");
        assert_eq!(extract_version_token("tool 1.0.0+build-,"), "1.0.0+build-");
        assert_eq!(extract_version_token("tool 1.0.0+build-:"), "1.0.0+build-");
        assert_eq!(extract_version_token("tool 1.0.0+build-;"), "1.0.0+build-");
    }

    #[test]
    fn test_sanitize_lifecycle_field_redacts_credentials_and_tokens() {
        let input = "Failed to fetch: password=supersecret, token: mytoken123, Bearer eyJhbGciOi..., Basic dXNlcjpwYXNz; url=https://example.com";
        let sanitized = sanitize_lifecycle_field(input);
        assert!(!sanitized.contains("supersecret"), "Password must be redacted");
        assert!(!sanitized.contains("mytoken123"), "Token must be redacted");
        assert!(!sanitized.contains("eyJhbGciOi"), "Bearer token must be redacted");
        assert!(!sanitized.contains("dXNlcjpwYXNz"), "Basic auth must be redacted");
        assert!(sanitized.contains("password=[REDACTED]"));
        assert!(sanitized.contains("token: [REDACTED]"));
        assert!(sanitized.contains("Bearer [REDACTED]"));
        assert!(sanitized.contains("Basic [REDACTED]"));

        // Quoted and multi-word credential values
        let multiword_input = r#"Encountered error with password="first SECRET_TAIL" and "secret": "alpha beta gamma" and 'token': 'delta epsilon'"#;
        let sanitized_multi = sanitize_lifecycle_field(multiword_input);
        assert!(!sanitized_multi.contains("SECRET_TAIL"), "Must not leak SECRET_TAIL");
        assert!(!sanitized_multi.contains("alpha beta gamma"), "Must not leak alpha beta gamma");
        assert!(!sanitized_multi.contains("beta gamma"), "Must not leak beta gamma");
        assert!(!sanitized_multi.contains("delta epsilon"), "Must not leak delta epsilon");
        assert!(sanitized_multi.contains("password=[REDACTED]"));
        assert!(sanitized_multi.contains(r#""secret": [REDACTED]"#));

        // Verify db_password and escaped quotes are completely redacted
        let db_pw_input = r#"db_password="secret_val""#;
        let sanitized_db_pw = sanitize_lifecycle_field(db_pw_input);
        assert!(!sanitized_db_pw.contains("secret_val"), "db_password value must be redacted");
        assert_eq!(sanitized_db_pw, "db_password=[REDACTED]");

        let json_db_pw = r#"{"db_password": "secret_val"}"#;
        let sanitized_json_db = sanitize_lifecycle_field(json_db_pw);
        assert!(!sanitized_json_db.contains("secret_val"), "JSON db_password must be redacted");
        assert_eq!(sanitized_json_db, r#"{"db_password": [REDACTED]}"#);

        let escaped_quotes_input = r#"secret="part1 \"quoted\" tail_secret""#;
        let sanitized_escaped = sanitize_lifecycle_field(escaped_quotes_input);
        assert!(!sanitized_escaped.contains("part1"), "Must not leak part1");
        assert!(!sanitized_escaped.contains("quoted"), "Must not leak quoted");
        assert!(!sanitized_escaped.contains("tail_secret"), "Must not leak tail_secret");
        assert_eq!(sanitized_escaped, "secret=[REDACTED]");
    }

    #[test]
    fn test_run_bounded_probe_command_cancellable_cancels_promptly() {
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("10");
        let start = std::time::Instant::now();
        let mut checks = 0;
        let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || {
            checks += 1;
            checks >= 2
        });
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "probe command cancelled");
        assert!(start.elapsed() < Duration::from_secs(2), "Cancellation must terminate immediately");
    }

    #[test]
    fn test_has_independent_runtime_evidence_systemd_unit_exec_start() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-unit-evidence-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let systemd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&systemd_dir).unwrap();
        let unit_file = systemd_dir.join("unitpkg.service");

        // Case 1: Empty service file -> false
        std::fs::write(&unit_file, b"").unwrap();
        assert!(
            !has_independent_runtime_evidence("unitpkg", &env_cfg),
            "Empty .service file must not count as independent runtime evidence"
        );

        // Case 2: Stale service file with nonexistent binary -> false
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/opt/unitpkg/bin/nonexistent\n",
        ).unwrap();
        assert!(
            !has_independent_runtime_evidence("unitpkg", &env_cfg),
            "Service pointing to nonexistent binary must not count as independent runtime evidence"
        );

        // Case 3: Binary exists but is not executable (0o644) -> false
        let bin_path = temp_dir.join("opt/unitpkg/bin/mybin");
        std::fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
        std::fs::write(&bin_path, b"not executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o644));
        }
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/opt/unitpkg/bin/mybin\n",
        ).unwrap();
        assert!(
            !has_independent_runtime_evidence("unitpkg", &env_cfg),
            "Service pointing to non-executable binary must not count as independent runtime evidence"
        );

        // Case 4: Binary is executable with systemd modifiers and quotes -> true
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=-@!\"/opt/unitpkg/bin/mybin\" --daemon\n",
        ).unwrap();
        assert!(
            has_independent_runtime_evidence("unitpkg", &env_cfg),
            "Service pointing to valid executable binary must count as independent runtime evidence"
        );

        // Case 5: Valid symlink to executable binary -> true
        let symlink_path = temp_dir.join("usr/local/bin/unitpkg-link");
        std::fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&bin_path, &symlink_path);
            std::fs::write(
                &unit_file,
                b"[Service]\nExecStart=/usr/local/bin/unitpkg-link\n",
            ).unwrap();
            assert!(
                has_independent_runtime_evidence("unitpkg", &env_cfg),
                "Service pointing to symlink to valid executable must count as independent runtime evidence"
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_run_bounded_probe_command_cancellable_grandchild_pipe_does_not_hang() {
        // Child spawns detached/background grandchild that holds stdout/stderr open
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "(sleep 30) & echo finished-parent"]);

        let start = std::time::Instant::now();
        let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_millis(500), || false);
        let elapsed = start.elapsed();

        assert!(res.is_ok(), "Command should succeed: {:?}", res);
        let output = res.unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("finished-parent"));
        assert!(
            elapsed < Duration::from_millis(1000),
            "Probe with open grandchild pipe must return in < 1s without hanging on pipe join, took {:?}",
            elapsed
        );

        // Test timeout case with grandchild holding pipes
        let mut hang_cmd = std::process::Command::new("sh");
        hang_cmd.args(["-c", "(sleep 30) & sleep 10"]);
        let start2 = std::time::Instant::now();
        let hang_res = run_bounded_probe_command_cancellable(&mut hang_cmd, Duration::from_millis(200), || false);
        let elapsed2 = start2.elapsed();
        assert!(hang_res.is_err());
        assert!(hang_res.unwrap_err().contains("timed out"));
        assert!(
            elapsed2 < Duration::from_millis(1000),
            "Timeout probe with grandchild pipe must return in < 1s, took {:?}",
            elapsed2
        );

        // Test cancellation case with grandchild holding pipes
        let mut cancel_cmd = std::process::Command::new("sh");
        cancel_cmd.args(["-c", "(sleep 30) & sleep 10"]);
        let start3 = std::time::Instant::now();
        let cancel_res = run_bounded_probe_command_cancellable(&mut cancel_cmd, Duration::from_secs(5), || true);
        let elapsed3 = start3.elapsed();
        assert!(cancel_res.is_err());
        assert_eq!(cancel_res.unwrap_err(), "probe command cancelled");
        assert!(
            elapsed3 < Duration::from_millis(1000),
            "Cancelled probe with grandchild pipe must return in < 1s, took {:?}",
            elapsed3
        );
    }

    #[test]
    fn test_run_bounded_probe_command_cancellable_process_group_cleanup_before_reap() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "(sleep 30) & exit 0"]);

        let start = std::time::Instant::now();
        let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || false);
        assert!(res.is_ok(), "Probe command should succeed: {:?}", res);
        let out = res.unwrap();
        assert!(out.status.success());
        assert!(start.elapsed() < Duration::from_secs(2), "Process group cleanup and reap must complete promptly");
    }

    #[test]
    fn test_restore_candidate_receipts_parent_enotdir_fails_closed() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-enotdir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let parent_file = temp_dir.join("parent_regular_file");
        std::fs::write(&parent_file, b"regular file content").unwrap();
        let receipt_path = parent_file.join(".af-version");

        let snapshots = vec![FileSnapshot::absent(receipt_path)];
        let res = restore_candidate_receipts(&snapshots);
        assert!(
            res.is_err(),
            "restore_candidate_receipts must return Err when parent is a regular file (ENOTDIR), got: {:?}",
            res
        );
        let err_msg = res.unwrap_err();
        assert!(
            err_msg.to_lowercase().contains("not a directory") || err_msg.contains("ENOTDIR") || err_msg.contains("stepwise"),
            "Error must indicate stepwise open failure on non-directory: {}",
            err_msg
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_has_independent_runtime_evidence_systemd_reset_and_interpreter_checks() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-systemd-audit-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let systemd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&systemd_dir).unwrap();
        let unit_file = systemd_dir.join("testpkg.service");

        // Finding 4a: ExecStart=/bin/true followed by empty ExecStart= reset must be REJECTED
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/bin/true\nExecStart=\n",
        ).unwrap();
        assert!(
            !has_independent_runtime_evidence("testpkg", &env_cfg),
            "Service with ExecStart reset by empty ExecStart= must be rejected"
        );

        // Finding 4b: ExecStart=/bin/sh with nonexistent script must be REJECTED
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/bin/sh /opt/testpkg/missing_script.sh\n",
        ).unwrap();
        assert!(
            !has_independent_runtime_evidence("testpkg", &env_cfg),
            "Service using shell interpreter with nonexistent script path must be rejected"
        );

        // Finding 4c: Shell interpreter with EXISTING regular script file must be ACCEPTED
        let script_path = temp_dir.join("opt/testpkg/real_script.sh");
        std::fs::create_dir_all(script_path.parent().unwrap()).unwrap();
        std::fs::write(&script_path, b"#!/bin/sh\necho ok\n").unwrap();
        std::fs::write(
            &unit_file,
            b"[Service]\nExecStart=/bin/sh /opt/testpkg/real_script.sh\n",
        ).unwrap();
        assert!(
            has_independent_runtime_evidence("testpkg", &env_cfg),
            "Service using shell interpreter with existing regular script file must be accepted"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
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

    #[test]
    fn test_run_bounded_probe_command_waitid_eperm_zombie_fallback_kills_descendants() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
        super::INJECT_WAITID_EPERM.store(true, std::sync::atomic::Ordering::SeqCst);

        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "(sleep 30) & exit 0"]);

        let start = std::time::Instant::now();
        let res = run_bounded_probe_command_cancellable(&mut cmd, Duration::from_secs(5), || false);
        super::INJECT_WAITID_EPERM.store(false, std::sync::atomic::Ordering::SeqCst);

        assert!(res.is_ok(), "Probe command should succeed under injected waitid EPERM: {:?}", res);
        let out = res.unwrap();
        assert!(out.status.success());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "Zombie fallback and PG cleanup must complete promptly without hanging on descendant"
        );
    }

    #[tokio::test]
    async fn test_script_failure_triggers_receipt_and_blueprint_rollback_when_services_restart_cleanly() {
        let (root, _path, conn, _) = test_fixture();
        let sonarr_dir = root.join("var/lib/sonarr");
        std::fs::create_dir_all(&sonarr_dir).unwrap();
        let opt_sonarr = root.join("opt/sonarr");
        std::fs::create_dir_all(&opt_sonarr).unwrap();

        let receipt_file = opt_sonarr.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let config_file = sonarr_dir.join("config.xml");
        std::fs::write(&config_file, b"<Config><Port>8989</Port></Config>\n").unwrap();

        let uncommitted_receipt = root.join("var/lib/sonarr/.af-version");

        let package = Package {
            name: "sonarr".into(),
            service_name: "sonarr".into(),
            service_type: "systemd".into(),
            default_port: 8989,
            ..Default::default()
        };

        struct FailScriptBackend {
            receipt_file: PathBuf,
            uncommitted_receipt: PathBuf,
            config_file: PathBuf,
        }
        impl LifecycleBackend for FailScriptBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8989 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(false) })
            }
            fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                let receipt_path = self.receipt_file.clone();
                let uncommitted_path = self.uncommitted_receipt.clone();
                let config_path = self.config_file.clone();
                Box::pin(async move {
                    std::fs::write(&receipt_path, b"2.0.0-uncommitted\n").unwrap();
                    std::fs::create_dir_all(uncommitted_path.parent().unwrap()).unwrap();
                    std::fs::write(&uncommitted_path, b"2.0.0-uncommitted\n").unwrap();
                    std::fs::write(&config_path, b"<Config><Port>9999</Port></Config>\n").unwrap();
                    anyhow::bail!("installer script failed deliberately")
                })
            }
        }

        let backend = FailScriptBackend {
            receipt_file: receipt_file.clone(),
            uncommitted_receipt: uncommitted_receipt.clone(),
            config_file: config_file.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "sonarr".into(),
            action: "install".into(),
            script_name: "installpackage-sonarr".into(),
            app_port: 8989,
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(conn, req, package, vec!["sonarr".into()]).unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed", "Execute must return failed receipt when installer script fails");

        // Verify receipt and blueprint files were restored
        assert_eq!(
            std::fs::read_to_string(&receipt_file).unwrap(),
            "1.0.0\n",
            "Pre-existing receipt must be restored on script failure"
        );
        assert!(
            !uncommitted_receipt.exists(),
            "Newly created receipt must be deleted on script failure"
        );
        assert_eq!(
            std::fs::read_to_string(&config_file).unwrap(),
            "<Config><Port>8989</Port></Config>\n",
            "Pre-existing blueprint config must be restored on script failure"
        );

        let (status, failure_category, sanitized_summary): (String, String, Option<String>) = op
            .conn
            .query_row(
                "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='sonarr'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(failure_category, "installer");
        assert!(
            sanitized_summary.as_deref().unwrap_or("").contains("installer script failed deliberately"),
            "Diagnostics must retain script failure: {:?}",
            sanitized_summary
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_snapshot_blueprint_targets_symlink_or_oversized_fails_closed() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-bp-snap-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let sonarr_dir = temp_dir.join("var/lib/sonarr");
        std::fs::create_dir_all(&sonarr_dir).unwrap();
        let config_target = sonarr_dir.join("config.xml");

        // 1. Symlink target
        let victim_file = temp_dir.join("victim.txt");
        std::fs::write(&victim_file, b"victim content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim_file, &config_target).unwrap();

        let snap_res = snapshot_blueprint_targets("sonarr", &env_cfg);
        assert!(snap_res.is_err(), "Snapshotting a symlink blueprint target must fail closed: {:?}", snap_res);
        let err_msg = snap_res.unwrap_err();
        assert!(
            err_msg.to_ascii_lowercase().contains("symlink"),
            "Error must mention symlink: {}",
            err_msg
        );
        // Verify victim file and symlink were NOT deleted
        assert!(victim_file.is_file(), "Victim file must not be deleted");
        assert!(
            std::fs::symlink_metadata(&config_target).unwrap().file_type().is_symlink(),
            "Symlink must not be unlinked"
        );

        // 2. Oversized file (> 1 MiB)
        let _ = std::fs::remove_file(&config_target);
        let oversized_buf = vec![0x41u8; 2 * 1024 * 1024];
        std::fs::write(&config_target, &oversized_buf).unwrap();

        let snap_res_over = snapshot_blueprint_targets("sonarr", &env_cfg);
        assert!(snap_res_over.is_err(), "Snapshotting an oversized blueprint target must fail closed: {:?}", snap_res_over);
        let over_err = snap_res_over.unwrap_err();
        assert!(
            over_err.contains("exceeds") && over_err.contains("byte limit"),
            "Error must mention length cap: {}",
            over_err
        );
        assert!(config_target.is_file(), "Oversized file must not be deleted");
        assert_eq!(std::fs::metadata(&config_target).unwrap().len(), 2 * 1024 * 1024);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_restore_preserves_exact_permissions_and_ownership() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-perms-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let secret_file = temp_dir.join("secret.conf");
        std::fs::write(&secret_file, b"SECRET_KEY=confidential_data_12345").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let state = read_file_entry_bounded_nofollow(&secret_file, 1024 * 1024)
            .expect("read_file_entry_bounded_nofollow must succeed")
            .expect("file must be present");
        assert_eq!(state.mode & 0o7777, 0o600);
        let expected_uid = state.uid;
        let expected_gid = state.gid;

        let snap = FileSnapshot {
            path: secret_file.clone(),
            state: Some(state),
        };

        // Mutate file to 0o644 with altered content
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::write(&secret_file, b"LEAKED_AND_MUTATED").unwrap();

        // Restore file
        let restore_res = restore_candidate_receipts(&[snap]);
        assert!(restore_res.is_ok(), "Restoration must succeed: {:?}", restore_res);

        // Verify content
        assert_eq!(
            std::fs::read(&secret_file).unwrap(),
            b"SECRET_KEY=confidential_data_12345"
        );

        // Verify permissions are exactly 0o600, NEVER 0o644!
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&secret_file).unwrap();
            let mode = meta.permissions().mode() & 0o7777;
            assert_eq!(mode, 0o600, "Restored file must have 0o600 mode, not 0o644");
            assert_eq!(meta.uid(), expected_uid, "Restored file must preserve UID");
            assert_eq!(meta.gid(), expected_gid, "Restored file must preserve GID");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_systemd_unit_exec_start_outside_service_section_rejected() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-unit-section-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let systemd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&systemd_dir).unwrap();
        let unit_file = systemd_dir.join("badsection.service");

        // ExecStart placed inside [Unit] section
        let unit_placement = "[Unit]\nDescription=Bad Unit Section Placement\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n";
        std::fs::write(&unit_file, unit_placement.as_bytes()).unwrap();
        assert!(
            !validate_systemd_unit_runtime_evidence(unit_placement, "badsection", &env_cfg),
            "validate_systemd_unit_runtime_evidence must reject ExecStart placed in [Unit]"
        );
        assert!(
            !has_independent_runtime_evidence("badsection", &env_cfg),
            "has_independent_runtime_evidence must reject service with ExecStart placed in [Unit]"
        );

        // ExecStart placed inside [Install] section
        let install_placement = "[Unit]\nDescription=Bad Unit Section Placement\n\n[Install]\nWantedBy=multi-user.target\nExecStart=/bin/true\n";
        std::fs::write(&unit_file, install_placement.as_bytes()).unwrap();
        assert!(
            !validate_systemd_unit_runtime_evidence(install_placement, "badsection", &env_cfg),
            "validate_systemd_unit_runtime_evidence must reject ExecStart placed in [Install]"
        );

        // ExecStart properly placed inside [Service] section
        let service_placement = "[Unit]\nDescription=Good Unit\n\n[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=multi-user.target\n";
        std::fs::write(&unit_file, service_placement.as_bytes()).unwrap();
        assert!(
            validate_systemd_unit_runtime_evidence(service_placement, "badsection", &env_cfg),
            "validate_systemd_unit_runtime_evidence must accept ExecStart placed in [Service]"
        );
        assert!(
            has_independent_runtime_evidence("badsection", &env_cfg),
            "has_independent_runtime_evidence must accept service with ExecStart placed in [Service]"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_post_commit_rollback_error_persisted_in_diagnostics() {
        let (root, _path, conn, package) = test_fixture();
        let req = PackageRunnerRequest {
            package_id: "syncthing".into(),
            action: "install".into(),
            script_name: "installpackage-syncthing".into(),
            app_port: 8384,
            ..Default::default()
        };

        struct PostCommitFailBackend {
            root: PathBuf,
        }
        impl LifecycleBackend for PostCommitFailBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8384 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(false) })
            }
            fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                let r = self.root.clone();
                Box::pin(async move {
                    // Create var/lib as directory with syncthing as regular file (causing ENOTDIR on rollback)
                    let var_lib = r.join("var/lib");
                    std::fs::create_dir_all(&var_lib).unwrap();
                    let syncthing_file = var_lib.join("syncthing");
                    let _ = std::fs::remove_dir_all(&syncthing_file);
                    std::fs::write(&syncthing_file, b"blocking regular file").unwrap();
                    Ok(())
                })
            }
        }

        let backend = PostCommitFailBackend { root: root.clone() };
        let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();

        // Drop the settings table so post_commit fails when trying to synchronize ingress
        op.conn.execute("DROP TABLE settings", []).unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed", "Execute must mark receipt as failed when post-commit sync fails");

        let (status, category, diag): (String, String, Option<String>) = op
            .conn
            .query_row(
                "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "failed");
        assert_eq!(category, "configuration");
        let summary = diag.expect("sanitized_summary must be persisted");
        assert!(
            summary.contains("receipt restoration error:"),
            "Diagnostic summary must preserve post-commit rollback error: {}",
            summary
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_validate_systemd_unit_runtime_evidence_exact_key_matching() {
        let env_cfg = crate::PackageExecutionEnv::default();

        // 1. ExecStartPre must NEVER be accepted as ExecStart
        let unit_pre = "[Service]\nExecStartPre=/bin/true\n";
        assert!(
            !validate_systemd_unit_runtime_evidence(unit_pre, "testpkg", &env_cfg),
            "ExecStartPre must not be accepted as ExecStart"
        );

        // 2. ExecStartPost must NEVER be accepted as ExecStart
        let unit_post = "[Service]\nExecStartPost=/bin/true\n";
        assert!(
            !validate_systemd_unit_runtime_evidence(unit_post, "testpkg", &env_cfg),
            "ExecStartPost must not be accepted as ExecStart"
        );

        // 3. Lowercase execstart must be rejected (exact case-sensitive matching required)
        let unit_lower = "[Service]\nexecstart=/bin/true\n";
        assert!(
            !validate_systemd_unit_runtime_evidence(unit_lower, "testpkg", &env_cfg),
            "Lowercase execstart must be rejected"
        );

        // 4. Lowercase execstartpre must be rejected
        let unit_lower_pre = "[Service]\nexecstartpre=/bin/true\n";
        assert!(
            !validate_systemd_unit_runtime_evidence(unit_lower_pre, "testpkg", &env_cfg),
            "Lowercase execstartpre must be rejected"
        );

        // 5. Valid ExecStart in [Service] with valid executable is accepted
        let unit_valid = "[Service]\nExecStart=/bin/true\n";
        assert!(
            validate_systemd_unit_runtime_evidence(unit_valid, "testpkg", &env_cfg),
            "Exact ExecStart in [Service] must be accepted"
        );
    }

    #[test]
    fn test_sanitize_lifecycle_field_attached_curl_and_comma_credentials() {
        // Attached curl -u credentials
        let curl_attached = "curl -uadmin:supersecret https://example.com/api";
        let sanitized_attached = sanitize_lifecycle_field(curl_attached);
        assert!(!sanitized_attached.contains("supersecret"), "Attached curl password must be redacted");
        assert!(!sanitized_attached.contains("admin:supersecret"), "Attached curl credentials must be redacted");
        assert_eq!(sanitized_attached, "curl -u[REDACTED] https://example.com/api");

        // Attached curl -u credentials with quotes
        let curl_quoted = "curl -u\"admin:supersecret\" https://example.com/api";
        let sanitized_quoted = sanitize_lifecycle_field(curl_quoted);
        assert!(!sanitized_quoted.contains("supersecret"), "Quoted curl password must be redacted");
        assert_eq!(sanitized_quoted, "curl -u[REDACTED] https://example.com/api");

        // Attached curl -u at end of command or line
        let curl_bare = "curl -uadmin:supersecret";
        let sanitized_bare = sanitize_lifecycle_field(curl_bare);
        assert_eq!(sanitized_bare, "curl -u[REDACTED]");

        // Attached curl with comma in credentials
        let curl_comma = "curl -uadmin:pass,word https://example.com";
        let sanitized_curl_comma = sanitize_lifecycle_field(curl_comma);
        assert!(!sanitized_curl_comma.contains("pass,word"), "Comma-containing curl credential must be redacted");
        assert_eq!(sanitized_curl_comma, "curl -u[REDACTED] https://example.com");

        // Unquoted credentials containing commas
        let input_comma = "Failed: password=part1,part2, status=500";
        let sanitized_comma = sanitize_lifecycle_field(input_comma);
        assert!(!sanitized_comma.contains("part1"), "part1 must be redacted");
        assert!(!sanitized_comma.contains("part2"), "part2 must be redacted");
        assert!(sanitized_comma.contains("password=[REDACTED]"));
        assert!(sanitized_comma.contains("status=500"));

        // Comma-separated key-value credentials: both password and token redacted cleanly
        let input_multi = "error: password=part1,part2, token: secret_token_xyz; details";
        let sanitized_multi = sanitize_lifecycle_field(input_multi);
        assert!(!sanitized_multi.contains("part1"));
        assert!(!sanitized_multi.contains("part2"));
        assert!(!sanitized_multi.contains("secret_token_xyz"));
        assert_eq!(sanitized_multi, "error: password=[REDACTED], token: [REDACTED]; details");

        // Semicolon-delimited unquoted credentials with commas
        let input_semi = "password=part1,part2; token=token1,token2; url=https://example.com";
        let sanitized_semi = sanitize_lifecycle_field(input_semi);
        assert!(!sanitized_semi.contains("part1"));
        assert!(!sanitized_semi.contains("part2"));
        assert!(!sanitized_semi.contains("token1"));
        assert!(!sanitized_semi.contains("token2"));
        assert_eq!(sanitized_semi, "password=[REDACTED]; token=[REDACTED]; url=https://example.com");
    }

    #[tokio::test]
    async fn test_coordinated_operation_quiesce_restore_restart_order() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        // Sub-scenario A: Script failure order
        // Expected: stop -> script -> stop -> rollback -> start -> active
        {
            let (root, _path, conn, _) = test_fixture();
            let opt_dir = root.join("opt/syncthing-order-script-fail");
            std::fs::create_dir_all(&opt_dir).unwrap();
            let receipt_file = opt_dir.join(".af-version");
            std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

            let package = Package {
                name: "syncthing-order-script-fail".into(),
                service_name: "syncthing-order-script-fail".into(),
                service_type: "systemd".into(),
                default_port: 8384,
                ..Default::default()
            };

            let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let events_for_hook = events.clone();

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
                if snaps.iter().any(|s| s.path.to_string_lossy().contains("syncthing-order-script-fail")) {
                    events_for_hook.lock().unwrap().push("rollback".to_string());
                }
            }));

            struct OrderScriptFailBackend {
                events: Arc<std::sync::Mutex<Vec<String>>>,
                receipt_file: PathBuf,
                receipt_at_start: Arc<std::sync::Mutex<Option<String>>>,
            }
            impl LifecycleBackend for OrderScriptFailBackend {
                fn runtime_port(&self, _: &str) -> i32 { 8384 }
                fn available_port(&self, _: i32) -> bool { true }
                fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                    let rolled_back = self.events.lock().unwrap().contains(&"rollback".to_string());
                    if rolled_back {
                        self.events.lock().unwrap().push("active".to_string());
                    }
                    Box::pin(async { Ok(true) })
                }
                fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                    let events = self.events.lock().unwrap();
                    let last_stop = events.iter().rposition(|e| e == "stop");
                    let last_start = events.iter().rposition(|e| e == "start");
                    let is_q = match (last_stop, last_start) {
                        (Some(s), Some(st)) => s > st,
                        (Some(_), None) => true,
                        _ => false,
                    };
                    Box::pin(async move { Ok(is_q) })
                }
                fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                    self.events.lock().unwrap().push(action.to_string());
                    if action == "start" {
                        let content = std::fs::read_to_string(&self.receipt_file).ok();
                        *self.receipt_at_start.lock().unwrap() = content;
                    }
                    Box::pin(async { Ok(()) })
                }
                fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                    self.events.lock().unwrap().push("script".to_string());
                    let rf = self.receipt_file.clone();
                    Box::pin(async move {
                        std::fs::write(&rf, b"2.0.0-broken\n").unwrap();
                        anyhow::bail!("simulated installer failure")
                    })
                }
            }

            let receipt_at_start = Arc::new(std::sync::Mutex::new(None));
            let backend = OrderScriptFailBackend {
                events: events.clone(),
                receipt_file: receipt_file.clone(),
                receipt_at_start: receipt_at_start.clone(),
            };

            let req = PackageRunnerRequest {
                package_id: "syncthing-order-script-fail".into(),
                action: "update".into(),
                script_name: "updatepackage-syncthing".into(),
                app_port: 8384,
                expected_target_version: Some("2.0.0".into()),
                ..Default::default()
            };

            let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing-order-script-fail".into()]).unwrap();
            let (sender, _receiver) = mpsc::channel(32);
            let receipt = op.execute(&backend, &sender).await.unwrap();
            assert_eq!(receipt.status, "failed");

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

            let recorded = events.lock().unwrap().clone();
            assert_eq!(
                recorded,
                vec!["stop", "script", "stop", "rollback", "start", "active"],
                "Script failure must follow exact order: stop -> script -> stop -> rollback -> start -> active"
            );

            // Assert rollback_operation_state ALWAYS happens before final service restart and verification
            let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
            let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
            let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
            assert!(
                rollback_pos < final_start_pos,
                "rollback_operation_state MUST occur before final service restart"
            );
            assert!(
                final_start_pos < final_active_pos,
                "Final service restart MUST occur before active verification"
            );

            // Verify receipt was restored on disk BEFORE start was called!
            assert_eq!(
                receipt_at_start.lock().unwrap().as_deref(),
                Some("1.0.0\n"),
                "Receipt on disk must be restored before service restart executes"
            );

            let _ = std::fs::remove_dir_all(root);
        }

        // Sub-scenario B: Certification failure order
        // Expected: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active
        {
            let (root, _path, conn, _) = test_fixture();
            let opt_dir = root.join("opt/syncthing-order-cert-fail");
            std::fs::create_dir_all(&opt_dir).unwrap();
            let receipt_file = opt_dir.join(".af-version");
            std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

            let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let events_for_rb = events.clone();
            let events_for_cf = events.clone();

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
                if snaps.iter().any(|s| s.path.to_string_lossy().contains("syncthing-order-cert-fail")) {
                    events_for_rb.lock().unwrap().push("rollback".to_string());
                }
            }));
            *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = Some(Box::new(move |pkg| {
                if pkg == "syncthing-order-cert-fail" {
                    events_for_cf.lock().unwrap().push("certify_fail".to_string());
                }
            }));

            struct OrderCertFailBackend {
                events: Arc<std::sync::Mutex<Vec<String>>>,
                receipt_file: PathBuf,
                receipts_at_start: Arc<std::sync::Mutex<Vec<String>>>,
            }
            impl LifecycleBackend for OrderCertFailBackend {
                fn runtime_port(&self, _: &str) -> i32 { 8384 }
                fn available_port(&self, _: i32) -> bool { true }
                fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                    let rolled_back = self.events.lock().unwrap().contains(&"rollback".to_string());
                    if rolled_back {
                        self.events.lock().unwrap().push("active".to_string());
                    }
                    Box::pin(async { Ok(true) })
                }
                fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                    let events = self.events.lock().unwrap();
                    let last_stop = events.iter().rposition(|e| e == "stop");
                    let last_start = events.iter().rposition(|e| e == "start");
                    let is_q = match (last_stop, last_start) {
                        (Some(s), Some(st)) => s > st,
                        (Some(_), None) => true,
                        _ => false,
                    };
                    Box::pin(async move { Ok(is_q) })
                }
                fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                    self.events.lock().unwrap().push(action.to_string());
                    if action == "start" {
                        let content = std::fs::read_to_string(&self.receipt_file).unwrap_or_default();
                        self.receipts_at_start.lock().unwrap().push(content);
                    }
                    Box::pin(async { Ok(()) })
                }
                fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                    self.events.lock().unwrap().push("script".to_string());
                    let rf = self.receipt_file.clone();
                    Box::pin(async move {
                        // Installer succeeds but writes version 1.5.0 which mismatches expected target 2.0.0
                        std::fs::write(&rf, b"1.5.0\n").unwrap();
                        Ok(())
                    })
                }
            }

            let receipts_at_start = Arc::new(std::sync::Mutex::new(Vec::new()));
            let backend = OrderCertFailBackend {
                events: events.clone(),
                receipt_file: receipt_file.clone(),
                receipts_at_start: receipts_at_start.clone(),
            };

            let syncthing_package = Package {
                name: "syncthing-order-cert-fail".into(),
                service_name: "syncthing-order-cert-fail".into(),
                service_type: "systemd".into(),
                default_port: 8384,
                ..Default::default()
            };

            let req = PackageRunnerRequest {
                package_id: "syncthing-order-cert-fail".into(),
                action: "update".into(),
                script_name: "updatepackage-syncthing".into(),
                app_port: 8384,
                expected_target_version: Some("2.0.0".into()),
                ..Default::default()
            };

            let mut op = CoordinatedOperation::admit(conn, req, syncthing_package, vec!["syncthing-order-cert-fail".into()]).unwrap();
            let (sender, _receiver) = mpsc::channel(32);
            let receipt = op.execute(&backend, &sender).await.unwrap();
            assert_eq!(receipt.status, "failed");

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;
            *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = None;

            let recorded = events.lock().unwrap().clone();
            assert_eq!(
                recorded,
                vec!["stop", "script", "start", "certify_fail", "stop", "rollback", "start", "active"],
                "Certification failure must follow exact order: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active"
            );

            // Assert rollback_operation_state ALWAYS happens before final service restart and verification
            let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
            let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
            let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
            assert!(
                rollback_pos < final_start_pos,
                "rollback_operation_state MUST occur before final service restart"
            );
            assert!(
                final_start_pos < final_active_pos,
                "Final service restart MUST occur before active verification"
            );

            // First start saw installer version 1.5.0, but final restart saw restored version 1.0.0!
            let starts = receipts_at_start.lock().unwrap().clone();
            assert_eq!(starts.len(), 2);
            assert_eq!(starts[0], "1.5.0\n");
            assert_eq!(starts[1], "1.0.0\n", "Final service restart must see restored pre-op receipt");

            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn test_parse_systemd_active_state_only_active_is_true() {
        // "active" must be confirmed active
        assert_eq!(super::parse_systemd_active_state("active").unwrap(), true);
        assert_eq!(super::parse_systemd_active_state("  active  \n").unwrap(), true);

        // Transitional and stopped states must return Ok(false)
        assert_eq!(super::parse_systemd_active_state("activating").unwrap(), false);
        assert_eq!(super::parse_systemd_active_state("deactivating").unwrap(), false);
        assert_eq!(super::parse_systemd_active_state("reloading").unwrap(), false);
        assert_eq!(super::parse_systemd_active_state("inactive").unwrap(), false);
        assert_eq!(super::parse_systemd_active_state("failed").unwrap(), false);

        // Unknown states must return Err
        assert!(super::parse_systemd_active_state("unknown").is_err());
        assert!(super::parse_systemd_active_state("maintenance").is_err());
        assert!(super::parse_systemd_active_state("").is_err());
    }

    #[test]
    fn test_parse_systemd_quiesced_state_inactive_and_failed_are_true() {
        // Genuinely quiescent states must return Ok(true)
        assert_eq!(super::parse_systemd_quiesced_state("inactive").unwrap(), true);
        assert_eq!(super::parse_systemd_quiesced_state("  inactive  \n").unwrap(), true);
        assert_eq!(super::parse_systemd_quiesced_state("failed").unwrap(), true);

        // Live and transitional states must return Ok(false)
        assert_eq!(super::parse_systemd_quiesced_state("active").unwrap(), false);
        assert_eq!(super::parse_systemd_quiesced_state("activating").unwrap(), false);
        assert_eq!(super::parse_systemd_quiesced_state("deactivating").unwrap(), false);
        assert_eq!(super::parse_systemd_quiesced_state("reloading").unwrap(), false);

        // Unknown states must return Err
        assert!(super::parse_systemd_quiesced_state("unknown").is_err());
        assert!(super::parse_systemd_quiesced_state("maintenance").is_err());
        assert!(super::parse_systemd_quiesced_state("").is_err());
    }

    #[test]
    fn test_is_incomplete_rollback_error_hyphenated_and_diagnostics() {
        assert!(is_incomplete_rollback_error("incomplete-rollback"));
        assert!(is_incomplete_rollback_error("incomplete rollback"));
        assert!(is_incomplete_rollback_error("incomplete_rollback"));
        assert!(is_incomplete_rollback_error("Rclone rollback aborted because service quiescence failed; preserving recovery archive ... (incomplete-rollback)"));
        assert!(is_incomplete_rollback_error("Application recovery is incomplete; recovery backup preserved"));
        assert!(is_incomplete_rollback_error("Rollback incomplete; recovery backup preserved"));
        assert!(is_incomplete_rollback_error("Failed to stop unit sonarr.service"));

        // Unrelated errors must return false
        assert!(!is_incomplete_rollback_error("connection reset by peer"));
        assert!(!is_incomplete_rollback_error("file not found"));
    }

    #[tokio::test]
    async fn test_restore_and_restart_units_quiesce_failure_gates_restoration_and_restart() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        struct QuiesceFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl LifecycleBackend for QuiesceFailBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                self.events.lock().unwrap().push("active".to_string());
                Box::pin(async { Ok(true) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                if action == "stop" {
                    Box::pin(async { anyhow::bail!("systemctl stop failed deliberately") })
                } else {
                    Box::pin(async { Ok(()) })
                }
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let backend = QuiesceFailBackend { events: events.clone() };

        let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb_called_hook = rollback_called.clone();
        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
            rb_called_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let stopped = vec!["mock-unit.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-quiesce-fail",
            "mockpkg",
            &stopped,
            &stopped,
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        // 1. rollback_operation_state must NOT have been called!
        assert!(!rollback_called.load(std::sync::atomic::Ordering::SeqCst), "Rollback must be gated on successful quiescence");

        // 2. Services must NOT have been restarted!
        let recorded = events.lock().unwrap().clone();
        assert_eq!(recorded, vec!["stop"], "Backend must only receive stop, never start or active verification");

        // 3. receipt_restore_error must indicate quiescence failure
        let r_err = receipt_restore_error.expect("receipt_restore_error must be set on quiesce failure");
        assert!(r_err.contains("Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"));

        // 4. restart_failures must contain the stop failure
        assert!(!restart_failures.is_empty());
        assert!(restart_failures[0].contains("stop before restoration failed"));
    }

    #[tokio::test]
    async fn test_restore_and_restart_units_snapshot_restore_failure_gates_restart() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        struct SnapshotFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl LifecycleBackend for SnapshotFailBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                self.events.lock().unwrap().push("active".to_string());
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let temp_dir = std::env::temp_dir().join(format!("af-test-snap-fail-gate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let blocking_file = temp_dir.join("block");
        std::fs::write(&blocking_file, b"file").unwrap();
        // Path whose parent is a regular file will fail stepwise directory traversal during restoration!
        let bad_snap = FileSnapshot::absent(blocking_file.join(".af-version"));

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let backend = SnapshotFailBackend { events: events.clone() };

        let stopped = vec!["mock-unit.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-snap-fail",
            "mockpkg",
            &stopped,
            &stopped,
            &[bad_snap],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        let _ = std::fs::remove_dir_all(&temp_dir);

        // 1. Backend must have stopped the unit, but NEVER called start or active
        let recorded = events.lock().unwrap().clone();
        assert_eq!(recorded, vec!["stop"], "Backend must not call start after snapshot restoration failure");

        // 2. receipt_restore_error must be populated
        assert!(receipt_restore_error.is_some());

        // 3. restart_failures must record refusal to restart
        assert!(restart_failures.iter().any(|f| f.contains("Refusing to restart pre-stopped service after snapshot restoration failure")));
    }

    #[tokio::test]
    async fn test_restore_and_restart_units_incomplete_rollback_gates_restart() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        struct IncRollbackBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl LifecycleBackend for IncRollbackBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                self.events.lock().unwrap().push("active".to_string());
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let backend = IncRollbackBackend { events: events.clone() };

        let stopped = vec!["mock-unit.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-inc-rb",
            "mockpkg",
            &stopped,
            &stopped,
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            true, // incomplete_rollback = true
            true,
        )
        .await;

        // 1. Backend must have stopped the unit, but NEVER called start or active
        let recorded = events.lock().unwrap().clone();
        assert_eq!(recorded, vec!["stop"], "Backend must not call start after incomplete rollback");

        // 2. restart_failures must record refusal to restart
        assert!(restart_failures.iter().any(|f| f.contains("Refusing to restart pre-stopped service after incomplete rollback")));
    }

    #[tokio::test]
    async fn test_skipped_runtime_restoration_preserves_recovery_snapshot() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        struct RecoveryBlockedBackend {
            quiescent: bool,
            events: std::sync::Mutex<Vec<String>>,
        }
        impl LifecycleBackend for RecoveryBlockedBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                self.events.lock().unwrap().push("active".to_string());
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async move { Ok(self.quiescent) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        for (quiescent, incomplete_rollback) in [(false, false), (true, true)] {
            let root = std::env::temp_dir().join(format!("af-test-blocked-recovery-{}", uuid::Uuid::new_v4()));
            let runtime = root.join("opt/sonarr");
            std::fs::create_dir_all(&runtime).unwrap();
            let live_file = runtime.join("database.db");
            std::fs::write(&live_file, b"original-database").unwrap();
            let env_cfg = crate::PackageExecutionEnv::isolated(&root);
            let mut snapshot = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
            let backup_root = snapshot.backup_root.clone();
            let backup_file = snapshot.entries.iter().find_map(|entry| match entry {
                RuntimeSnapshotEntry::Directory { target_path, backup_path, .. } if target_path == &runtime => {
                    Some(backup_path.join("database.db"))
                }
                _ => None,
            }).expect("runtime directory must be captured");
            std::fs::write(&live_file, b"installer-modified-database").unwrap();
            let backend = RecoveryBlockedBackend {
                quiescent,
                events: std::sync::Mutex::new(Vec::new()),
            };
            let units = vec!["sonarr.service".to_string()];
            let mut receipt_restore_error = None;
            let mut restart_failures = Vec::new();

            CoordinatedOperation::restore_and_restart_units_with_runtime(
                &backend,
                "job-blocked-recovery",
                "sonarr",
                &units,
                &units,
                &[],
                &[],
                &mut receipt_restore_error,
                &mut restart_failures,
                incomplete_rollback,
                true,
                Some(&mut snapshot),
            ).await;

            assert_eq!(*backend.events.lock().unwrap(), vec!["stop"]);
            assert_eq!(std::fs::read(&live_file).unwrap(), b"installer-modified-database");
            assert!(snapshot.preserve_on_drop);
            assert!(!restart_failures.is_empty());
            if quiescent {
                assert!(receipt_restore_error.is_none());
                assert!(restart_failures.iter().any(|failure| failure.contains("incomplete rollback")));
            } else {
                assert!(receipt_restore_error.unwrap().contains("quiescence failed"));
            }
            drop(snapshot);
            assert!(backup_root.is_dir());
            assert_eq!(std::fs::read(&backup_file).unwrap(), b"original-database");
            force_remove_backup_tree(&root);
        }
    }

    #[tokio::test]
    async fn test_rollback_quiesces_initially_inactive_unit_started_during_install() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/test-multi-unit");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "test-multi-unit".into(),
            service_name: "unit-a.service".into(),
            service_type: "systemd".into(),
            default_port: 8384,
            ..Default::default()
        };

        let unit_a_active = Arc::new(std::sync::Mutex::new(true));
        let unit_b_active = Arc::new(std::sync::Mutex::new(false));
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let hook_events = events.clone();
        let hook_a = unit_a_active.clone();
        let hook_b = unit_b_active.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| s.path.to_string_lossy().contains("test-multi-unit")) {
                let a_is_active = *hook_a.lock().unwrap();
                let b_is_active = *hook_b.lock().unwrap();
                assert!(!a_is_active, "unit-a.service must be inactive BEFORE rollback_operation_state");
                assert!(!b_is_active, "unit-b.service must be inactive BEFORE rollback_operation_state");
                hook_events.lock().unwrap().push("rollback".to_string());
            }
        }));

        struct MultiUnitBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            unit_a_active: Arc<std::sync::Mutex<bool>>,
            unit_b_active: Arc<std::sync::Mutex<bool>>,
        }

        impl LifecycleBackend for MultiUnitBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8384 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let is_act = match unit {
                    "unit-a.service" => *self.unit_a_active.lock().unwrap(),
                    "unit-b.service" => *self.unit_b_active.lock().unwrap(),
                    _ => false,
                };
                self.events.lock().unwrap().push(format!("active:{}:{}", unit, is_act));
                Box::pin(async move { Ok(is_act) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{}:{}", action, unit));
                match action {
                    "stop" => {
                        if unit == "unit-a.service" {
                            *self.unit_a_active.lock().unwrap() = false;
                        } else if unit == "unit-b.service" {
                            *self.unit_b_active.lock().unwrap() = false;
                        }
                    }
                    "start" => {
                        if unit == "unit-a.service" {
                            *self.unit_a_active.lock().unwrap() = true;
                        } else if unit == "unit-b.service" {
                            *self.unit_b_active.lock().unwrap() = true;
                        }
                    }
                    _ => {}
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                // Installer script starts initially-inactive unit-b.service
                *self.unit_b_active.lock().unwrap() = true;
                self.events.lock().unwrap().push("script_started:unit-b.service".to_string());
                // Then script fails
                Box::pin(async { anyhow::bail!("installer failed deliberately") })
            }
        }

        let backend = MultiUnitBackend {
            events: events.clone(),
            unit_a_active: unit_a_active.clone(),
            unit_b_active: unit_b_active.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "test-multi-unit".into(),
            action: "update".into(),
            script_name: "updatepackage-test-multi".into(),
            app_port: 8384,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["unit-a.service".into(), "unit-b.service".into()],
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();

        // 1. Rollback must have occurred
        let rollback_pos = recorded.iter().position(|e| e == "rollback").expect("Rollback must be recorded");

        // 2. Both unit-a and unit-b must have been stopped BEFORE rollback
        let stop_a_quiesce = recorded[..rollback_pos].iter().rposition(|e| e == "stop:unit-a.service").expect("unit-a must be stopped before rollback");
        let stop_b_quiesce = recorded[..rollback_pos].iter().rposition(|e| e == "stop:unit-b.service").expect("unit-b must be stopped before rollback");
        assert!(stop_a_quiesce < rollback_pos);
        assert!(stop_b_quiesce < rollback_pos);

        // 3. ONLY unit-a.service must be restarted after rollback
        let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
            .iter()
            .filter(|e| e.starts_with("start:"))
            .cloned()
            .collect();
        assert_eq!(starts_after_rollback, vec!["start:unit-a.service"], "Only initially-active unit-a must be restarted");

        // 4. Verify final active states: unit-a is active, unit-b remains inactive
        assert!(*unit_a_active.lock().unwrap(), "unit-a must be active after restoration");
        assert!(!*unit_b_active.lock().unwrap(), "unit-b must remain inactive after restoration");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_fresh_install_script_fail_quiesces_installer_started_unit() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        let (root, _path, conn, _) = test_fixture();
        // Genuine fresh install: no /opt/<package> directory or receipt on disk!

        let package = Package {
            name: "test-fresh-pkg".into(),
            service_name: "fresh-unit.service".into(),
            service_type: "systemd".into(),
            default_port: 8484,
            ..Default::default()
        };

        let fresh_unit_active = Arc::new(std::sync::Mutex::new(false));
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let hook_events = events.clone();
        let hook_unit = fresh_unit_active.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| s.path.to_string_lossy().contains("test-fresh-pkg")) {
                let unit_is_active = *hook_unit.lock().unwrap();
                assert!(!unit_is_active, "fresh-unit.service must be quiesced/inactive BEFORE rollback_operation_state");
                hook_events.lock().unwrap().push("rollback".to_string());
            }
        }));

        struct FreshInstallBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            fresh_unit_active: Arc<std::sync::Mutex<bool>>,
        }

        impl LifecycleBackend for FreshInstallBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8484 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let is_act = if unit == "fresh-unit.service" {
                    *self.fresh_unit_active.lock().unwrap()
                } else {
                    false
                };
                self.events.lock().unwrap().push(format!("active:{}:{}", unit, is_act));
                Box::pin(async move { Ok(is_act) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{}:{}", action, unit));
                if action == "stop" && unit == "fresh-unit.service" {
                    *self.fresh_unit_active.lock().unwrap() = false;
                } else if action == "start" && unit == "fresh-unit.service" {
                    *self.fresh_unit_active.lock().unwrap() = true;
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                // Fresh installer starts fresh-unit.service during installation
                *self.fresh_unit_active.lock().unwrap() = true;
                self.events.lock().unwrap().push("installer_started:fresh-unit.service".to_string());
                // Then installer fails
                Box::pin(async { anyhow::bail!("fresh installer failed deliberately") })
            }
        }

        let backend = FreshInstallBackend {
            events: events.clone(),
            fresh_unit_active: fresh_unit_active.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "test-fresh-pkg".into(),
            action: "install".into(),
            script_name: "installpackage-test-fresh".into(),
            app_port: 8484,
            expected_target_version: Some("1.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["fresh-unit.service".into()],
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();

        // 1. Rollback must have occurred
        let rollback_pos = recorded.iter().position(|e| e == "rollback").expect("Rollback must be recorded");

        // 2. fresh-unit.service must have been stopped during rollback quiescence (before rollback hook)
        let stop_quiesce = recorded[..rollback_pos].iter().rposition(|e| e == "stop:fresh-unit.service").expect("fresh-unit.service must be stopped during rollback quiescence");
        assert!(stop_quiesce < rollback_pos);

        // 3. fresh-unit.service must NOT have been started after rollback (it was not initially active)
        let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
            .iter()
            .filter(|e| e.starts_with("start:"))
            .cloned()
            .collect();
        assert!(starts_after_rollback.is_empty(), "Fresh installer started unit must not be restarted after rollback");

        // 4. Verify final active state: fresh-unit is inactive
        assert!(!*fresh_unit_active.lock().unwrap(), "fresh-unit.service must remain inactive");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_running_oneshot_quiesced_on_rollback_and_not_restarted() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/test-oneshot");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "test-oneshot".into(),
            service_name: "recyclarr.timer".into(),
            service_type: "systemd".into(),
            default_port: 8585,
            ..Default::default()
        };

        let timer_active = Arc::new(std::sync::Mutex::new(true));
        let oneshot_active = Arc::new(std::sync::Mutex::new(true)); // oneshot is currently running!
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let hook_events = events.clone();
        let hook_timer = timer_active.clone();
        let hook_oneshot = oneshot_active.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| s.path.to_string_lossy().contains("test-oneshot")) {
                let timer_is_active = *hook_timer.lock().unwrap();
                let oneshot_is_active = *hook_oneshot.lock().unwrap();
                assert!(!timer_is_active, "recyclarr.timer must be inactive BEFORE rollback");
                assert!(!oneshot_is_active, "recyclarr oneshot must be inactive BEFORE rollback");
                hook_events.lock().unwrap().push("rollback".to_string());
            }
        }));

        struct OneshotBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            timer_active: Arc<std::sync::Mutex<bool>>,
            oneshot_active: Arc<std::sync::Mutex<bool>>,
        }

        impl LifecycleBackend for OneshotBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8585 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let is_act = match unit {
                    "recyclarr.timer" => *self.timer_active.lock().unwrap(),
                    "recyclarr" => *self.oneshot_active.lock().unwrap(),
                    _ => false,
                };
                self.events.lock().unwrap().push(format!("active:{}:{}", unit, is_act));
                Box::pin(async move { Ok(is_act) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{}:{}", action, unit));
                match action {
                    "stop" => {
                        if unit == "recyclarr.timer" {
                            *self.timer_active.lock().unwrap() = false;
                        } else if unit == "recyclarr" {
                            *self.oneshot_active.lock().unwrap() = false;
                        }
                    }
                    "start" => {
                        if unit == "recyclarr.timer" {
                            *self.timer_active.lock().unwrap() = true;
                        } else if unit == "recyclarr" {
                            *self.oneshot_active.lock().unwrap() = true;
                        }
                    }
                    _ => {}
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                // Installer script starts running oneshot again
                *self.oneshot_active.lock().unwrap() = true;
                self.events.lock().unwrap().push("script_started:recyclarr".to_string());
                // Then fails
                Box::pin(async { anyhow::bail!("installer failed deliberately") })
            }
        }

        let backend = OneshotBackend {
            events: events.clone(),
            timer_active: timer_active.clone(),
            oneshot_active: oneshot_active.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "test-oneshot".into(),
            action: "update".into(),
            script_name: "updatepackage-test-oneshot".into(),
            app_port: 8585,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["recyclarr.timer".into(), "recyclarr".into()],
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();

        // 1. Both timer and running oneshot must be stopped before script execution (pre-operation)
        let script_pos = recorded.iter().position(|e| e == "script").expect("Script must run");
        assert!(recorded[..script_pos].contains(&"stop:recyclarr.timer".to_string()));
        assert!(recorded[..script_pos].contains(&"stop:recyclarr".to_string()));

        // 2. Rollback must have occurred
        let rollback_pos = recorded.iter().position(|e| e == "rollback").expect("Rollback must be recorded");

        // 3. During rollback quiescence, running oneshot is stopped
        let stop_oneshot_quiesce = recorded[script_pos..rollback_pos].iter().rposition(|e| e == "stop:recyclarr");
        assert!(stop_oneshot_quiesce.is_some(), "Running oneshot recyclarr must be stopped during rollback quiescence");

        // 4. ONLY recyclarr.timer is restarted after rollback; recyclarr oneshot is NOT restarted!
        let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
            .iter()
            .filter(|e| e.starts_with("start:"))
            .cloned()
            .collect();
        assert_eq!(starts_after_rollback, vec!["start:recyclarr.timer".to_string()], "Only recyclarr.timer should be restarted, not oneshot");

        // 5. Final states
        assert!(*timer_active.lock().unwrap(), "recyclarr.timer must be active");
        assert!(!*oneshot_active.lock().unwrap(), "recyclarr oneshot must be inactive");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_unit_in_transitional_state_stopped_before_op_and_restarted_on_rollback() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        // Verify parse_systemd_active_state directly: only "active" is true
        assert!(parse_systemd_active_state("active").unwrap());
        assert!(!parse_systemd_active_state("activating").unwrap());
        assert!(!parse_systemd_active_state("reloading").unwrap());
        assert!(!parse_systemd_active_state("deactivating").unwrap());
        assert!(!parse_systemd_active_state("inactive").unwrap());
        assert!(!parse_systemd_active_state("failed").unwrap());

        // Verify parse_systemd_quiesced_state directly: only inactive/failed are true
        assert!(!parse_systemd_quiesced_state("active").unwrap());
        assert!(!parse_systemd_quiesced_state("activating").unwrap());
        assert!(!parse_systemd_quiesced_state("reloading").unwrap());
        assert!(!parse_systemd_quiesced_state("deactivating").unwrap());
        assert!(parse_systemd_quiesced_state("inactive").unwrap());
        assert!(parse_systemd_quiesced_state("failed").unwrap());

        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/test-trans");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "test-trans".into(),
            service_name: "trans-unit.service".into(),
            service_type: "systemd".into(),
            default_port: 8686,
            ..Default::default()
        };

        // Initially in transitional state: !quiescent() reports true because parse_systemd_quiesced_state treats activating as false
        let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        struct TransBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            unit_state: Arc<std::sync::Mutex<String>>,
        }

        impl LifecycleBackend for TransBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8686 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let st = self.unit_state.lock().unwrap().clone();
                let is_act = parse_systemd_active_state(&st).unwrap();
                self.events.lock().unwrap().push(format!("active:{}:{}", unit, is_act));
                Box::pin(async move { Ok(is_act) })
            }
            fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let st = self.unit_state.lock().unwrap().clone();
                let is_q = parse_systemd_quiesced_state(&st).unwrap();
                self.events.lock().unwrap().push(format!("quiescent:{}:{}", unit, is_q));
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{}:{}", action, unit));
                match action {
                    "stop" => {
                        *self.unit_state.lock().unwrap() = "inactive".to_string();
                    }
                    "start" => {
                        *self.unit_state.lock().unwrap() = "active".to_string();
                    }
                    _ => {}
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                Box::pin(async { anyhow::bail!("script failed deliberately") })
            }
        }

        let backend = TransBackend {
            events: events.clone(),
            unit_state: unit_state.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "test-trans".into(),
            action: "update".into(),
            script_name: "updatepackage-test-trans".into(),
            app_port: 8686,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["trans-unit.service".into()],
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        let recorded = events.lock().unwrap().clone();

        // 1. Pre-operation stopped trans-unit.service because !backend.quiescent returned true for "activating"
        let script_pos = recorded.iter().position(|e| e == "script").expect("Script must run");
        assert!(recorded[..script_pos].contains(&"stop:trans-unit.service".to_string()));

        // 2. Rollback restarts trans-unit.service because it was included in stopped
        assert!(recorded[script_pos..].contains(&"start:trans-unit.service".to_string()));
        assert_eq!(*unit_state.lock().unwrap(), "active");

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_transitional_unit_fails_post_start_health_certification() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/test-trans-cert");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "test-trans-cert".into(),
            service_name: "trans-cert.service".into(),
            service_type: "systemd".into(),
            default_port: 8787,
            ..Default::default()
        };

        // Initially in transitional state: "activating"
        let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        struct TransCertBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            unit_state: Arc<std::sync::Mutex<String>>,
        }

        impl LifecycleBackend for TransCertBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8787 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let st = self.unit_state.lock().unwrap().clone();
                let is_act = parse_systemd_active_state(&st).unwrap();
                self.events.lock().unwrap().push(format!("active:{}:{}:{}", unit, st, is_act));
                Box::pin(async move { Ok(is_act) })
            }
            fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                let st = self.unit_state.lock().unwrap().clone();
                let is_q = parse_systemd_quiesced_state(&st).unwrap();
                self.events.lock().unwrap().push(format!("quiescent:{}:{}:{}", unit, st, is_q));
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{}:{}", action, unit));
                match action {
                    "stop" => {
                        *self.unit_state.lock().unwrap() = "inactive".to_string();
                    }
                    "start" => {
                        // Remains stuck in transitional "activating" state instead of reaching "active"
                        *self.unit_state.lock().unwrap() = "activating".to_string();
                    }
                    _ => {}
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                Box::pin(async { Ok(()) })
            }
        }

        let backend = TransCertBackend {
            events: events.clone(),
            unit_state: unit_state.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "test-trans-cert".into(),
            action: "update".into(),
            script_name: "updatepackage-test-trans-cert".into(),
            app_port: 8787,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["trans-cert.service".into()],
        )
        .unwrap();

        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed", "Operation must fail when service remains in activating state after start");

        let recorded = events.lock().unwrap().clone();

        // 1. Pre-operation stopped trans-cert.service because !backend.quiescent returned true for activating
        let script_pos = recorded.iter().position(|e| e == "script").expect("Script must run");
        assert!(recorded[..script_pos].contains(&"stop:trans-cert.service".to_string()));

        // 2. Start was attempted after installer script
        let start_pos = recorded.iter().position(|e| e == "start:trans-cert.service").expect("Start must be called");
        assert!(start_pos > script_pos);

        // 3. Post-start active check saw "activating" and returned false, failing certification
        assert!(recorded.contains(&"active:trans-cert.service:activating:false".to_string()));

        // 4. Job diagnostic records that unit is not active after start
        let (diag,): (Option<String>,) = op
            .conn
            .query_row(
                "SELECT sanitized_summary FROM package_lifecycle_jobs WHERE package_id='test-trans-cert'",
                [],
                |row| Ok((row.get(0)?,)),
            )
            .unwrap();
        assert!(diag.as_deref().unwrap_or("").contains("is not active after start"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_absent_unit_rollback_allows_snapshot_restoration_whereas_active_stop_failure_gates_restoration() {
        let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

        struct AbsentRollbackBackend {
            fail_as_absent: bool,
            quiescent_result: bool,
            events: Arc<std::sync::Mutex<Vec<String>>>,
        }

        impl LifecycleBackend for AbsentRollbackBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8080 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(false) })
            }
            fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
                self.events.lock().unwrap().push(format!("quiescent:{unit}"));
                let res = self.quiescent_result;
                Box::pin(async move { Ok(res) })
            }
            fn control<'a>(&'a self, unit: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(format!("{action}:{unit}"));
                if action == "stop" {
                    if self.fail_as_absent {
                        Box::pin(async { anyhow::bail!("Unit radarr.service not loaded (exit status: 5)") })
                    } else {
                        Box::pin(async { anyhow::bail!("Failed to stop radarr.service: unit is active and locked") })
                    }
                } else {
                    Box::pin(async { Ok(()) })
                }
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        // Scenario 1: Absent unit on fresh install rollback
        // control("stop") fails with "Unit radarr.service not loaded (exit status: 5)"
        // but quiescent returns Ok(true).
        // Rollback restoration MUST proceed!
        {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let backend = AbsentRollbackBackend {
                fail_as_absent: true,
                quiescent_result: true,
                events: events.clone(),
            };

            let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let rb_hook = rollback_called.clone();
            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
                rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
            }));

            let units = vec!["radarr.service".to_string()];
            let mut receipt_restore_error = None;
            let mut restart_failures = Vec::new();

            CoordinatedOperation::restore_and_restart_units(
                &backend,
                "job-absent-unit",
                "radarr",
                &units,
                &[], // fresh install: no restart units
                &[],
                &[],
                &mut receipt_restore_error,
                &mut restart_failures,
                false,
                true,
            )
            .await;

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

            // Rollback restoration must NOT be gated because the unit is absent and quiescent!
            assert!(rollback_called.load(std::sync::atomic::Ordering::SeqCst), "Rollback must proceed for absent quiescent unit");
            assert!(receipt_restore_error.is_none(), "receipt_restore_error must not be set on benign absent stop");
            assert!(restart_failures.is_empty(), "restart_failures must be empty for absent quiescent unit");
        }

        // Scenario 2: Active unit where stop fails
        // control("stop") fails on active unit and quiescent returns false (or error is not absent).
        // Rollback restoration MUST be gated!
        {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let backend = AbsentRollbackBackend {
                fail_as_absent: false,
                quiescent_result: false,
                events: events.clone(),
            };

            let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let rb_hook = rollback_called.clone();
            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
                rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
            }));

            let units = vec!["radarr.service".to_string()];
            let mut receipt_restore_error = None;
            let mut restart_failures = Vec::new();

            CoordinatedOperation::restore_and_restart_units(
                &backend,
                "job-active-stop-fail",
                "radarr",
                &units,
                &[],
                &[],
                &[],
                &mut receipt_restore_error,
                &mut restart_failures,
                false,
                true,
            )
            .await;

            *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

            // Rollback restoration MUST be gated on non-absent quiesce failure!
            assert!(!rollback_called.load(std::sync::atomic::Ordering::SeqCst), "Rollback must be gated when active unit stop fails");
            assert!(receipt_restore_error.is_some(), "receipt_restore_error must indicate quiescence failure");
            assert!(receipt_restore_error.as_ref().unwrap().contains("Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"));
            assert!(!restart_failures.is_empty());
            assert!(restart_failures[0].contains("radarr.service: stop before restoration failed"));
        }
    }

    #[test]
    fn test_sanitize_lifecycle_field_redacts_nested_json_object_and_array_secrets() {
        // Raw key-value with nested object
        let raw_obj = sanitize_lifecycle_field("failed with password: {\"value\":\"CANARY_SECRET\"}");
        assert!(!raw_obj.contains("CANARY_SECRET"), "Secret must be redacted: {}", raw_obj);
        assert!(raw_obj.contains("password: [REDACTED]"), "Must redact raw object: {}", raw_obj);

        // JSON key-value with nested object
        let json_obj = sanitize_lifecycle_field("{\"password\":{\"value\":\"CANARY_SECRET\"}}");
        assert!(!json_obj.contains("CANARY_SECRET"), "Secret must be redacted: {}", json_obj);
        assert!(json_obj.contains("\"password\":[REDACTED]"), "Must redact JSON object: {}", json_obj);

        // Raw key-value with JSON array
        let raw_arr = sanitize_lifecycle_field("secret: [\"CANARY_SECRET_1\", \"CANARY_SECRET_2\"]");
        assert!(!raw_arr.contains("CANARY_SECRET"), "Secrets in array must be redacted: {}", raw_arr);
        assert!(raw_arr.contains("secret: [REDACTED]"), "Must redact raw array: {}", raw_arr);

        // JSON key-value with array
        let json_arr = sanitize_lifecycle_field("{\"token\":[\"SECRET_A\",\"SECRET_B\"]}");
        assert!(!json_arr.contains("SECRET"), "Secrets in JSON array must be redacted: {}", json_arr);
        assert!(json_arr.contains("\"token\":[REDACTED]"), "Must redact JSON array: {}", json_arr);

        // 2 levels of nested braces
        let nested_2_lvl = sanitize_lifecycle_field("api_key: {\"outer\": {\"inner\": \"SECRET_KEY\"}}");
        assert!(!nested_2_lvl.contains("SECRET_KEY"), "2-level nested secret must be redacted: {}", nested_2_lvl);
        assert!(nested_2_lvl.contains("api_key: [REDACTED]"));

        // 3-level and 4-level nested JSON objects
        let nested_3_lvl = sanitize_lifecycle_field("{\"password\": {\"l1\": {\"l2\": {\"l3\": \"CANARY_3LVL\"}}}}");
        assert!(!nested_3_lvl.contains("CANARY_3LVL"), "3-level nested secret must be redacted: {}", nested_3_lvl);
        assert!(nested_3_lvl.contains("\"password\": [REDACTED]") || nested_3_lvl.contains("\"password\":[REDACTED]"));

        let nested_4_lvl = sanitize_lifecycle_field("api_key: {\"l1\": {\"l2\": {\"l3\": {\"l4\": \"CANARY_4LVL\"}}}}");
        assert!(!nested_4_lvl.contains("CANARY_4LVL"), "4-level nested secret must be redacted: {}", nested_4_lvl);
        assert!(nested_4_lvl.contains("api_key: [REDACTED]"));

        // Multiline nested JSON objects
        let nested_multiline = sanitize_lifecycle_field("\"secret\": {\n  \"l1\": {\n    \"l2\": \"CANARY_MULTILINE\"\n  }\n}");
        assert!(!nested_multiline.contains("CANARY_MULTILINE"), "Multiline nested secret must be redacted: {}", nested_multiline);
        assert!(nested_multiline.contains("\"secret\": [REDACTED]"));

        // Already redacted strings should not be corrupted
        let already_redacted_raw = sanitize_lifecycle_field("password: [REDACTED]");
        assert_eq!(already_redacted_raw, "password: [REDACTED]");

        let already_redacted_json = sanitize_lifecycle_field("{\"password\":[REDACTED]}");
        assert_eq!(already_redacted_json, "{\"password\":[REDACTED]}");
    }

    #[tokio::test]
    async fn test_post_certification_failure_restores_runtime_state_and_receipt() {
        let (root, _path, conn, package) = test_fixture();

        let opt_syncthing = root.join("opt/syncthing");
        std::fs::create_dir_all(&opt_syncthing).unwrap();
        let bin_file = opt_syncthing.join("syncthing");
        std::fs::write(&bin_file, b"bin-1.22.0").unwrap();

        let usr_bin = root.join("usr/local/bin");
        std::fs::create_dir_all(&usr_bin).unwrap();
        let usr_bin_file = usr_bin.join("syncthing");
        std::fs::write(&usr_bin_file, b"bin-1.22.0").unwrap();

        let var_lib_syncthing = root.join("var/lib/syncthing");
        std::fs::create_dir_all(&var_lib_syncthing).unwrap();
        let config_txt = var_lib_syncthing.join("config.txt");
        std::fs::write(&config_txt, b"state-1.22.0").unwrap();
        let receipt_file = var_lib_syncthing.join(".af-version");
        std::fs::write(&receipt_file, b"1.22.0\n").unwrap();

        struct PostCertFailBackend {
            root: PathBuf,
            actions: Arc<std::sync::Mutex<Vec<String>>>,
            files_before_final_start: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        }
        impl LifecycleBackend for PostCertFailBackend {
            fn runtime_port(&self, _: &str) -> i32 { 8384 }
            fn available_port(&self, _: i32) -> bool { true }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let acts = self.actions.lock().unwrap();
                let last_stop = acts.iter().rposition(|e| e == "stop");
                let last_start = acts.iter().rposition(|e| e == "start");
                let is_q = match (last_stop, last_start) {
                    (Some(s), Some(st)) => s > st,
                    (Some(_), None) => true,
                    _ => false,
                };
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(&'a self, _: &'a str, action: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
                let r = self.root.clone();
                let acts = self.actions.clone();
                let files_rec = self.files_before_final_start.clone();
                let action_str = action.to_string();
                Box::pin(async move {
                    acts.lock().unwrap().push(action_str.clone());
                    if action_str == "start" {
                        let total_starts = acts.lock().unwrap().iter().filter(|a| a.as_str() == "start").count();
                        if total_starts >= 2 {
                            // This is the post-rollback restart!
                            let bin = std::fs::read_to_string(r.join("opt/syncthing/syncthing")).unwrap_or_default();
                            let usr_bin = std::fs::read_to_string(r.join("usr/local/bin/syncthing")).unwrap_or_default();
                            let cfg = std::fs::read_to_string(r.join("var/lib/syncthing/config.txt")).unwrap_or_default();
                            let ver = std::fs::read_to_string(r.join("var/lib/syncthing/.af-version")).unwrap_or_default();
                            let mut lock = files_rec.lock().unwrap();
                            *lock = vec![
                                ("bin".into(), bin),
                                ("usr_bin".into(), usr_bin),
                                ("cfg".into(), cfg),
                                ("ver".into(), ver),
                            ];
                        }
                    }
                    Ok(())
                })
            }
            fn script<'a>(&'a self, _: &'a PackageRunnerRequest, _: &'a mpsc::Sender<String>) -> BoxFuture<'a, Result<()>> {
                let r = self.root.clone();
                Box::pin(async move {
                    std::fs::write(r.join("opt/syncthing/syncthing"), b"bin-1.23.4").unwrap();
                    std::fs::write(r.join("usr/local/bin/syncthing"), b"bin-1.23.4").unwrap();
                    std::fs::write(r.join("var/lib/syncthing/config.txt"), b"state-1.23.4").unwrap();
                    std::fs::write(r.join("var/lib/syncthing/.af-version"), b"1.23.4\n").unwrap();
                    Ok(())
                })
            }
        }

        let actions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let files_before_final_start = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = PostCertFailBackend {
            root: root.clone(),
            actions: actions.clone(),
            files_before_final_start: files_before_final_start.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "syncthing".into(),
            action: "update".into(),
            script_name: "updatepackage-syncthing".into(),
            app_port: 8384,
            expected_target_version: Some("1.24.0".into()), // forces target certification failure
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed", "Execute must mark receipt as failed when certification fails");

        // Verify BEFORE final restart:
        let recorded = files_before_final_start.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![
                ("bin".into(), "bin-1.22.0".into()),
                ("usr_bin".into(), "bin-1.22.0".into()),
                ("cfg".into(), "state-1.22.0".into()),
                ("ver".into(), "1.22.0\n".into()),
            ],
            "Files BEFORE final restart must be restored to 1.22.0"
        );

        // Verify on disk afterward:
        assert_eq!(std::fs::read_to_string(&bin_file).unwrap(), "bin-1.22.0");
        assert_eq!(std::fs::read_to_string(&usr_bin_file).unwrap(), "bin-1.22.0");
        assert_eq!(std::fs::read_to_string(&config_txt).unwrap(), "state-1.22.0");
        assert_eq!(std::fs::read_to_string(&receipt_file).unwrap().trim(), "1.22.0");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn test_filebot_receipt_resolution_prefers_filebot_node_over_cli() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-filebot-receipt-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let opt_filebot = temp_dir.join("opt/filebot");
        std::fs::create_dir_all(&opt_filebot).unwrap();
        std::fs::write(opt_filebot.join(".af-version"), b"5.1.6\n").unwrap();

        // When /opt/filebot-node/.af-version is absent while /opt/filebot/.af-version = 5.1.6
        // read_af_version_receipt must return None (never 5.1.6!)
        assert_eq!(
            read_af_version_receipt("filebot", &env_cfg),
            None,
            "read_af_version_receipt must never read /opt/filebot/.af-version CLI receipt"
        );

        // Now create /opt/filebot-node/.af-version = 0.4.8.1
        let opt_filebot_node = temp_dir.join("opt/filebot-node");
        std::fs::create_dir_all(&opt_filebot_node).unwrap();
        std::fs::write(opt_filebot_node.join(".af-version"), b"0.4.8.1\n").unwrap();

        assert_eq!(
            read_af_version_receipt("filebot", &env_cfg),
            Some("0.4.8.1".to_string()),
            "read_af_version_receipt must prefer /opt/filebot-node/.af-version"
        );

        // Verify candidate_version_marker_paths_with_env includes both receipts with filebot-node first
        let paths = candidate_version_marker_paths_with_env("filebot", &env_cfg).unwrap();
        let node_path = temp_dir.join("opt/filebot-node/.af-version");
        let cli_path = temp_dir.join("opt/filebot/.af-version");
        assert!(paths.contains(&node_path), "Must contain /opt/filebot-node/.af-version");
        assert!(paths.contains(&cli_path), "Must contain /opt/filebot/.af-version");

        let node_idx = paths.iter().position(|p| p == &node_path).unwrap();
        let cli_idx = paths.iter().position(|p| p == &cli_path).unwrap();
        assert!(node_idx < cli_idx, "/opt/filebot-node/.af-version must appear before /opt/filebot/.af-version");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_wave22_sanitize_lifecycle_field_scalar_credentials() {
        let test_cases = [
            "Cookie: session=CANARY_COOKIE",
            "Set-Cookie: theme=\"CANARY_COOKIE\"; HttpOnly",
            "session=CANARY_SESSION",
            "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
            "pass=CANARY_PASSWORD",
        ];

        for tc in test_cases {
            let sanitized = sanitize_lifecycle_field(tc);
            assert!(
                !sanitized.contains("CANARY_"),
                "Sanitized text must contain zero CANARY_ substrings for input {:?}, got {:?}",
                tc,
                sanitized
            );
        }

        // Idempotency check:
        assert_eq!(
            sanitize_lifecycle_field("password: [REDACTED]"),
            "password: [REDACTED]"
        );
        assert_eq!(
            sanitize_lifecycle_field("{\"password\":[REDACTED]}"),
            "{\"password\":[REDACTED]}"
        );
    }

    #[test]
    fn test_wave23_large_sparse_mutable_database_restored_on_mutation_and_deletion() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w23-sparse-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let sonarr_db_dir = temp_dir.join("var/lib/sonarr");
        std::fs::create_dir_all(&sonarr_db_dir).unwrap();
        let db_file = sonarr_db_dir.join("sonarr.db");

        let file_len: u64 = 268_435_457; // 256 MiB + 1
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&db_file).unwrap();
            f.write_all(b"OLD_DB01").unwrap();
            f.seek(SeekFrom::Start(file_len - 8)).unwrap();
            f.write_all(b"TRAIL001").unwrap();
            f.set_len(file_len).unwrap();
        }

        // Test part (a): Mutation
        {
            let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
            {
                use std::io::{Seek, SeekFrom, Write};
                let mut f = std::fs::OpenOptions::new().write(true).open(&db_file).unwrap();
                f.write_all(b"NEW_DB02").unwrap();
                f.seek(SeekFrom::Start(file_len - 8)).unwrap();
                f.write_all(b"TRAILNEW").unwrap();
            }
            assert_eq!(&std::fs::read(&db_file).unwrap()[..8], b"NEW_DB02");

            snap.restore().expect("restore must succeed");

            let restored_meta = std::fs::metadata(&db_file).unwrap();
            assert_eq!(restored_meta.len(), file_len);
            let mut f = std::fs::File::open(&db_file).unwrap();
            let mut head = [0u8; 8];
            use std::io::{Read, Seek, SeekFrom};
            f.read_exact(&mut head).unwrap();
            assert_eq!(&head, b"OLD_DB01");
            f.seek(SeekFrom::Start(file_len - 8)).unwrap();
            let mut tail = [0u8; 8];
            f.read_exact(&mut tail).unwrap();
            assert_eq!(&tail, b"TRAIL001");
        }

        // Test part (b): Deletion
        {
            let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
            std::fs::remove_file(&db_file).unwrap();
            assert!(!db_file.exists());

            snap.restore().expect("restore must succeed");

            assert!(db_file.exists(), "Deleted sonarr.db must be restored");
            let restored_meta = std::fs::metadata(&db_file).unwrap();
            assert_eq!(restored_meta.len(), file_len);
            let mut f = std::fs::File::open(&db_file).unwrap();
            let mut head = [0u8; 8];
            use std::io::{Read, Seek, SeekFrom};
            f.read_exact(&mut head).unwrap();
            assert_eq!(&head, b"OLD_DB01");
            f.seek(SeekFrom::Start(file_len - 8)).unwrap();
            let mut tail = [0u8; 8];
            f.read_exact(&mut tail).unwrap();
            assert_eq!(&tail, b"TRAIL001");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w23-footprint-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        // Plex footprint: /usr/lib/plexmediaserver/Plex Media Server and /var/lib/plexmediaserver/library.db
        let plex_lib = temp_dir.join("usr/lib/plexmediaserver");
        let plex_var = temp_dir.join("var/lib/plexmediaserver");
        std::fs::create_dir_all(&plex_lib).unwrap();
        std::fs::create_dir_all(&plex_var).unwrap();
        let plex_bin = plex_lib.join("Plex Media Server");
        let plex_db = plex_var.join("library.db");
        std::fs::write(&plex_bin, b"OLD_PLEX_BIN").unwrap();
        std::fs::write(&plex_db, b"OLD_PLEX_DB").unwrap();

        let mut plex_snap = PackageRuntimeSnapshot::capture(
            "plex",
            &["plexmediaserver.service".into()],
            &env_cfg,
            false,
        )
        .unwrap();

        std::fs::write(&plex_bin, b"NEW_PLEX_BIN").unwrap();
        std::fs::write(&plex_db, b"NEW_PLEX_DB").unwrap();
        plex_snap.restore().expect("plex restore must succeed");

        assert_eq!(std::fs::read(&plex_bin).unwrap(), b"OLD_PLEX_BIN");
        assert_eq!(std::fs::read(&plex_db).unwrap(), b"OLD_PLEX_DB");

        // Mcvnc footprint: aliased unit /etc/systemd/system/af-mcvnc.service
        let sysd_dir = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&sysd_dir).unwrap();
        let mcvnc_unit = sysd_dir.join("af-mcvnc.service");
        std::fs::write(&mcvnc_unit, b"OLD_UNIT").unwrap();

        // Capture with &[] units (catalog expands mcvnc -> af-mcvnc.service)
        let mut mcvnc_snap = PackageRuntimeSnapshot::capture("mcvnc", &[], &env_cfg, false).unwrap();
        std::fs::write(&mcvnc_unit, b"NEW_UNIT").unwrap();
        mcvnc_snap.restore().expect("mcvnc restore must succeed");
        assert_eq!(std::fs::read(&mcvnc_unit).unwrap(), b"OLD_UNIT");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave23_escaped_cookie_header_quotes_redacted() {
        let input1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
        let sanitized1 = sanitize_lifecycle_field(input1);
        assert!(
            !sanitized1.contains("COOKIE_CANARY"),
            "Escaped cookie canary must be redacted: {}",
            sanitized1
        );
        assert!(
            sanitized1.contains("Cookie: [REDACTED]"),
            "Must contain redacted cookie header: {}",
            sanitized1
        );

        let input2 = r#"curl -H "Set-Cookie: token=\"COOKIE_CANARY\"; Path=/" https://example.invalid"#;
        let sanitized2 = sanitize_lifecycle_field(input2);
        assert!(!sanitized2.contains("COOKIE_CANARY"), "Set-Cookie canary must be redacted: {}", sanitized2);

        let input3 = r#"{"args": ["curl", "-H", "Cookie: sid=\"COOKIE_CANARY\""]}"#;
        let sanitized3 = sanitize_lifecycle_field(input3);
        assert!(!sanitized3.contains("COOKIE_CANARY"), "JSON escaped cookie must be redacted: {}", sanitized3);
    }

    #[test]
    fn test_wave23_runtime_restore_failure_never_rewinds_embedded_receipt() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w23-receipt-gate-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let opt_sonarr = temp_dir.join("opt/sonarr");
        let var_lib_sonarr = temp_dir.join("var/lib/sonarr");
        std::fs::create_dir_all(&opt_sonarr).unwrap();
        std::fs::create_dir_all(&var_lib_sonarr).unwrap();

        let receipt_file = opt_sonarr.join(".af-version");
        let bin_file = opt_sonarr.join("Sonarr");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();
        std::fs::write(&bin_file, b"old").unwrap();

        let mut rt = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();

        // Mutate receipt to 2.0.0 and binary to "new"
        std::fs::write(&receipt_file, b"2.0.0\n").unwrap();
        std::fs::write(&bin_file, b"new").unwrap();

        // Replace var/lib with a regular file blocker to cause Phase 1 preflight failure
        let var_dir = temp_dir.join("var");
        let var_lib = var_dir.join("lib");
        std::fs::remove_dir_all(&var_lib).unwrap();
        std::fs::write(&var_lib, b"blocking regular file").unwrap();

        // Direct rt.restore() must fail
        let res = rt.restore();
        assert!(res.is_err(), "rt.restore must fail when ancestor is blocked");

        // .af-version MUST still be "2.0.0\n" (never rewound to 1.0.0!)
        let current_receipt = std::fs::read_to_string(&receipt_file).unwrap();
        assert_eq!(
            current_receipt,
            "2.0.0\n",
            "Receipt must NOT be rewound when runtime restore fails!"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn merged_usr_aliases(root: &std::path::Path) {
        for alias in ["bin", "sbin", "lib", "lib32", "lib64", "libx32"] {
            let real_dir = root.join("usr").join(alias);
            std::fs::create_dir_all(&real_dir).unwrap();
            std::os::unix::fs::symlink(format!("usr/{alias}"), root.join(alias)).unwrap();
        }
    }

    #[test]
    fn test_wave24_merged_usr_catalog_capture_and_restore() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w24-merged-usr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        merged_usr_aliases(&temp_dir);
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let packages_json = manifest_dir.join("../../../config/packages.json");
        let raw = std::fs::read_to_string(&packages_json)
            .unwrap_or_else(|e| panic!("read {}: {e}", packages_json.display()));
        let catalog: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        let names: Vec<String> = catalog
            .iter()
            .filter_map(|pkg| pkg.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect();
        assert!(
            names.len() >= 70,
            "expected the full catalog, found {}",
            names.len()
        );

        let mut failures = Vec::new();
        for name in &names {
            if let Err(err) = PackageRuntimeSnapshot::capture(name, &[], &env_cfg, false) {
                failures.push(format!("{name}: {err}"));
            }
        }
        assert!(
            failures.is_empty(),
            "merged-/usr capture failures ({}): {failures:?}",
            failures.len()
        );

        let unit_dir = temp_dir.join("usr/lib/systemd/system");
        std::fs::create_dir_all(&unit_dir).unwrap();
        let unit = unit_dir.join("sonarr.service");
        std::fs::write(&unit, b"OLD_UNIT").unwrap();
        let opt_bin = temp_dir.join("opt/sonarr/Sonarr");
        std::fs::create_dir_all(opt_bin.parent().unwrap()).unwrap();
        std::fs::write(&opt_bin, b"OLD_BIN").unwrap();

        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &["sonarr.service".into()], &env_cfg, false)
            .expect("sonarr capture on merged-/usr");
        let lib_prefix = temp_dir.join("lib");
        for entry in &snap.entries {
            let target = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. }
                | RuntimeSnapshotEntry::File { target_path, .. }
                | RuntimeSnapshotEntry::Symlink { target_path, .. }
                | RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            assert!(
                !target.starts_with(&lib_prefix),
                "merged-/usr target was not rewritten onto /usr: {}",
                target.display()
            );
        }
        std::fs::write(&unit, b"NEW_UNIT").unwrap();
        std::fs::write(&opt_bin, b"NEW_BIN").unwrap();
        snap.restore().expect("merged-/usr restore");
        assert_eq!(std::fs::read(&unit).unwrap(), b"OLD_UNIT");
        assert_eq!(std::fs::read(&opt_bin).unwrap(), b"OLD_BIN");

        let untrusted = temp_dir.join("untrusted-opt");
        std::fs::create_dir_all(untrusted.join("usr/opt")).unwrap();
        std::os::unix::fs::symlink("usr/opt", untrusted.join("opt")).unwrap();
        let mut bad_env = crate::PackageExecutionEnv::default();
        bad_env.fs_root = Some(untrusted);
        let bad = PackageRuntimeSnapshot::capture("sonarr", &[], &bad_env, false);
        assert!(
            bad.unwrap_err().contains("is a symlink"),
            "non-merged-usr symlinks must still fail closed"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave24_installer_footprint_round_trip() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w24-footprint-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let files = [
            ("grafana", "usr/share/grafana/public/build/app.js", "OLD_GRAFANA"),
            ("jellyfin", "usr/share/jellyfin/web/index.html", "OLD_JELLYFIN"),
            ("netdata", "usr/sbin/netdata", "OLD_NETDATA_BIN"),
            ("netdata", "usr/libexec/netdata/plugins.d/apps.plugin", "OLD_NETDATA_PLUGIN"),
            ("kasmvnc", "usr/share/kasmvnc/www/vnc.html", "OLD_KASM_WWW"),
            ("kasmvnc", "usr/bin/Xvnc", "OLD_XVNC"),
        ];
        for (_, rel, body) in files {
            let path = temp_dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body.as_bytes()).unwrap();
        }

        let mut snaps = Vec::new();
        for pkg in ["grafana", "jellyfin", "netdata", "kasmvnc"] {
            snaps.push((
                pkg,
                PackageRuntimeSnapshot::capture(pkg, &[], &env_cfg, false)
                    .unwrap_or_else(|e| panic!("{pkg} capture failed: {e}")),
            ));
        }
        for (_, rel, _) in files {
            let path = temp_dir.join(rel);
            std::fs::write(&path, b"NEW").unwrap();
        }
        for (pkg, mut snap) in snaps {
            snap.restore().unwrap_or_else(|e| panic!("{pkg} restore failed: {e}"));
        }
        for (_, rel, body) in files {
            let path = temp_dir.join(rel);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                body.as_bytes(),
                "round-trip failed for {}",
                path.display()
            );
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave24_unreadable_database_never_yields_partial_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w24-perm-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());
        let db_dir = temp_dir.join("var/lib/sonarr");
        std::fs::create_dir_all(&db_dir).unwrap();
        let protected = db_dir.join("protected.db");
        std::fs::write(&protected, b"SECRETDB").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();

        let euid = unsafe { libc::geteuid() };
        for ignore in [true, false] {
            let captured = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, ignore);
            if euid != 0 {
                let err = captured.expect_err("unreadable database must fail capture");
                assert!(
                    err.to_ascii_lowercase().contains("permission"),
                    "ignore={ignore} error should be permission denied, got {err}"
                );
                let meta = std::fs::symlink_metadata(&protected)
                    .expect("unreadable database must remain on disk");
                assert!(meta.is_file());
                assert_eq!(meta.len(), b"SECRETDB".len() as u64);
                std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644)).unwrap();
                assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
                std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
            } else {
                let mut snap = captured.expect("root can read mode 000");
                std::fs::remove_file(&protected).unwrap();
                snap.restore().expect("root restore keeps the database");
                assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
                std::fs::write(&protected, b"SECRETDB").unwrap();
                std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
            }
        }
        let _ = std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave24_sanitize_escaped_quotes_cli_flags_and_redacted_suffix() {
        let cases = [
            r#"password=\"SECRET words\""#,
            r#"api_key=\"SECRET words\""#,
            r#"client_secret=\"SECRET words\""#,
            r#"session=\"SECRET words\""#,
            r#"webhook=\"SECRET words\""#,
            r#"rclone_rc_pass=\"SECRET words\""#,
            "--password SECRET words",
            "--passwd SECRET words",
            "--pwd SECRET words",
            "--pass SECRET words",
            "--secret SECRET words",
            "--token SECRET words",
            "--api-key SECRET words",
            "--apikey SECRET words",
            "--cookie SECRET words",
            "--cookies SECRET words",
            "--session SECRET words",
            "--webhook SECRET words",
            "--password=SECRET words",
            r#"--password=\"SECRET words\""#,
            r#"--token=\"SECRET words\""#,
            r#"curl --user=\"admin:SECRET words\" https://example.invalid"#,
            r#"curl -u \"admin:SECRET words\" https://example.invalid"#,
            "bypass=visible passed=true monkey=1",
        ];
        for input in cases {
            let sanitized = sanitize_lifecycle_field(input);
            assert!(
                !sanitized.contains("SECRET"),
                "secret leaked for {input:?} -> {sanitized:?}"
            );
        }

        let boundary = sanitize_lifecycle_field("bypass=visible passed=true monkey=1");
        assert!(boundary.contains("bypass=visible"), "{boundary}");
        assert!(boundary.contains("passed=true"), "{boundary}");
        assert!(boundary.contains("monkey=1"), "{boundary}");

        let json_password = "AF_DIAG_FAILURE={\"stage\": \"password=[REDACTED]\\\"SECRET words\\\\\\\"\", \"status\": \"ok\"}";
        let sanitized_password = sanitize_lifecycle_field(json_password);
        assert!(!sanitized_password.contains("SECRET"), "{sanitized_password}");
        let payload = sanitized_password.trim_start_matches("AF_DIAG_FAILURE=");
        serde_json::from_str::<serde_json::Value>(payload)
            .unwrap_or_else(|e| panic!("password diagnostic is not JSON ({e}): {sanitized_password}"));

        let json_user = "AF_DIAG_FAILURE={\"stage\": \"--user [REDACTED]\\\"user:SECRET words\\\\\\\"\", \"status\": \"ok\"}";
        let sanitized_user = sanitize_lifecycle_field(json_user);
        assert!(!sanitized_user.contains("SECRET"), "{sanitized_user}");
        let payload = sanitized_user.trim_start_matches("AF_DIAG_FAILURE=");
        serde_json::from_str::<serde_json::Value>(payload)
            .unwrap_or_else(|e| panic!("user diagnostic is not JSON ({e}): {sanitized_user}"));

        let token_json = sanitize_lifecycle_field(r#"{"note":"token=SECRET\""}"#);
        assert!(!token_json.contains("SECRET"), "{token_json}");
        serde_json::from_str::<serde_json::Value>(&token_json)
            .unwrap_or_else(|e| panic!("token JSON broken ({e}): {token_json}"));
    }

    fn sonarr_runtime_snap_dirs_in(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        if let Ok(rd) = std::fs::read_dir(root) {
            for ent in rd.flatten() {
                if ent
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".af-rt-snap-sonarr-")
                {
                    found.push(ent.path());
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn test_wave25_capture_failure_drops_orphan_backup_root() {
        let temp_dir = std::env::temp_dir().join(format!("af-test-w25-orphan-{}", uuid::Uuid::new_v4()));
        let snap_tmp = temp_dir.join("snap-tmp");
        std::fs::create_dir_all(&snap_tmp).unwrap();
        let mut env_cfg = crate::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());
        env_cfg.temp_dir = snap_tmp.clone();
        let opt = temp_dir.join("opt/sonarr");
        let ro_sub = opt.join("ro-bin");
        let etc = temp_dir.join("etc/sonarr");
        std::fs::create_dir_all(&ro_sub).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        let readable = opt.join("readable.db");
        let ro_nested = ro_sub.join("helper.bin");
        let unreadable = etc.join("unreadable.db");
        {
            let file = std::fs::File::create(&readable).unwrap();
            file.set_len(1024 * 1024).unwrap();
        }
        std::fs::write(&ro_nested, b"RO_HELPER").unwrap();
        std::fs::write(&unreadable, b"SECRETDB").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
        let etc_parent = temp_dir.join("etc");
        let etc_real = temp_dir.join("etc-real");
        std::fs::rename(&etc_parent, &etc_real).unwrap();
        std::os::unix::fs::symlink(&etc_real, &etc_parent).unwrap();
        let err = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
            .expect_err("symlink ancestor must fail capture even as root");
        assert!(err.to_ascii_lowercase().contains("symlink"), "unexpected capture failure: {err}");
        assert!(err.contains("/etc"), "failure must follow capture of /opt/sonarr: {err}");
        let after = sonarr_runtime_snap_dirs_in(&snap_tmp);
        assert!(
            after.is_empty(),
            "capture failure left orphaned snapshot directories: {after:?}"
        );

        std::fs::remove_file(&etc_parent).unwrap();
        std::fs::rename(&etc_real, &etc_parent).unwrap();
        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
            .expect("readable tree captures");
        let preserved = snap.backup_root.clone();
        assert!(preserved.is_dir(), "backup_root must exist before restore");
        assert!(
            preserved.starts_with(&snap_tmp),
            "capture must honor env_cfg.temp_dir ({}) -> got {}",
            snap_tmp.display(),
            preserved.display()
        );
        std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let opt_parent = temp_dir.join("opt");
        std::fs::remove_dir_all(&opt).unwrap();
        std::fs::remove_dir_all(&opt_parent).unwrap();
        std::fs::write(&opt_parent, b"not-a-directory").unwrap();
        let restore_err = snap.restore().expect_err("non-directory ancestor must fail restore");
        assert!(
            snap.preserve_on_drop,
            "incomplete restore must preserve backup_root, err={restore_err}"
        );
        drop(snap);
        assert!(
            preserved.is_dir(),
            "preserve_on_drop must keep {} after Drop",
            preserved.display()
        );
        force_remove_backup_tree(&preserved);
        let _ = std::fs::remove_file(&opt_parent);
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
        force_remove_backup_tree(&temp_dir);
    }

    #[test]
    fn test_wave25_sanitize_shell_escapes_glued_suffixes_and_unicode_keys() {
        let cases = [
            r#"curl --password prefix\ SENTINEL --verbose"#,
            "curl --user operator:prefix\\ SENTINEL https://example.invalid",
            r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
            r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
            r#"password=prefix\;SENTINEL"#,
            r#"password=prefix\&SENTINEL"#,
            r#"password=prefix\,SENTINEL"#,
            "curl --password $'SENTINEL' https://example.invalid",
            "curl --password $\"SENTINEL\" https://example.invalid",
            "curl --password prefix\"SENTINEL\" https://example.invalid",
            "curl --password prefix'SENTINEL' https://example.invalid",
            "password=[REDACTED]SENTINEL",
            "curl --password [REDACTED]SENTINEL --verbose",
            "curl --password [REDACTED]'SENTINEL'",
            "curl --password [REDACTED]\"SENTINEL\" --verbose",
            "curl --password [REDACTED]$'SENTINEL' --verbose",
            r#"{"pass\u0077ord":"SENTINEL"}"#,
            r#"{"pass\\u0077ord":"SENTINEL"}"#,
        ];
        assert_eq!(cases.len(), 18, "wave 25 sanitizer scenario count");
        for input in cases {
            let once = sanitize_lifecycle_field(input);
            let twice = sanitize_lifecycle_field(&once);
            assert!(
                !once.contains("SENTINEL"),
                "secret leaked for {input:?} -> {once:?}"
            );
            assert_eq!(once, twice, "not idempotent for {input:?} -> {once:?}");
        }

        assert_eq!(
            sanitize_lifecycle_field(r#"curl --password prefix\ SENTINEL --verbose"#),
            "curl --password [REDACTED] --verbose"
        );
        assert_eq!(
            sanitize_lifecycle_field("curl --user operator:prefix\\ SENTINEL https://example.invalid"),
            "curl --user [REDACTED] https://example.invalid"
        );
        assert_eq!(
            sanitize_lifecycle_field(r#"password=prefix\;SENTINEL"#),
            "password=[REDACTED]"
        );
        assert_eq!(
            sanitize_lifecycle_field("curl --password $'SENTINEL' https://example.invalid"),
            "curl --password [REDACTED] https://example.invalid"
        );
        assert_eq!(
            sanitize_lifecycle_field("curl --password prefix\"SENTINEL\" https://example.invalid"),
            "curl --password [REDACTED] https://example.invalid"
        );
        assert_eq!(
            sanitize_lifecycle_field("password=[REDACTED]SENTINEL"),
            "password=[REDACTED]"
        );

        let json_cmd = sanitize_lifecycle_field(
            r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
        );
        assert!(!json_cmd.contains("SENTINEL"), "{json_cmd}");
        serde_json::from_str::<serde_json::Value>(&json_cmd)
            .unwrap_or_else(|e| panic!("command JSON broken ({e}): {json_cmd}"));

        let unicode_key = sanitize_lifecycle_field(r#"{"pass\u0077ord":"SENTINEL"}"#);
        assert!(!unicode_key.contains("SENTINEL"), "{unicode_key}");
        assert!(
            unicode_key.contains("password") || unicode_key.contains("pass\\u0077ord"),
            "{unicode_key}"
        );
        let double_escaped = sanitize_lifecycle_field(r#"{"pass\\u0077ord":"SENTINEL"}"#);
        assert!(!double_escaped.contains("SENTINEL"), "{double_escaped}");

        let untouched = r#"{"na\u006de":"VISIBLE"}"#;
        assert_eq!(sanitize_lifecycle_field(untouched), untouched);

        assert_eq!(
            sanitize_lifecycle_field("webhook_url=[REDACTED_URL]"),
            "webhook_url=[REDACTED_URL]"
        );
        assert_eq!(
            sanitize_lifecycle_field("webhook_url=[REDACTED_url]"),
            "webhook_url=[REDACTED_url]"
        );

        let enclosing = r#"{"stage":"password=[REDACTED]","ok":true}"#;
        let enclosing_out = sanitize_lifecycle_field(enclosing);
        assert_eq!(enclosing_out, enclosing, "{enclosing_out}");
        serde_json::from_str::<serde_json::Value>(&enclosing_out)
            .unwrap_or_else(|e| panic!("enclosing JSON broken ({e}): {enclosing_out}"));

        let closer = r#"{"note":"--password [REDACTED]\" https://example.invalid"}"#;
        let closer_out = sanitize_lifecycle_field(closer);
        assert!(closer_out.contains("https://example.invalid"), "{closer_out}");
        assert!(!closer_out.contains("SENTINEL"), "{closer_out}");
        serde_json::from_str::<serde_json::Value>(&closer_out)
            .unwrap_or_else(|e| panic!("closer JSON broken ({e}): {closer_out}"));
    }
}
