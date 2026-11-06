use af_models::{Package, PackageRunnerRequest, SystemctlRequest};
use af_release::lifecycle::{self, OwnerLease};
use anyhow::{Context, Result};
use futures::{future::BoxFuture, StreamExt};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
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
    if let Ok(path) = std::env::var(variable) {
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
                let _ = sender.send("__RUNNER_EXIT_ERROR__:Lifecycle completion could not be confirmed; inspect durable package status before retrying\n".into()).await;
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
        fail_stop: bool,
        fail_restore: bool,
        runtime_port: i32,
        started: Option<Arc<tokio::sync::Notify>>,
        release: Option<Arc<tokio::sync::Notify>>,
        conflict_database: Option<PathBuf>,
    }

    impl LifecycleBackend for FakeBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            self.runtime_port
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
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
                    vec!["stop syncthing", "start syncthing"]
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
            match status.trim() {
                "active" | "reloading" | "activating" | "deactivating" => Ok(true),
                "inactive" | "failed" => Ok(false),
                _ => anyhow::bail!("Application service state is unknown"),
            }
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
            anyhow::ensure!(
                response.success,
                "Application service {action} failed: {}",
                response.error
            );
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
        units: Vec<String>,
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
        request.lifecycle_job_id = uuid::Uuid::new_v4().to_string();
        let started_at = chrono::Utc::now().to_rfc3339();
        let owner = lifecycle::admit_job(
            &mut conn,
            &request.package_id,
            &request.lifecycle_job_id,
            &request.action,
            &started_at,
            &units,
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

    fn resolve_port(&self, backend: &impl LifecycleBackend) -> Result<i32> {
        if self.request.action == "remove" {
            return Ok(0);
        }
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
                return Ok(runtime);
            }
            if saved > 0 {
                anyhow::ensure!(
                    (1024..=65535).contains(&saved),
                    "Persisted listen port is invalid"
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
            return Ok(self.request.app_port);
        }
        if saved > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&saved),
                "Persisted listen port is invalid"
            );
            return Ok(saved);
        }
        let default = self.package.default_port;
        if default <= 0 {
            return Ok(0);
        }
        if backend.available_port(default) {
            return Ok(default);
        }
        anyhow::ensure!(
            !matches!(self.request.package_id.as_str(), "plex" | "calibreweb"),
            "Fixed application port is unavailable"
        );
        (17000..=19999)
            .find(|port| backend.available_port(*port))
            .context("No application listen port is available")
    }

    fn update_units(&self) -> Vec<String> {
        if self.request.action != "update"
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
                !matches!(unit.as_str(), "recyclarr" | "scrutiny-collector")
                    && (unit.as_str() != "rclone-vfs" || configured)
            })
            .cloned()
            .collect();
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        units
    }

    async fn execute(
        &mut self,
        backend: &impl LifecycleBackend,
        sender: &mpsc::Sender<String>,
    ) -> Result<LifecycleReceipt> {
        let mut stopped = Vec::new();
        let mut failure = "preparation";
        let execution: Result<()> = async {
            self.request.app_port = self.resolve_port(backend)?;
            for unit in self.update_units() {
                if backend.active(&unit).await? {
                    stopped.push(unit.clone());
                    backend
                        .control(&unit, "stop", &self.request.lifecycle_job_id)
                        .await?;
                }
            }
            failure = "installer";
            backend.script(&self.request, sender).await?;
            failure = if self.request.action == "remove" {
                "retention"
            } else {
                "configuration"
            };
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
        let mut restore_failed = false;
        for unit in stopped.iter().rev() {
            if let Err(error) = backend
                .control(unit, "start", &self.request.lifecycle_job_id)
                .await
            {
                tracing::error!(unit, error = %error, "Application service restoration failed");
                restore_failed = true;
            }
        }
        let success = execution.is_ok() && !restore_failed;
        if let Err(error) = &execution {
            tracing::error!(package = %self.request.package_id, error = %error, "Required lifecycle phase failed");
        }
        if restore_failed {
            failure = if execution.is_err() && failure == "configuration" {
                "configuration_and_service_restore"
            } else if execution.is_ok() {
                "service_restore"
            } else {
                failure
            };
        }
        lifecycle::finish_job(
            &self.conn,
            &self.request.package_id,
            &self.request.lifecycle_job_id,
            &self.request.action,
            success,
            failure,
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
