pub(crate) mod snapshot_policy;
use snapshot_policy::{preflight_runtime_snapshot, RuntimeFilter, SnapshotBudget};

use af_models::{Package, PackageRunnerRequest, SystemctlRequest};
use af_release::lifecycle::{self, OwnerLease};
use anyhow::{Context, Result};
use futures::{future::BoxFuture, StreamExt};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
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
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(crate::open_and_read_regular_config(std::path::Path::new(
                trimmed,
            ))?);
        }
    }
    for path in crate::canonical_config_candidates(filename) {
        match crate::open_and_read_regular_config(&path) {
            Ok(s) => return Ok(s),
            Err(error) if crate::is_missing_config_candidate(&error) => {}
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
        af_models::merge_package_automation(&mut package, automation);
    }
    Ok(package)
}

struct AdmittedLifecycleSnapshot {
    package_id: String,
    lifecycle_job_id: String,
    captured_at: std::time::Instant,
    fs_root: Option<PathBuf>,
    receipt_snapshots: Vec<FileSnapshot>,
    blueprint_snapshots: Vec<FileSnapshot>,
    vhost_backups: Vec<crate::VhostBackup>,
    runtime_snapshot: PackageRuntimeSnapshot,
}

static RUNNER_LIFECYCLE_SNAPSHOTS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<String, AdmittedLifecycleSnapshot>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

pub fn has_admitted_lifecycle_snapshot(package_id: &str, lifecycle_job_id: &str) -> bool {
    RUNNER_LIFECYCLE_SNAPSHOTS
        .lock()
        .ok()
        .and_then(|map| {
            map.get(package_id)
                .map(|snap| snap.lifecycle_job_id == lifecycle_job_id)
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub fn admitted_lifecycle_snapshot_backup_root(
    package_id: &str,
    lifecycle_job_id: &str,
) -> Option<PathBuf> {
    RUNNER_LIFECYCLE_SNAPSHOTS.lock().ok().and_then(|map| {
        map.get(package_id)
            .filter(|snap| snap.lifecycle_job_id == lifecycle_job_id)
            .map(|snap| snap.runtime_snapshot.backup_root.clone())
    })
}

fn collect_stale_admitted_snapshots(database: &Path) -> Vec<AdmittedLifecycleSnapshot> {
    const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(2 * 3600);
    let candidate_keys: Vec<(String, String, bool)> = {
        let Ok(map) = RUNNER_LIFECYCLE_SNAPSHOTS.lock() else {
            return Vec::new();
        };
        map.values()
            .map(|s| {
                (
                    s.package_id.clone(),
                    s.lifecycle_job_id.clone(),
                    s.captured_at.elapsed() > MAX_SNAPSHOT_AGE,
                )
            })
            .collect()
    };
    if candidate_keys.is_empty() {
        return Vec::new();
    }
    let conn = Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .ok();
    if let Some(ref c) = conn {
        let _ = c.busy_timeout(Duration::from_secs(2));
    }
    let mut to_evict: Vec<(String, String, bool)> = Vec::new();
    for (pkg, job_id, expired) in candidate_keys {
        let status: Option<String> = conn.as_ref().and_then(|c| {
            c.query_row(
                "SELECT status FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                rusqlite::params![&pkg, &job_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()
        });
        let still_active = matches!(
            status.as_deref(),
            Some("installing" | "updating" | "uninstalling")
        ) && !expired;
        if !still_active {
            let preserve = status.as_deref() == Some("interrupted");
            to_evict.push((pkg, job_id, preserve));
        }
    }
    if to_evict.is_empty() {
        return Vec::new();
    }
    let Ok(mut map) = RUNNER_LIFECYCLE_SNAPSHOTS.lock() else {
        return Vec::new();
    };
    let mut evicted = Vec::new();
    for (pkg, job_id, preserve) in to_evict {
        if map
            .get(&pkg)
            .is_some_and(|entry| entry.lifecycle_job_id == job_id)
        {
            if let Some(mut removed) = map.remove(&pkg) {
                if preserve {
                    removed.runtime_snapshot.preserve_on_drop = true;
                }
                evicted.push(removed);
            }
        }
    }
    evicted
}

pub async fn capture_admitted_lifecycle_snapshot(
    package_id: &str,
    lifecycle_job_id: &str,
    extra_units: &[String],
) -> Result<()> {
    let pkg_id = package_id.trim();
    let job_id = lifecycle_job_id.trim();
    anyhow::ensure!(
        !pkg_id.is_empty() && crate::SAFE_PKG_ID.is_match(pkg_id) && !pkg_id.contains(".."),
        "Invalid package identifier"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "lifecycle_job_id is required for admitted snapshot capture"
    );
    let _pkg = package_definition(pkg_id)?;
    let env_cfg = crate::PackageExecutionEnv::default();
    let (guard, database) =
        crate::acquire_owned_lifecycle_snapshot_guard(env_cfg.fs_root.as_deref(), pkg_id, job_id)
            .await?;

    if has_admitted_lifecycle_snapshot(pkg_id, job_id) {
        drop(guard);
        return Ok(());
    }

    let mut units: Vec<String> = package_service_units(pkg_id)?
        .into_iter()
        .filter(|u| !u.starts_with("port:"))
        .collect();
    for u in extra_units {
        let trimmed = u.trim();
        if !trimmed.is_empty()
            && !trimmed.starts_with("port:")
            && crate::SAFE_SERVICE_NAME.is_match(trimmed)
            && !units.iter().any(|existing| existing == trimmed)
        {
            units.push(trimmed.to_string());
        }
    }

    let pkg_owned = pkg_id.to_string();
    let job_owned = job_id.to_string();
    let captured = tokio::task::spawn_blocking(move || -> Result<AdmittedLifecycleSnapshot> {
        let stale = collect_stale_admitted_snapshots(&database);
        drop(stale);
        let receipt_snapshots = snapshot_candidate_receipts_with_env(&pkg_owned, &env_cfg)
            .map_err(anyhow::Error::msg)?;
        let blueprint_snapshots =
            snapshot_blueprint_targets(&pkg_owned, &env_cfg).map_err(anyhow::Error::msg)?;
        let vhost_backups =
            crate::snapshot_app_vhost_backups(&pkg_owned, env_cfg.fs_root.as_deref())?;
        let runtime_snapshot = PackageRuntimeSnapshot::capture(&pkg_owned, &units, &env_cfg, false)
            .map_err(anyhow::Error::msg)?;
        Ok(AdmittedLifecycleSnapshot {
            package_id: pkg_owned,
            lifecycle_job_id: job_owned,
            captured_at: std::time::Instant::now(),
            fs_root: env_cfg.fs_root.clone(),
            receipt_snapshots,
            blueprint_snapshots,
            vhost_backups,
            runtime_snapshot,
        })
    })
    .await
    .context("Runner lifecycle snapshot capture worker failed")??;

    let replaced = {
        let mut map = RUNNER_LIFECYCLE_SNAPSHOTS
            .lock()
            .map_err(|_| anyhow::anyhow!("Runner lifecycle snapshot registry poisoned"))?;
        map.insert(pkg_id.to_string(), captured)
    };
    if let Some(old) = replaced {
        let _ = tokio::task::spawn_blocking(move || drop(old)).await;
    }
    drop(guard);
    Ok(())
}

pub async fn restore_admitted_lifecycle_snapshot(
    package_id: &str,
    lifecycle_job_id: &str,
) -> Result<()> {
    let pkg_id = package_id.trim();
    let job_id = lifecycle_job_id.trim();
    anyhow::ensure!(
        !pkg_id.is_empty() && crate::SAFE_PKG_ID.is_match(pkg_id) && !pkg_id.contains(".."),
        "Invalid package identifier"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "lifecycle_job_id is required for admitted snapshot restoration"
    );
    let env_cfg = crate::PackageExecutionEnv::default();
    let (guard, _database) =
        crate::acquire_owned_lifecycle_snapshot_guard(env_cfg.fs_root.as_deref(), pkg_id, job_id)
            .await?;

    let snapshot = {
        let mut map = RUNNER_LIFECYCLE_SNAPSHOTS
            .lock()
            .map_err(|_| anyhow::anyhow!("Runner lifecycle snapshot registry poisoned"))?;
        match map.get(pkg_id) {
            Some(entry) if entry.lifecycle_job_id == job_id => map.remove(pkg_id),
            _ => None,
        }
    };
    let Some(entry) = snapshot else {
        drop(guard);
        anyhow::bail!(
            "No active runtime snapshot registered for package '{}' and job '{}'",
            pkg_id,
            job_id
        );
    };

    let (restore_res, fs_root, vhosts_changed) = tokio::task::spawn_blocking(move || {
        let AdmittedLifecycleSnapshot {
            fs_root,
            receipt_snapshots,
            blueprint_snapshots,
            vhost_backups,
            mut runtime_snapshot,
            ..
        } = entry;
        let mut vhosts_reverted = false;
        let res = (|| -> Result<(), String> {
            rollback_operation_state_with_runtime(
                &receipt_snapshots,
                &blueprint_snapshots,
                Some(&mut runtime_snapshot),
            )?;
            vhosts_reverted =
                crate::restore_app_vhost_backups(&vhost_backups).map_err(|e| e.to_string())?;
            Ok(())
        })();
        let res = match res {
            Ok(()) => Ok(()),
            Err(err) => {
                runtime_snapshot.preserve_on_drop = true;
                let preserved = runtime_snapshot.backup_root.display().to_string();
                Err(format!("{err}; recovery backup preserved at {preserved}"))
            }
        };
        drop(runtime_snapshot);
        (res, fs_root, vhosts_reverted)
    })
    .await
    .context("Runner lifecycle snapshot restore worker failed")?;

    if restore_res.is_ok() {
        if fs_root.is_none() && std::env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none() {
            let systemctl_bin = std::env::var("AETHERFLOW_SYSTEMCTL_BIN")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "systemctl".to_string());
            let _ = tokio::time::timeout(
                Duration::from_secs(15),
                tokio::process::Command::new(systemctl_bin)
                    .arg("daemon-reload")
                    .kill_on_drop(true)
                    .output(),
            )
            .await;
        }
        if vhosts_changed {
            crate::reload_apache_after_rollback_if_live(fs_root.as_deref()).await;
        }
    }
    drop(guard);
    restore_res.map_err(anyhow::Error::msg)
}

pub async fn discard_admitted_lifecycle_snapshot(
    package_id: &str,
    lifecycle_job_id: &str,
    preserve_backup: bool,
) -> Result<bool> {
    let pkg_id = package_id.trim();
    let job_id = lifecycle_job_id.trim();
    anyhow::ensure!(
        !pkg_id.is_empty() && crate::SAFE_PKG_ID.is_match(pkg_id) && !pkg_id.contains(".."),
        "Invalid package identifier"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "lifecycle_job_id is required for admitted snapshot discard"
    );
    let removed = {
        let mut map = RUNNER_LIFECYCLE_SNAPSHOTS
            .lock()
            .map_err(|_| anyhow::anyhow!("Runner lifecycle snapshot registry poisoned"))?;
        match map.get(pkg_id) {
            Some(entry) if entry.lifecycle_job_id == job_id => map.remove(pkg_id),
            _ => None,
        }
    };
    let Some(mut entry) = removed else {
        return Ok(false);
    };
    if preserve_backup {
        entry.runtime_snapshot.preserve_on_drop = true;
    }
    tokio::task::spawn_blocking(move || drop(entry))
        .await
        .context("Runner lifecycle snapshot discard worker failed")?;
    Ok(true)
}

pub fn execute_coordinated_package_stream(
    request: PackageRunnerRequest,
) -> impl futures::Stream<Item = std::io::Result<String>> + Send {
    async_stream::stream! {
        if !request.lifecycle_job_id.is_empty() {
            if matches!(request.action.as_str(), "install" | "reinstall" | "update")
                && !has_admitted_lifecycle_snapshot(&request.package_id, &request.lifecycle_job_id)
            {
                if let Err(error) = capture_admitted_lifecycle_snapshot(
                    &request.package_id,
                    &request.lifecycle_job_id,
                    &[],
                )
                .await
                {
                    let sanitized = sanitize_lifecycle_field(&error.to_string());
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{sanitized}\n"));
                    return;
                }
            }
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
                        let _ = std::fs::write(
                            &bin,
                            format!("#!/bin/sh\necho \"syncthing {target}\"\n"),
                        );
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &bin,
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
        af_db::synchronize_lifecycle_ingress(&mut conn, "sonarr", "remove", "", 0, false, "").ok();
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
        assert!(
            exec_res.is_err(),
            "Execute must fail closed at preflight when blueprint target is a symlink"
        );
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
            CoordinatedOperation::admit(conn, req, package.clone(), vec!["syncthing".into()])
                .is_err(),
            "admission must reject update request with missing target version"
        );

        let (_r2, _p2, conn2, _pkg2) = fixture();
        let mut req2 = request("update");
        req2.expected_target_version = Some("invalid target with spaces".into());
        assert!(
            CoordinatedOperation::admit(conn2, req2, package, vec!["syncthing".into()]).is_err(),
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
        let mut op =
            CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
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
        let mut op =
            CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
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
            diag.as_deref()
                .unwrap_or("")
                .contains("not active after start"),
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
        let mut op =
            CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
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
            diag.as_deref()
                .unwrap_or("")
                .contains("exited or became inactive during certification"),
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
        std::fs::write(
            &config_file,
            b"<Config><Port>8989</Port><ApiKey>PRE_OP_KEY</ApiKey></Config>\n",
        )
        .unwrap();

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
            fn runtime_port(&self, _: &str) -> i32 {
                8989
            }
            fn available_port(&self, _: i32) -> bool {
                true
            }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let s = *self.stopped.lock().unwrap();
                Box::pin(async move { Ok(s) })
            }
            fn control<'a>(
                &'a self,
                _: &'a str,
                action: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<()>> {
                if action == "stop" {
                    *self.stopped.lock().unwrap() = true;
                } else if action == "start" {
                    *self.stopped.lock().unwrap() = false;
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(
                &'a self,
                _: &'a PackageRunnerRequest,
                _: &'a mpsc::Sender<String>,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    // Installer mutates blueprint config and writes receipt that mismatches target
                    std::fs::write(
                        &self.config_file,
                        b"<Config><Port>8989</Port><ApiKey>MODIFIED_KEY</ApiKey></Config>\n",
                    )
                    .unwrap();
                    std::fs::write(&self.receipt_file, b"2.5.0\n").unwrap();
                    let bin = self.root.join("usr/bin/sonarr");
                    let _ = std::fs::create_dir_all(bin.parent().unwrap());
                    let _ = std::fs::write(&bin, b"#!/bin/sh\necho \"sonarr 2.5.0\"\n");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
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
        let mut op =
            CoordinatedOperation::admit(conn, req, sonarr_package, vec!["sonarr".into()]).unwrap();

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

    #[tokio::test]
    async fn pihole_and_adguardhome_are_mutually_exclusive_on_install_only() {
        let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
        struct FsRootRestore {
            prev: Option<std::ffi::OsString>,
            root: std::path::PathBuf,
        }
        impl Drop for FsRootRestore {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => std::env::set_var("AETHERFLOW_FS_ROOT", v),
                    None => std::env::remove_var("AETHERFLOW_FS_ROOT"),
                }
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
        let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
        let (root, db_path, conn, _) = fixture();
        std::env::set_var("AETHERFLOW_FS_ROOT", &root);
        let _restore = FsRootRestore {
            prev: prev_fs_root,
            root: root.clone(),
        };
        std::fs::create_dir_all(root.join("install")).unwrap();

        let pihole_pkg = Package {
            name: "pihole".into(),
            label: "Pi-hole".into(),
            lock_file: "/install/.pihole.lock".into(),
            service_name: "pihole-FTL".into(),
            service_type: "systemd".into(),
            default_port: 8089,
            ..Default::default()
        };
        let adguard_pkg = Package {
            name: "adguardhome".into(),
            label: "AdGuard Home".into(),
            lock_file: "/install/.adguardhome.lock".into(),
            service_name: "adguardhome".into(),
            service_type: "systemd".into(),
            default_port: 3080,
            ..Default::default()
        };

        // 1. When AdGuard Home is installed, installing Pi-hole must fail with a :53 conflict error.
        std::fs::write(root.join("install/.adguardhome.lock"), "installed\n").unwrap();
        let err = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "pihole".into(),
                action: "install".into(),
                script_name: "installpackage-pihole".into(),
                ..Default::default()
            },
            pihole_pkg.clone(),
            vec!["pihole-FTL".into()],
        )
        .err()
        .expect("pihole install must be rejected when adguardhome is installed");
        let msg = err.to_string();
        assert!(msg.contains(":53") && msg.contains("AdGuard Home"), "{msg}");

        // Updating/removing already-installed AdGuard Home must still be admitted.
        let upd_adguard = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "adguardhome".into(),
                action: "update".into(),
                script_name: "installpackage-adguardhome".into(),
                expected_target_version: Some("0.107.52".into()),
                ..Default::default()
            },
            adguard_pkg.clone(),
            vec!["adguardhome".into()],
        )
        .unwrap();
        drop(upd_adguard);
        conn.execute("DELETE FROM package_lifecycle_jobs", [])
            .unwrap();

        let rm_adguard = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "adguardhome".into(),
                action: "remove".into(),
                script_name: "removepackage-adguardhome".into(),
                ..Default::default()
            },
            adguard_pkg.clone(),
            vec!["adguardhome".into()],
        )
        .unwrap();
        drop(rm_adguard);
        conn.execute("DELETE FROM package_lifecycle_jobs", [])
            .unwrap();

        // 2. Swap: remove AdGuard Home lock, create Pi-hole lock; installing AdGuard Home must fail.
        std::fs::remove_file(root.join("install/.adguardhome.lock")).unwrap();
        std::fs::write(root.join("install/.pihole.lock"), "installed\n").unwrap();
        let err2 = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "adguardhome".into(),
                action: "install".into(),
                script_name: "installpackage-adguardhome".into(),
                ..Default::default()
            },
            adguard_pkg,
            vec!["adguardhome".into()],
        )
        .err()
        .expect("adguardhome install must be rejected when pihole is installed");
        let msg2 = err2.to_string();
        assert!(msg2.contains(":53") && msg2.contains("Pi-hole"), "{msg2}");

        // Updating/removing already-installed Pi-hole must still be admitted.
        let upd_pihole = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "pihole".into(),
                action: "update".into(),
                script_name: "installpackage-pihole".into(),
                expected_target_version: Some("6.0.0".into()),
                ..Default::default()
            },
            pihole_pkg.clone(),
            vec!["pihole-FTL".into()],
        )
        .unwrap();
        drop(upd_pihole);
        conn.execute("DELETE FROM package_lifecycle_jobs", [])
            .unwrap();

        let rm_pihole = CoordinatedOperation::admit(
            Connection::open(&db_path).unwrap(),
            PackageRunnerRequest {
                package_id: "pihole".into(),
                action: "remove".into(),
                script_name: "removepackage-pihole".into(),
                ..Default::default()
            },
            pihole_pkg,
            vec!["pihole-FTL".into()],
        )
        .unwrap();
        drop(rm_pihole);
        conn.execute("DELETE FROM package_lifecycle_jobs", [])
            .unwrap();
    }

    #[tokio::test]
    async fn failed_reinstall_verified_recovery_vs_incomplete_fresh_and_remove_receipts() {
        let (root, path, conn, mut package) = fixture();
        package.lock_file = "/install/.syncthing.lock".into();
        let lock_path = root.join("install/.syncthing.lock");
        std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        std::fs::write(&lock_path, "installed\n").unwrap();
        let version_path = root.join("var/lib/syncthing/.af-version");
        std::fs::create_dir_all(version_path.parent().unwrap()).unwrap();
        std::fs::write(&version_path, "1.28.0\n").unwrap();
        let vhost_dir = root.join("etc/apache2/sites-available");
        std::fs::create_dir_all(&vhost_dir).unwrap();
        let vhost_path = vhost_dir.join("aetherflow-ext-syncthing.conf");
        std::fs::write(&vhost_path, "# prior vhost\n").unwrap();

        let read_recovery = |c: &Connection| -> (String, String, String) {
            c.query_row(
                "SELECT status, failure_category, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
        };

        let (sender, _receiver) = mpsc::channel(32);

        // 1. Failed reinstall with complete restoration of runtime/lock/receipt/vhost and service.
        let backend_complete = FakeBackend {
            fail_script: true,
            ..Default::default()
        };
        let mut op1 = CoordinatedOperation::admit(
            conn,
            request("reinstall"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        let r1 = op1.execute(&backend_complete, &sender).await.unwrap();
        assert_eq!(r1.status, "failed");
        assert_eq!(
            read_recovery(&op1.conn),
            (
                "failed".into(),
                "installer".into(),
                lifecycle::RECOVERY_STATE_PRIOR_VERIFIED.into()
            )
        );
        assert!(lock_path.is_file());
        assert_eq!(
            std::fs::read_to_string(&vhost_path).unwrap(),
            "# prior vhost\n"
        );
        drop(op1);

        // 2. Failed reinstall with incomplete rollback must NOT record verified recovery.
        let backend_incomplete = FakeBackend {
            script_error_message: Some("script failed; incomplete rollback: partial files".into()),
            ..Default::default()
        };
        let mut op2 = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("reinstall"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        let r2 = op2.execute(&backend_incomplete, &sender).await.unwrap();
        assert_eq!(r2.status, "failed");
        assert_eq!(read_recovery(&op2.conn).2, "");
        drop(op2);

        // 3. Failed reinstall where service restart fails after rollback must NOT record verified recovery.
        let backend_restore_fail = FakeBackend {
            fail_script: true,
            fail_restore: true,
            ..Default::default()
        };
        let mut op3 = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("reinstall"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        let r3 = op3.execute(&backend_restore_fail, &sender).await.unwrap();
        assert_eq!(r3.status, "failed");
        assert_eq!(read_recovery(&op3.conn).2, "");
        drop(op3);

        // 4. Failed remove must NEVER record verified recovery.
        let mut op4 = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("remove"),
            package.clone(),
            vec!["syncthing".into()],
        )
        .unwrap();
        let r4 = op4.execute(&backend_complete, &sender).await.unwrap();
        assert_eq!(r4.status, "failed");
        assert_eq!(read_recovery(&op4.conn).2, "");
        drop(op4);

        // 5. Failed fresh install (not previously installed) must NEVER record verified recovery.
        std::fs::remove_file(&lock_path).unwrap();
        let mut op5 = CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            request("install"),
            package,
            vec!["syncthing".into()],
        )
        .unwrap();
        let r5 = op5.execute(&backend_complete, &sender).await.unwrap();
        assert_eq!(r5.status, "failed");
        assert_eq!(read_recovery(&op5.conn).2, "");
        drop(op5);

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
                        .args([
                            "show",
                            "--property=LoadState,ActiveState",
                            "--value",
                            "--",
                            unit,
                        ])
                        .output(),
                )
                .await
                {
                    if show_out.status.success() {
                        let text = String::from_utf8_lossy(&show_out.stdout);
                        let lines: Vec<&str> = text
                            .lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();
                        if (lines.first() == Some(&"not-found")
                            || text.contains("LoadState=not-found"))
                            && (lines.get(1) == Some(&"inactive")
                                || text.contains("ActiveState=inactive"))
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
                            .args([
                                "show",
                                "--property=LoadState,ActiveState,SubState",
                                "--value",
                                "--",
                                unit,
                            ])
                            .output(),
                    )
                    .await
                    {
                        if output.status.success() {
                            let text = String::from_utf8_lossy(&output.stdout);
                            let lines: Vec<&str> = text
                                .lines()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .collect();
                            if lines.len() >= 2
                                && (lines[0] == "not-found" || text.contains("LoadState=not-found"))
                                && (lines[1] == "inactive" || text.contains("ActiveState=inactive"))
                                && (lines.len() < 3
                                    || lines[2] == "dead"
                                    || text.contains("SubState=dead"))
                            {
                                return Ok(());
                            }
                        }
                    }
                }
                anyhow::bail!("Application service {action} failed: {}", response.error);
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
        if matches!(request.action.as_str(), "install" | "reinstall") {
            let conflicting_dns = match request.package_id.as_str() {
                "pihole" => Some(("adguardhome", "AdGuard Home", "/install/.adguardhome.lock")),
                "adguardhome" => Some(("pihole", "Pi-hole", "/install/.pihole.lock")),
                _ => None,
            };
            if let Some((other_id, other_label, other_lock)) = conflicting_dns {
                let env_cfg = crate::PackageExecutionEnv::default();
                let resolved_lock = match &env_cfg.fs_root {
                    Some(root) => root.join(other_lock.trim_start_matches(['/', '\\'])),
                    None => Path::new(other_lock).to_path_buf(),
                };
                if std::fs::symlink_metadata(&resolved_lock).is_ok_and(|meta| meta.is_file()) {
                    anyhow::bail!(
                        "Cannot {} {} while {} ({}) is already installed ({}): both bind DNS TCP/UDP :53. Remove {} first before installing {}.",
                        request.action,
                        package.label,
                        other_label,
                        other_id,
                        other_lock,
                        other_id,
                        request.package_id
                    );
                }
            }
        }
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
                anyhow::bail!(
                    "Cannot start update: expected_target_version is missing, empty, or invalid"
                );
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

    fn is_installed_on_disk_in(&self, fs_root: Option<&Path>) -> bool {
        let trimmed = self.package.lock_file.trim();
        if trimmed.is_empty() {
            return false;
        }
        let raw_path = Path::new(trimmed);
        let resolved = match fs_root {
            Some(root) if !raw_path.starts_with(root) => {
                root.join(trimmed.trim_start_matches(['/', '\\']))
            }
            _ => raw_path.to_path_buf(),
        };
        std::fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.is_file())
    }

    fn is_installed_on_disk(&self) -> bool {
        let env_cfg = crate::PackageExecutionEnv::default();
        self.is_installed_on_disk_in(env_cfg.fs_root.as_deref())
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
        let [start, end] = af_models::MARKETPLACE_FALLBACK_PORT_RANGE;
        (start..=end)
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
        if !matches!(
            self.request.action.as_str(),
            "install" | "update" | "reinstall"
        ) || self.package.service_type == "pm2"
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
        Some(b'"' | b'\'' | b',' | b'}' | b']' | b';' | b'&') => true,
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
        if c == q && bs.is_multiple_of(2) {
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
    static MARKER_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"\[REDACTED_(?:URL|url)\]").unwrap());
    MARKER_RE
        .replace_all(input, |captures: &regex::Captures| {
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
        })
        .into_owned()
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
            if quote_closes_outer_span(after, false)
                && (!after.is_some_and(|next| next.is_ascii_whitespace())
                    || !af_release::lifecycle::has_matching_secret_quote(bytes, i + bs0, bs0))
            {
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
                if i > 0
                    && quote_closes_outer_span(after_q, false)
                    && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                        || !af_release::lifecycle::has_matching_secret_quote(bytes, q_idx, bs))
                {
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
                        if inner_bs == bs
                            || (inner_bs % 2 == 1 && escaped_quote_closes_payload(bytes, j))
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
                if quote_closes_outer_span(after_q, true)
                    && (!after_q.is_some_and(|next| next.is_ascii_whitespace())
                        || !af_release::lifecycle::has_matching_secret_quote(bytes, i, 0))
                {
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
        if af_release::lifecycle::is_complete_redacted_header(
            &slice[mat.start()..mat.end()],
            &text[value_off..],
        ) {
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
    static CLI_FLAG_PREFIX_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(
            r#"(?i)(?:^|[^A-Za-z0-9])(--(?:password|passwd|api-key|apikey|cookies|cookie|secret|token|session|webhook|pwd|pass))(?:\s+|=)"#,
        )
        .unwrap()
        },
    );
    let with_curl = redact_prefixed_secrets(text, &CURL_PREFIX_RE, true);
    let with_kv = redact_prefixed_secrets(
        &with_curl,
        &af_release::lifecycle::SENSITIVE_ASSIGNMENT_PREFIX_RE,
        true,
    );
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
    static SENSITIVE_JSON_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
            regex::Regex::new(
            r#"(?i)("[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|bearer|cookie|session|webhook|passphrase|rclone_pass|jwt_secret)[\w.-]*"\s*:\s*)(\{(?:[^{}\r\n]|\{[^{}\r\n]*\})*\}|\[(?:[^\[\]\r\n]|\[[^\[\]\r\n]*\])*\])"#
        ).unwrap()
        });
    static SENSITIVE_RAW_NESTED_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| {
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
        SENSITIVE_RAW_NESTED_RE
            .replace_all(&s, |caps: &regex::Captures| {
                let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if redacted_container_value(val) {
                    format!("{prefix}{val}")
                } else {
                    format!("{prefix}[REDACTED]")
                }
            })
            .into_owned()
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

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
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

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
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
        runtime_snapshot: Option<PackageRuntimeSnapshot>,
    ) {
        Self::restore_and_restart_units_with_runtime_and_vhosts(
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
            runtime_snapshot,
            Vec::new(),
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn restore_and_restart_units_with_runtime_and_vhosts(
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
        mut runtime_snapshot: Option<PackageRuntimeSnapshot>,
        vhost_backups: Vec<crate::VhostBackup>,
        fs_root: Option<PathBuf>,
    ) {
        if incomplete_rollback {
            if let Some(snapshot) = runtime_snapshot.as_mut() {
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
                    Ok(()) => {
                        match backend.quiescent(unit).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::error!(
                                    unit,
                                    "Unit is still active after stop before restoration"
                                );
                                quiesce_failed = true;
                                restart_failures.push(format!(
                                    "{unit}: still active after stop before restoration"
                                ));
                            }
                            Err(error) => {
                                tracing::error!(unit, error = %error, "Failed to verify quiescence before restoration");
                                quiesce_failed = true;
                                restart_failures.push(format!("{unit}: failed to verify quiescence before restoration: {error}"));
                            }
                        }
                    }
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
                            restart_failures
                                .push(format!("{unit}: stop before restoration failed: {error}"));
                        }
                    }
                }
            }
        }

        if quiesce_failed {
            let preserved_path = runtime_snapshot.as_mut().map(|snapshot| {
                snapshot.preserve_on_drop = true;
                snapshot.backup_root.display().to_string()
            });
            let msg = match preserved_path {
                Some(path) => format!(
                    "Skipped snapshot restoration because service quiescence failed (incomplete-rollback); recovery backup preserved at {path}"
                ),
                None => "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)".to_string(),
            };
            if let Some(ref mut existing) = receipt_restore_error {
                existing.push_str(&format!("; {}", msg));
            } else {
                *receipt_restore_error = Some(msg);
            }
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            return;
        }

        let receipt_snapshots = receipt_snapshots.to_vec();
        let blueprint_snapshots = blueprint_snapshots.to_vec();
        let restoration = tokio::task::spawn_blocking(move || {
            rollback_operation_state_with_runtime(
                &receipt_snapshots,
                &blueprint_snapshots,
                if incomplete_rollback {
                    None
                } else {
                    runtime_snapshot.as_mut()
                },
            )?;
            let vhosts_changed = if incomplete_rollback || vhost_backups.is_empty() {
                false
            } else {
                crate::restore_app_vhost_backups(&vhost_backups).map_err(|e| e.to_string())?
            };
            Ok::<bool, String>(vhosts_changed)
        })
        .await
        .map_err(|err| format!("Snapshot restore worker failed: {err}"))
        .and_then(|result| result);
        let mut snapshot_restore_failed = false;
        match restoration {
            Ok(vhosts_changed) => {
                if vhosts_changed {
                    crate::reload_apache_after_rollback_if_live(fs_root.as_deref()).await;
                }
            }
            Err(restore_err) => {
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
        }

        if incomplete_rollback || snapshot_restore_failed {
            if !restart_units.is_empty() {
                if incomplete_rollback {
                    tracing::error!(
                        package = %package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after incomplete rollback"
                            .to_string(),
                    );
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
                if let Err(error) = backend.control(unit, "start", lifecycle_job_id).await {
                    tracing::error!(unit, error = %error, "Application service restoration failed");
                    restart_failures.push(format!(
                        "Application service start for unit '{unit}' failed: {error}"
                    ));
                } else {
                    match backend.active(unit).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let msg = format!(
                                "Application service unit '{unit}' is not active after start"
                            );
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
        let receipt_snapshots = match snapshot_candidate_receipts_with_env(
            &self.request.package_id,
            &pre_op_env,
        ) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!(
                    "Failed to snapshot candidate receipts before execution: {}",
                    snap_err
                );
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight candidate receipt snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self
                    .request
                    .expected_target_version
                    .as_deref()
                    .map(sanitize_lifecycle_field);
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
        let blueprint_snapshots = match snapshot_blueprint_targets(
            &self.request.package_id,
            &pre_op_env,
        ) {
            Ok(snaps) => snaps,
            Err(snap_err) => {
                let err_msg = format!(
                    "Failed to snapshot blueprint targets before execution: {}",
                    snap_err
                );
                tracing::error!(package = %self.request.package_id, error = %err_msg, "Preflight blueprint target snapshot failed");
                let sanitized_err = sanitize_lifecycle_field(&err_msg);
                let sanitized_expected = self
                    .request
                    .expected_target_version
                    .as_deref()
                    .map(sanitize_lifecycle_field);
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

        let prior_installed = self.is_installed_on_disk_in(pre_op_env.fs_root.as_deref());
        let mut stopped = Vec::new();
        let mut failure = "preparation";
        let mut runtime_snapshot: Option<PackageRuntimeSnapshot> = None;
        let mut vhost_backups: Vec<crate::VhostBackup> = Vec::new();
        let mut prep_services_verified = false;
        let mut snapshot_captured = false;
        let mut script_attempted = false;
        let all_controllable_units = self.update_units();
        let should_quiesce_oneshots_pre_op =
            prior_installed || matches!(self.request.action.as_str(), "update" | "reinstall");
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
            prep_services_verified = true;
            if matches!(self.request.action.as_str(), "install" | "reinstall" | "update") {
                vhost_backups = crate::snapshot_app_vhost_backups(
                    &self.request.package_id,
                    pre_op_env.fs_root.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("Failed to snapshot Apache vhosts before execution: {e}"))?;
                runtime_snapshot = Some(
                    PackageRuntimeSnapshot::capture_blocking(
                        self.request.package_id.clone(),
                        rollback_quiesce_units.clone(),
                        pre_op_env.clone(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to snapshot package runtime before execution: {e}"))?,
                );
                snapshot_captured = true;
            }
            failure = "installer";
            script_attempted = true;
            backend.script(&self.request, sender).await?;
            Ok(())
        }
        .await;
        let incomplete_rollback = execution
            .as_ref()
            .err()
            .is_some_and(|err| is_incomplete_rollback_error(&err.to_string()));
        let mut restart_failures: Vec<String> = Vec::new();
        let mut rollback_restart_failures: Vec<String> = Vec::new();
        let mut rollback_ran = false;
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
            Self::restore_and_restart_units_with_runtime_and_vhosts(
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
                runtime_snapshot.take(),
                std::mem::take(&mut vhost_backups),
                pre_op_env.fs_root.clone(),
            )
            .await;
            rollback_ran = true;
            rollback_restart_failures = restart_failures.clone();
            restore_failed = !restart_failures.is_empty();
        } else {
            if incomplete_rollback {
                if !stopped.is_empty() {
                    tracing::error!(
                        package = %self.request.package_id,
                        "Refusing to restart pre-stopped service after incomplete rollback"
                    );
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after incomplete rollback"
                            .to_string(),
                    );
                }
            } else {
                for unit in stopped.iter().rev() {
                    if let Err(error) = backend
                        .control(unit, "start", &self.request.lifecycle_job_id)
                        .await
                    {
                        tracing::error!(unit, error = %error, "Application service restoration failed");
                        restart_failures.push(format!(
                            "Application service start for unit '{unit}' failed: {error}"
                        ));
                    } else {
                        match backend.active(unit).await {
                            Ok(true) => {}
                            Ok(false) => {
                                let msg = format!(
                                    "Application service unit '{unit}' is not active after start"
                                );
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
                Self::restore_and_restart_units_with_runtime_and_vhosts(
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
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restore_restart_failures.clone();
                restart_failures = initial_failures;
                restart_failures.extend(restore_restart_failures);
                restore_failed = true;
            }
        }

        // Target certification BEFORE post-install ingress synchronization & configuration commit
        let mut target_match_failed = false;
        let mut achieved_ver: Option<String> = None;
        if execution.is_ok()
            && !restore_failed
            && self.request.expected_target_version.is_some()
            && self.request.action != "remove"
        {
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
                Self::restore_and_restart_units_with_runtime_and_vhosts(
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
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restart_failures.clone();
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
                Self::restore_and_restart_units_with_runtime_and_vhosts(
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
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restore_restart_failures.clone();
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
                if self.request.action != "remove"
                    && (1024..=65535).contains(&self.request.app_port)
                {
                    let fs_root = self.effective_fs_root();
                    crate::package_executor::apply_runner_blueprint_in_background(
                        fs_root,
                        self.request.package_id.clone(),
                        self.request.app_port,
                    )
                    .await
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
                Self::restore_and_restart_units_with_runtime_and_vhosts(
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
                    runtime_snapshot.take(),
                    std::mem::take(&mut vhost_backups),
                    pre_op_env.fs_root.clone(),
                )
                .await;
                rollback_ran = true;
                rollback_restart_failures = restart_failures.clone();
                if !restart_failures.is_empty() {
                    restore_failed = true;
                }
            }
        }

        if runtime_snapshot.is_some() {
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
        }
        let success = execution.is_ok() && !restore_failed && !target_match_failed;
        let prior_state_recovered = !success
            && matches!(
                self.request.action.as_str(),
                "reinstall" | "update" | "install"
            )
            && prior_installed
            && prep_services_verified
            && !incomplete_rollback
            && rollback_ran
            && (!script_attempted || snapshot_captured)
            && receipt_restore_error.is_none()
            && rollback_restart_failures.is_empty()
            && self.is_installed_on_disk_in(pre_op_env.fs_root.as_deref());
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
        } else {
            receipt_restore_error
                .as_ref()
                .map(|r_err| format!("Receipt restoration error: {}", r_err))
        };
        let sanitized_diag_summary = diag_summary.as_deref().map(sanitize_lifecycle_field);
        let sanitized_expected = self
            .request
            .expected_target_version
            .as_deref()
            .map(sanitize_lifecycle_field);
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
                sanitized_summary: sanitized_diag_summary
                    .as_deref()
                    .or(if target_match_failed {
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
                recovery_state: prior_state_recovered
                    .then_some(lifecycle::RECOVERY_STATE_PRIOR_VERIFIED),
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
    let alias = MERGED_USR_ALIASES
        .iter()
        .copied()
        .find(|alias| dir_path.components().eq(base_root.join(alias).components()));
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

fn verify_no_symlink_ancestors_with_root(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<(), String> {
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
            let p = env_cfg.resolve_path(&vf).map_err(|e| {
                format!("Failed to resolve version file logical path {}: {}", vf, e)
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && package_id.eq_ignore_ascii_case("filebot") {
            let candidate = "/opt/filebot-node/.af-version";
            let p = env_cfg.resolve_path(candidate).map_err(|e| {
                format!(
                    "Failed to resolve candidate receipt path {}: {}",
                    candidate, e
                )
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [package_id, &package_id.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = env_cfg.resolve_path(&candidate).map_err(|e| {
                format!(
                    "Failed to resolve candidate receipt path {}: {}",
                    candidate, e
                )
            })?;
            verify_no_symlink_ancestors_with_root(&p, env_cfg.fs_root.as_deref())?;
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if package_id.eq_ignore_ascii_case("piped") {
        for extra in [
            "/opt/piped/.af-components.json",
            "/var/lib/piped/.af-components.json",
        ] {
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
    let paths = crate::package_executor::collect_blueprint_target_paths(
        package_id,
        env_cfg.fs_root.as_deref(),
    );
    for path in paths {
        if matches!(package_id, "transmission" | "transmission-daemon")
            && crate::blueprint::is_transmission_config_alias(&path, |logical| {
                env_cfg.fs_root.as_ref().map_or_else(
                    || PathBuf::from(logical),
                    |root| root.join(logical.trim_start_matches('/')),
                )
            })
        {
            continue;
        }
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
        if self.preserve_on_drop {
            tracing::warn!(
                package = %self.package_id,
                backup_root = %self.backup_root.display(),
                "Preserved package runtime recovery snapshot on disk for manual recovery"
            );
        } else {
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
    comp_count <= 1
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
                    if needed_bytes > avail_bytes {
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

    let mut source = std::fs::OpenOptions::new();
    source.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut src_file = match source.open(src) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            return Err(format!("Failed to open {}: {}", src.display(), e));
        }
    };

    if !src_file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        let _ = std::fs::remove_file(dst);
        return Err(format!(
            "Snapshot source {} is no longer a regular file",
            src.display()
        ));
    }

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
                let data_start =
                    unsafe { libc::lseek(src_fd, offset as libc::off_t, libc::SEEK_DATA) };
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
                let next_hole =
                    unsafe { libc::lseek(src_fd, data_start as libc::off_t, libc::SEEK_HOLE) };
                let extent_end = if next_hole < 0 {
                    len
                } else {
                    (next_hole as u64).min(len)
                };
                if extent_end <= data_start {
                    break;
                }

                if let Err(e) =
                    copy_range_sparse(&mut src_file, &mut dst_file, data_start, extent_end)
                {
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

fn copy_live_receipts_to_stage(
    live_dir: &Path,
    stage_dir: &Path,
    filter: RuntimeFilter,
) -> Result<(), String> {
    if !std::fs::symlink_metadata(live_dir).is_ok_and(|meta| meta.is_dir()) {
        return Ok(());
    }
    fn walk(
        curr_live: &Path,
        rel_path: &Path,
        stage_root: &Path,
        filter: RuntimeFilter,
    ) -> Result<(), String> {
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
                if filter.excludes(&child_rel, &meta) {
                    continue;
                }
                if meta.is_dir() {
                    walk(&child_live, &child_rel, stage_root, filter)?;
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
    walk(live_dir, Path::new(""), stage_dir, filter)
}

fn remove_untracked_receipt_files(dir: &Path, embedded: &[FileSnapshot], filter: RuntimeFilter) {
    fn walk(curr: &Path, root: &Path, embedded: &[FileSnapshot], filter: RuntimeFilter) {
        let entries = match std::fs::read_dir(curr) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if filter.excludes(p.strip_prefix(root).expect("child is beneath root"), &meta) {
                    continue;
                }
                if meta.is_dir() {
                    walk(&p, root, embedded, filter);
                } else if meta.is_file()
                    && is_receipt_file_name(&name_str)
                    && !embedded.iter().any(|snap| snap.path == p)
                {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    walk(dir, dir, embedded, filter);
}

fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    root: &Path,
    mut embedded_receipts: Option<&mut Vec<FileSnapshot>>,
    filter: RuntimeFilter,
    fs_root: Option<&Path>,
    mut budget: Option<&mut SnapshotBudget>,
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
        if filter.excludes(
            child_src.strip_prefix(root).expect("child is beneath root"),
            &meta,
        ) {
            continue;
        }
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = match std::fs::read_link(&child_src) {
                Ok(t) => t,
                Err(e) => {
                    return Err(format!(
                        "Failed to read symlink {}: {}",
                        child_src.display(),
                        e
                    ))
                }
            };
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &child_dst).map_err(|e| {
                    format!("Failed to create symlink {}: {}", child_dst.display(), e)
                })?;
            }
        } else if ft.is_dir() {
            let receipts_sub = embedded_receipts.as_deref_mut();
            copy_dir_recursive(
                &child_src,
                &child_dst,
                root,
                receipts_sub,
                filter,
                fs_root,
                budget.as_deref_mut(),
            )?;
        } else if ft.is_file() {
            if let Some(budget) = budget.as_deref_mut() {
                budget.charge(&child_src, meta.len())?;
            }
            if let Some(ref mut receipts) = embedded_receipts {
                if is_receipt_file_name(&name_str) {
                    verify_no_symlink_ancestors_with_root(&child_src, fs_root)?;
                    let state = read_file_entry_bounded_nofollow(&child_src, 1024 * 1024)?;
                    receipts.push(FileSnapshot {
                        path: child_src,
                        state,
                    });
                    continue;
                }
            }
            if let Err(e) = copy_file_preserving_sparse_and_meta(&child_src, &child_dst, &meta) {
                return Err(format!(
                    "Failed to copy file {}: {}",
                    child_src.display(),
                    e
                ));
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
            dir_candidates.extend(["/opt/filebot".into(), "/opt/filebot-node".into()]);
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
            dir_candidates.extend(["/opt/Ombi".into(), "/etc/Ombi".into()]);
        }
        "organizr" => dir_candidates.push("/var/www/organizr".into()),
        "paperless-ngx" => {
            dir_candidates.extend(["/opt/paperless".into(), "/var/lib/paperless".into()]);
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
            dir_candidates.extend(["/opt/Sonarr".into(), "/opt/NzbDrone".into()]);
        }
        "tautulli" => {
            dir_candidates.extend(["/opt/Tautulli".into(), "/opt/plexpy".into()]);
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
        "dispatcharr" => all_units.extend([
            "dispatcharr-celery.service".into(),
            "dispatcharr-celerybeat.service".into(),
        ]),
        "emby" => all_units.push("emby-server.service".into()),
        "grafana" => all_units.push("grafana-server.service".into()),
        "homeassistant" => all_units.push("home-assistant@homeassistant.service".into()),
        "invidious" => all_units.extend([
            "af-invidious.service".into(),
            "af-invidious-companion.service".into(),
        ]),
        "kasmvnc" => all_units.push("af-kasmvnc.service".into()),
        "maintainerr" => all_units.push("af-maintainerr.service".into()),
        "mcvnc" => all_units.push("af-mcvnc.service".into()),
        "novnc" => all_units.extend(["novnc-xvnc.service".into(), "novnc-session.service".into()]),
        "palate" => all_units.push("af-palate.service".into()),
        "paperless-ngx" => all_units.extend([
            "paperless-webserver.service".into(),
            "paperless-worker.service".into(),
            "paperless-scheduler.service".into(),
        ]),
        "pihole" => all_units.push("pihole-FTL.service".into()),
        "piped" => all_units.extend([
            "af-piped.service".into(),
            "af-piped-api.service".into(),
            "af-piped-proxy.service".into(),
            "piped-backend.service".into(),
            "piped-proxy.service".into(),
        ]),
        "plex" => all_units.push("plexmediaserver.service".into()),
        "prometheus" => all_units.extend([
            "node_exporter.service".into(),
            "prometheus-node-exporter.service".into(),
        ]),
        "quassel" => all_units.push("quasselcore.service".into()),
        "rclone" => all_units.push("rclone-vfs.service".into()),
        "recyclarr" => all_units.extend(["recyclarr.service".into(), "recyclarr.timer".into()]),
        "scrutiny" => all_units.extend([
            "scrutiny-collector.service".into(),
            "scrutiny-collector.timer".into(),
        ]),
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
        "netdata" => {
            file_candidates.extend(["/usr/sbin/netdata".into(), "/usr/local/sbin/netdata".into()])
        }
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
        "wireguard" => file_candidates.extend(["/usr/bin/wg".into(), "/usr/bin/wg-quick".into()]),
        "x2go" => file_candidates.extend([
            "/usr/bin/x2goruncommand".into(),
            "/usr/bin/x2gostartagent".into(),
            "/usr/sbin/x2gocleansessions".into(),
        ]),
        "xrdp" => file_candidates.extend(["/usr/sbin/xrdp".into(), "/usr/sbin/xrdp-sesman".into()]),
        _ => {}
    }

    if let Some(recipe) = crate::package_executor::get_declarative_recipe(pkg) {
        for step in recipe
            .install_steps
            .iter()
            .chain(recipe.update_steps.iter())
        {
            match step {
                crate::package_executor::DeclarativeStep::WriteTemplateFile { path, .. } => {
                    file_candidates.push(path.clone());
                }
                crate::package_executor::DeclarativeStep::WriteSystemdUnit {
                    unit_name, ..
                } => {
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
                crate::package_executor::DeclarativeStep::DownloadAndExtractTarGz {
                    dest_dir,
                    extract_binaries,
                    ..
                } => {
                    let clean = dest_dir.trim_end_matches('/');
                    for b in extract_binaries {
                        file_candidates.push(format!("{clean}/{b}"));
                    }
                }
                crate::package_executor::DeclarativeStep::GenerateSelfSignedTlsCert {
                    cert_path,
                    key_out_path,
                    ..
                } => {
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

    let bp_paths =
        crate::package_executor::collect_blueprint_target_paths(pkg, env_cfg.fs_root.as_deref());

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
    retained: Vec<PathBuf>,
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

#[cfg(test)]
static SNAPSHOT_CAPTURE_THREAD: std::sync::Mutex<Option<std::thread::ThreadId>> =
    std::sync::Mutex::new(None);

#[derive(Debug, Clone, Copy)]
struct RecoveryStoragePolicy {
    privileged: bool,
    expected_uid: u32,
}

impl RecoveryStoragePolicy {
    fn current() -> Self {
        #[cfg(unix)]
        {
            let euid = unsafe { libc::geteuid() };
            Self {
                privileged: euid == 0,
                expected_uid: euid,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                privileged: false,
                expected_uid: 0,
            }
        }
    }
}

fn normalize_recovery_path(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    if path.as_os_str().is_empty() {
        return Err("Recovery root path must not be empty".to_string());
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err("Recovery root path must not contain NUL bytes".to_string());
    }
    if !path.is_absolute() {
        return Err(format!(
            "Recovery root must be an absolute path: {}",
            path.display()
        ));
    }
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "Recovery root must not contain '..' traversal: {}",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "Unsupported path prefix in recovery root: {}",
                    path.display()
                ));
            }
        }
    }
    if normalized == Path::new("/") {
        return Err("Refusing filesystem root '/' as recovery root".to_string());
    }
    Ok(normalized)
}

fn is_ephemeral_tmp_logical_path(logical: &Path) -> bool {
    let norm = logical.to_string_lossy();
    let trimmed = norm.trim_end_matches('/');
    matches!(
        trimmed,
        "/tmp" | "/var/tmp" | "/dev/shm" | "/run" | "/var/run"
    ) || trimmed.starts_with("/tmp/")
        || trimmed.starts_with("/var/tmp/")
        || trimmed.starts_with("/dev/shm/")
        || trimmed.starts_with("/run/")
        || trimmed.starts_with("/var/run/")
}

fn is_protected_recovery_logical_root(logical: &Path) -> bool {
    if is_protected_root(logical) {
        return true;
    }
    let norm = logical.to_string_lossy();
    matches!(
        norm.trim_end_matches('/'),
        "/var/backups"
            | "/var/log"
            | "/srv"
            | "/home"
            | "/root"
            | "/tmp"
            | "/var/tmp"
            | "/dev"
            | "/dev/shm"
            | "/run"
            | "/var/run"
    )
}

#[cfg(unix)]
fn is_symlink_open_error(err: &std::io::Error, path: &Path) -> bool {
    if err.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    if err.raw_os_error() == Some(libc::ENOTDIR) {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            return meta.file_type().is_symlink();
        }
    }
    false
}

#[cfg(unix)]
fn is_symlink_openat_error(
    err: &std::io::Error,
    dir_fd: libc::c_int,
    name: &std::ffi::CStr,
) -> bool {
    if err.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    if err.raw_os_error() == Some(libc::ENOTDIR) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0
        {
            return (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
        }
    }
    false
}

#[cfg(unix)]
fn open_dir_nofollow(path: &Path, label: &str) -> Result<std::os::fd::OwnedFd, String> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| format!("Invalid {} path {}: {}", label, path.display(), e))?;
    let raw = unsafe {
        libc::open(
            path_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let err = std::io::Error::last_os_error();
        if is_symlink_open_error(&err, path) {
            return Err(format!(
                "{} {} is a symlink (symlink traversal prohibited)",
                label,
                path.display()
            ));
        }
        return Err(format!(
            "Failed to open {} {}: {}",
            label,
            path.display(),
            err
        ));
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

#[cfg(unix)]
fn deepest_existing_ancestor(path: &Path) -> PathBuf {
    let mut probe = path.to_path_buf();
    while std::fs::symlink_metadata(&probe).is_err() {
        let Some(parent) = probe.parent() else {
            return PathBuf::from("/");
        };
        if parent == probe {
            break;
        }
        probe = parent.to_path_buf();
    }
    probe
}

#[cfg(unix)]
fn create_private_snapshot_under_recovery_root(
    recovery_root: &Path,
    folder_name: &str,
    strict_ancestor_anchor: Option<(&Path, bool)>,
    policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let (start_path, check_start, rel_target) = match strict_ancestor_anchor {
        Some((anchor, include_anchor)) if anchor == Path::new("/") => (
            PathBuf::from("/"),
            include_anchor,
            recovery_root.to_path_buf(),
        ),
        Some((anchor, include_anchor)) => {
            if !include_anchor && std::fs::symlink_metadata(anchor).is_err() {
                std::fs::create_dir_all(anchor).map_err(|e| {
                    format!(
                        "Failed to create recovery fixture root {}: {}",
                        anchor.display(),
                        e
                    )
                })?;
            }
            let rel = recovery_root.strip_prefix(anchor).map_err(|_| {
                format!(
                    "Recovery root {} is outside expected anchor {}",
                    recovery_root.display(),
                    anchor.display()
                )
            })?;
            (anchor.to_path_buf(), include_anchor, rel.to_path_buf())
        }
        None => {
            let parent = recovery_root.parent().ok_or_else(|| {
                format!("Invalid recovery root path: {}", recovery_root.display())
            })?;
            let existing = deepest_existing_ancestor(parent);
            let rel = recovery_root
                .strip_prefix(&existing)
                .map_err(|_| format!("Invalid recovery root path: {}", recovery_root.display()))?;
            (existing, false, rel.to_path_buf())
        }
    };

    let components: Vec<&std::ffi::OsStr> = rel_target
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err(format!(
            "Invalid recovery root path: {}",
            recovery_root.display()
        ));
    }

    let mut curr_fd = if start_path == Path::new("/") {
        let root_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(format!(
                "Failed to open root directory /: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { OwnedFd::from_raw_fd(root_raw) }
    } else {
        open_dir_nofollow(&start_path, "Recovery root ancestor")?
    };
    let mut current = start_path.clone();

    if check_start {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(curr_fd.as_raw_fd(), &mut st) } != 0 {
            return Err(format!(
                "Failed to stat recovery ancestor {}: {}",
                current.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mode = (st.st_mode as u32) & 0o777;
        if st.st_uid != policy.expected_uid || (mode & 0o022) != 0 {
            return Err(format!(
                "Recovery root ancestor {} has untrusted ownership/mode (uid={}, mode=0o{:o})",
                current.display(),
                st.st_uid,
                mode
            ));
        }
    }

    let (ancestors, leaf) = components.split_at(components.len() - 1);
    let leaf = leaf[0];

    for comp in ancestors {
        current.push(comp);
        let part_cstr = CString::new(comp.as_bytes()).map_err(|e| {
            format!(
                "Invalid path component in {}: {}",
                recovery_root.display(),
                e
            )
        })?;
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
                let mk_rc =
                    unsafe { libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755) };
                if mk_rc != 0 {
                    let mk_err = std::io::Error::last_os_error();
                    if mk_err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(format!(
                            "Failed to create recovery ancestor directory {}: {}",
                            current.display(),
                            mk_err
                        ));
                    }
                }
                next_raw = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            if next_raw < 0 {
                let open_err = std::io::Error::last_os_error();
                if is_symlink_openat_error(&open_err, curr_fd.as_raw_fd(), &part_cstr) {
                    return Err(format!(
                        "Recovery root ancestor {} is a symlink (symlink traversal prohibited)",
                        current.display()
                    ));
                }
                return Err(format!(
                    "Failed to open recovery ancestor directory {}: {}",
                    current.display(),
                    open_err
                ));
            }
        }
        let next_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        if let Some((_, include_anchor)) = strict_ancestor_anchor {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(next_fd.as_raw_fd(), &mut st) } != 0 {
                return Err(format!(
                    "Failed to stat recovery ancestor {}: {}",
                    current.display(),
                    std::io::Error::last_os_error()
                ));
            }
            let mode = (st.st_mode as u32) & 0o777;
            if st.st_uid != policy.expected_uid {
                return Err(format!(
                    "Recovery root ancestor {} is owned by uid {}, expected {}",
                    current.display(),
                    st.st_uid,
                    policy.expected_uid
                ));
            }
            let forbidden_write_bits = if policy.privileged || include_anchor {
                0o022
            } else {
                0o002
            };
            if (mode & forbidden_write_bits) != 0 {
                return Err(format!(
                    "Recovery root ancestor {} has unsafe writable permissions 0o{:o}",
                    current.display(),
                    mode
                ));
            }
        }
        curr_fd = next_fd;
    }

    current.push(leaf);
    let leaf_cstr = CString::new(leaf.as_bytes()).map_err(|e| {
        format!(
            "Invalid recovery root name in {}: {}",
            recovery_root.display(),
            e
        )
    })?;
    let mut created_leaf = false;
    let mut leaf_raw = unsafe {
        libc::openat(
            curr_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if leaf_raw < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            let mk_rc = unsafe { libc::mkdirat(curr_fd.as_raw_fd(), leaf_cstr.as_ptr(), 0o700) };
            if mk_rc == 0 {
                created_leaf = true;
            } else {
                let mk_err = std::io::Error::last_os_error();
                if mk_err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(format!(
                        "Failed to create recovery root {}: {}",
                        current.display(),
                        mk_err
                    ));
                }
            }
            leaf_raw = unsafe {
                libc::openat(
                    curr_fd.as_raw_fd(),
                    leaf_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if leaf_raw < 0 {
            let open_err = std::io::Error::last_os_error();
            if is_symlink_openat_error(&open_err, curr_fd.as_raw_fd(), &leaf_cstr) {
                return Err(format!(
                    "Recovery root {} is a symlink (symlink traversal prohibited)",
                    current.display()
                ));
            }
            return Err(format!(
                "Failed to open recovery root {}: {}",
                current.display(),
                open_err
            ));
        }
    }
    let leaf_fd = unsafe { OwnedFd::from_raw_fd(leaf_raw) };
    if created_leaf {
        let _ = unsafe { libc::fchmod(leaf_fd.as_raw_fd(), 0o700) };
    }
    let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(leaf_fd.as_raw_fd(), &mut leaf_st) } != 0 {
        return Err(format!(
            "Failed to stat recovery root {}: {}",
            current.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mode_mask = if policy.privileged { 0o7777 } else { 0o777 };
    let leaf_mode = (leaf_st.st_mode as u32) & mode_mask;
    if leaf_st.st_uid != policy.expected_uid {
        return Err(format!(
            "Recovery root {} is owned by uid {}, expected {}",
            current.display(),
            leaf_st.st_uid,
            policy.expected_uid
        ));
    }
    if leaf_mode != 0o700 {
        return Err(format!(
            "Recovery root {} has permissions 0o{:o}, expected private 0o700",
            current.display(),
            leaf_mode
        ));
    }

    let child_cstr = CString::new(folder_name.as_bytes())
        .map_err(|e| format!("Invalid snapshot folder name: {}", e))?;
    let mk_child = unsafe { libc::mkdirat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), 0o700) };
    if mk_child != 0 {
        return Err(format!(
            "Failed to create backup root {}/{}: {}",
            current.display(),
            folder_name,
            std::io::Error::last_os_error()
        ));
    }
    let child_raw = unsafe {
        libc::openat(
            leaf_fd.as_raw_fd(),
            child_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_raw < 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to verify created backup root {}/{}: {}",
            current.display(),
            folder_name,
            err
        ));
    }
    let child_fd = unsafe { OwnedFd::from_raw_fd(child_raw) };
    let _ = unsafe { libc::fchmod(child_fd.as_raw_fd(), 0o700) };
    let mut child_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(child_fd.as_raw_fd(), &mut child_st) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to stat backup root {}/{}: {}",
            current.display(),
            folder_name,
            err
        ));
    }
    let child_mode = (child_st.st_mode as u32) & mode_mask;
    if child_st.st_uid != policy.expected_uid || child_mode != 0o700 {
        let _ =
            unsafe { libc::unlinkat(leaf_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Created backup root {}/{} has unexpected ownership/mode (uid={}, mode=0o{:o})",
            current.display(),
            folder_name,
            child_st.st_uid,
            child_mode
        ));
    }
    Ok(current.join(folder_name))
}

#[cfg(unix)]
fn create_private_snapshot_under_fallback_parent(
    parent: &Path,
    folder_name: &str,
    allow_create_parent: bool,
    policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let norm_parent = normalize_recovery_path(parent)?;
    let existing = deepest_existing_ancestor(&norm_parent);
    let rel = norm_parent.strip_prefix(&existing).map_err(|_| {
        format!(
            "Invalid fallback snapshot parent: {}",
            norm_parent.display()
        )
    })?;
    let mut curr_fd = if existing == Path::new("/") {
        let root_raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_raw < 0 {
            return Err(format!(
                "Failed to open root directory /: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { OwnedFd::from_raw_fd(root_raw) }
    } else {
        open_dir_nofollow(&existing, "Fallback snapshot parent")?
    };
    let mut current = existing;
    for comp in rel.components() {
        if let Component::Normal(part) = comp {
            current.push(part);
            let part_cstr = CString::new(part.as_bytes())
                .map_err(|e| format!("Invalid path component in {}: {}", parent.display(), e))?;
            let mut next_raw = unsafe {
                libc::openat(
                    curr_fd.as_raw_fd(),
                    part_cstr.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next_raw < 0 && allow_create_parent {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    let mk_rc =
                        unsafe { libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o700) };
                    if mk_rc == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
                    {
                        next_raw = unsafe {
                            libc::openat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW
                                    | libc::O_CLOEXEC,
                            )
                        };
                    }
                }
            }
            if next_raw < 0 {
                return Err(format!(
                    "Failed to open fallback snapshot parent {}: {}",
                    current.display(),
                    std::io::Error::last_os_error()
                ));
            }
            curr_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
        }
    }

    let child_cstr = CString::new(folder_name.as_bytes())
        .map_err(|e| format!("Invalid snapshot folder name: {}", e))?;
    let mk_child = unsafe { libc::mkdirat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), 0o700) };
    if mk_child != 0 {
        return Err(format!(
            "Failed to create backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            std::io::Error::last_os_error()
        ));
    }
    let child_raw = unsafe {
        libc::openat(
            curr_fd.as_raw_fd(),
            child_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if child_raw < 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to verify fallback backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            err
        ));
    }
    let child_fd = unsafe { OwnedFd::from_raw_fd(child_raw) };
    let _ = unsafe { libc::fchmod(child_fd.as_raw_fd(), 0o700) };
    let mut child_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(child_fd.as_raw_fd(), &mut child_st) } != 0 {
        let err = std::io::Error::last_os_error();
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Failed to stat fallback backup root {}/{}: {}",
            norm_parent.display(),
            folder_name,
            err
        ));
    }
    let child_mode = (child_st.st_mode as u32) & 0o777;
    if child_st.st_uid != policy.expected_uid || child_mode != 0o700 {
        let _ =
            unsafe { libc::unlinkat(curr_fd.as_raw_fd(), child_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(format!(
            "Fallback backup root {}/{} has unexpected ownership/mode (uid={}, mode=0o{:o})",
            norm_parent.display(),
            folder_name,
            child_st.st_uid,
            child_mode
        ));
    }
    Ok(norm_parent.join(folder_name))
}

#[cfg(not(unix))]
fn create_private_snapshot_under_recovery_root(
    recovery_root: &Path,
    folder_name: &str,
    _strict_ancestor_anchor: Option<(&Path, bool)>,
    _policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(recovery_root).map_err(|e| {
        format!(
            "Failed to create recovery root {}: {}",
            recovery_root.display(),
            e
        )
    })?;
    let candidate = recovery_root.join(folder_name);
    std::fs::create_dir(&candidate).map_err(|e| {
        format!(
            "Failed to create backup root {}: {}",
            candidate.display(),
            e
        )
    })?;
    Ok(candidate)
}

#[cfg(not(unix))]
fn create_private_snapshot_under_fallback_parent(
    parent: &Path,
    folder_name: &str,
    allow_create_parent: bool,
    _policy: RecoveryStoragePolicy,
) -> Result<PathBuf, String> {
    if allow_create_parent {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create fallback snapshot parent {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    let candidate = parent.join(folder_name);
    std::fs::create_dir(&candidate).map_err(|e| {
        format!(
            "Failed to create backup root {}: {}",
            candidate.display(),
            e
        )
    })?;
    Ok(candidate)
}

fn prepare_runtime_snapshot_backup_root_with_policy(
    folder_name: &str,
    env_cfg: &crate::PackageExecutionEnv,
    policy: RecoveryStoragePolicy,
    data_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let norm_fs_root = match env_cfg.fs_root.as_deref() {
        Some(root) => Some(normalize_recovery_path(root)?),
        None => None,
    };

    // Mode 1: Explicit recovery root configured on PackageExecutionEnv (or AETHERFLOW_RECOVERY_ROOT).
    if let Some(ref custom) = env_cfg.recovery_root {
        let norm_custom = normalize_recovery_path(custom)?;
        if let Some(ref fs_root) = norm_fs_root {
            if let Ok(rel) = norm_custom.strip_prefix(fs_root) {
                let logical = Path::new("/").join(rel);
                if is_protected_recovery_logical_root(&logical) {
                    return Err(format!(
                        "Refusing protected directory as recovery root: {}",
                        norm_custom.display()
                    ));
                }
                if is_ephemeral_tmp_logical_path(&logical) {
                    return Err(format!(
                        "Recovery root {} must reside on persistent storage outside /tmp, /var/tmp, /dev/shm, and /run",
                        norm_custom.display()
                    ));
                }
                return create_private_snapshot_under_recovery_root(
                    &norm_custom,
                    folder_name,
                    Some((fs_root.as_path(), false)),
                    policy,
                );
            }
            if is_protected_recovery_logical_root(&norm_custom) {
                return Err(format!(
                    "Refusing protected directory as recovery root: {}",
                    norm_custom.display()
                ));
            }
            return create_private_snapshot_under_recovery_root(
                &norm_custom,
                folder_name,
                None,
                policy,
            );
        }

        if is_protected_recovery_logical_root(&norm_custom) {
            return Err(format!(
                "Refusing protected directory as recovery root: {}",
                norm_custom.display()
            ));
        }
        if policy.privileged && is_ephemeral_tmp_logical_path(&norm_custom) {
            return Err(format!(
                "Privileged recovery root {} must reside on persistent storage outside /tmp, /var/tmp, /dev/shm, and /run",
                norm_custom.display()
            ));
        }
        let anchor = if policy.privileged {
            Some((Path::new("/"), true))
        } else {
            None
        };
        return create_private_snapshot_under_recovery_root(
            &norm_custom,
            folder_name,
            anchor,
            policy,
        );
    }

    // Mode 2: Isolated fixture (fs_root set, no explicit recovery_root).
    if let Some(ref fs_root) = norm_fs_root {
        let isolated_recovery = fs_root.join("var/backups/aetherflow-recovery");
        return create_private_snapshot_under_recovery_root(
            &isolated_recovery,
            folder_name,
            Some((fs_root.as_path(), false)),
            policy,
        );
    }

    // Mode 3: Privileged real host (root runner or direct root CLI). Never fall back to /tmp or /var/tmp.
    if policy.privileged {
        let default_root = PathBuf::from(crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT);
        return create_private_snapshot_under_recovery_root(
            &default_root,
            folder_name,
            Some((Path::new("/"), true)),
            policy,
        );
    }

    // Mode 4: Unprivileged API fallback on a real host.
    // Prefer persistent <DATA_DIR>/recovery (e.g. /var/lib/aetherflow/recovery inside aetherflow-api.service)
    // when available and owned by this user; otherwise fall back to private 0700 temp_dir / /var/tmp / TMPDIR.
    if let Some(dd) = data_dir {
        if let Ok(norm_dd) = normalize_recovery_path(dd) {
            if !is_ephemeral_tmp_logical_path(&norm_dd)
                && !is_protected_recovery_logical_root(&norm_dd)
                && norm_dd.is_dir()
            {
                let dd_recovery = norm_dd.join("recovery");
                if let Ok(created) = create_private_snapshot_under_recovery_root(
                    &dd_recovery,
                    folder_name,
                    Some((norm_dd.as_path(), true)),
                    policy,
                ) {
                    return Ok(created);
                }
            }
        }
    }

    let mut parent_candidates: Vec<(PathBuf, bool)> = Vec::new();
    if !env_cfg.temp_dir.as_os_str().is_empty() {
        parent_candidates.push((env_cfg.temp_dir.clone(), true));
    }
    let var_tmp = Path::new("/var/tmp");
    if var_tmp.is_dir() && !parent_candidates.iter().any(|(p, _)| p == var_tmp) {
        parent_candidates.push((var_tmp.to_path_buf(), false));
    }
    let sys_tmp = std::env::temp_dir();
    if !parent_candidates.iter().any(|(p, _)| p == &sys_tmp) {
        parent_candidates.push((sys_tmp, false));
    }
    let mut last_create_err = String::from("No usable fallback directory for runtime snapshot");
    for (parent, allow_create) in parent_candidates {
        match create_private_snapshot_under_fallback_parent(
            &parent,
            folder_name,
            allow_create,
            policy,
        ) {
            Ok(created) => return Ok(created),
            Err(err) => {
                last_create_err = err;
            }
        }
    }
    Err(last_create_err)
}

fn prepare_runtime_snapshot_backup_root(
    folder_name: &str,
    env_cfg: &crate::PackageExecutionEnv,
) -> Result<PathBuf, String> {
    let data_dir = std::env::var_os("DATA_DIR")
        .or_else(|| std::env::var_os("AETHERFLOW_DATA_DIR"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    prepare_runtime_snapshot_backup_root_with_policy(
        folder_name,
        env_cfg,
        RecoveryStoragePolicy::current(),
        data_dir.as_deref(),
    )
}

impl PackageRuntimeSnapshot {
    async fn capture_blocking(
        package_id: String,
        units: Vec<String>,
        env_cfg: crate::PackageExecutionEnv,
    ) -> Result<Self, String> {
        tokio::task::spawn_blocking(move || Self::capture(&package_id, &units, &env_cfg, false))
            .await
            .map_err(|err| format!("Snapshot capture worker failed: {err}"))?
    }

    pub fn capture(
        package_id: &str,
        units: &[String],
        env_cfg: &crate::PackageExecutionEnv,
        _ignore_permission_denied: bool,
    ) -> Result<Self, String> {
        #[cfg(test)]
        {
            *SNAPSHOT_CAPTURE_THREAD.lock().unwrap() = Some(std::thread::current().id());
        }
        let safe_pkg: String = package_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let folder_name = format!(".af-rt-snap-{}-{}", safe_pkg, uuid::Uuid::new_v4());
        let backup_root = prepare_runtime_snapshot_backup_root(&folder_name, env_cfg)?;
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

        let targets = candidate_runtime_targets(package_id, units, env_cfg);
        let mut budget = preflight_runtime_snapshot(
            package_id,
            env_cfg.fs_root.as_deref(),
            &backup_root,
            &targets,
        )?;
        let mut entries = Vec::new();
        let mut embedded_receipts = Vec::new();

        for (idx, (target_path, kind)) in targets.into_iter().enumerate() {
            let filter =
                RuntimeFilter::for_target(package_id, &target_path, env_cfg.fs_root.as_deref());
            verify_no_symlink_ancestors_with_root(&target_path, env_cfg.fs_root.as_deref())?;
            match std::fs::symlink_metadata(&target_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    entries.push(RuntimeSnapshotEntry::Absent { target_path, kind });
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to read metadata for {}: {}",
                        target_path.display(),
                        e
                    ));
                }
                Ok(meta) if meta.file_type().is_symlink() => {
                    let link_target = std::fs::read_link(&target_path).map_err(|e| {
                        format!("Failed to read link {}: {}", target_path.display(), e)
                    })?;
                    entries.push(RuntimeSnapshotEntry::Symlink {
                        target_path,
                        link_target,
                    });
                }
                Ok(meta) if meta.is_file() => {
                    budget.charge(&target_path, meta.len())?;
                    let file_name = target_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if is_receipt_file_name(&file_name) {
                        verify_no_symlink_ancestors_with_root(
                            &target_path,
                            env_cfg.fs_root.as_deref(),
                        )?;
                        let state = read_file_entry_bounded_nofollow(&target_path, 1024 * 1024)?;
                        embedded_receipts.push(FileSnapshot {
                            path: target_path.clone(),
                            state,
                        });
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
                    entries.push(RuntimeSnapshotEntry::File {
                        target_path,
                        backup_path,
                        mode,
                        uid,
                        gid,
                    });
                }
                Ok(meta) if meta.is_dir() => {
                    let backup_path = backup_root.join(format!("entry_{idx}"));
                    copy_dir_recursive(
                        &target_path,
                        &backup_path,
                        &target_path,
                        Some(&mut embedded_receipts),
                        filter,
                        env_cfg.fs_root.as_deref(),
                        Some(&mut budget),
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
        fn dir_contains_any_non_dir(path: &Path) -> std::io::Result<bool> {
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.is_dir() {
                return Ok(true);
            }
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if dir_contains_any_non_dir(&entry.path())? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn absent_filtered_dir_has_user_payloads(
            root: &Path,
            current: &Path,
            filter: RuntimeFilter,
        ) -> std::io::Result<bool> {
            for entry in std::fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)?;
                let rel = path.strip_prefix(root).unwrap_or(&path);
                if filter.excludes(rel, &meta) {
                    if dir_contains_any_non_dir(&path)? {
                        return Ok(true);
                    }
                } else if meta.is_dir()
                    && absent_filtered_dir_has_user_payloads(root, &path, filter)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        // Phase 1 (Preflight & Stage — zero live mutations!)
        let mut staged_items: Vec<StagedRuntimeItem> = Vec::new();
        let mut absent_staged_targets: std::collections::HashSet<PathBuf> =
            std::collections::HashSet::new();

        for entry in &self.entries {
            let entry_target = match entry {
                RuntimeSnapshotEntry::Absent { target_path, .. } => target_path,
                RuntimeSnapshotEntry::File { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Symlink { target_path, .. } => target_path,
                RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
            };
            if let Err(e) =
                verify_no_symlink_ancestors_with_root(entry_target, self.fs_root.as_deref())
            {
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
                        return Err(format!(
                            "Failed to stat ancestor {}: {}",
                            ancestor.display(),
                            e
                        ));
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
                            let filter = RuntimeFilter::for_target(
                                &self.package_id,
                                target_path,
                                self.fs_root.as_deref(),
                            );
                            if *kind == RuntimeTargetKind::Directory
                                && meta.is_dir()
                                && filter != RuntimeFilter::None
                            {
                                let has_payloads = match absent_filtered_dir_has_user_payloads(
                                    target_path,
                                    target_path,
                                    filter,
                                ) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        return Err(format!(
                                            "Failed to inspect absent filtered target {}: {}",
                                            target_path.display(),
                                            e
                                        ));
                                    }
                                };
                                if has_payloads {
                                    let parent = target_path.parent().ok_or_else(|| {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        format!(
                                            "Target path {} has no parent",
                                            target_path.display()
                                        )
                                    })?;
                                    let name = target_path
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy();
                                    let stage = parent.join(format!(
                                        ".{}.af-rt-stage-{}",
                                        name,
                                        uuid::Uuid::new_v4()
                                    ));
                                    if let Err(e) = std::fs::create_dir_all(&stage) {
                                        cleanup_staged_items(&staged_items);
                                        self.preserve_on_drop = true;
                                        return Err(format!(
                                            "Failed to stage absent filtered directory {}: {}",
                                            stage.display(),
                                            e
                                        ));
                                    }
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::{MetadataExt, PermissionsExt};
                                        let _ = std::fs::set_permissions(
                                            &stage,
                                            std::fs::Permissions::from_mode(meta.mode()),
                                        );
                                        unsafe {
                                            if libc::geteuid() == 0 {
                                                if let Ok(c_path) = std::ffi::CString::new(
                                                    stage.as_os_str().as_bytes(),
                                                ) {
                                                    libc::chown(
                                                        c_path.as_ptr(),
                                                        meta.uid(),
                                                        meta.gid(),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    absent_staged_targets.insert(target_path.clone());
                                    staged_items.push(StagedRuntimeItem::Directory {
                                        target_path: target_path.clone(),
                                        stage_path: stage,
                                    });
                                }
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
                RuntimeSnapshotEntry::File {
                    target_path,
                    backup_path,
                    mode,
                    uid,
                    gid,
                } => {
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
                        format!(
                            "Failed to stat backup file {}: {}",
                            backup_path.display(),
                            e
                        )
                    })?;
                    if let Err(e) = copy_file_preserving_sparse_and_meta(backup_path, &stage, &meta)
                    {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to stage restored file {}: {}",
                            stage.display(),
                            e
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &stage,
                            std::fs::Permissions::from_mode(*mode),
                        );
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) =
                                    std::ffi::CString::new(stage.as_os_str().as_bytes())
                                {
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
                RuntimeSnapshotEntry::Symlink {
                    target_path,
                    link_target,
                } => {
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
                            return Err(format!(
                                "Failed to create symlink {}: {}",
                                stage.display(),
                                e
                            ));
                        }
                    }
                    staged_items.push(StagedRuntimeItem::Symlink {
                        target_path: target_path.clone(),
                        stage_path: stage,
                    });
                }
                RuntimeSnapshotEntry::Directory {
                    target_path,
                    backup_path,
                    mode,
                    uid,
                    gid,
                } => {
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
                    let name = target_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let stage =
                        parent.join(format!(".{}.af-rt-stage-{}", name, uuid::Uuid::new_v4()));
                    if let Err(e) = copy_dir_recursive(
                        backup_path,
                        &stage,
                        backup_path,
                        None,
                        RuntimeFilter::None,
                        self.fs_root.as_deref(),
                        None,
                    ) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to stage restored directory {}: {}",
                            stage.display(),
                            e
                        ));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &stage,
                            std::fs::Permissions::from_mode(*mode),
                        );
                        unsafe {
                            if libc::geteuid() == 0 {
                                if let Ok(c_path) =
                                    std::ffi::CString::new(stage.as_os_str().as_bytes())
                                {
                                    libc::chown(c_path.as_ptr(), *uid, *gid);
                                }
                            }
                        }
                    }
                    if let Err(e) = copy_live_receipts_to_stage(
                        target_path,
                        &stage,
                        RuntimeFilter::for_target(
                            &self.package_id,
                            target_path,
                            self.fs_root.as_deref(),
                        ),
                    ) {
                        cleanup_staged_items(&staged_items);
                        self.preserve_on_drop = true;
                        return Err(format!(
                            "Failed to preserve live receipts into stage {}: {}",
                            stage.display(),
                            e
                        ));
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

        let mut staged = staged_items.into_iter();
        for item in staged.by_ref() {
            let (target_path, stage_path, is_dir) = match item {
                StagedRuntimeItem::File {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, false),
                StagedRuntimeItem::Symlink {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, false),
                StagedRuntimeItem::Directory {
                    target_path,
                    stage_path,
                } => (target_path, stage_path, true),
            };
            let parent = match target_path.parent() {
                Some(p) => p,
                None => {
                    let _ = if is_dir {
                        std::fs::remove_dir_all(&stage_path)
                    } else {
                        std::fs::remove_file(&stage_path)
                    };
                    swap_err = Some(format!("Target {} has no parent", target_path.display()));
                    break;
                }
            };
            let name = target_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let old_path = parent.join(format!(".{}.af-rt-old-{}", name, uuid::Uuid::new_v4()));
            let had_target = std::fs::symlink_metadata(&target_path).is_ok();
            if had_target {
                if let Err(e) = std::fs::rename(&target_path, &old_path) {
                    let _ = if is_dir {
                        std::fs::remove_dir_all(&stage_path)
                    } else {
                        std::fs::remove_file(&stage_path)
                    };
                    swap_err = Some(format!(
                        "Failed to move old {} to {}: {}",
                        target_path.display(),
                        old_path.display(),
                        e
                    ));
                    break;
                }
            }
            if let Err(e) = std::fs::rename(&stage_path, &target_path) {
                if had_target {
                    let _ = std::fs::rename(&old_path, &target_path);
                }
                let _ = if is_dir {
                    std::fs::remove_dir_all(&stage_path)
                } else {
                    std::fs::remove_file(&stage_path)
                };
                swap_err = Some(format!(
                    "Failed to move stage {} to {}: {}",
                    stage_path.display(),
                    target_path.display(),
                    e
                ));
                break;
            }
            let mut swap = CommittedSwap {
                target_path,
                old_path: had_target.then_some(old_path),
                retained: Vec::new(),
            };
            if is_dir {
                let filter = RuntimeFilter::for_target(
                    &self.package_id,
                    &swap.target_path,
                    self.fs_root.as_deref(),
                );
                if let Err(error) = swap.retain_exclusions(filter) {
                    swap_err = Some(format!("Failed to retain runtime payloads: {error}"));
                }
            }
            committed_swaps.push(swap);
            if swap_err.is_some() {
                break;
            }
        }

        if let Some(err) = swap_err {
            cleanup_staged_items(staged.as_slice());
            for swap in committed_swaps.into_iter().rev() {
                if let Err(error) = swap.revert() {
                    tracing::error!(%error, "Runtime swap rollback failed");
                }
            }
            self.preserve_on_drop = true;
            return Err(err);
        }

        let mut absent_parked: Vec<(PathBuf, PathBuf)> = Vec::new();
        let mut absent_err: Option<String> = None;
        for entry in &self.entries {
            if let RuntimeSnapshotEntry::Absent { target_path, .. } = entry {
                if absent_staged_targets.contains(target_path) {
                    continue;
                }
                match std::fs::symlink_metadata(target_path) {
                    Ok(meta) => {
                        if let Some(parent) = target_path.parent() {
                            let name = target_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy();
                            let parked = parent.join(format!(
                                ".{}.af-rt-abs-{}",
                                name,
                                uuid::Uuid::new_v4()
                            ));
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
                if let Err(error) = swap.revert() {
                    tracing::error!(%error, "Runtime swap rollback failed");
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
                if let Ok(meta) = std::fs::symlink_metadata(&old) {
                    let _ = if meta.is_dir() {
                        std::fs::remove_dir_all(&old)
                    } else {
                        std::fs::remove_file(&old)
                    };
                }
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
                        if name.starts_with(&prefix) && de.file_type().is_ok_and(|ft| ft.is_dir()) {
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
                remove_untracked_receipt_files(
                    target_path,
                    &self.embedded_receipts,
                    RuntimeFilter::for_target(
                        &self.package_id,
                        target_path,
                        self.fs_root.as_deref(),
                    ),
                );
            }
        }
        restore_candidate_receipts(&self.embedded_receipts)?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub static TEST_ROLLBACK_HOOK: once_cell::sync::Lazy<
    std::sync::Mutex<Option<Box<dyn Fn(&[FileSnapshot]) + Send + Sync>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
#[allow(clippy::type_complexity)]
pub static TEST_CERTIFY_FAIL_HOOK: once_cell::sync::Lazy<
    std::sync::Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

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

pub fn snapshot_candidate_receipts(package_id: &str) -> Result<Vec<FileSnapshot>, String> {
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
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Component;

    if !dir_path.is_absolute() {
        return Err(StepwiseDirError {
            message: format!("Directory path must be absolute: {}", dir_path.display()),
            raw_os_error: Some(libc::EINVAL),
        });
    }

    let root_raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
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
                    Err(e) => {
                        return Err(StepwiseDirError {
                            message: format!("CString error: {}", e),
                            raw_os_error: Some(libc::EINVAL),
                        })
                    }
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
                                    libc::O_RDONLY
                                        | libc::O_DIRECTORY
                                        | libc::O_NOFOLLOW
                                        | libc::O_CLOEXEC,
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
                    message: format!(
                        "Parent directory traversal '..' forbidden: {}",
                        dir_path.display()
                    ),
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

pub fn open_dir_nofollow_stepwise_inner(
    dir_path: &Path,
) -> Result<std::os::fd::OwnedFd, StepwiseDirError> {
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
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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

    let file_cstr =
        CString::new(file_name.as_bytes()).map_err(|e| format!("CString error: {}", e))?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            file_cstr.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!(
            "fstatat failed on receipt {}: {}",
            path.display(),
            err
        ));
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
        return Err(format!(
            "openat failed on receipt {}: {}",
            path.display(),
            err
        ));
    }
    let file_fd = unsafe { OwnedFd::from_raw_fd(file_raw) };

    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_rc = unsafe { libc::fstat(file_fd.as_raw_fd(), &mut fst) };
    if fstat_rc != 0 {
        return Err(format!(
            "fstat failed on receipt {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    if (fst.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "Receipt path {} is not a regular file after opening",
            path.display()
        ));
    }
    if fst.st_dev != st.st_dev || fst.st_ino != st.st_ino {
        return Err(format!(
            "Inode or device changed for receipt {}",
            path.display()
        ));
    }
    if fst.st_size > max_bytes as libc::off_t {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    let mut std_file = std::fs::File::from(file_fd);
    let mut buf = Vec::new();
    std_file
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read receipt {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "Receipt path {} exceeds {} byte limit during read",
            path.display(),
            max_bytes
        ));
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
        verify_no_symlink_ancestors_with_root(&path, env_cfg.fs_root.as_deref())?;
        let state = read_file_entry_bounded_nofollow(&path, 512 * 1024)?;
        snapshots.push(FileSnapshot { path, state });
    }
    Ok(snapshots)
}

pub fn restore_candidate_receipts(snapshots: &[FileSnapshot]) -> Result<(), String> {
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
                errors.push(format!(
                    "Invalid receipt path with no parent: {}",
                    path.display()
                ));
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
                errors.push(format!(
                    "Failed to open directory stepwise {}: {}",
                    parent.display(),
                    e
                ));
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
            libc::fstatat(
                dir_fd,
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && prior_state.is_some() {
            errors.push(format!(
                "Refusing to overwrite directory at receipt path {}",
                path.display()
            ));
            continue;
        }

        if let Some(entry) = prior_state {
            let tmp_name = format!(
                ".af-receipt-tmp-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            );
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
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
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
                let chown_rc =
                    unsafe { libc::fchown(fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
                if chown_rc != 0 {
                    let err = std::io::Error::last_os_error();
                    unsafe {
                        libc::close(fd);
                        libc::unlinkat(dir_fd, tmp_cstr.as_ptr(), 0);
                    };
                    errors.push(format!(
                        "Failed to restore ownership (uid={}, gid={}) on {}: {}",
                        entry.uid,
                        entry.gid,
                        path.display(),
                        err
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
                    target_mode,
                    path.display(),
                    err
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

            let rename_rc =
                unsafe { libc::renameat(dir_fd, tmp_cstr.as_ptr(), dir_fd, file_cstr.as_ptr()) };
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
                    let rmdir_rc =
                        unsafe { libc::unlinkat(dir_fd, file_cstr.as_ptr(), libc::AT_REMOVEDIR) };
                    if rmdir_rc != 0 {
                        let rmdir_err = std::io::Error::last_os_error();
                        if rmdir_err.raw_os_error() != Some(libc::ENOENT) {
                            errors.push(format!(
                                "Failed to remove directory at receipt path {}: {}",
                                path.display(),
                                rmdir_err
                            ));
                        }
                    }
                } else if raw_err != Some(libc::ENOENT) {
                    errors.push(format!(
                        "Failed to unlink receipt {}: {}",
                        path.display(),
                        err
                    ));
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
) where
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
                                libc::read(
                                    fd,
                                    scratch.as_mut_ptr() as *mut libc::c_void,
                                    scratch.len(),
                                )
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
                                libc::read(
                                    fd,
                                    scratch.as_mut_ptr() as *mut libc::c_void,
                                    scratch.len(),
                                )
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
                let _ = pipe
                    .by_ref()
                    .take(MAX_PROBE_OUTPUT_BYTES as u64)
                    .read_to_end(&mut buf);
            }
        }
        let _ = tx.send(buf);
    });
}

#[cfg(test)]
pub static INJECT_WAITID_EPERM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn probe command: {}", e))?;
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
        child
            .wait()
            .map_err(|e| format!("failed waiting for child after kill: {}", e))?
    } else {
        #[cfg(unix)]
        if exit_status.is_none() {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        match exit_status {
            Some(s) => s,
            None => child
                .wait()
                .map_err(|e| format!("failed waiting for child: {}", e))?,
        }
    };

    stop_reading.store(true, std::sync::atomic::Ordering::SeqCst);

    let stdout = stdout_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();
    let stderr = stderr_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();

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
    if let Some(pos) = token.find(['-', '+']) {
        token[pos + 1..]
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || c == '-')
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
    static DOTTED_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
        },
    );
    static DEFAULT_VERSION_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(
        || {
            regex::Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:(?:[-+~:][0-9A-Za-z.+~:-]*[0-9A-Za-z-])|[0-9A-Za-z.+~:-]*[0-9A-Za-z])?)")
            .unwrap()
        },
    );
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
                if let (Ok(fe_hash), Ok(be_hash), Ok(pr_hash)) = (
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&fe),
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&be),
                    crate::probe_metadata::resolve_git_head_commit_nofollow(&pr),
                ) {
                    return LiveRuntimeProbeOutcome::Verified(format!(
                        "frontend:{fe_hash},backend:{be_hash},proxy:{pr_hash}"
                    ));
                } else {
                    return LiveRuntimeProbeOutcome::Failed(
                        "Piped pure-Rust .git/HEAD resolution failed for one or more sub-repos"
                            .into(),
                    );
                }
            } else {
                return LiveRuntimeProbeOutcome::Failed(
                    "Piped partial git checkouts detected: expected frontend, backend, and proxy"
                        .into(),
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
        let rebase_static = |raw: &str| {
            env_cfg
                .resolve_path(raw)
                .unwrap_or_else(|_| std::path::PathBuf::from(raw))
        };
        if let Some(static_res) = crate::probe_metadata::extract_static_package_version(
            package_id,
            &pkg.version_command,
            &rebase_static,
        ) {
            return match static_res {
                Ok(ver) if !ver.is_empty() => LiveRuntimeProbeOutcome::Verified(ver),
                Ok(_) => LiveRuntimeProbeOutcome::Failed(
                    "Static version probe returned empty version".into(),
                ),
                Err(e) => LiveRuntimeProbeOutcome::Failed(e),
            };
        }

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

        let sanitized_args = crate::probe_metadata::sanitize_probe_shell_args(
            std::path::Path::new(&prog_to_run),
            args,
        );
        let mut cmd = std::process::Command::new(&prog_to_run);
        cmd.args(&sanitized_args);
        let sandbox_spec = crate::probe_metadata::ProbeSandboxSpec {
            drop_to_path_owner: true,
            fs_root: env_cfg.fs_root.clone(),
            package_user: Some(package_id.to_string()),
        };
        if let Err(err) = crate::probe_metadata::configure_sandboxed_std_command(
            &mut cmd,
            std::path::Path::new(&prog_to_run),
            &sanitized_args,
            &sandbox_spec,
        ) {
            return LiveRuntimeProbeOutcome::Failed(format!(
                "Refused unsafe version probe command '{}': {}",
                prog_to_run, err
            ));
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
                    if let Some(stripped) = extracted
                        .strip_prefix('v')
                        .or_else(|| extracted.strip_prefix('V'))
                    {
                        if stripped.chars().next().is_some_and(|c| c.is_ascii_digit()) {
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
            match crate::probe_metadata::resolve_git_head_commit_nofollow(&opt_dir.join(".git")) {
                Ok(hash) if !hash.is_empty() => return LiveRuntimeProbeOutcome::Verified(hash),
                Ok(_) => {
                    return LiveRuntimeProbeOutcome::Failed(
                        "Git HEAD resolved to empty hash".into(),
                    )
                }
                Err(e) => {
                    return LiveRuntimeProbeOutcome::Failed(format!(
                        "Failed to resolve .git/HEAD cleanly: {}",
                        e
                    ))
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

    let fallback_sandbox_spec = crate::probe_metadata::ProbeSandboxSpec {
        drop_to_path_owner: true,
        fs_root: env_cfg.fs_root.clone(),
        package_user: Some(package_id.to_string()),
    };
    let dpkg_prog = if let Some(root) = &env_cfg.fs_root {
        [
            "usr/bin/dpkg-query",
            "usr/local/bin/dpkg-query",
            "bin/dpkg-query",
        ]
        .into_iter()
        .map(|rel| root.join(rel))
        .find(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dpkg-query".to_string())
    } else if Path::new("/usr/bin/dpkg-query").exists() {
        "/usr/bin/dpkg-query".to_string()
    } else {
        "dpkg-query".to_string()
    };

    for name in &pkg_names {
        if name.is_empty() {
            continue;
        }
        let mut dpkg_args: Vec<String> = Vec::new();
        if let Some(root) = &env_cfg.fs_root {
            let dpkg_dir = root.join("var/lib/dpkg");
            if dpkg_dir.exists() {
                dpkg_args.push(format!("--admindir={}", dpkg_dir.display()));
            }
        }
        dpkg_args.push("-W".to_string());
        dpkg_args.push("-f=${Version}\n".to_string());
        dpkg_args.push(name.clone());

        let mut cmd = std::process::Command::new(&dpkg_prog);
        if crate::probe_metadata::configure_sandboxed_std_command(
            &mut cmd,
            Path::new(&dpkg_prog),
            &dpkg_args,
            &fallback_sandbox_spec,
        )
        .is_err()
        {
            continue;
        }
        cmd.args(&dpkg_args);
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

    static VERSION_TOKEN_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:[0-9]+:)?[0-9]+\.[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z.+~_-]+)?(?:-[0-9A-Za-z.+~_-]+)?(?:\+[0-9A-Za-z.+~_-]+)?|\b[0-9a-f]{7,40}\b)"
        )
        .expect("valid version regex")
    });
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
            let bin_args = vec!["--version".to_string()];
            let mut cmd = std::process::Command::new(&bin);
            if crate::probe_metadata::configure_sandboxed_std_command(
                &mut cmd,
                &bin,
                &bin_args,
                &fallback_sandbox_spec,
            )
            .is_err()
            {
                continue;
            }
            cmd.args(&bin_args);
            if let Ok(output) = run_bounded_probe_command(&mut cmd, Duration::from_secs(5)) {
                if output.status.success() {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if let Some(cap) = VERSION_TOKEN_RE.captures(&combined) {
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
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "env"
                | "python"
                | "python2"
                | "python3"
                | "node"
                | "nodejs"
                | "java"
                | "ruby"
                | "perl"
                | "php"
                | "dotnet"
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
                            wd.join(target)
                                .to_str()
                                .and_then(|s| env_cfg.resolve_path(s).ok())
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
                        wd.join(arg)
                            .to_str()
                            .and_then(|s| env_cfg.resolve_path(s).ok())
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
            let u_name = if u.ends_with(".service") {
                u
            } else {
                format!("{}.service", u)
            };
            if !unit_candidates.contains(&u_name) {
                unit_candidates.push(u_name);
            }
        }
    }
    for unit in &unit_candidates {
        for prefix in [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ] {
            let unit_path = format!("{}/{}", prefix, unit);
            if let Ok(p) = env_cfg.resolve_path(&unit_path) {
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.is_file() {
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            if validate_systemd_unit_runtime_evidence(&content, package_id, env_cfg)
                            {
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
#[allow(clippy::await_holding_lock, clippy::field_reassign_with_default)]
mod version_verification_tests;
