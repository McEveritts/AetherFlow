use super::backend::run_direct;
use super::receipt_snapshots::{
    rollback_operation_state_with_runtime, snapshot_blueprint_targets,
    snapshot_candidate_receipts_with_env, FileSnapshot,
};
use super::redaction::sanitize_lifecycle_field;
use super::runtime_snapshot::PackageRuntimeSnapshot;
use af_models::{Package, PackageRunnerRequest};
use af_release::lifecycle;
use anyhow::{Context, Result};
use futures::StreamExt;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
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

pub(super) fn package_definition(name: &str) -> Result<Package> {
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
    let conn = af_release::fs_security::open_sqlite_isolated_readonly(database).ok();
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
            // Restore vhost backups before runtime and blueprint snapshots because
            // PackageRuntimeSnapshot::capture also snapshots Apache vhosts; running
            // restore_app_vhost_backups first detects drift for Apache reload.
            vhosts_reverted =
                crate::restore_app_vhost_backups(&vhost_backups).map_err(|e| e.to_string())?;
            rollback_operation_state_with_runtime(
                &receipt_snapshots,
                &blueprint_snapshots,
                Some(&mut runtime_snapshot),
            )?;
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

    if restore_res.is_ok()
        && fs_root.is_none()
        && std::env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none()
    {
        let systemctl_bin = std::env::var("AETHERFLOW_SYSTEMCTL_BIN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "systemctl".to_string());
        let mut cmd = tokio::process::Command::new(systemctl_bin);
        cmd.arg("daemon-reload");
        let _ = crate::bounded_command::output(cmd, Duration::from_secs(15), 64 * 1024).await;
    }
    if vhosts_changed {
        crate::reload_apache_after_rollback_if_live(fs_root.as_deref()).await;
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

pub(super) fn spawn_worker<Run, RunFuture>(
    request: PackageRunnerRequest,
    run: Run,
) -> mpsc::Receiver<String>
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
