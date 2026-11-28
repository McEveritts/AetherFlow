use super::lifecycle::{is_restart_eligible_unit, PackageLifecycleFailure};
use super::receipts::{restore_candidate_receipts, ReceiptSnapshotEntry};
use af_models::AppIngressConfig;
use std::path::{Path, PathBuf};

pub(in crate::routes) async fn finalize_post_script_lifecycle_with<
    ApplyFut,
    SaveIngressFn,
    ControlFn,
    ControlFut,
    RefreshFut,
>(
    stopped_units: &[String],
    apply_blueprint: ApplyFut,
    mut control_unit: ControlFn,
    query_status: impl Fn(&str) -> String,
    refresh_update: RefreshFut,
    save_ingress: SaveIngressFn,
) -> Result<Option<String>, PackageLifecycleFailure>
where
    ApplyFut: std::future::Future<Output = Result<Option<AppIngressConfig>, String>>,
    SaveIngressFn: FnOnce(&AppIngressConfig) -> anyhow::Result<()>,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    RefreshFut: std::future::Future<Output = Option<String>>,
{
    let ingress = apply_blueprint.await;
    let mut service_failures = Vec::new();
    for unit in af_runner::af_release::lifecycle::ordered_units_for_start(stopped_units) {
        if let Err(error) = control_unit(unit.clone(), "start").await {
            service_failures.push(format!("Failed to restart stopped unit {unit}: {error}"));
        }
    }
    let achieved_version = refresh_update.await;
    for unit in stopped_units {
        let status = query_status(unit);
        if status != "running" && status != "idle" {
            service_failures.push(format!(
                "Application service failed to remain active after execution: {unit} ({status})"
            ));
        }
    }

    let ingress = ingress.map_err(|error| {
        let mut message =
            format!("Required blueprint configuration synchronization failed: {error}");
        let kind = if service_failures.is_empty() {
            af_services::PackageJobFailure::Configuration
        } else {
            message.push_str(&format!("; {}", service_failures.join("; ")));
            af_services::PackageJobFailure::ConfigurationAndServiceRestore
        };
        PackageLifecycleFailure { kind, message }
    })?;
    if !service_failures.is_empty() {
        return Err(PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::ServiceRestore,
            message: service_failures.join("; "),
        });
    }

    // Commit only after all phases that can trigger runtime rollback. A
    // failed transaction leaves both active and retained ingress intact.
    if let Some(config) = ingress {
        save_ingress(&config).map_err(|error| PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::Configuration,
            message: format!("Failed to persist ingress configuration: {error}"),
        })?;
    }
    Ok(achieved_version)
}

pub(in crate::routes) fn is_incomplete_rollback_error(err_msg: &str) -> bool {
    af_runner::package_lifecycle::is_incomplete_rollback_error(err_msg)
}

#[cfg(test)]
pub(in crate::routes) async fn restore_pre_stopped_units_after_installer_failure_with<
    ControlFn,
    ControlFut,
>(
    clean_id: &str,
    stopped_units: &[String],
    installer_error: &str,
    mut control_unit: ControlFn,
) -> (af_services::PackageJobFailure, String)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut restore_errors: Vec<String> = Vec::new();
    if af_services::should_pre_stop_on_update(clean_id) && !stopped_units.is_empty() {
        if is_incomplete_rollback_error(installer_error) {
            restore_errors.push(
                "Refusing to restart pre-stopped service after incomplete rollback".to_string(),
            );
        } else {
            for unit in af_runner::af_release::lifecycle::ordered_units_for_start(stopped_units) {
                if let Err(restore_err) = control_unit(unit.clone(), "start").await {
                    restore_errors.push(format!(
                        "Failed to restore stopped unit {}: {}",
                        unit, restore_err
                    ));
                }
            }
        }
    }
    if restore_errors.is_empty() {
        (
            af_services::PackageJobFailure::Installer,
            installer_error.to_string(),
        )
    } else {
        (
            af_services::PackageJobFailure::ServiceRestore,
            format!("{}; {}", installer_error, restore_errors.join("; ")),
        )
    }
}

pub(crate) struct RunnerLifecycleSnapshotHandle {
    package_id: String,
    job_id: String,
    pub(in crate::routes) active: bool,
}

impl RunnerLifecycleSnapshotHandle {
    pub(crate) fn new(package_id: String, job_id: String) -> Self {
        Self {
            package_id,
            job_id,
            active: true,
        }
    }

    pub(crate) async fn restore(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        af_runner::dispatch_package_lifecycle_snapshot_restore(&self.package_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub(crate) async fn discard(&mut self, preserve_backup: bool) {
        if !self.active {
            return;
        }
        self.active = false;
        if let Err(err) = af_runner::dispatch_package_lifecycle_snapshot_discard_for_job(
            &self.package_id,
            &self.job_id,
            preserve_backup,
        )
        .await
        {
            tracing::warn!(
                package = %self.package_id,
                job_id = %self.job_id,
                preserve_backup,
                error = %err,
                "Failed to discard runner lifecycle snapshot"
            );
        }
    }
}

impl Drop for RunnerLifecycleSnapshotHandle {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let pkg = self.package_id.clone();
        let job = self.job_id.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = af_runner::dispatch_package_lifecycle_snapshot_discard_for_job(
                    &pkg, &job, true,
                )
                .await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    vhost_backups: &[af_runner::VhostBackup],
    fs_root: Option<&Path>,
    refuse_restart: bool,
    mut runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    mut runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    mut control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    // Step 1: Quiesce (stop) quiesce_units BEFORE restore_candidate_receipts runs
    let mut quiesce_failures: Vec<String> = Vec::new();
    if af_services::should_pre_stop_on_update(clean_id) && !quiesce_units.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let mut ordered_quiesce: Vec<String> = quiesce_units
            .iter()
            .filter(|unit| seen.insert((*unit).clone()))
            .cloned()
            .collect();
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut ordered_quiesce);
        for unit in &ordered_quiesce {
            if let Err(e) = control_unit(unit.clone(), "stop").await {
                let err_str = e.to_string();
                let err_lower = err_str.to_ascii_lowercase();
                let is_absent_err = err_lower.contains("not loaded")
                    || err_lower.contains("not-found")
                    || err_lower.contains("not found")
                    || err_lower.contains("no such file")
                    || err_lower.contains("could not be found")
                    || err_lower.contains("exit status: 5")
                    || err_lower.contains("exit code 5");

                if is_absent_err
                    && matches!(
                        query_status(unit).as_str(),
                        "stopped" | "idle" | "not-found"
                    )
                {
                    tracing::info!(
                        unit = %unit,
                        error = %e,
                        "Absent unit not loaded during stop before restoration, confirmed quiescent"
                    );
                } else {
                    tracing::error!(unit = %unit, error = %e, "Failed to quiesce unit before receipt restoration");
                    quiesce_failures.push(format!(
                        "Failed to quiesce unit '{unit}' before receipt restoration: {e}"
                    ));
                }
            }
        }
    }

    if !quiesce_failures.is_empty() {
        if let Some(ref mut rt) = runtime_snapshot {
            rt.preserve_on_drop = true;
        }
        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(true).await;
        }
        return (
            Some("Skipped candidate receipt restoration because service quiescence failed (incomplete-rollback)".to_string()),
            quiesce_failures,
        );
    }

    // Incomplete rollback did not recover runtime. Leave candidate receipts on
    // disk so a NEW runtime is not paired with a rewound .af-version.
    let mut restart_failures: Vec<String> = Vec::new();
    if refuse_restart {
        if let Some(ref mut rt) = runtime_snapshot {
            rt.preserve_on_drop = true;
        }
        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(true).await;
        }
        if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
            restart_failures.push(
                "Refusing to restart pre-stopped service after incomplete rollback".to_string(),
            );
        }
        return (
            Some("Skipped candidate receipt restoration after incomplete rollback".to_string()),
            restart_failures,
        );
    }

    let receipt_restore_error = if let Some(ref mut rs) = runner_snapshot {
        if let Err(rt_err) = rs.restore().await {
            if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                restart_failures.push(
                    "Refusing to restart pre-stopped service after runtime restoration failure"
                        .to_string(),
                );
            }
            return (Some(rt_err), restart_failures);
        }
        None
    } else {
        // Restore vhost backups before runtime and blueprint snapshots because
        // PackageRuntimeSnapshot::capture also snapshots collect_blueprint_target_paths
        // (including sites-available and sites-enabled vhosts); running rt.restore()
        // first would erase drift before restore_app_vhost_backups() can detect it
        // for reload_apache_after_rollback_if_live.
        let vhosts_changed = if !vhost_backups.is_empty() {
            match af_runner::restore_app_vhost_backups(vhost_backups) {
                Ok(changed) => changed,
                Err(vhost_err) => {
                    if let Some(ref mut rt) = runtime_snapshot {
                        rt.preserve_on_drop = true;
                    }
                    if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty()
                    {
                        restart_failures.push(
                            "Refusing to restart pre-stopped service after receipt restoration failure"
                                .to_string(),
                        );
                    }
                    return (Some(vhost_err.to_string()), restart_failures);
                }
            }
        } else {
            false
        };

        // Step 2: Restore runtime snapshot if present
        if let Some(ref mut rt) = runtime_snapshot {
            if let Err(rt_err) = rt.restore() {
                if vhosts_changed {
                    af_runner::reload_apache_after_rollback_if_live(fs_root).await;
                }
                if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after runtime restoration failure"
                            .to_string(),
                    );
                }
                return (Some(rt_err), restart_failures);
            }
        }

        if !blueprint_snapshots.is_empty() {
            if let Err(bp_err) =
                af_runner::package_lifecycle::restore_candidate_receipts(blueprint_snapshots)
            {
                if vhosts_changed {
                    af_runner::reload_apache_after_rollback_if_live(fs_root).await;
                }
                if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                    restart_failures.push(
                        "Refusing to restart pre-stopped service after receipt restoration failure"
                            .to_string(),
                    );
                }
                return (Some(bp_err), restart_failures);
            }
        }

        if vhosts_changed {
            af_runner::reload_apache_after_rollback_if_live(fs_root).await;
        }

        // Step 3: Restore candidate receipts
        if !receipt_snapshots.is_empty() {
            restore_candidate_receipts(receipt_snapshots).err()
        } else {
            None
        }
    };

    // Step 4: Restart restart_units AFTER restore_candidate_receipts completes
    if receipt_restore_error.is_some() {
        if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
            restart_failures.push(
                "Refusing to restart pre-stopped service after receipt restoration failure"
                    .to_string(),
            );
        }
        return (receipt_restore_error, restart_failures);
    }

    if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
        for unit in af_runner::af_release::lifecycle::ordered_units_for_start(restart_units) {
            if let Err(e) = control_unit(unit.clone(), "start").await {
                tracing::error!(unit = %unit, error = %e, "Application service restart failed after receipt restoration");
                restart_failures.push(format!("{unit}: {e}"));
            }
        }

        // Step 5: Verify restart_units active
        for unit in restart_units {
            let st = query_status(unit);
            if st != "running"
                && st != "idle"
                && !restart_failures.iter().any(|f| f.starts_with(unit))
            {
                restart_failures.push(format!("{unit} is {st}"));
            }
        }
    }

    (receipt_restore_error, restart_failures)
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_ext_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts(
        clean_id,
        quiesce_units,
        restart_units,
        receipt_snapshots,
        blueprint_snapshots,
        &[],
        None,
        refuse_restart,
        runtime_snapshot,
        runner_snapshot,
        control_unit,
        query_status,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
        clean_id,
        quiesce_units,
        restart_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_with<ControlFn, ControlFut, StatusFn>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    quiesce_and_restore_candidate_receipts_and_runtime_with(
        clean_id,
        quiesce_units,
        restart_units,
        receipt_snapshots,
        refuse_restart,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
pub(in crate::routes) static CANDIDATE_QUIESCE_RECORDER: std::sync::Mutex<Option<Vec<String>>> =
    std::sync::Mutex::new(None);

#[allow(clippy::too_many_arguments)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_with_vhosts(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    vhost_backups: &[af_runner::VhostBackup],
    fs_root: Option<&Path>,
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
) -> (Option<String>, Vec<String>) {
    let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
    let mut quiesce_units = stopped_units.to_vec();
    for u in all_controllable {
        if !quiesce_units.contains(&u) {
            quiesce_units.push(u);
        }
    }
    af_runner::af_release::lifecycle::sort_units_for_stop(&mut quiesce_units);
    let restart_units: Vec<String> = stopped_units
        .iter()
        .filter(|u| is_restart_eligible_unit(u))
        .cloned()
        .collect();
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts(
        clean_id,
        &quiesce_units,
        &restart_units,
        receipt_snapshots,
        blueprint_snapshots,
        vhost_backups,
        fs_root,
        refuse_restart,
        runtime_snapshot,
        runner_snapshot,
        |unit, ctl_action| async move {
            #[cfg(test)]
            {
                if let Ok(mut lock) = CANDIDATE_QUIESCE_RECORDER.lock() {
                    if let Some(ref mut vec) = *lock {
                        vec.push(format!("{ctl_action} {unit}"));
                    }
                }
            }
            if std::env::var("AETHERFLOW_FS_ROOT")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return Ok(());
            }
            af_services::control_service_with_manager(&unit, ctl_action, "systemd-unit").await
        },
        |unit| {
            if std::env::var("AETHERFLOW_FS_ROOT")
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                return "running".to_string();
            }
            af_services::get_systemd_unit_info(unit).0
        },
    )
    .await
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_ext(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
) -> (Option<String>, Vec<String>) {
    quiesce_and_restore_candidate_receipts_and_runtime_with_vhosts(
        clean_id,
        stopped_units,
        receipt_snapshots,
        blueprint_snapshots,
        &[],
        None,
        refuse_restart,
        runtime_snapshot,
        runner_snapshot,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
) -> (Option<String>, Vec<String>) {
    quiesce_and_restore_candidate_receipts_and_runtime_ext(
        clean_id,
        stopped_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn quiesce_and_restore_candidate_receipts(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
) -> (Option<String>, Vec<String>) {
    quiesce_and_restore_candidate_receipts_and_runtime(
        clean_id,
        stopped_units,
        receipt_snapshots,
        refuse_restart,
        None,
    )
    .await
}

pub(crate) fn should_rollback_post_certification_failure(
    action: &str,
    kind: af_services::PackageJobFailure,
) -> bool {
    matches!(action, "install" | "reinstall" | "update")
        && matches!(
            kind,
            af_services::PackageJobFailure::Configuration
                | af_services::PackageJobFailure::ServiceRestore
                | af_services::PackageJobFailure::ConfigurationAndServiceRestore
        )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_post_certification_finalization_failure_ext_with_vhosts<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    action: &str,
    mut required_err: PackageLifecycleFailure,
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    vhost_backups: &[af_runner::VhostBackup],
    fs_root: Option<&Path>,
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (PackageLifecycleFailure, Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    if should_rollback_post_certification_failure(action, required_err.kind) {
        let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
        let mut quiesce_units = stopped_units.to_vec();
        for u in all_controllable {
            if !quiesce_units.contains(&u) {
                quiesce_units.push(u);
            }
        }
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut quiesce_units);
        let restart_units: Vec<String> = stopped_units
            .iter()
            .filter(|u| is_restart_eligible_unit(u))
            .cloned()
            .collect();
        let (receipt_restore_error, restart_failures) =
            quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts(
                clean_id,
                &quiesce_units,
                &restart_units,
                receipt_snapshots,
                blueprint_snapshots,
                vhost_backups,
                fs_root,
                refuse_restart,
                runtime_snapshot,
                runner_snapshot,
                control_unit,
                query_status,
            )
            .await;
        if let Some(ref r_err) = receipt_restore_error {
            required_err
                .message
                .push_str(&format!("; receipt restoration error: {}", r_err));
        }
        if !restart_failures.is_empty() {
            required_err.message.push_str(&format!(
                "; post-restoration restart failures: {}",
                restart_failures.join("; ")
            ));
        }
        if required_err.kind == af_services::PackageJobFailure::Configuration
            && (receipt_restore_error.is_some() || !restart_failures.is_empty())
        {
            required_err.kind = af_services::PackageJobFailure::ConfigurationAndServiceRestore;
        }
        (required_err, receipt_restore_error, restart_failures)
    } else {
        (required_err, None, Vec::new())
    }
}

#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) async fn handle_post_certification_finalization_failure_ext_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    action: &str,
    required_err: PackageLifecycleFailure,
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    blueprint_snapshots: &[af_runner::package_lifecycle::FileSnapshot],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    runner_snapshot: Option<&mut RunnerLifecycleSnapshotHandle>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (PackageLifecycleFailure, Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    handle_post_certification_finalization_failure_ext_with_vhosts(
        action,
        required_err,
        clean_id,
        stopped_units,
        receipt_snapshots,
        blueprint_snapshots,
        &[],
        None,
        refuse_restart,
        runtime_snapshot,
        runner_snapshot,
        control_unit,
        query_status,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) async fn handle_post_certification_finalization_failure_with<
    ControlFn,
    ControlFut,
    StatusFn,
>(
    action: &str,
    required_err: PackageLifecycleFailure,
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
    control_unit: ControlFn,
    query_status: StatusFn,
) -> (PackageLifecycleFailure, Option<String>, Vec<String>)
where
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    StatusFn: Fn(&str) -> String,
{
    handle_post_certification_finalization_failure_ext_with(
        action,
        required_err,
        clean_id,
        stopped_units,
        receipt_snapshots,
        &[],
        refuse_restart,
        runtime_snapshot,
        None,
        control_unit,
        query_status,
    )
    .await
}

#[cfg(test)]
mod vhost_rollback_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn non_runner_rollback_restores_vhosts_and_refuses_restart_on_vhost_restore_error() {
        let root = std::env::temp_dir().join(format!("af-api-vhost-rb-{}", uuid::Uuid::new_v4()));
        let sites_avail = root.join("etc/apache2/sites-available");
        let sites_en = root.join("etc/apache2/sites-enabled");
        std::fs::create_dir_all(&sites_avail).unwrap();
        std::fs::create_dir_all(&sites_en).unwrap();

        let app_avail = sites_avail.join("aetherflow-app-sonarr.conf");
        let app_en = sites_en.join("aetherflow-app-sonarr.conf");
        let ext_avail = sites_avail.join("aetherflow-ext-sonarr.conf");
        let ext_en = sites_en.join("aetherflow-ext-sonarr.conf");

        std::fs::write(&app_avail, b"ProxyPass / http://127.0.0.1:18989/\n").unwrap();
        std::fs::write(&ext_avail, b"ProxyPass / http://127.0.0.1:18989/\n").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("../sites-available/aetherflow-app-sonarr.conf", &app_en)
                .unwrap();
            std::os::unix::fs::symlink("../sites-available/aetherflow-ext-sonarr.conf", &ext_en)
                .unwrap();
        }

        let vhost_backups = af_runner::snapshot_app_vhost_backups("sonarr", Some(&root)).unwrap();

        // Mutate vhosts: rewrite app_avail, delete ext_avail and ext_en symlink
        std::fs::write(&app_avail, b"ProxyPass / http://127.0.0.1:28989/\n").unwrap();
        std::fs::remove_file(&ext_avail).unwrap();
        #[cfg(unix)]
        std::fs::remove_file(&ext_en).unwrap();

        let actions = Arc::new(Mutex::new(Vec::<String>::new()));
        let actions_ref = Arc::clone(&actions);
        let units = vec!["sonarr".to_string()];
        let (restore_err, restart_failures) =
            quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts(
                "sonarr",
                &units,
                &units,
                &[],
                &[],
                &vhost_backups,
                Some(&root),
                false,
                None,
                None,
                move |unit, act| {
                    let rec = Arc::clone(&actions_ref);
                    async move {
                        rec.lock().unwrap().push(format!("{act} {unit}"));
                        Ok(())
                    }
                },
                |_| "running".to_string(),
            )
            .await;

        assert!(restore_err.is_none(), "unexpected error: {:?}", restore_err);
        assert!(
            restart_failures.is_empty(),
            "unexpected restart failures: {:?}",
            restart_failures
        );
        assert_eq!(
            std::fs::read_to_string(&app_avail).unwrap(),
            "ProxyPass / http://127.0.0.1:18989/\n"
        );
        assert_eq!(
            std::fs::read_to_string(&ext_avail).unwrap(),
            "ProxyPass / http://127.0.0.1:18989/\n"
        );
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(&ext_en).unwrap(),
                PathBuf::from("../sites-available/aetherflow-ext-sonarr.conf")
            );
        }
        assert_eq!(
            *actions.lock().unwrap(),
            vec!["stop sonarr".to_string(), "start sonarr".to_string()]
        );

        // Error case: replacing sites-available file with a symlink causes restore_app_vhost_backups
        // to fail and must refuse to restart pre-stopped units.
        #[cfg(unix)]
        {
            std::fs::remove_file(&app_avail).unwrap();
            let decoy = root.join("decoy.conf");
            std::fs::write(&decoy, b"decoy\n").unwrap();
            std::os::unix::fs::symlink(&decoy, &app_avail).unwrap();

            actions.lock().unwrap().clear();
            let actions_err_ref = Arc::clone(&actions);
            let (err_res, err_restarts) =
                quiesce_and_restore_candidate_receipts_and_runtime_ext_with_vhosts(
                    "sonarr",
                    &units,
                    &units,
                    &[],
                    &[],
                    &vhost_backups,
                    Some(&root),
                    false,
                    None,
                    None,
                    move |unit, act| {
                        let rec = Arc::clone(&actions_err_ref);
                        async move {
                            rec.lock().unwrap().push(format!("{act} {unit}"));
                            Ok(())
                        }
                    },
                    |_| "running".to_string(),
                )
                .await;

            assert!(
                err_res.is_some(),
                "expected vhost restore error when sites-available target is a symlink"
            );
            assert!(
                err_restarts
                    .iter()
                    .any(|msg| msg.contains("Refusing to restart pre-stopped service")),
                "expected restart refusal on vhost restore failure, got: {:?}",
                err_restarts
            );
            assert_eq!(
                *actions.lock().unwrap(),
                vec!["stop sonarr".to_string()],
                "must NOT start sonarr after vhost restore failure"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}
