use super::lifecycle::{
    allocate_or_resolve_app_port_for_job, append_package_job_output, emit_package_progress,
    finish_package_lifecycle, finish_package_lifecycle_with_recovery,
    finish_package_lifecycle_with_recovery_and_retention, is_lock_file_present,
    load_authoritative_app_ingress_config, reserve_api_lifecycle_ports,
    run_package_lifecycle_dispatch_gate_with, system_update_lifecycle_block,
    verified_prior_state_recovery, versions_match_target,
};
use super::receipts::{snapshot_candidate_receipts, ReceiptSnapshotEntry};
use super::rollback::{
    finalize_post_script_lifecycle_with, handle_post_certification_finalization_failure_ext_with,
    is_incomplete_rollback_error, quiesce_and_restore_candidate_receipts_and_runtime_ext,
    should_rollback_post_certification_failure, RunnerLifecycleSnapshotHandle,
};
#[cfg(test)]
use super::rollback::CANDIDATE_QUIESCE_RECORDER;
use std::env;
use std::fs;
use std::path::PathBuf;

pub(in crate::routes) struct PackageLifecycleJobContext {
    pub(in crate::routes) job_lease: Option<af_runner::af_release::lifecycle::OwnerLease>,
    pub(in crate::routes) job_id: String,
    pub(in crate::routes) started_at: String,
    pub(in crate::routes) clean_id: String,
    pub(in crate::routes) action: &'static str,
    pub(in crate::routes) status_label: &'static str,
    pub(in crate::routes) delete_data: bool,
    pub(in crate::routes) expected_target_version: Option<String>,
    pub(in crate::routes) script_name: String,
    pub(in crate::routes) pkg_label: String,
    pub(in crate::routes) pkg_default_port: i32,
    pub(in crate::routes) pkg_lock_file: String,
}

pub(in crate::routes) fn spawn_package_lifecycle_job(ctx: PackageLifecycleJobContext) {
    let scope_job_id = ctx.job_id.clone();
    tokio::spawn(af_runner::PACKAGE_JOB_ID.scope(scope_job_id, run_package_lifecycle_job(ctx)));
}

async fn run_package_lifecycle_job(ctx: PackageLifecycleJobContext) {
    let PackageLifecycleJobContext {
        job_lease,
        job_id,
        started_at,
        clean_id,
        action,
        status_label,
        delete_data,
        expected_target_version,
        script_name,
        pkg_label,
        pkg_default_port,
        pkg_lock_file,
    } = ctx;
    let _job_lease = job_lease;
    let _lifecycle_guard = match af_services::PACKAGE_LIFECYCLE_MUTEX.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            emit_package_progress(
                &clean_id,
                action,
                status_label,
                5,
                &format!(
                    "Queued: waiting for another lifecycle operation to finish before {} {}...",
                    action, pkg_label
                ),
                &started_at,
                &job_id,
            );
            af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await
        }
    };
    let fs_root_override_raw = env::var("AETHERFLOW_FS_ROOT").unwrap_or_default();
    let fs_root_override =
        Option::from(fs_root_override_raw.clone()).filter(|root| !root.trim().is_empty());
    let prior_installed = is_lock_file_present(&pkg_lock_file, fs_root_override.as_deref());

    // Re-check under the lifecycle mutex: a system update may have been
    // launched while this job was queued (run_update holds this mutex
    // while launching, so the check cannot race with the launch).
    if let Some(message) = system_update_lifecycle_block().await {
        let prior_state_recovered = verified_prior_state_recovery(
            action,
            prior_installed,
            true,
            None,
            &[],
            &pkg_lock_file,
            fs_root_override.as_deref(),
        );
        finish_package_lifecycle_with_recovery(
            &clean_id,
            action,
            Some(af_services::PackageJobFailure::Preparation),
            5,
            &message.to_string(),
            &started_at,
            &job_id,
            expected_target_version.as_deref(),
            None,
            &[],
            prior_state_recovered,
        );
        return;
    }
    emit_package_progress(
        &clean_id,
        action,
        status_label,
        10,
        &format!("Preparing environment for {}...", pkg_label),
        &started_at,
        &job_id,
    );

    let can_run_bash =
        cfg!(unix) && fs_root_override.is_none() && std::path::Path::new("/bin/bash").exists();

    let expected_target_for_runner = expected_target_version.clone();
    #[allow(clippy::type_complexity)]
    let captured_receipt_snapshots: std::sync::Arc<
        std::sync::Mutex<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let snapshots_slot = captured_receipt_snapshots.clone();
    let captured_blueprint_snapshots: std::sync::Arc<
        std::sync::Mutex<Vec<af_runner::package_lifecycle::FileSnapshot>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let blueprint_snapshots_slot = captured_blueprint_snapshots.clone();
    let captured_runtime_snapshot: std::sync::Arc<
        std::sync::Mutex<Option<af_runner::package_lifecycle::PackageRuntimeSnapshot>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let runtime_snapshot_slot = captured_runtime_snapshot.clone();
    let captured_runner_snapshot: std::sync::Arc<
        std::sync::Mutex<Option<RunnerLifecycleSnapshotHandle>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(None));
    let runner_snapshot_slot = captured_runner_snapshot.clone();
    let pre_remove_rclone_api_port = if clean_id == "rclone"
        && action == "remove"
        && !delete_data
    {
        af_runner::extract_rclone_runtime_api_port_for_root(
            fs_root_override.as_deref().map(std::path::Path::new),
        )
        .map(i32::from)
    } else {
        None
    };
    let (allocated_port, stopped_units, execution_result) =
        match run_package_lifecycle_dispatch_gate_with(
            action,
            &clean_id,
            pkg_default_port,
            &fs_root_override_raw,
            |app_id| af_services::mutators::get_app_runtime_meta(app_id).configured_port,
            load_authoritative_app_ingress_config,
            |app_name, default_port| {
                allocate_or_resolve_app_port_for_job(
                    app_name,
                    default_port,
                    &job_id,
                    action,
                    fs_root_override.as_deref().map(std::path::Path::new),
                )
            },
            |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
            |unit_name| af_services::get_systemd_unit_info(unit_name).0,
            |unit_name, control_action| async move {
                af_services::control_service_with_manager(
                    &unit_name,
                    control_action,
                    "systemd-unit",
                )
                .await
            },
            |resolved_port| {
                let clean_id = clean_id.clone();
                let pkg_label = pkg_label.clone();
                let script_name = script_name.clone();
                let pkg_lock_file = pkg_lock_file.clone();
                let started_at = started_at.clone();
                let job_id = job_id.clone();
                let fs_root_override = fs_root_override.clone();
                let runner_target = expected_target_for_runner.clone();
                let snapshots_slot = snapshots_slot.clone();
                let blueprint_snapshots_slot = blueprint_snapshots_slot.clone();
                let runtime_snapshot_slot = runtime_snapshot_slot.clone();
                let runner_snapshot_slot = runner_snapshot_slot.clone();
                async move {
                    if let Err(err) = reserve_api_lifecycle_ports(
                        &clean_id,
                        &job_id,
                        action,
                        resolved_port,
                        fs_root_override.as_deref().map(std::path::Path::new),
                    ) {
                        return Err(anyhow::anyhow!("Preparation: {err}"));
                    }
                    if matches!(action, "install" | "reinstall" | "update") {
                        let mut capture_units =
                            af_services::resolve_controllable_service_units(&clean_id, "stop");
                        if let Ok(pkgs) = af_services::get_packages() {
                            if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_id) {
                                let svc = p.service_name.trim().to_string();
                                if !svc.is_empty()
                                    && !matches!(
                                        svc.as_str(),
                                        "apache2"
                                            | "nginx"
                                            | "apache2.service"
                                            | "nginx.service"
                                    )
                                    && !capture_units.contains(&svc)
                                {
                                    capture_units.push(svc);
                                }
                            }
                        }
                        let use_runner = can_run_bash && af_runner::is_runner_available();
                        if use_runner {
                            match af_runner::dispatch_package_lifecycle_snapshot_capture(
                                &clean_id,
                                &capture_units,
                            )
                            .await
                            {
                                Ok(()) => {
                                    *runner_snapshot_slot.lock().unwrap() =
                                        Some(RunnerLifecycleSnapshotHandle::new(
                                            clean_id.clone(),
                                            job_id.clone(),
                                        ));
                                }
                                Err(err) => {
                                    return Err(anyhow::anyhow!("Preparation: {err}"));
                                }
                            }
                        } else {
                            match snapshot_candidate_receipts(&clean_id) {
                                Ok(s) => *snapshots_slot.lock().unwrap() = s,
                                Err(err) => {
                                    return Err(anyhow::anyhow!("Preparation: {err}"));
                                }
                            }
                            let env_cfg = af_runner::PackageExecutionEnv {
                                fs_root: fs_root_override
                                    .as_ref()
                                    .map(|s| PathBuf::from(s.trim()))
                                    .or_else(|| af_runner::PackageExecutionEnv::default().fs_root),
                                ..af_runner::PackageExecutionEnv::default()
                            };
                            match af_runner::package_lifecycle::snapshot_blueprint_targets(
                                &clean_id,
                                &env_cfg,
                            ) {
                                Ok(bp_snaps) => {
                                    *blueprint_snapshots_slot.lock().unwrap() = bp_snaps;
                                }
                                Err(err) => {
                                    return Err(anyhow::anyhow!("Preparation: {err}"));
                                }
                            }
                            match af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
                                &clean_id,
                                &capture_units,
                                &env_cfg,
                                false,
                            ) {
                                Ok(rt_snap) => {
                                    *runtime_snapshot_slot.lock().unwrap() = Some(rt_snap);
                                }
                                Err(err) => {
                                    return Err(anyhow::anyhow!("Preparation: {err}"));
                                }
                            }
                        }
                    }
                    emit_package_progress(
                        &clean_id,
                        action,
                        status_label,
                        25,
                        &format!("Executing {} script for {}...", action, pkg_label),
                        &started_at,
                        &job_id,
                    );

                    if can_run_bash && af_runner::is_runner_available() {
                        af_runner::dispatch_package_action_with_target(
                            action,
                            &clean_id,
                            &script_name,
                            resolved_port,
                            delete_data,
                            runner_target,
                            |line| {
                                let (pct, msg) = af_runner::parse_progress_line(&line)
                                    .map(|(p, m)| (p as i32, m))
                                    .unwrap_or_else(|| (60, line));
                                let display_msg = if msg.is_empty() {
                                    format!("Running {} for {}...", action, pkg_label)
                                } else {
                                    msg
                                };
                                emit_package_progress(
                                    &clean_id,
                                    action,
                                    status_label,
                                    pct,
                                    &display_msg,
                                    &started_at,
                                    &job_id,
                                );
                            },
                        )
                        .await
                    } else if can_run_bash {
                        Err(anyhow::anyhow!(
                            "AetherFlow runner service is unavailable; refusing to execute privileged package operation in-process"
                        ))
                    } else {
                        emit_package_progress(
                            &clean_id,
                            action,
                            status_label,
                            60,
                            &format!("Applying package state changes for {}...", pkg_label),
                            &started_at,
                            &job_id,
                        );
                        if !pkg_lock_file.is_empty() {
                            let root_path = fs_root_override.as_deref().map(std::path::Path::new);
                            let lock_paths = af_models::resolve_package_lock_paths(
                                &clean_id,
                                Some(&pkg_lock_file),
                                root_path,
                            );
                            if action == "remove" {
                                let had_canonical = af_models::inspect_receipt_file(
                                    &lock_paths.canonical,
                                    root_path,
                                )
                                .unwrap_or(false);
                                let had_legacy = lock_paths.legacy_swizzin.as_ref().is_some_and(
                                    |legacy_path| {
                                        af_models::inspect_receipt_file(legacy_path, root_path)
                                            .unwrap_or(false)
                                    },
                                );
                                let had_retained = !lock_paths.retained.as_os_str().is_empty()
                                    && af_models::inspect_receipt_file(
                                        &lock_paths.retained,
                                        root_path,
                                    )
                                    .unwrap_or(false);
                                if !delete_data {
                                    if (had_canonical || had_legacy || had_retained)
                                        && !lock_paths.retained.as_os_str().is_empty()
                                    {
                                        if let Some(parent) = lock_paths.retained.parent() {
                                            let _ = fs::create_dir_all(parent);
                                        }
                                        let payload = af_models::format_retained_package_receipt(
                                            &clean_id,
                                            &chrono::Utc::now().to_rfc3339(),
                                        );
                                        let _ = fs::write(&lock_paths.retained, payload);
                                    }
                                } else if had_retained {
                                    let _ = fs::remove_file(&lock_paths.retained);
                                }
                                let _ = fs::remove_file(&lock_paths.canonical);
                                if had_legacy {
                                    if let Some(ref legacy_path) = lock_paths.legacy_swizzin {
                                        let _ = fs::remove_file(legacy_path);
                                    }
                                }
                            } else if fs_root_override.is_some() {
                                if let Some(parent) = lock_paths.canonical.parent() {
                                    let _ = fs::create_dir_all(parent);
                                }
                                let _ = fs::write(&lock_paths.canonical, b"installed\n");
                                if !lock_paths.retained.as_os_str().is_empty()
                                    && af_models::inspect_receipt_file(
                                        &lock_paths.retained,
                                        root_path,
                                    )
                                    .unwrap_or(false)
                                {
                                    let _ = fs::remove_file(&lock_paths.retained);
                                }
                                if let Some(ref legacy_path) = lock_paths.legacy_swizzin {
                                    if af_models::inspect_receipt_file(legacy_path, root_path)
                                        .unwrap_or(false)
                                    {
                                        let _ = fs::remove_file(legacy_path);
                                    }
                                }
                            }
                        }
                        Ok(())
                    }
                }
            },
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error_message) => {
                finish_package_lifecycle(
                    &clean_id,
                    action,
                    Some(af_services::PackageJobFailure::Preparation),
                    10,
                    &error_message,
                    &started_at,
                    &job_id,
                    expected_target_version.as_deref(),
                    None,
                    &[],
                );
                return;
            }
        };

    let receipt_snapshots = captured_receipt_snapshots.lock().unwrap().clone();
    let blueprint_snapshots = captured_blueprint_snapshots.lock().unwrap().clone();
    let mut runtime_snapshot = captured_runtime_snapshot.lock().unwrap().take();
    let mut runner_snapshot = captured_runner_snapshot.lock().unwrap().take();

    if let Err(error) = execution_result {
        af_services::mutators::clear_app_runtime_meta_cache();
        let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
        let err_str = error.to_string();
        let is_prep_err = err_str.starts_with("Preparation: ");
        let refuse_restart = is_incomplete_rollback_error(&err_str);
        let snapshot_captured =
            runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
        if refuse_restart {
            if let Some(ref mut snapshot) = runtime_snapshot {
                snapshot.preserve_on_drop = true;
            }
        }
        let (receipt_restore_error, restart_failures) =
            if matches!(action, "install" | "reinstall" | "update") {
                quiesce_and_restore_candidate_receipts_and_runtime_ext(
                    &clean_id,
                    &stopped_units,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    refuse_restart,
                    if refuse_restart {
                        None
                    } else {
                        runtime_snapshot.as_mut()
                    },
                    runner_snapshot.as_mut(),
                )
                .await
            } else {
                let mut restart_failures = Vec::new();
                if refuse_restart {
                    restart_failures.push("Refusing to restart pre-stopped service after incomplete rollback".to_string());
                } else if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
                    for unit in af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units) {
                        if let Err(e) = af_services::control_service_with_manager(&unit, "start", "systemd-unit").await {
                            restart_failures.push(format!("{unit}: {e}"));
                        }
                    }
                }
                (None, restart_failures)
            };

        let prior_state_recovered = verified_prior_state_recovery(
            action,
            prior_installed,
            !refuse_restart && (is_prep_err || snapshot_captured),
            receipt_restore_error.as_deref(),
            &restart_failures,
            &pkg_lock_file,
            fs_root_override.as_deref(),
        );

        let failure_kind = if is_prep_err {
            af_services::PackageJobFailure::Preparation
        } else if restart_failures.is_empty() {
            af_services::PackageJobFailure::Installer
        } else {
            af_services::PackageJobFailure::ServiceRestore
        };
        let clean_err = err_str.strip_prefix("Preparation: ").unwrap_or(&err_str);
        let mut failure_message = if restart_failures.is_empty() {
            clean_err.to_string()
        } else {
            format!("{clean_err}; {}", restart_failures.join("; "))
        };
        if let Some(ref r_err) = receipt_restore_error {
            tracing::error!(
                package = %clean_id,
                error = %r_err,
                "Failed to restore candidate receipts after script execution failure"
            );
            append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
            failure_message.push_str(&format!("; receipt restoration error: {}", r_err));
        }
        if let Some(ref mut rs) = runner_snapshot {
            rs.discard(false).await;
        }
        if runtime_snapshot.is_some() {
            let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
        }

        af_services::clear_service_status_cache();
        af_services::mutators::clear_app_runtime_meta_cache();
        finish_package_lifecycle_with_recovery(
            &clean_id,
            action,
            Some(failure_kind),
            60,
            &failure_message,
            &started_at,
            &job_id,
            expected_target_version.as_deref(),
            None,
            &stopped_units,
            prior_state_recovered,
        );
        return;
    }

    let mut achieved_ver: Option<String> = None;

    if matches!(action, "install" | "reinstall" | "update") {
        let mut restart_failures: Vec<String> = Vec::new();
        if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
            for unit in af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units) {
                if let Err(e) = af_services::control_service_with_manager(&unit, "start", "systemd-unit").await {
                    tracing::error!(unit, error = %e, "Application service restoration failed after script execution");
                    restart_failures.push(format!("{unit}: {e}"));
                }
            }
            for unit in &stopped_units {
                let (st, _, _) = af_services::get_systemd_unit_info(unit);
                if st != "running" && st != "idle"
                    && !restart_failures.iter().any(|f| f.starts_with(unit)) {
                        restart_failures.push(format!("{unit} is {st}"));
                    }
            }
        }

        if !restart_failures.is_empty() {
            let snapshot_captured =
                runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
            let (receipt_restore_error, post_restore_failures) =
                quiesce_and_restore_candidate_receipts_and_runtime_ext(
                    &clean_id,
                    &stopped_units,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    false,
                    runtime_snapshot.as_mut(),
                    runner_snapshot.as_mut(),
                )
                .await;
            let prior_state_recovered = verified_prior_state_recovery(
                action,
                prior_installed,
                snapshot_captured,
                receipt_restore_error.as_deref(),
                &post_restore_failures,
                &pkg_lock_file,
                fs_root_override.as_deref(),
            );
            if let Some(ref r_err) = receipt_restore_error {
                tracing::error!(
                    package = %clean_id,
                    error = %r_err,
                    "Failed to restore candidate receipts after service restart failure"
                );
                append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
            }
            for pf in post_restore_failures {
                if !restart_failures.contains(&pf) {
                    restart_failures.push(pf);
                }
            }

            let mut msg = format!(
                "Application service restart failed after execution: {}",
                restart_failures.join("; ")
            );
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }

            if let Some(ref mut rs) = runner_snapshot {
                rs.discard(false).await;
            }
            if runtime_snapshot.is_some() {
                let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            }

            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle_with_recovery(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::ServiceRestore),
                95,
                &msg,
                &started_at,
                &job_id,
                expected_target_version.as_deref(),
                achieved_ver.as_deref(),
                &stopped_units,
                prior_state_recovered,
            );
            return;
        }

        let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
        let pkgs = af_services::get_packages().unwrap_or_default();
        achieved_ver = if let Some(pkg) = pkgs.into_iter().find(|p| p.name == clean_id) {
            af_services::workers::probe_installed_package_version_strict(&pkg)
                .await
                .ok()
                .filter(|s| !s.trim().is_empty())
        } else {
            None
        };

        let target_match_failed = if action == "update" || expected_target_version.is_some() {
            let target = expected_target_version.as_deref().unwrap_or("");
            let matches_target = match achieved_ver.as_deref() {
                Some(achieved) if !achieved.trim().is_empty() => {
                    if !target.is_empty() {
                        versions_match_target(achieved, target)
                    } else {
                        true
                    }
                }
                _ => false,
            };
            !matches_target
        } else {
            false
        };

        if target_match_failed {
            let snapshot_captured =
                runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
            let (receipt_restore_error, post_restore_failures) =
                quiesce_and_restore_candidate_receipts_and_runtime_ext(
                    &clean_id,
                    &stopped_units,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    false,
                    runtime_snapshot.as_mut(),
                    runner_snapshot.as_mut(),
                )
                .await;
            let prior_state_recovered = verified_prior_state_recovery(
                action,
                prior_installed,
                snapshot_captured,
                receipt_restore_error.as_deref(),
                &post_restore_failures,
                &pkg_lock_file,
                fs_root_override.as_deref(),
            );
            if let Some(ref r_err) = receipt_restore_error {
                tracing::error!(
                    package = %clean_id,
                    error = %r_err,
                    "Failed to restore candidate receipts after target certification failure"
                );
                append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
            }

            let mut msg = format!(
                "Target certification failed after installer execution (runtime state may be partially committed): expected {}, achieved {}",
                expected_target_version.as_deref().unwrap_or(""),
                achieved_ver.as_deref().unwrap_or("none")
            );
            if !post_restore_failures.is_empty() {
                msg.push_str(&format!("; service restart after receipt restoration failed: {}", post_restore_failures.join("; ")));
            }
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }

            if let Some(ref mut rs) = runner_snapshot {
                rs.discard(false).await;
            }
            if runtime_snapshot.is_some() {
                let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            }

            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle_with_recovery(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::TargetVerification),
                95,
                &msg,
                &started_at,
                &job_id,
                expected_target_version.as_deref(),
                achieved_ver.as_deref(),
                &stopped_units,
                prior_state_recovered,
            );
            return;
        }

        emit_package_progress(
            &clean_id,
            action,
            status_label,
            85,
            &format!("Synchronizing blueprint & ingress for {}...", pkg_label),
            &started_at,
            &job_id,
        );

        let finalization = finalize_post_script_lifecycle_with(
            &stopped_units,
            af_services::mutators::apply_lifecycle_blueprint_app_config(&clean_id, allocated_port),
            |unit_name, ctrl_action| async move {
                af_services::control_service_with_manager(
                    &unit_name,
                    ctrl_action,
                    "systemd-unit",
                )
                .await
            },
            |unit| af_services::get_systemd_unit_info(unit).0,
            async {
                let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
                let pkgs = af_services::get_packages().unwrap_or_default();
                let version = if let Some(pkg) = pkgs.into_iter().find(|p| p.name == clean_id) {
                    af_services::workers::probe_installed_package_version_strict(&pkg)
                        .await
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                } else {
                    None
                };
                if !stopped_units.is_empty() {
                    af_services::clear_service_status_cache();
                }
                version
            },
            |cfg| {
                let secondary_update = (clean_id == "rclone").then(|| {
                    let fallback = fs_root_override.is_none().then(|| {
                        af_services::mutators::get_app_runtime_meta("rclone").secondary_port
                    });
                    af_runner::rclone_secondary_port_update_for_root(
                        fs_root_override.as_deref().map(std::path::Path::new),
                        cfg.listen_port,
                        fallback,
                    )
                }).flatten();
                af_db::set_app_ingress_and_secondary_port_for_lifecycle(
                    cfg,
                    secondary_update,
                    &job_id,
                    action,
                )
            },
        )
        .await;
        if let Err(required_err) = finalization {
            let snapshot_captured =
                runner_snapshot.as_ref().is_some_and(|rs| rs.active) || runtime_snapshot.is_some();
            let rollback_attempted =
                should_rollback_post_certification_failure(action, required_err.kind);
            let (required_err, receipt_restore_error, post_restore_failures) =
                handle_post_certification_finalization_failure_ext_with(
                    action,
                    required_err,
                    &clean_id,
                    &stopped_units,
                    &receipt_snapshots,
                    &blueprint_snapshots,
                    false,
                    runtime_snapshot.as_mut(),
                    runner_snapshot.as_mut(),
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
                .await;
            let prior_state_recovered = verified_prior_state_recovery(
                action,
                prior_installed,
                rollback_attempted && snapshot_captured,
                receipt_restore_error.as_deref(),
                &post_restore_failures,
                &pkg_lock_file,
                fs_root_override.as_deref(),
            );
            if let Some(r_err) = receipt_restore_error {
                tracing::error!(
                    package = %clean_id,
                    error = %r_err,
                    "Failed to restore candidate receipts after service restoration failure"
                );
                append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
            }
            if let Some(ref mut rs) = runner_snapshot {
                rs.discard(false).await;
            }
            if runtime_snapshot.is_some() {
                let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
            }

            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle_with_recovery(
                &clean_id,
                action,
                Some(required_err.kind),
                90,
                &required_err.message,
                &started_at,
                &job_id,
                expected_target_version.as_deref(),
                None,
                &stopped_units,
                prior_state_recovered,
            );
            return;
        }

        if achieved_ver.is_none() {
            achieved_ver = finalization.ok().flatten();
        }
        if achieved_ver.is_none() {
            if let Ok(conn) = af_db::get_conn() {
                if let Ok(ver) = conn.query_row(
                    "SELECT installed_version FROM app_updates WHERE package_name = ?1",
                    rusqlite::params![&clean_id],
                    |r| r.get::<_, String>(0),
                ) {
                    let trimmed = ver.trim();
                    if !trimmed.is_empty() {
                        achieved_ver = Some(trimmed.to_string());
                    }
                }
            }
        }
    } else if action == "remove" {
        let retained = af_db::get_conn().and_then(|mut conn| {
            let secondary_update = pre_remove_rclone_api_port
                .map(|p| (af_models::RCLONE_RC_API_PORT_ROLE, Some(p)));
            af_db::synchronize_lifecycle_ingress_with_secondary_port(
                &mut conn,
                &clean_id,
                action,
                &job_id,
                0,
                secondary_update,
                delete_data,
                "",
            )
        });
        if let Err(error) = retained {
            finish_package_lifecycle(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::Retention),
                90,
                &format!(
                    "Package removed but reinstall settings could not be retained: {}",
                    error
                ),
                &started_at,
                &job_id,
                None,
                None,
                &stopped_units,
            );
            return;
        }
        if let Err(dns_err) = af_services::mutators::sync_network_dns_providers().await {
            if let Some(ref mut rs) = runner_snapshot {
        rs.discard(false).await;
    }
    if runtime_snapshot.is_some() {
        let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
    }

    af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::Configuration),
                95,
                &format!(
                    "[STAGE:dns_cleanup] Package removed but local DNS reconciliation failed: {}",
                    dns_err
                ),
                &started_at,
                &job_id,
                None,
                None,
                &stopped_units,
            );
            return;
        }
    }

    if let Some(ref mut rs) = runner_snapshot {
        rs.discard(false).await;
    }
    if runtime_snapshot.is_some() {
        let _ = tokio::task::spawn_blocking(move || drop(runtime_snapshot)).await;
    }

    af_services::clear_service_status_cache();
    af_services::mutators::clear_app_runtime_meta_cache();

    finish_package_lifecycle_with_recovery_and_retention(
        &clean_id,
        action,
        None,
        100,
        &format!("Completed {} for {}", action, pkg_label),
        &started_at,
        &job_id,
        expected_target_version.as_deref(),
        achieved_ver.as_deref(),
        // Final service verification already ran before ingress persistence.
        &[],
        false,
        (action == "remove").then_some(if delete_data {
            af_runner::af_release::lifecycle::RETENTION_STATE_PURGED
        } else {
            af_runner::af_release::lifecycle::RETENTION_STATE_RETAINED
        }),
    );
}
