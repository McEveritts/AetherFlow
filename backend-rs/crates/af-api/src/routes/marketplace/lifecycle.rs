use crate::ws::broadcast_ws_message;
use af_models::AppIngressConfig;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use std::env;
use std::path::PathBuf;

/// Appends diagnostic lines to the active job record if present.
pub(crate) fn append_package_job_output(job_id: &str, line: &str) {
    let sanitized_line = af_services::redact_secrets(line);
    if let Ok(snapshot) = af_services::package_job_snapshot() {
        for (_pkg_id, info) in snapshot.active {
            if info.job_id == job_id {
                let mut updated = info.clone();
                if !updated.last_line.is_empty() {
                    updated.last_line.push_str("; ");
                }
                updated.last_line.push_str(&sanitized_line);
                let _ = af_services::set_package_job_info(updated);
                break;
            }
        }
    }
}

pub(in crate::routes) fn is_lock_file_present(lock_file: &str, fs_root_override: Option<&str>) -> bool {
    af_models::inspect_canonical_package_receipt(
        "",
        Some(lock_file),
        fs_root_override
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(std::path::Path::new),
    )
    .unwrap_or(false)
}

pub(in crate::routes) fn verified_prior_state_recovery(
    action: &str,
    prior_installed: bool,
    recovery_eligible: bool,
    receipt_restore_error: Option<&str>,
    post_restore_failures: &[String],
    lock_file: &str,
    fs_root_override: Option<&str>,
) -> bool {
    matches!(action, "reinstall" | "update" | "install")
        && prior_installed
        && recovery_eligible
        && receipt_restore_error.is_none()
        && post_restore_failures.is_empty()
        && is_lock_file_present(lock_file, fs_root_override)
}

/// Ends a lifecycle job: records the terminal outcome (so polling clients can
/// distinguish failure from success) and broadcasts the terminal event.
#[allow(clippy::too_many_arguments)]
pub(in crate::routes) fn finish_package_lifecycle(
    pkg_id: &str,
    action: &str,
    failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
) {
    finish_package_lifecycle_with_recovery(
        pkg_id,
        action,
        failure,
        progress,
        message,
        started_at,
        job_id,
        expected_target_version,
        achieved_version,
        stopped_units,
        false,
    );
}

/// Ends a lifecycle job with optional verified prior-state recovery confirmation
/// for failed in-place operations. Any inactive pre-stopped service forces
/// `prior_state_recovered` back to `false` (fail-closed).
#[allow(clippy::too_many_arguments)]
pub(in crate::routes) fn finish_package_lifecycle_with_recovery(
    pkg_id: &str,
    action: &str,
    failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
    prior_state_recovered: bool,
) {
    finish_package_lifecycle_with_recovery_and_retention(
        pkg_id,
        action,
        failure,
        progress,
        message,
        started_at,
        job_id,
        expected_target_version,
        achieved_version,
        stopped_units,
        prior_state_recovered,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
pub(in crate::routes) fn finish_package_lifecycle_with_recovery_and_retention(
    pkg_id: &str,
    action: &str,
    mut failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
    expected_target_version: Option<&str>,
    achieved_version: Option<&str>,
    stopped_units: &[String],
    mut prior_state_recovered: bool,
    retention_state: Option<&str>,
) {
    let mut message_buf = message.to_string();

    if !stopped_units.is_empty() {
        let mut inactive_units = Vec::new();
        for unit in stopped_units {
            let (status, _, _) = af_services::get_systemd_unit_info(unit);
            if status != "running" && status != "idle" {
                inactive_units.push(format!("{unit} ({status})"));
            }
        }
        if !inactive_units.is_empty() {
            prior_state_recovered = false;
            let inactive_diagnostic = format!(
                "Application stopped services failed to resume: {}",
                inactive_units.join(", ")
            );
            append_package_job_output(job_id, &inactive_diagnostic);
            if failure.is_none() {
                failure = Some(af_services::PackageJobFailure::ServiceRestore);
                message_buf = format!(
                    "Application completed but stopped services failed to resume: {}",
                    inactive_units.join(", ")
                );
            } else {
                if !message_buf.is_empty() {
                    message_buf.push_str("; ");
                }
                message_buf.push_str(&inactive_diagnostic);
            }
        }
    }

    let sanitized_msg = af_services::redact_secrets(&message_buf);
    let message = sanitized_msg.as_str();
    let succeeded = failure.is_none();
    let recovery_state = if !succeeded
        && prior_state_recovered
        && matches!(action, "reinstall" | "update" | "install")
    {
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED.to_string())
    } else {
        None
    };
    let (failed_stage, exit_code, sanitized_summary) = if !succeeded {
        if failure == Some(af_services::PackageJobFailure::TargetVerification) {
            (
                Some("target_certification_after_install_commit".to_string()),
                Some(1),
                Some(af_services::sanitize_diagnostic_summary(message, 280)),
            )
        } else {
            let (st, ec, su) = af_services::parse_diagnostic_markers(message);
            (
                st.or_else(|| failure.as_ref().map(|f| f.category().to_string())),
                ec,
                su.or_else(|| {
                    if !message.trim().is_empty() {
                        Some(af_services::sanitize_diagnostic_summary(message, 280))
                    } else {
                        None
                    }
                }),
            )
        }
    } else {
        (None, None, None)
    };

    let outcome = af_services::finish_package_job_with_recovery_and_retention(
        pkg_id,
        action,
        succeeded,
        failure,
        job_id,
        failed_stage,
        exit_code,
        sanitized_summary,
        expected_target_version.map(|s| s.to_string()),
        achieved_version.map(|s| s.to_string()),
        recovery_state,
        retention_state.map(|s| s.to_string()),
    );
    let Some(outcome) = outcome else {
        return;
    };

    let mut ws_payload = serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": outcome.status,
        "progress": if succeeded { 100 } else { progress.min(95) },
        "line": message,
        "started_at": started_at,
        "job_id": outcome.job_id,
        "finished_at": outcome.finished_at,
    });
    if let Some(target) = expected_target_version {
        ws_payload["expected_target_version"] = serde_json::json!(target);
    }
    if let Some(achieved) = achieved_version {
        ws_payload["achieved_version"] = serde_json::json!(achieved);
    }
    broadcast_ws_message(&ws_payload);
}

pub(in crate::routes) struct SystemUpdateLifecycleBlock {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    error_id: Option<String>,
}

impl std::fmt::Display for SystemUpdateLifecycleBlock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl IntoResponse for SystemUpdateLifecycleBlock {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "code": self.code, "message": self.message, "error_id": self.error_id,
            })),
        )
            .into_response()
    }
}

/// Discover authoritative runner receipts; do not rely on API process memory.
pub(in crate::routes) async fn system_update_lifecycle_block_with<QueryFn, QueryFut>(
    query_status: QueryFn,
) -> Option<SystemUpdateLifecycleBlock>
where
    QueryFn: FnOnce() -> QueryFut,
    QueryFut: std::future::Future<Output = anyhow::Result<af_models::SelfUpdateJobStatus>>,
{
    match query_status().await {
        Ok(status) if status.completed && matches!(status.status.as_str(), "succeeded" | "failed") && (status.job_unit.is_empty() || status.validate_invariants(None).is_ok()) => None,
        Ok(_) => Some(SystemUpdateLifecycleBlock {
            status: StatusCode::CONFLICT,
            code: "SYSTEM_UPDATE_IN_PROGRESS",
            message: "An AetherFlow system update is in progress or requires recovery; retry after it completes",
            error_id: None,
        }),
        Err(error) => {
            let error_id = uuid::Uuid::new_v4().to_string();
            tracing::error!(%error_id, detail = %format!("{error:#}"), "system update observation failed");
            Some(SystemUpdateLifecycleBlock {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "STATUS_UNAVAILABLE",
                message: "AetherFlow system update status is unavailable; retry after it can be verified",
                error_id: Some(error_id),
            })
        },
    }
}

pub(in crate::routes) async fn system_update_lifecycle_block() -> Option<SystemUpdateLifecycleBlock> {
    system_update_lifecycle_block_with(|| async {
        af_runner::dispatch_self_update_status_request(&af_models::SelfUpdateStatusRequest {
            job_unit: String::new(),
        })
        .await
    })
    .await
}

fn load_reserved_ports_for_api(app_name: &str) -> anyhow::Result<std::collections::BTreeSet<i32>> {
    let mut reserved = af_db::get_reserved_ports_excluding(app_name)?;
    let fs_root = env::var("AETHERFLOW_FS_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    reserved.extend(af_runner::rclone_extra_reserved_ports(
        app_name,
        fs_root.as_deref(),
    ));
    Ok(reserved)
}

#[cfg(test)]
pub(in crate::routes) fn allocate_or_resolve_app_port(app_name: &str, default_port: i32) -> i32 {
    allocate_or_resolve_app_port_with(
        app_name,
        default_port,
        load_authoritative_app_ingress_config,
        load_reserved_ports_for_api,
    )
}

pub(in crate::routes) fn allocate_or_resolve_app_port_for_job(
    app_name: &str,
    default_port: i32,
    job_id: &str,
    action: &str,
    fs_root: Option<&std::path::Path>,
) -> i32 {
    let Ok(mut conn) = af_db::get_conn() else {
        return 0;
    };
    let extra_reserved = af_runner::rclone_extra_reserved_ports(app_name, fs_root);
    af_db::reserve_lifecycle_port_in_tx(&mut conn, app_name, job_id, Some(action), |tx, base| {
        let mut reserved = base.clone();
        reserved.extend(extra_reserved.iter().copied());
        if app_name.eq_ignore_ascii_case("rclone") {
            if let Some(sec) = af_db::load_lifecycle_secondary_port(
                tx,
                "rclone",
                af_models::RCLONE_RC_API_PORT_ROLE,
            )? {
                reserved.insert(sec);
            }
        }
        let port = allocate_or_resolve_app_port_with(
            app_name,
            default_port,
            |app| af_db::load_lifecycle_ingress(tx, app),
            |_| Ok(reserved.clone()),
        );
        Ok((port > 0).then_some(port))
    })
    .ok()
    .flatten()
    .unwrap_or(0)
}

pub(in crate::routes) fn reserve_api_lifecycle_ports(
    app_name: &str,
    job_id: &str,
    action: &str,
    resolved_port: i32,
    fs_root: Option<&std::path::Path>,
) -> Result<(), String> {
    if action == "remove" {
        return Ok(());
    }
    let mut conn = af_db::get_conn().map_err(|e| e.to_string())?;
    let extra_reserved = af_runner::rclone_extra_reserved_ports(app_name, fs_root);
    if (1024..=65535).contains(&resolved_port) {
        af_db::reserve_lifecycle_port_in_tx(
            &mut conn,
            app_name,
            job_id,
            Some(action),
            |_, reserved| {
                anyhow::ensure!(
                    !reserved.contains(&resolved_port) && !extra_reserved.contains(&resolved_port),
                    "Listen port {resolved_port} is already reserved by another application"
                );
                Ok(Some(resolved_port))
            },
        )
        .map_err(|e| e.to_string())?;
    }
    if app_name.eq_ignore_ascii_case("rclone") {
        let _ = af_db::reserve_lifecycle_port_in_tx(
            &mut conn,
            "rclone",
            job_id,
            Some(action),
            |tx, reserved| {
                let secondary = af_db::load_lifecycle_secondary_port(
                    tx,
                    "rclone",
                    af_models::RCLONE_RC_API_PORT_ROLE,
                )?
                .or_else(|| {
                    af_runner::extract_rclone_runtime_api_port_for_root(fs_root).map(i32::from)
                })
                .filter(|&p| {
                    (1..=65535).contains(&p) && p != resolved_port && !reserved.contains(&p)
                });
                Ok(secondary)
            },
        );
    }
    Ok(())
}

pub(in crate::routes) fn allocate_or_resolve_app_port_with<LoadExistingFn, LoadReservedFn>(
    app_name: &str,
    default_port: i32,
    mut load_existing: LoadExistingFn,
    mut load_reserved: LoadReservedFn,
) -> i32
where
    LoadExistingFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    LoadReservedFn: FnMut(&str) -> anyhow::Result<std::collections::BTreeSet<i32>>,
{
    match load_existing(app_name) {
        Ok(Some(existing)) if existing.listen_port > 0 => return existing.listen_port,
        Ok(_) => {}
        Err(_) => return 0,
    }
    let Ok(reserved) = load_reserved(app_name) else {
        return 0;
    };
    let bp = af_services::get_blueprint(app_name);
    let candidate = bp.as_ref().map(|b| b.default_port).unwrap_or(default_port);
    if !(1024..=65535).contains(&candidate) {
        return 0;
    }
    if !reserved.contains(&candidate)
        && std::net::TcpListener::bind(("127.0.0.1", candidate as u16)).is_ok()
    {
        return candidate;
    }
    // These applications do not expose a configurable native listen port.
    if matches!(app_name, "plex" | "calibreweb") {
        return 0;
    }
    let [start, end] = bp
        .as_ref()
        .map(|b| b.fallback_port_range)
        .filter(|[start, end]| (1024..=65535).contains(start) && (*start..=65535).contains(end))
        .unwrap_or(af_models::MARKETPLACE_FALLBACK_PORT_RANGE);
    for port in start..=end {
        if !reserved.contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok()
        {
            return port;
        }
    }
    0
}

pub(in crate::routes) fn emit_package_progress(
    pkg_id: &str,
    action: &str,
    status: &str,
    progress: i32,
    line: &str,
    started_at: &str,
    job_id: &str,
) {
    let target = af_services::get_package_job_info(pkg_id).and_then(|j| j.expected_target_version);
    let sanitized_line = af_services::redact_secrets(line);
    let info = af_services::PackageJobInfo {
        job_id: job_id.to_string(),
        package_id: pkg_id.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        progress,
        last_line: sanitized_line.clone(),
        started_at: started_at.to_string(),
        expected_target_version: target.clone(),
    };
    let Some(info) = af_services::set_package_job_info(info) else {
        return;
    };
    let progress = info.progress;
    let mut payload = serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": status,
        "job_id": job_id,
        "progress": progress,
        "line": sanitized_line,
        "started_at": started_at,
    });
    if let Some(target_ver) = target {
        payload["expected_target_version"] = serde_json::json!(target_ver);
    }
    broadcast_ws_message(&payload);
}

pub(in crate::routes) fn is_oneshot_service_unit(unit: &str) -> bool {
    let lower = unit
        .trim()
        .trim_end_matches(".service")
        .to_ascii_lowercase();
    matches!(lower.as_str(), "recyclarr" | "scrutiny-collector")
}

pub(in crate::routes) fn is_restart_eligible_unit(unit: &str) -> bool {
    !is_oneshot_service_unit(unit)
}

pub(in crate::routes) async fn pre_stop_units_for_package_update_with<
    ResolveFn,
    StatusFn,
    ControlFn,
    ControlFut,
>(
    action: &str,
    clean_id: &str,
    fs_root_override: &str,
    mut resolve_units: ResolveFn,
    mut query_status: StatusFn,
    mut control_unit: ControlFn,
) -> Result<Vec<String>, (String, String)>
where
    ResolveFn: FnMut(&str) -> Vec<String>,
    StatusFn: FnMut(&str) -> String,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut stopped_units: Vec<String> = Vec::new();
    let is_reinstall = action == "reinstall"
        || (action == "install" && af_services::is_package_installed(clean_id));
    if (action == "update" || is_reinstall)
        && af_services::should_pre_stop_on_update(clean_id)
        && fs_root_override.trim().is_empty()
    {
        let mut units = resolve_units(clean_id);
        let mut seen = std::collections::HashSet::new();
        units.retain(|unit| seen.insert(unit.clone()));
        af_runner::af_release::lifecycle::sort_units_for_stop(&mut units);
        let mut running_units = Vec::new();
        for unit_name in units {
            let is_oneshot = is_oneshot_service_unit(&unit_name);
            match query_status(&unit_name).as_str() {
                "running" => running_units.push(unit_name),
                "restarting" if is_oneshot => running_units.push(unit_name),
                "stopped" | "failed" | "idle" | "not-found" => {}
                observation => {
                    return Err((
                        unit_name,
                        format!(
                            "Required service state is unconfirmed ({observation}); update was not started"
                        ),
                    ))
                }
            }
        }
        for unit_name in running_units {
            if is_restart_eligible_unit(&unit_name) {
                stopped_units.push(unit_name.clone());
            }
            if let Err(error) = control_unit(unit_name.clone(), "stop").await {
                let mut errors = vec![error.to_string()];
                for stopped_unit in
                    af_runner::af_release::lifecycle::ordered_units_for_start(&stopped_units)
                {
                    if let Err(restore_error) = control_unit(stopped_unit.clone(), "start").await {
                        errors.push(format!(
                            "Required restoration of {stopped_unit} failed: {restore_error}"
                        ));
                    }
                }
                return Err((unit_name, errors.join("; ")));
            }
        }
    }
    Ok(stopped_units)
}

pub(in crate::routes) fn load_authoritative_app_ingress_config(
    app_name: &str,
) -> anyhow::Result<Option<AppIngressConfig>> {
    af_db::invalidate_ingress_cache();
    let conn = af_db::get_read_conn()?;
    af_db::load_lifecycle_ingress(&conn, app_name)
}

pub(in crate::routes) fn resolve_existing_update_port_with<LoadIngressFn>(
    pkg_id: &str,
    mut load_ingress_config: LoadIngressFn,
) -> Result<i32, String>
where
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
{
    let mut canonical_app = pkg_id
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(".service")
        .to_string();
    if canonical_app == "af-maintainerr" {
        canonical_app = "maintainerr".to_string();
    }
    if let Some(blueprint) = af_services::get_blueprint(&canonical_app) {
        if blueprint.default_port <= 0 {
            return Ok(0);
        }
        if !blueprint.app_name.is_empty() {
            canonical_app = blueprint.app_name;
        }
    }

    let existing_config = load_ingress_config(&canonical_app).map_err(|error| {
        format!(
            "cannot read existing configured port for {}: {}",
            canonical_app, error
        )
    })?;
    let Some(existing_config) = existing_config else {
        return Err(format!(
            "missing persisted ingress port mapping for {} update",
            canonical_app
        ));
    };
    if !(1024..=65535).contains(&existing_config.listen_port) {
        return Err(format!(
            "invalid persisted listen port {} for {} update",
            existing_config.listen_port, canonical_app
        ));
    }
    Ok(existing_config.listen_port)
}

pub(in crate::routes) fn resolve_package_lifecycle_port_with<
    RuntimePortFn,
    LoadIngressFn,
    AllocateInstallPortFn,
>(
    action: &str,
    clean_id: &str,
    pkg_default_port: i32,
    mut query_runtime_port: RuntimePortFn,
    mut load_ingress_config: LoadIngressFn,
    mut allocate_install_port: AllocateInstallPortFn,
) -> Result<i32, String>
where
    RuntimePortFn: FnMut(&str) -> i32,
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    AllocateInstallPortFn: FnMut(&str, i32) -> i32,
{
    if action == "update" {
        if !af_services::should_pre_stop_on_update(clean_id)
            && af_services::resolve_service_control_scope(clean_id) != "shared-vhost"
        {
            return resolve_existing_update_port_with(clean_id, load_ingress_config);
        }
        // Read native configuration before stopping the application. An update
        // must keep its port even while that port is owned by the old process.
        let configured_port = query_runtime_port(clean_id);
        let ingress = load_ingress_config(clean_id).map_err(|error| {
            format!("cannot read existing configured port for {clean_id}: {error}")
        })?;
        let ingress_port = ingress.map(|config| config.listen_port).unwrap_or(0);
        let resolved_port = if (1024..=65535).contains(&configured_port) {
            configured_port
        } else if (1024..=65535).contains(&ingress_port) {
            ingress_port
        } else if pkg_default_port <= 0 {
            0
        } else {
            return Err(format!(
                "existing configured port for {clean_id} update is unavailable"
            ));
        };
        Ok(resolved_port)
    } else if action == "install" || action == "reinstall" {
        if action == "reinstall" || af_services::is_package_installed(clean_id) {
            let configured_port = query_runtime_port(clean_id);
            if (1024..=65535).contains(&configured_port) {
                return Ok(configured_port);
            }
            if let Ok(Some(ingress)) = load_ingress_config(clean_id) {
                if (1024..=65535).contains(&ingress.listen_port) {
                    return Ok(ingress.listen_port);
                }
            }
            if let Ok(Some(receipt_port)) = af_services::package_receipt_port(clean_id) {
                if (1024..=65535).contains(&receipt_port)
                    && load_reserved_ports_for_api(clean_id)
                        .is_ok_and(|reserved| !reserved.contains(&receipt_port))
                {
                    return Ok(receipt_port);
                }
            }
        }
        let allocated_port = allocate_install_port(clean_id, pkg_default_port);
        if pkg_default_port > 0 && allocated_port <= 0 {
            return Err("No supported listen port is available for this application".to_string());
        }
        Ok(allocated_port)
    } else {
        Ok(pkg_default_port)
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::routes) async fn run_package_lifecycle_dispatch_gate_with<
    RuntimePortFn,
    LoadIngressFn,
    AllocateInstallPortFn,
    ResolveUnitsFn,
    StatusFn,
    ControlFn,
    ControlFut,
    DispatchFn,
    DispatchFut,
>(
    action: &str,
    clean_id: &str,
    pkg_default_port: i32,
    fs_root_override: &str,
    query_runtime_port: RuntimePortFn,
    load_ingress_config: LoadIngressFn,
    allocate_install_port: AllocateInstallPortFn,
    resolve_units: ResolveUnitsFn,
    query_status: StatusFn,
    control_unit: ControlFn,
    mut dispatch_package: DispatchFn,
) -> Result<(i32, Vec<String>, anyhow::Result<()>), String>
where
    RuntimePortFn: FnMut(&str) -> i32,
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    AllocateInstallPortFn: FnMut(&str, i32) -> i32,
    ResolveUnitsFn: FnMut(&str) -> Vec<String>,
    StatusFn: FnMut(&str) -> String,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    DispatchFn: FnMut(i32) -> DispatchFut,
    DispatchFut: std::future::Future<Output = anyhow::Result<()>>,
{
    let allocated_port = resolve_package_lifecycle_port_with(
        action,
        clean_id,
        pkg_default_port,
        query_runtime_port,
        load_ingress_config,
        allocate_install_port,
    )?;

    let stopped_units = pre_stop_units_for_package_update_with(
        action,
        clean_id,
        fs_root_override,
        resolve_units,
        query_status,
        control_unit,
    )
    .await
    .map_err(|(failed_unit, error_message)| {
        format!("Could not stop {}: {}", failed_unit, error_message)
    })?;

    let execution_result = dispatch_package(allocated_port).await;
    Ok((allocated_port, stopped_units, execution_result))
}

#[derive(Debug, Clone)]
pub(crate) struct PackageLifecycleFailure {
    pub(crate) kind: af_services::PackageJobFailure,
    pub(crate) message: String,
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    af_runner::af_release::lifecycle::versions_match_target(achieved, expected)
}

pub fn target_version_matches(expected: &str, achieved: &str) -> bool {
    versions_match_target(achieved, expected)
}
