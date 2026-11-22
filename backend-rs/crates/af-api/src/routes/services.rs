use super::marketplace::system_update_lifecycle_block;
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Extension, Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use std::collections::HashMap;

pub(super) async fn get_services(Extension(auth_user): Extension<AuthUser>) -> Response {
    let diagnostics_allowed = crate::ws::package_diagnostics_allowed(&auth_user);
    match read_service_inventory().await {
        Some(services) => {
            let mut services = serde_json::to_value(services).unwrap_or_default();
            if !diagnostics_allowed {
                crate::ws::sanitize_services_for_viewer(&mut services);
            }
            Json(services).into_response()
        }
        None => service_inventory_unavailable(),
    }
}

pub(crate) async fn read_service_inventory(
) -> Option<HashMap<String, af_services::ServiceStatusItem>> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(af_services::get_active_services),
    )
    .await
    .ok()?
    .ok()?
    .ok()
}

pub(crate) fn service_inventory_unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "STATUS_UNAVAILABLE",
        "Service status could not be confirmed; retry shortly",
    )
}

#[derive(Clone, Deserialize)]
pub(super) struct ServiceControlReq {
    pub(super) action: String,
    #[serde(default)]
    pub(super) managed_by: String,
    #[serde(default)]
    pub(super) process: String,
}

/// Validates a Services control request before any privileged command runs.
/// Returns the exact target to control, or an `(status, code, message)` error.
pub(super) fn validate_service_control_request(
    name: &str,
    req: &ServiceControlReq,
) -> Result<String, (StatusCode, &'static str, String)> {
    if !matches!(req.action.as_str(), "start" | "stop" | "restart") {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid action. Allowed: start, stop, restart".to_string(),
        ));
    }
    let manager = req.managed_by.trim();
    if manager == "embedded" {
        return Err((
            StatusCode::BAD_REQUEST,
            "EMBEDDED_SERVICE_CONTROL_UNSUPPORTED",
            format!(
                "{} is served by the AetherFlow API process and has no separate daemon to control",
                name
            ),
        ));
    }
    if !matches!(manager, "" | "systemd" | "systemd-unit" | "pm2") {
        return Err((
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!("Unsupported service manager {:?}", manager),
        ));
    }
    let shared_vhost_error = |target: &str| {
        (
            StatusCode::BAD_REQUEST,
            "SHARED_VHOST_CONTROL_UNSUPPORTED",
            format!(
                "{} is hosted as a shared Apache vhost; use the Apache2 Web Server card for daemon-wide controls",
                target
            ),
        )
    };
    if manager != "systemd-unit"
        && af_services::resolve_service_control_scope(name) == "shared-vhost"
    {
        return Err(shared_vhost_error(name));
    }
    // The card may only control its own service and catalog companion units;
    // this endpoint is not a generic root systemctl proxy.
    let target = af_services::authorize_service_control_target(name, &req.process, manager)
        .map_err(|message| (StatusCode::FORBIDDEN, "SERVICE_CONTROL_FORBIDDEN", message))?;
    if manager != "systemd-unit"
        && af_services::resolve_service_control_scope(&target) == "shared-vhost"
    {
        return Err(shared_vhost_error(&target));
    }
    // Lifecycle jobs stop, replace, and restart units themselves. A manual
    // control in the middle would race the installer (for example starting an
    // old binary during an atomic swap or undoing an update pre-stop).
    let jobs = af_services::package_job_snapshot().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Lifecycle status could not be confirmed; retry shortly".to_string(),
        )
    })?;
    for candidate in [name, target.as_str()] {
        if let Some(owner) = af_services::resolve_owning_package_id(candidate) {
            if let Some(job) = jobs.active.get(&owner) {
                return Err((
                    StatusCode::CONFLICT,
                    "PACKAGE_LIFECYCLE_IN_PROGRESS",
                    format!(
                        "{} is currently {}; service controls are unavailable until the operation finishes",
                        owner, job.status
                    ),
                ));
            }
        }
    }
    Ok(target)
}

pub(super) fn service_control_failure_response(error: &anyhow::Error, target: &str, action: &str) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    tracing::error!(error_id = %id, %target, %action, detail = %format!("{error:#}"), "service control failed");
    let (status, code, message) = if af_services::is_service_control_timeout(error) {
        (StatusCode::GATEWAY_TIMEOUT, "SERVICE_CONTROL_TIMEOUT", "Service control timed out; refresh status before retrying. The resulting service state is unconfirmed.")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "SERVICE_CONTROL_FAILED", "Service control failed; check service state and authorized diagnostics before retrying.")
    };
    (
        status,
        Json(serde_json::json!({"code":code,"message":message,"error_id":id})),
    )
        .into_response()
}

pub(super) async fn control_service_handler(
    Path(name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<ServiceControlReq>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }
    let validation_name = name.clone();
    let validation_request = req.clone();
    let target = match tokio::task::spawn_blocking(move || {
        validate_service_control_request(&validation_name, &validation_request)
    })
    .await
    {
        Ok(Ok(target)) => target,
        Ok(Err((status, code, message))) => return api_error(status, code, message),
        Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Service control status could not be confirmed",
            )
        }
    };
    let manager = req.managed_by.trim();

    let deferred = req.action == "restart"
        && matches!(
            target.trim_end_matches(".service"),
            "aetherflow-api" | "aetherflow-runner"
        );
    let mut restart_job_unit = None;
    let result = if deferred {
        af_runner::dispatch_core_restart(&target)
            .await
            .map(|unit| restart_job_unit = Some(unit))
    } else if manager.is_empty() {
        af_services::control_service(&target, &req.action).await
    } else {
        af_services::control_service_with_manager(&target, &req.action, manager).await
    };

    if let Err(e) = result {
        if af_runner::is_lifecycle_busy(&e) {
            return api_error(
                StatusCode::CONFLICT,
                "LIFECYCLE_BUSY",
                af_runner::LifecycleBusy.to_string(),
            );
        }
        return service_control_failure_response(&e, &target, &req.action);
    }

    af_services::mutators::clear_app_runtime_meta_cache();

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        &format!("service_{}", req.action),
        "service",
        &target,
        &req.managed_by,
        &ip,
        ua,
    );

    (if deferred { StatusCode::ACCEPTED } else { StatusCode::OK }, Json(serde_json::json!({
        "message": if deferred { "Restart scheduled; poll its receipt before checking readiness" } else { "Service control command executed successfully" },
        "status": if deferred { "accepted" } else { "completed" },
        "service": name,
        "action": req.action,
        "job_unit": restart_job_unit,
    }))).into_response()
}

pub(crate) fn is_valid_core_restart_job_unit(unit: &str) -> bool {
    let trimmed = unit.trim();
    !trimmed.is_empty()
        && trimmed == unit
        && trimmed.starts_with("aetherflow-self-update-restart-")
        && af_models::is_valid_self_update_job_unit_name(trimmed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CoreRestartReceiptOutcome {
    Working,
    Succeeded,
    Failed,
    Missing,
    Corrupt,
    TransientUnavailable,
}

pub(super) fn classify_core_restart_receipt(
    unit: &str,
    result: &anyhow::Result<af_models::SelfUpdateJobStatus>,
) -> CoreRestartReceiptOutcome {
    match result {
        Ok(status) => {
            if status.job_unit != status.job_unit.trim()
                || status.validate_invariants(Some(unit)).is_err()
            {
                return CoreRestartReceiptOutcome::Corrupt;
            }
            if status.completed && status.success && status.status == "succeeded" {
                CoreRestartReceiptOutcome::Succeeded
            } else if (status.completed && !status.success)
                || matches!(status.status.as_str(), "failed" | "recovery_required")
            {
                CoreRestartReceiptOutcome::Failed
            } else if !status.completed
                && matches!(
                    status.status.as_str(),
                    "initiated" | "queued" | "launching" | "running"
                )
            {
                CoreRestartReceiptOutcome::Working
            } else {
                CoreRestartReceiptOutcome::Corrupt
            }
        }
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("not found") || msg.contains("Not found") {
                CoreRestartReceiptOutcome::Missing
            } else if msg.contains("corrupt self-update status file")
                || msg.contains("contradictory self-update status")
                || msg.contains("invalid self-update job_unit")
            {
                CoreRestartReceiptOutcome::Corrupt
            } else {
                CoreRestartReceiptOutcome::TransientUnavailable
            }
        }
    }
}

pub(super) fn core_restart_outcome_log(unit: &str, outcome: &CoreRestartReceiptOutcome) -> Option<String> {
    match outcome {
        CoreRestartReceiptOutcome::Succeeded => Some(format!(
            "Deferred core restart confirmed via durable receipt '{unit}'."
        )),
        CoreRestartReceiptOutcome::Failed => Some(format!(
            "Deferred core restart failed per durable receipt '{unit}'; inspect service logs and readiness."
        )),
        CoreRestartReceiptOutcome::Missing => Some(format!(
            "Deferred core restart receipt '{unit}' was not found; check service state and logs before retrying."
        )),
        CoreRestartReceiptOutcome::Corrupt => Some(format!(
            "Deferred core restart receipt '{unit}' could not be verified; check service state and logs before retrying."
        )),
        CoreRestartReceiptOutcome::TransientUnavailable => Some(format!(
            "Deferred core restart receipt '{unit}' is currently unavailable; check service state and logs before retrying."
        )),
        CoreRestartReceiptOutcome::Working => None,
    }
}

pub(super) fn reconcile_core_restart_receipt_by_unit(unit: &str, outcome: &CoreRestartReceiptOutcome) {
    let final_status = match outcome {
        CoreRestartReceiptOutcome::Succeeded => Some("executed"),
        CoreRestartReceiptOutcome::Failed => Some("failed"),
        CoreRestartReceiptOutcome::Missing | CoreRestartReceiptOutcome::Corrupt => {
            Some("unavailable")
        }
        CoreRestartReceiptOutcome::Working | CoreRestartReceiptOutcome::TransientUnavailable => {
            None
        }
    };
    if let (Some(status), Some(log)) = (final_status, core_restart_outcome_log(unit, outcome)) {
        if let Err(err) = af_db::finalize_queued_action_by_job_unit(unit, status, &log) {
            tracing::warn!(%unit, %status, error = %err, "Failed to reconcile pending action for core restart receipt");
        }
    }
}

pub(crate) async fn reconcile_pending_action(
    mut action: af_db::PendingAction,
) -> af_db::PendingAction {
    if action.status != "queued" {
        return action;
    }
    let unit = action.job_unit.as_deref().map(str::trim).unwrap_or("");
    if !is_valid_core_restart_job_unit(unit) {
        let log = "Deferred core restart action is missing a valid receipt identity; check service state and logs before retrying.";
        if let Ok(Some(updated)) = af_db::mark_action_unavailable(action.id, None, log) {
            return updated;
        }
        action.status = "unavailable".into();
        action.execution_log = Some(log.into());
        return action;
    }

    let status_req = af_models::SelfUpdateStatusRequest {
        job_unit: unit.to_string(),
    };
    let result = af_runner::dispatch_self_update_status_request(&status_req).await;
    let outcome = classify_core_restart_receipt(unit, &result);
    match outcome {
        CoreRestartReceiptOutcome::Working => action,
        CoreRestartReceiptOutcome::TransientUnavailable => {
            action.status = "unavailable".into();
            action.execution_log = core_restart_outcome_log(unit, &outcome);
            action
        }
        CoreRestartReceiptOutcome::Succeeded
        | CoreRestartReceiptOutcome::Failed
        | CoreRestartReceiptOutcome::Missing
        | CoreRestartReceiptOutcome::Corrupt => {
            let final_status = match outcome {
                CoreRestartReceiptOutcome::Succeeded => "executed",
                CoreRestartReceiptOutcome::Failed => "failed",
                CoreRestartReceiptOutcome::Missing | CoreRestartReceiptOutcome::Corrupt => {
                    "unavailable"
                }
                CoreRestartReceiptOutcome::Working
                | CoreRestartReceiptOutcome::TransientUnavailable => unreachable!(),
            };
            let log = core_restart_outcome_log(unit, &outcome).unwrap_or_default();
            match af_db::finalize_queued_action_by_id(action.id, unit, final_status, &log) {
                Ok(Some(updated)) => updated,
                _ => {
                    action.status = final_status.into();
                    action.execution_log = Some(log);
                    action
                }
            }
        }
    }
}

pub(super) async fn get_core_restart_status(Query(query): Query<HashMap<String, String>>) -> Response {
    let unit = query.get("job_unit").map(String::as_str).unwrap_or("");
    if !is_valid_core_restart_job_unit(unit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RESTART_RECEIPT",
            "A valid core restart receipt is required",
        );
    }
    if query
        .get("action")
        .is_some_and(|expected| expected != "restart")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Update action does not match job identity",
        );
    }
    let status_req = af_models::SelfUpdateStatusRequest {
        job_unit: unit.to_string(),
    };
    let result = af_runner::dispatch_self_update_status_request(&status_req).await;
    let outcome = classify_core_restart_receipt(unit, &result);
    reconcile_core_restart_receipt_by_unit(unit, &outcome);
    crate::storage::render_self_update_status_response(unit, result)
}
