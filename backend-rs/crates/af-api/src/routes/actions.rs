use super::marketplace::system_update_lifecycle_block;
use super::services::{
    is_valid_core_restart_job_unit, reconcile_pending_action, validate_service_control_request,
    ServiceControlReq,
};
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Extension, Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use std::collections::HashMap;

pub(super) async fn reconcile_queued_actions_for_list() -> HashMap<i64, (String, Option<String>)> {
    let mut transient_overlays = HashMap::new();
    let Ok(queued) = af_db::list_queued_actions_with_receipts(100) else {
        return transient_overlays;
    };
    for action in queued {
        let id = action.id;
        let reconciled = reconcile_pending_action(action).await;
        if reconciled.status == "unavailable" {
            if let Ok(Some(persisted)) = af_db::get_pending_action_by_id(id) {
                if persisted.status == "queued" {
                    transient_overlays.insert(id, (reconciled.status, reconciled.execution_log));
                }
            }
        }
    }
    transient_overlays
}

pub(super) async fn list_pending_actions(Query(q): Query<HashMap<String, String>>) -> Response {
    let status_filter = q
        .get("status")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("pending");

    if !matches!(
        status_filter,
        "pending"
            | "approved"
            | "queued"
            | "approved_history"
            | "rejected"
            | "executed"
            | "failed"
            | "unavailable"
            | "all"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid status filter. Use: pending, approved, queued, approved_history, rejected, executed, failed, unavailable, all",
        );
    }

    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&l| l > 0)
        .unwrap_or(100)
        .min(500);
    let offset = q
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
        .min(i64::MAX as usize);

    let transient_overlays = if !matches!(status_filter, "pending" | "rejected") {
        reconcile_queued_actions_for_list().await
    } else {
        HashMap::new()
    };

    let (mut actions, total) =
        match af_db::query_pending_actions(status_filter, limit as i64, offset as i64) {
            Ok(result) => result,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Could not load pending actions",
                )
            }
        };
    if !transient_overlays.is_empty() {
        for action in &mut actions {
            if let Some((status, log)) = transient_overlays.get(&action.id) {
                action.status = status.clone();
                if log.is_some() {
                    action.execution_log = log.clone();
                }
            }
        }
    }
    let count = actions.len();
    Json(serde_json::json!({
        "actions": actions,
        "filter": status_filter,
        "count": count,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

pub(super) fn parse_action_gate_service_command(raw_action: &str) -> Result<(String, String, String), String> {
    let trimmed = raw_action.trim();
    if trimmed.is_empty() {
        return Err("Action payload is empty".into());
    }
    let lower = trimmed.to_ascii_lowercase();
    for (prefix, act) in [
        ("restart_service:", "restart"),
        ("start_service:", "start"),
        ("stop_service:", "stop"),
        ("service_restart:", "restart"),
        ("service_start:", "start"),
        ("service_stop:", "stop"),
        ("restart:", "restart"),
        ("start:", "start"),
        ("stop:", "stop"),
    ] {
        if lower.starts_with(prefix) {
            let rest = trimmed[prefix.len()..].trim();
            if rest.is_empty() {
                return Err("Missing target service name".into());
            }
            if let Some((svc, mgr)) = rest.split_once(':') {
                let svc = svc.trim();
                let mgr = mgr.trim();
                if svc.is_empty() || svc.contains(':') || mgr.contains(':') {
                    return Err("Malformed service action target".into());
                }
                return Ok((svc.to_string(), act.to_string(), mgr.to_string()));
            }
            return Ok((rest.to_string(), act.to_string(), String::new()));
        }
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() == 2 {
        let verb = parts[0].to_ascii_lowercase();
        if matches!(verb.as_str(), "restart" | "start" | "stop") {
            return Ok((parts[1].to_string(), verb, String::new()));
        }
    }
    if parts.len() == 3 && parts[0].eq_ignore_ascii_case("systemctl") {
        let verb = parts[1].to_ascii_lowercase();
        if matches!(verb.as_str(), "restart" | "start" | "stop") {
            return Ok((parts[2].to_string(), verb, "systemd".to_string()));
        }
    }
    Err(format!(
        "Unsupported or non-executable gated action: {}",
        trimmed
    ))
}

pub(super) fn is_ambiguous_core_restart_dispatch_error(error: &anyhow::Error) -> bool {
    if af_runner::is_lifecycle_busy(error) {
        return false;
    }
    for cause in error.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::PermissionDenied
            ) {
                return false;
            }
        }
    }
    let msg = error.to_string();
    if msg.contains("Core restart already failed")
        || msg.contains("Could not schedule core restart: Ok(")
        || msg.contains("runner core restart error: Invalid")
        || msg.contains("disallowed")
    {
        return false;
    }
    true
}

pub(super) async fn already_resolved_conflict_response(existing: af_db::PendingAction) -> Response {
    let reconciled = reconcile_pending_action(existing).await;
    let message = match reconciled.status.as_str() {
        "queued" => match reconciled.job_unit.as_deref() {
            Some(unit) => format!(
                "Action already approved; deferred restart is queued (receipt: {unit}). Poll its receipt instead of retrying."
            ),
            None => "Action already approved; deferred restart is queued. Check its status instead of retrying.".into(),
        },
        "unavailable" => "Action already approved, but its deferred restart outcome is unavailable; inspect service state and logs instead of retrying.".into(),
        "approved" => "Action already approved without a confirmed execution outcome; inspect service state and logs instead of retrying.".into(),
        other => format!("Action already resolved: {other}"),
    };
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "code": "CONFLICT",
            "message": message,
            "status": reconciled.status,
            "job_unit": reconciled.job_unit,
            "action": reconciled,
        })),
    )
        .into_response()
}

pub(super) async fn approve_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let existing = match af_db::get_pending_action_by_id(id) {
        Ok(Some(existing)) => {
            if existing.status != "pending" {
                return already_resolved_conflict_response(existing).await;
            }
            existing
        }
        Ok(None) => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Action not found");
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query action",
            );
        }
    };

    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }

    let (svc_name, svc_act, managed_by) = match parse_action_gate_service_command(&existing.action)
    {
        Ok(parsed) => parsed,
        Err(msg) => return api_error(StatusCode::BAD_REQUEST, "UNSUPPORTED_ACTION", msg),
    };

    let validation_req = ServiceControlReq {
        action: svc_act.clone(),
        managed_by: managed_by.clone(),
        process: svc_name.clone(),
    };
    let validation_name = svc_name.clone();
    let target = match tokio::task::spawn_blocking(move || {
        validate_service_control_request(&validation_name, &validation_req)
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

    let mut action = match af_db::resolve_action(id, "approved", &auth_user.username) {
        Ok(action) => action,
        Err(_) => match af_db::get_pending_action_by_id(id) {
            Ok(Some(current)) => return already_resolved_conflict_response(current).await,
            Ok(None) => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Action not found"),
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to query action",
                );
            }
        },
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let manager = managed_by.trim();
    let deferred = svc_act == "restart"
        && matches!(
            target.trim_end_matches(".service"),
            "aetherflow-api" | "aetherflow-runner"
        );

    if deferred {
        match af_runner::dispatch_core_restart(&target).await {
            Ok(job_unit) if is_valid_core_restart_job_unit(&job_unit) => {
                let log_msg = format!(
                    "Deferred restart queued for '{}' by {} (receipt: {}); awaiting durable receipt confirmation.",
                    target, auth_user.username, job_unit
                );
                let queued_action = match af_db::mark_action_queued(id, &job_unit, &log_msg) {
                    Ok(updated) => updated,
                    Err(err) => {
                        tracing::error!(
                            action_id = id,
                            %job_unit,
                            error = %err,
                            "Deferred core restart was scheduled, but persisting its receipt on pending_actions failed"
                        );
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({
                                "code": "RESTART_RECEIPT_PERSISTENCE_FAILED",
                                "message": "Deferred restart was scheduled, but saving its receipt failed; poll the receipt and inspect service logs instead of retrying.",
                                "job_unit": job_unit,
                                "action": action,
                            })),
                        )
                            .into_response();
                    }
                };
                af_services::mutators::clear_app_runtime_meta_cache();
                af_db::record_audit(
                    auth_user.user_id,
                    &auth_user.username,
                    "action_approve",
                    "action_gate",
                    &id.to_string(),
                    &format!("{} (receipt: {})", queued_action.action, job_unit),
                    &ip,
                    ua,
                );
                return (
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({
                        "status": "queued",
                        "message": "Action approved; deferred restart queued. Poll its receipt before checking readiness.",
                        "job_unit": job_unit,
                        "action": queued_action,
                    })),
                )
                    .into_response();
            }
            Ok(invalid_unit) => {
                let err_msg = format!(
                    "Deferred restart for '{}' returned an invalid receipt identity ('{}'); check service state and logs before retrying.",
                    target, invalid_unit
                );
                let updated = af_db::mark_action_unavailable(id, None, &err_msg)
                    .ok()
                    .flatten()
                    .unwrap_or(action);
                af_db::record_audit(
                    auth_user.user_id,
                    &auth_user.username,
                    "action_approve_failed",
                    "action_gate",
                    &id.to_string(),
                    &existing.action,
                    &ip,
                    ua,
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "code": "RESTART_RECEIPT_UNAVAILABLE",
                        "message": "Deferred restart was accepted without a valid receipt identity; check service state and logs before retrying.",
                        "status": updated.status,
                        "action": updated,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                if af_runner::is_lifecycle_busy(&e) {
                    let err_msg = format!(
                        "Deferred restart for '{}' was not started because another lifecycle operation is active.",
                        target
                    );
                    af_db::mark_action_failed(id, &err_msg);
                    af_db::record_audit(
                        auth_user.user_id,
                        &auth_user.username,
                        "action_approve_failed",
                        "action_gate",
                        &id.to_string(),
                        &existing.action,
                        &ip,
                        ua,
                    );
                    return api_error(
                        StatusCode::CONFLICT,
                        "LIFECYCLE_BUSY",
                        af_runner::LifecycleBusy.to_string(),
                    );
                }
                if is_ambiguous_core_restart_dispatch_error(&e) {
                    let err_msg = format!(
                        "Deferred restart dispatch for '{}' could not be confirmed with a durable receipt; check service state and logs before retrying.",
                        target
                    );
                    let updated = af_db::mark_action_unavailable(id, None, &err_msg)
                        .ok()
                        .flatten()
                        .unwrap_or(action);
                    af_db::record_audit(
                        auth_user.user_id,
                        &auth_user.username,
                        "action_approve_failed",
                        "action_gate",
                        &id.to_string(),
                        &existing.action,
                        &ip,
                        ua,
                    );
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({
                            "code": "RESTART_RECEIPT_UNAVAILABLE",
                            "message": "Deferred restart outcome could not be confirmed with a durable receipt; inspect service state and logs instead of retrying.",
                            "status": updated.status,
                            "action": updated,
                        })),
                    )
                        .into_response();
                }
                let err_msg = format!("Failed to {} service '{}': {}", svc_act, target, e);
                af_db::mark_action_failed(id, &err_msg);
                af_db::record_audit(
                    auth_user.user_id,
                    &auth_user.username,
                    "action_approve_failed",
                    "action_gate",
                    &id.to_string(),
                    &existing.action,
                    &ip,
                    ua,
                );
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "ACTION_EXECUTION_FAILED",
                    "Approved service action failed to execute; check service diagnostics.",
                );
            }
        }
    }

    let exec_res = if manager.is_empty() {
        af_services::control_service(&target, &svc_act).await
    } else {
        af_services::control_service_with_manager(&target, &svc_act, manager).await
    };

    match exec_res {
        Ok(()) => {
            let log_msg = format!(
                "Service '{}' {} executed successfully by {}",
                target, svc_act, auth_user.username
            );
            af_db::mark_action_executed(id, &log_msg);
            af_services::mutators::clear_app_runtime_meta_cache();
        }
        Err(e) => {
            let err_msg = format!("Failed to {} service '{}': {}", svc_act, target, e);
            af_db::mark_action_failed(id, &err_msg);
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                "action_approve_failed",
                "action_gate",
                &id.to_string(),
                &existing.action,
                &ip,
                ua,
            );
            if af_runner::is_lifecycle_busy(&e) {
                return api_error(
                    StatusCode::CONFLICT,
                    "LIFECYCLE_BUSY",
                    af_runner::LifecycleBusy.to_string(),
                );
            }
            return api_error(
                StatusCode::BAD_GATEWAY,
                "ACTION_EXECUTION_FAILED",
                "Approved service action failed to execute; check service diagnostics.",
            );
        }
    }

    if let Ok(Some(updated)) = af_db::get_pending_action_by_id(id) {
        action = updated;
    }

    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "action_approve",
        "action_gate",
        &id.to_string(),
        &action.action,
        &ip,
        ua,
    );
    Json(serde_json::json!({
        "status": "executed",
        "message": "Action approved and executed successfully.",
        "action": action,
    }))
    .into_response()
}

pub(super) async fn reject_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let action = match af_db::resolve_action(id, "rejected", &auth_user.username) {
        Ok(action) => action,
        Err(error) if error.to_string() == "Action not found or already resolved" => {
            return api_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Action not found or already resolved",
            );
        }
        Err(error) => {
            tracing::warn!(action_id = id, %error, "Failed to reject pending action");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not reject pending action",
            );
        }
    };
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "action_reject",
        "action_gate",
        &id.to_string(),
        &action.action,
        &ip,
        ua,
    );
    Json(serde_json::json!({
        "status": "rejected",
        "message": "Action rejected",
        "action": action,
    }))
    .into_response()
}
