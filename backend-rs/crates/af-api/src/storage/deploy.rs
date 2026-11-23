use super::deploy_rollback::{
    finalize_failed_deploy_rollback, is_transmission_deploy_unit, snapshot_deploy_files,
    DeployStage,
};
use crate::auth::{api_error, AuthUser};
use axum::body::Body;
use axum::extract::{Path, Query};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::OptionalExtension;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::broadcast;

pub(super) static DEPLOY_STREAMS: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static DEPLOY_LAST_EVENT: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
#[cfg(test)]
pub static SSE_DEPLOY_TX: Lazy<Mutex<HashMap<String, broadcast::Sender<String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(super) struct DeploymentRegistration {
    app_name: String,
    sender: broadcast::Sender<String>,
}

#[allow(clippy::result_large_err)]
pub(super) fn register_deployment(app_name: &str) -> Result<DeploymentRegistration, Response> {
    let mut streams = DEPLOY_STREAMS.lock().map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INTERNAL_ERROR",
            "Deployment state unavailable",
        )
    })?;
    if streams.contains_key(app_name) {
        return Err(api_error(
            StatusCode::CONFLICT,
            "DEPLOYMENT_IN_PROGRESS",
            "A deployment for this application is already running",
        ));
    }
    let (sender, _) = broadcast::channel(64);
    streams.insert(app_name.to_string(), sender.clone());
    if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
        last.remove(app_name);
    }
    Ok(DeploymentRegistration {
        app_name: app_name.to_string(),
        sender,
    })
}

pub(crate) fn ensure_or_reuse_deploy_stream(app_name: &str) -> Option<broadcast::Sender<String>> {
    let mut streams = DEPLOY_STREAMS.lock().ok()?;
    let sender = if let Some(existing) = streams.get(app_name) {
        existing.clone()
    } else {
        let (sender, _) = broadcast::channel(64);
        streams.insert(app_name.to_string(), sender.clone());
        sender
    };
    Some(sender)
}

pub(crate) fn publish_deploy_json_event(
    app_name: &str,
    sender: &broadcast::Sender<String>,
    payload: &serde_json::Value,
) {
    let serialized = payload.to_string();
    if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
        last.insert(app_name.to_string(), serialized.clone());
    }
    if app_name == "mediaflow_engine" {
        af_services::publish_mediaflow_progress(payload);
    }
    let _ = sender.send(serialized);
}

pub(crate) fn release_deploy_stream_if_matching(
    app_name: &str,
    sender: &broadcast::Sender<String>,
) {
    if let Ok(mut streams) = DEPLOY_STREAMS.lock() {
        if streams
            .get(app_name)
            .is_some_and(|current| current.same_channel(sender))
        {
            streams.remove(app_name);
            if let Ok(mut last) = DEPLOY_LAST_EVENT.lock() {
                last.remove(app_name);
            }
        }
    }
}

pub(crate) fn is_terminal_deploy_event(msg: &str) -> bool {
    if msg.starts_with("[SUCCESS]") || msg.starts_with("[ROLLBACK]") || msg.starts_with("[ERROR]") {
        return true;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(msg) {
        if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
            return matches!(
                status.to_ascii_lowercase().as_str(),
                "complete"
                    | "completed"
                    | "failed"
                    | "error"
                    | "success"
                    | "done"
                    | "cancelled"
                    | "needs_rescan"
            );
        }
    }
    false
}

impl Drop for DeploymentRegistration {
    fn drop(&mut self) {
        release_deploy_stream_if_matching(&self.app_name, &self.sender);
    }
}

pub mod af_common {
    pub mod redact {
        pub fn redact_secrets(input: &str) -> String {
            af_services::redact_secrets(input)
        }
    }
}

pub(super) fn deployment_restart_status(result: anyhow::Result<()>) -> String {
    match result {
        Ok(()) => {
            "[SUCCESS] Deployment configuration applied and managed service restarted.".to_string()
        }
        Err(error) => {
            let sanitized = af_common::redact::redact_secrets(&format!("{error:#}"));
            format!(
                "[ERROR] Deployment configuration applied, but managed service restart failed: {}",
                sanitized
            )
        }
    }
}

#[allow(clippy::result_large_err)]
fn require_admin(auth_user: &AuthUser) -> Result<(), Response> {
    if auth_user.role != "admin" {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Admin access required",
        ));
    }
    Ok(())
}

pub(super) fn allocate_or_verify_deploy_port(bp: &af_services::AppBlueprint) -> i32 {
    if bp.default_port <= 0 {
        return 0;
    }
    if let Ok(Some(existing)) = af_db::get_app_ingress_config(&bp.app_name) {
        if (1..=65535).contains(&existing.listen_port) {
            return existing.listen_port;
        }
    }
    if !bp.supports_dynamic_port || bp.fallback_port_range == [0, 0] {
        return bp.default_port;
    }
    if (1..=65535).contains(&bp.default_port)
        && std::net::TcpListener::bind(("127.0.0.1", bp.default_port as u16)).is_ok()
    {
        return bp.default_port;
    }
    let start = bp.fallback_port_range[0].max(17000) as u16;
    let end = bp.fallback_port_range[1].max(19999) as u16;
    for candidate in start..=end {
        if std::net::TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate as i32;
        }
    }
    bp.default_port
}

pub(super) fn deployment_ingress_config(
    app_name: &str,
    listen_port: i32,
    existing: Option<af_models::AppIngressConfig>,
) -> af_models::AppIngressConfig {
    let mut config = existing.unwrap_or_else(|| af_models::AppIngressConfig {
        app_name: app_name.to_string(),
        ..Default::default()
    });
    config.listen_port = listen_port;
    config.updated_at = Utc::now();
    config
}

pub async fn handle_deploy_process(
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    Path(app_name): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&auth_user) {
        return resp;
    }
    if app_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Application string param omitted" })),
        )
            .into_response();
    }
    let Some(bp) = af_services::get_blueprint(&app_name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Application blueprint missing or unsupported: {}", app_name)
            })),
        )
            .into_response();
    };

    let registration = match register_deployment(&bp.app_name) {
        Ok(registration) => registration,
        Err(response) => return response,
    };
    let tx = registration.sender.clone();

    let bp_clone = bp.clone();
    tokio::spawn(async move {
        // Release the slot and both stream registrations on every exit,
        // including task cancellation or panic.
        let _registration = registration;
        let send_step = |msg: String| {
            let _ = tx.send(msg);
        };

        send_step("[STEP 0] Deployment sequence queued asynchronously.".to_string());
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let _lifecycle_guard = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        let prior_ingress = match af_db::get_app_ingress_config(&bp_clone.app_name) {
            Ok(cfg) => cfg,
            Err(err) => {
                let sanitized = af_common::redact::redact_secrets(&format!("{err:#}"));
                send_step(format!(
                    "[ERROR] Deployment aborted before mutation: failed to read prior ingress state: {sanitized}"
                ));
                cleanup_deploy_channel().await;
                return;
            }
        };
        let file_snapshots = snapshot_deploy_files(&bp_clone);

        let service_unit = if bp_clone.service_name.trim().is_empty() {
            bp_clone.app_name.clone()
        } else {
            bp_clone.service_name.clone()
        };
        let transmission_safe_lifecycle =
            is_transmission_deploy_unit(&bp_clone.app_name, &service_unit);

        let mut stage = DeployStage::BeforeHostMutation;
        let mut transmission_stopped = false;

        let configuration =
            af_services::mutators::with_blueprint_mutation(&bp_clone.app_name, async {
                send_step(format!(
                    "[STEP 1] Validating and synchronizing local DNS for {}...",
                    bp_clone.internal_domain
                ));
                if !bp_clone.internal_domain.trim().is_empty() {
                    af_services::mutators::sync_local_dns_domains(std::slice::from_ref(
                        &bp_clone.internal_domain,
                    ))
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "Local DNS synchronization failed for {}: {}",
                            bp_clone.internal_domain,
                            error
                        )
                    })?;
                }
                let target_port = allocate_or_verify_deploy_port(&bp_clone);
                if target_port > 0 {
                    if transmission_safe_lifecycle {
                        // Stop transmission-daemon BEFORE mutating settings.json so its SIGTERM
                        // exit handler flushes prior state first and never overwrites our changes!
                        send_step(format!(
                            "[STEP 2] Stopping {} prior to safe settings.json mutation...",
                            service_unit
                        ));
                        transmission_stopped =
                            af_services::control_service(&service_unit, "stop")
                                .await
                                .is_ok();
                    }
                    send_step(format!(
                        "[STEP 2] Applying blueprint configuration for {} on port {}...",
                        bp_clone.app_name, target_port
                    ));
                    stage = DeployStage::HostConfigMutated { target_port };
                    af_services::mutators::apply_blueprint_app_config(
                        &bp_clone.app_name,
                        target_port,
                    )
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("Blueprint configuration mutation failed: {}", error)
                    })?;
                    send_step(format!(
                        "[STEP 3] Persisting ingress routing configuration ({} -> 127.0.0.1:{})...",
                        bp_clone.internal_domain, target_port
                    ));
                    let existing =
                        af_db::get_app_ingress_config(&bp_clone.app_name).map_err(|error| {
                            anyhow::anyhow!("Failed to read ingress configuration: {}", error)
                        })?;
                    let ingress_cfg =
                        deployment_ingress_config(&bp_clone.app_name, target_port, existing);
                    af_db::set_app_ingress_config(&ingress_cfg).map_err(|error| {
                        anyhow::anyhow!("Failed to persist ingress configuration: {}", error)
                    })?;
                    stage = DeployStage::IngressPersisted { target_port };
                } else {
                    send_step(format!(
                        "[STEP 2] Portless service blueprint {} confirmed (port=0); skipping port mutation...",
                        bp_clone.app_name
                    ));
                    send_step(format!(
                        "[STEP 3] Skipping reverse-proxy port binding for portless service {}...",
                        bp_clone.app_name
                    ));
                }

                // Step 4: Start (for pre-stopped transmission-daemon) or Restart the managed service
                let lifecycle_action = if transmission_safe_lifecycle && target_port > 0 {
                    "start"
                } else {
                    "restart"
                };
                send_step(format!(
                    "[STEP 4] Executing '{}' on managed service {}...",
                    lifecycle_action, service_unit
                ));
                if let Err(restart_error) =
                    af_services::control_service(&service_unit, lifecycle_action).await
                {
                    return Err(anyhow::anyhow!(
                        "Managed service {} failed for {}: {}",
                        lifecycle_action,
                        service_unit,
                        restart_error
                    ));
                }
                Ok(())
            })
            .await;

        match configuration {
            Ok(()) => {
                send_step(deployment_restart_status(Ok(())));
            }
            Err(error) => {
                let rollback_report = finalize_failed_deploy_rollback(
                    &bp_clone,
                    &service_unit,
                    transmission_stopped,
                    stage,
                    prior_ingress.as_ref(),
                    &file_snapshots,
                )
                .await;
                let sanitized = af_common::redact::redact_secrets(&format!("{error:#}"));
                if rollback_report.fully_reverted {
                    if rollback_report.warnings.is_empty() {
                        send_step(format!(
                            "[ROLLBACK] Deployment configuration rejected and rolled back cleanly: {sanitized}"
                        ));
                    } else {
                        let warns =
                            af_common::redact::redact_secrets(&rollback_report.warnings.join("; "));
                        send_step(format!(
                            "[ROLLBACK] Deployment configuration rejected and rolled back ({warns}): {sanitized}"
                        ));
                    }
                } else {
                    let details = af_common::redact::redact_secrets(&rollback_report.summary());
                    tracing::error!(
                        app = %bp_clone.app_name,
                        rollback_details = %details,
                        "deploy rollback incomplete or failed"
                    );
                    send_step(format!(
                        "[ROLLBACK] Rollback INCOMPLETE after deployment failure ({sanitized}): {details}"
                    ));
                }
                send_step(format!(
                    "[ERROR] Deployment configuration rejected: {sanitized}"
                ));
            }
        }
        cleanup_deploy_channel().await;
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "Initiated deployment cycle",
            "target": bp.internal_domain,
            "streamTarget": format!("/api/v1/auth/deploy/stream?appName={}", bp.app_name),
        })),
    )
        .into_response()
}

async fn cleanup_deploy_channel() {
    // Give connected subscribers time to receive the terminal event. The
    // owning registration removes only its own channels when the task ends.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

pub(super) fn deploy_sse_session_still_authorized_for_peer_with_conn(
    conn: &rusqlite::Connection,
    auth_user: &AuthUser,
    peer: Option<&crate::auth::PeerPrincipal>,
    initial_revoked_after: Option<i64>,
) -> bool {
    if auth_user.plugin_id.is_some() || auth_user.role != "admin" {
        return false;
    }
    match crate::auth::table_exists(conn, "users") {
        Ok(false) => return peer.is_none(),
        Ok(true) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                "Failed to verify users table during deploy SSE authorization; failing closed"
            );
            return false;
        }
    }
    if let Some(principal) = peer {
        if principal.run_as_user_id != auth_user.user_id {
            return false;
        }
        let Ok(Some(live_grant)) =
            af_db::peers::get_active_peer_grant_for_link(conn, &principal.link_id)
        else {
            return false;
        };
        if live_grant.id != principal.grant_id
            || live_grant.run_as_user_id != principal.run_as_user_id
            || live_grant.access != principal.access
        {
            return false;
        }
    } else if !auth_user.jti.is_empty()
        && crate::auth::is_session_token_revoked_beyond_grace_with_conn(
            conn,
            &auth_user.jti,
            auth_user.user_id,
        )
    {
        return false;
    }
    let Ok(subj) = crate::auth::load_active_subject_for_request(conn, auth_user.user_id, peer)
    else {
        return false;
    };
    if subj.role != "admin" {
        return false;
    }
    if let Some(issued_ver) = initial_revoked_after {
        if subj.sessions_revoked_after > issued_ver {
            return false;
        }
    }
    true
}

fn deploy_sse_session_still_authorized(
    auth_user: &AuthUser,
    peer: Option<&crate::auth::PeerPrincipal>,
    initial_revoked_after: Option<i64>,
) -> bool {
    if auth_user.plugin_id.is_some() || auth_user.role != "admin" {
        return false;
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return false;
    };
    deploy_sse_session_still_authorized_for_peer_with_conn(
        &conn,
        auth_user,
        peer,
        initial_revoked_after,
    )
}

async fn deploy_sse_session_still_authorized_async(
    auth_user: &AuthUser,
    peer: Option<&crate::auth::PeerPrincipal>,
    initial_revoked_after: Option<i64>,
) -> bool {
    let cloned = auth_user.clone();
    let peer_cloned = peer.cloned();
    crate::auth::blocking_auth_work(move || {
        deploy_sse_session_still_authorized(&cloned, peer_cloned.as_ref(), initial_revoked_after)
    })
    .await
    .unwrap_or(false)
}

pub(super) fn load_mediaflow_initial_snapshot_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<Option<String>> {
    let proc_file: Option<String> = conn
        .query_row(
            "SELECT file_path FROM mediaflow_queue WHERE status = 'PROCESSING' ORDER BY updated_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(file) = proc_file {
        return Ok(Some(
            serde_json::json!({
                "status": "running",
                "file": file,
                "progress": 0,
                "message": "Transcode in progress",
            })
            .to_string(),
        ));
    }
    let approved_file: Option<String> = conn
        .query_row(
            "SELECT file_path FROM mediaflow_queue WHERE status = 'APPROVED' ORDER BY updated_at ASC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(approved_file.map(|file| {
        serde_json::json!({
            "status": "running",
            "file": file,
            "progress": 0,
            "message": "Transcode job queued",
        })
        .to_string()
    }))
}

fn build_sse_response(body: Body) -> Response {
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    h.insert("X-Accel-Buffering", HeaderValue::from_static("no"));
    resp
}

pub async fn handle_deploy_stream(
    axum::Extension(auth_user): axum::Extension<AuthUser>,
    peer: Option<axum::Extension<crate::auth::PeerPrincipal>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = require_admin(&auth_user) {
        return resp;
    }
    let peer_principal = peer.map(|axum::Extension(p)| p);
    let uid = auth_user.user_id;
    let peer_for_init = peer_principal.clone();
    let initial_revoked_after = crate::auth::blocking_auth_work(move || {
        af_db::get_read_conn()
            .ok()
            .and_then(|c| {
                crate::auth::load_active_subject_for_request(&c, uid, peer_for_init.as_ref()).ok()
            })
            .map(|s| s.sessions_revoked_after)
    })
    .await
    .ok()
    .flatten();
    if !deploy_sse_session_still_authorized_async(
        &auth_user,
        peer_principal.as_ref(),
        initial_revoked_after,
    )
    .await
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Administrative session is no longer active",
        );
    }
    let Some(app_name) = q.get("appName").filter(|s| !s.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "appName query parameter is required" })),
        )
            .into_response();
    };

    if app_name == "mediaflow_engine" {
        let mut rx = af_services::subscribe_mediaflow_progress();
        let cached_event = DEPLOY_LAST_EVENT
            .lock()
            .ok()
            .and_then(|map| map.get(app_name).cloned());
        let initial_snapshot = match cached_event {
            Some(ev) if !is_terminal_deploy_event(&ev) => ev,
            _ => {
                let db_snapshot =
                    tokio::task::spawn_blocking(|| -> anyhow::Result<Option<String>> {
                        let conn = af_db::get_read_conn()?;
                        Ok(load_mediaflow_initial_snapshot_conn(&conn)?)
                    })
                    .await;
                match db_snapshot {
                    Ok(Ok(Some(snapshot))) => snapshot,
                    Ok(Ok(None)) => serde_json::json!({
                        "status": "idle",
                        "progress": 0,
                        "message": "MediaFlow Engine idle",
                    })
                    .to_string(),
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "Failed to query MediaFlow queue status for deploy stream");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            "Failed to query MediaFlow queue status",
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "MediaFlow queue snapshot worker failed");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            "Failed to query MediaFlow queue status",
                        );
                    }
                }
            }
        };

        let stream = async_stream::stream! {
            let mut revalidate_tick = tokio::time::interval(std::time::Duration::from_secs(5));
            revalidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let _ = revalidate_tick.tick().await;
            let safe_init = af_common::redact::redact_secrets(&initial_snapshot);
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_init));
            loop {
                tokio::select! {
                    _ = revalidate_tick.tick() => {
                        if !deploy_sse_session_still_authorized_async(&auth_user, peer_principal.as_ref(), initial_revoked_after).await {
                            break;
                        }
                    }
                    recv_res = rx.recv() => {
                        match recv_res {
                            Ok(msg) => {
                                if !deploy_sse_session_still_authorized_async(&auth_user, peer_principal.as_ref(), initial_revoked_after).await {
                                    break;
                                }
                                let safe_msg = af_common::redact::redact_secrets(&msg);
                                yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
                                if is_terminal_deploy_event(&safe_msg) {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::debug!(skipped, "mediaflow progress stream lagged; continuing");
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        };

        return build_sse_response(Body::from_stream(stream));
    }

    let rx_opt = DEPLOY_STREAMS
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).map(|tx| tx.subscribe()));

    let Some(mut rx) = rx_opt else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": "No active deployment found for this application." }),
            ),
        )
            .into_response();
    };
    let initial_event = DEPLOY_LAST_EVENT
        .lock()
        .ok()
        .and_then(|map| map.get(app_name).cloned());

    let stream = async_stream::stream! {
        let mut revalidate_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        revalidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = revalidate_tick.tick().await;
        if let Some(first_msg) = initial_event {
            let safe_msg = af_common::redact::redact_secrets(&first_msg);
            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
            if is_terminal_deploy_event(&safe_msg) {
                return;
            }
        }
        loop {
            tokio::select! {
                _ = revalidate_tick.tick() => {
                    if !deploy_sse_session_still_authorized_async(&auth_user, peer_principal.as_ref(), initial_revoked_after).await {
                        break;
                    }
                }
                recv_res = rx.recv() => {
                    match recv_res {
                        Ok(msg) => {
                            if !deploy_sse_session_still_authorized_async(&auth_user, peer_principal.as_ref(), initial_revoked_after).await {
                                break;
                            }
                            let safe_msg = af_common::redact::redact_secrets(&msg);
                            yield Ok::<_, std::convert::Infallible>(format!("data: {}\n\n", safe_msg));
                            if is_terminal_deploy_event(&safe_msg) {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::debug!(skipped, "deploy stream lagged; continuing");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    };

    build_sse_response(Body::from_stream(stream))
}
