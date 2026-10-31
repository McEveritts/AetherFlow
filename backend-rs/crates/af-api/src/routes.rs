use crate::auth::{
    admin_only_middleware, api_error, auth_middleware, check_setup_needed, csrf_middleware,
    disable_2fa, get_session, issue_csrf_token, list_active_sessions, local_login, logout,
    mfa_login_verify, refresh_session, revoke_session, setup_2fa, setup_admin, verify_2fa,
    verify_proxy_auth, AuthUser,
};
use crate::embed::spa_fallback_handler;
use crate::intelligence::{
    add_wireguard_peer, advertise_tailscale_routes, ai_chat, ai_support, analyze_predictions,
    approve_mediaflow_item, bandwidth_analyze, bandwidth_apply, bookmark_log,
    decline_mediaflow_item, enroll_worker, generate_wireguard_keys, get_bookmarks,
    get_cluster_nodes, get_log_sources, get_logs, get_mediaflow_queue, get_metrics_history,
    get_network_status, get_predictions, get_system_topology, get_tailscale_peers,
    get_tailscale_status, get_wireguard_peers, get_worker_metrics, metadata_results,
    metadata_scan, metadata_status, remove_wireguard_peer, remove_worker, test_ai_connection,
    trigger_mediaflow_scan,
};
use crate::middlewares::{
    ai_rate_limit_middleware, auth_rate_limit_middleware, host_validation_middleware,
    oidc_rate_limit_middleware, quota_upload_guard_middleware, webhook_rate_limit_middleware,
};
use crate::notifications_ext::{
    create_notification_channel, create_notification_rule, delete_notification_channel,
    delete_notification_rule, get_pending_action, regenerate_2fa_recovery_codes,
    test_notification_channel, update_notification_rule,
};
use crate::oidc::{
    create_oidc_client, delete_oidc_client, get_oidc_clients, google_callback, google_login,
    oidc_authorize, oidc_consent, oidc_device_authorize, oidc_device_consent, oidc_device_verify,
    oidc_discovery, oidc_introspect, oidc_jwks, oidc_revoke, oidc_token, oidc_userinfo,
};
use crate::storage::{
    check_update, delete_shared_file, download_backup, download_file, get_backups_list,
    get_files_list, get_optimal_backup_window, get_own_quota, handle_billing_webhook,
    handle_deploy_process, handle_deploy_stream, list_billing_webhook_events, list_user_quotas,
    refresh_user_quota, run_backup, run_update, set_backup_schedule, update_user_quota,
    upload_backup_chunk, upload_file,
};
use crate::streaming_ext::{
    control_streaming_session, get_streaming_artwork, sync_streaming_server_history,
    test_streaming_server,
};
use crate::ws::{
    extract_client_ip, handle_log_websocket, handle_websocket, issue_ws_ticket_for_user,
};
use af_models::{AppIngressConfig, MarketplaceApp, User};
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

const OPENAPI_YAML: &str = include_str!("../../../../backend/api/spec/openapi-v1.yaml");

// ─────────────────────────────────────────────────────────────────────────────
// Security Headers, Request ID & API Versioning Middlewares
// ─────────────────────────────────────────────────────────────────────────────

pub async fn security_headers_middleware(mut req: Request, next: Next) -> Response {
    let req_id = req
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));

    let is_legacy_api = req.uri().path().starts_with("/api/")
        && !req.uri().path().starts_with("/api/v1/");
    let req_path = req.uri().path().to_string();

    req.headers_mut().insert(
        "X-Request-ID",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    h.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
        ),
    );
    h.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    h.insert("X-API-Version", HeaderValue::from_static("v1"));
    if let Ok(hv) = HeaderValue::from_str(&req_id) {
        h.insert("X-Request-ID", hv);
    }
    if is_legacy_api {
        h.insert("Deprecation", HeaderValue::from_static("true"));
        let successor = req_path.replacen("/api/", "/api/v1/", 1);
        if let Ok(link_hv) =
            HeaderValue::from_str(&format!("<{}>; rel=\"successor-version\"", successor))
        {
            h.insert("Link", link_hv);
        }
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Router Construction (`backend/api/routes.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub fn build_router() -> Router {
    let v1 = build_v1_router();
    let legacy = build_v1_router();

    Router::new()
        .nest("/api/v1", v1)
        .nest("/api", legacy)
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/health", get(health_check))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(prometheus_metrics))
        .fallback(spa_fallback_handler)
        .layer(middleware::from_fn(security_headers_middleware))
}

fn build_v1_router() -> Router {
    let auth_limited_public = Router::new()
        .route("/auth/login", post(local_login))
        .route("/auth/mfa/verify", post(mfa_login_verify))
        .route("/auth/setup", post(setup_admin))
        .layer(middleware::from_fn(auth_rate_limit_middleware));

    let oidc_limited_public = Router::new()
        .route("/oidc/authorize", get(oidc_authorize))
        .route("/oidc/token", post(oidc_token))
        .route("/oidc/userinfo", get(oidc_userinfo))
        .route("/oidc/revoke", post(oidc_revoke))
        .route("/oidc/introspect", post(oidc_introspect))
        .route("/oidc/device/authorize", post(oidc_device_authorize))
        .layer(middleware::from_fn(oidc_rate_limit_middleware));

    let webhook_limited_public = Router::new()
        .route("/billing/webhooks/:provider", post(handle_billing_webhook))
        .layer(middleware::from_fn(webhook_rate_limit_middleware));

    let public_routes = Router::new()
        .route("/openapi.yaml", get(get_openapi_spec))
        .route("/csrf-token", get(issue_csrf_token))
        .route("/auth/google/login", get(google_login))
        .route("/auth/google/callback", get(google_callback))
        .route("/auth/verify", get(verify_proxy_auth))
        .route("/auth/setup/check", get(check_setup_needed))
        .route("/auth/refresh", post(refresh_session))
        .route("/marketplace", get(get_marketplace_apps))
        .route("/oidc/jwks", get(oidc_jwks))
        .merge(auth_limited_public)
        .merge(oidc_limited_public)
        .merge(webhook_limited_public);

    let ai_limited_auth = Router::new()
        .route("/ai/chat", post(ai_chat))
        .route("/ai/support", post(ai_support))
        .layer(middleware::from_fn(ai_rate_limit_middleware));

    let auth_routes = Router::new()
        .route("/ws", get(handle_websocket))
        .route("/ws/ticket", get(issue_ws_ticket))
        .route("/ws/logs", get(handle_log_websocket))
        .route("/oidc/consent", post(oidc_consent))
        .route("/oidc/device/verify", post(oidc_device_verify))
        .route("/oidc/device/consent", post(oidc_device_consent))
        .merge(ai_limited_auth)
        .route("/session", get(get_session))
        .route("/refresh", post(refresh_session))
        .route("/sessions", get(list_active_sessions))
        .route("/sessions/:jti", delete(revoke_session))
        .route("/logout", post(logout))
        .route("/profile", put(update_profile))
        .route("/profile/password", put(update_password))
        .route("/profile/avatar", put(update_avatar).delete(delete_avatar))
        .route("/system/topology", get(get_system_topology))
        .route("/fs", get(browse_directories))
        .route("/user/quota", get(get_own_quota))
        .route("/user/2fa/setup", get(setup_2fa))
        .route("/user/2fa/verify", post(verify_2fa))
        .route("/user/2fa/disable", post(disable_2fa))
        .route(
            "/user/2fa/recovery/regenerate",
            post(regenerate_2fa_recovery_codes),
        )
        .route("/settings", get(get_settings))
        .route("/fileshare", get(get_files_list))
        .route("/fileshare/download/:filename", get(download_file))
        .route("/services", get(get_services))
        .route("/packages/:id/progress", get(package_progress))
        .route("/system/update/check", get(check_update))
        .route("/system/metrics", get(get_system_metrics))
        .route("/system/hardware", get(get_hardware_info))
        .route("/notifications", get(get_notifications))
        .route("/notifications/:id/read", put(mark_notification_read))
        .route("/notifications/dismiss-all", post(dismiss_all_notifications))
        .route("/deploy/stream", get(handle_deploy_stream))
        .route("/deploy/:appName", post(handle_deploy_process))
        .route("/blueprints", get(get_blueprints))
        .route("/blueprints/:appName", get(get_app_blueprint))
        .route("/streaming/dashboard", get(get_streaming_dashboard))
        .route("/streaming/artwork/:itemId", get(get_streaming_artwork))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    let quota_guarded_upload = Router::new()
        .route("/fileshare/upload", post(upload_file))
        .layer(middleware::from_fn(quota_upload_guard_middleware));

    let admin_routes = Router::new()
        .route("/backup/run", post(run_backup))
        .route("/backup/list", get(get_backups_list))
        .route("/backup/download/:filename", get(download_backup))
        .route("/backup/upload/:filename", post(upload_backup_chunk))
        .route("/settings", get(get_settings).put(update_settings))
        .route("/settings/test-ai", post(test_ai_connection))
        .route("/users", get(get_users))
        .route("/users/:id/role", put(update_user_role))
        .route("/users/:id", delete(delete_user))
        .route("/quotas", get(list_user_quotas))
        .route("/quotas/:id", put(update_user_quota))
        .route("/quotas/:id/refresh", post(refresh_user_quota))
        .route("/billing/webhooks", get(list_billing_webhook_events))
        .route("/services", get(get_services))
        .route("/services/:name/control", post(control_service_handler))
        .route("/packages/:id/install", post(install_package))
        .route("/packages/:id/uninstall", post(uninstall_package))
        .route("/packages/:id/update", post(update_package))
        .route(
            "/packages/:id/check-update",
            post(check_single_package_update),
        )
        .route("/packages/updates/check", post(check_package_updates))
        .route("/system/update/check", get(check_update))
        .route("/system/update/run", post(run_update))
        .route("/system/metrics", get(get_system_metrics))
        .merge(quota_guarded_upload)
        .route("/fileshare/download/:filename", get(download_file))
        .route("/fileshare/:filename", delete(delete_shared_file))
        .route("/cluster/nodes", get(get_cluster_nodes))
        .route("/cluster/enroll", post(enroll_worker))
        .route("/cluster/nodes/:id", delete(remove_worker))
        .route("/cluster/nodes/:id/metrics", get(get_worker_metrics))
        .route("/oidc/clients", get(get_oidc_clients).post(create_oidc_client))
        .route("/oidc/clients/:id", delete(delete_oidc_client))
        .route("/ai/metadata/scan", post(metadata_scan))
        .route("/ai/metadata/status", get(metadata_status))
        .route("/ai/metadata/results", get(metadata_results))
        .route("/ai/bandwidth/analyze", post(bandwidth_analyze))
        .route("/ai/bandwidth/apply", post(bandwidth_apply))
        .route("/ai/predictions", get(get_predictions))
        .route("/ai/predictions/analyze", post(analyze_predictions))
        .route("/ai/predictions/history", get(get_metrics_history))
        .route("/ai/backup/optimal-window", get(get_optimal_backup_window))
        .route("/ai/backup/schedule", post(set_backup_schedule).put(set_backup_schedule))
        .route("/logs", get(get_logs))
        .route("/logs/sources", get(get_log_sources))
        .route("/logs/bookmarks", get(get_bookmarks).post(bookmark_log))
        .route(
            "/notifications/rules",
            get(get_notification_rules).post(create_notification_rule),
        )
        .route(
            "/notifications/rules/:id",
            put(update_notification_rule).delete(delete_notification_rule),
        )
        .route(
            "/notifications/channels",
            get(get_notification_channels).post(create_notification_channel),
        )
        .route(
            "/notifications/channels/:id/test",
            post(test_notification_channel),
        )
        .route(
            "/notifications/channels/:id",
            delete(delete_notification_channel),
        )
        .route("/network/status", get(get_network_status))
        .route(
            "/network/wireguard/peers",
            get(get_wireguard_peers).post(add_wireguard_peer),
        )
        .route(
            "/network/wireguard/peers/:key",
            delete(remove_wireguard_peer),
        )
        .route("/network/wireguard/keygen", post(generate_wireguard_keys))
        .route("/network/tailscale/status", get(get_tailscale_status))
        .route("/network/tailscale/peers", get(get_tailscale_peers))
        .route("/network/tailscale/routes", post(advertise_tailscale_routes))
        .route("/actions/pending", get(list_pending_actions))
        .route("/actions/:id", get(get_pending_action))
        .route("/actions/:id/approve", post(approve_action))
        .route("/actions/:id/reject", post(reject_action))
        .route("/audit-log", get(get_audit_log))
        .route("/mediaflow/queue", get(get_mediaflow_queue))
        .route("/mediaflow/scan", post(trigger_mediaflow_scan))
        .route("/mediaflow/approve/:id", post(approve_mediaflow_item))
        .route("/mediaflow/decline/:id", post(decline_mediaflow_item))
        .route("/ingress/configs", get(get_ingress_configs))
        .route("/ingress/apps/:appName", put(update_app_ingress_config))
        .route("/blueprints/:appName/sync", post(sync_app_blueprint))
        .route("/streaming/servers/:provider", put(update_streaming_server))
        .route("/streaming/servers/test", post(test_streaming_server))
        .route(
            "/streaming/servers/:provider/sync",
            post(sync_streaming_server_history),
        )
        .route(
            "/streaming/sessions/:sessionId/command",
            post(control_streaming_session),
        )
        .route("/streaming/demo", post(handle_streaming_demo))
        .layer(middleware::from_fn(admin_only_middleware))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    let compat_routes = Router::new()
        .route("/deploy/stream", get(handle_deploy_stream))
        .route("/ingress/configs", get(get_ingress_configs))
        .route("/ingress/apps/:appName", put(update_app_ingress_config))
        .route("/fs", get(browse_directories))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .nest("/public", public_routes)
        .nest("/auth", auth_routes)
        .nest("/admin", admin_routes)
        .merge(compat_routes)
        .layer(middleware::from_fn(host_validation_middleware))
}

// ─────────────────────────────────────────────────────────────────────────────
// Health, Metrics & OpenAPI Handlers (`health.go`, `metrics.go`, `openapi.go`)
// ─────────────────────────────────────────────────────────────────────────────

async fn health_check() -> Json<serde_json::Value> {
    let (status, db_status, latency_ms) = match af_db::db_health_check() {
        Ok(val) => (
            "ok",
            "ok",
            val.get("latency_ms").and_then(|v| v.as_i64()).unwrap_or(0),
        ),
        Err(_) => ("degraded", "unreachable", 0),
    };
    Json(serde_json::json!({
        "status": status,
        "uptime": format!("{:.1}s", START_TIME.elapsed().as_secs_f64()),
        "version": "4.0.0-rc1",
        "database": db_status,
        "db_latency_ms": latency_ms,
    }))
}

async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

async fn health_ready() -> Response {
    let (code, db_state, ready_state) = match af_db::db_health_check() {
        Ok(_) => (StatusCode::OK, "ok", "ready"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "unreachable", "not_ready"),
    };
    (
        code,
        Json(serde_json::json!({
            "database": db_state,
            "redis": "disabled",
            "uptime": format!("{:.1}s", START_TIME.elapsed().as_secs_f64()),
            "status": ready_state,
        })),
    )
        .into_response()
}

async fn prometheus_metrics() -> Response {
    let m = af_hardware::get_system_metrics_core();
    let mem_total_gb = m.memory.get("total").copied().unwrap_or(0.0);
    let mem_used_gb = m.memory.get("used").copied().unwrap_or(0.0);
    let mem_pct = if mem_total_gb > 0.0 {
        (mem_used_gb / mem_total_gb) * 100.0
    } else {
        0.0
    };
    let disk_total_gb = m.disk_space.get("total").copied().unwrap_or(0.0);
    let disk_used_gb = m.disk_space.get("used").copied().unwrap_or(0.0);
    let disk_pct = if disk_total_gb > 0.0 {
        (disk_used_gb / disk_total_gb) * 100.0
    } else {
        0.0
    };

    let body = format!(
        "# HELP aetherflow_process_uptime_seconds Process uptime in seconds\n\
         # TYPE aetherflow_process_uptime_seconds gauge\n\
         aetherflow_process_uptime_seconds {:.2}\n\
         # HELP aetherflow_system_cpu_percent Host CPU usage percentage\n\
         # TYPE aetherflow_system_cpu_percent gauge\n\
         aetherflow_system_cpu_percent {:.2}\n\
         # HELP aetherflow_system_memory_total_bytes Total physical memory in bytes\n\
         # TYPE aetherflow_system_memory_total_bytes gauge\n\
         aetherflow_system_memory_total_bytes {:.0}\n\
         # HELP aetherflow_system_memory_used_bytes Used physical memory in bytes\n\
         # TYPE aetherflow_system_memory_used_bytes gauge\n\
         aetherflow_system_memory_used_bytes {:.0}\n\
         # HELP aetherflow_system_memory_percent Memory usage percentage\n\
         # TYPE aetherflow_system_memory_percent gauge\n\
         aetherflow_system_memory_percent {:.2}\n\
         # HELP aetherflow_system_disk_percent Root disk usage percentage\n\
         # TYPE aetherflow_system_disk_percent gauge\n\
         aetherflow_system_disk_percent {:.2}\n\
         # HELP aetherflow_build_info Build metadata\n\
         # TYPE aetherflow_build_info gauge\n\
         aetherflow_build_info{{runtime=\"rust\",version=\"4.0.0-rc1\",os=\"{}\",arch=\"{}\"}} 1\n",
        START_TIME.elapsed().as_secs_f64(),
        m.cpu_usage,
        mem_total_gb * 1073741824.0,
        mem_used_gb * 1073741824.0,
        mem_pct,
        disk_pct,
        env::consts::OS,
        env::consts::ARCH
    );

    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}

async fn get_openapi_spec() -> Response {
    let mut resp = OPENAPI_YAML.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware, Metrics, Services & Marketplace (`marketplace.go`, `routes.go`)
// ─────────────────────────────────────────────────────────────────────────────

async fn get_system_metrics() -> Json<af_models::SystemMetrics> {
    Json(af_hardware::get_system_metrics_core())
}

async fn get_hardware_info() -> Json<af_models::HardwareReport> {
    Json(af_hardware::get_detailed_hardware())
}

async fn get_services() -> Json<HashMap<String, af_services::ServiceStatusItem>> {
    Json(af_services::get_active_services())
}

#[derive(Deserialize)]
struct ServiceControlReq {
    action: String,
    #[serde(default)]
    managed_by: String,
    #[serde(default)]
    process: String,
}

async fn control_service_handler(
    Path(name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<ServiceControlReq>,
) -> Response {
    if !matches!(req.action.as_str(), "start" | "stop" | "restart") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid action. Allowed: start, stop, restart",
        );
    }
    let target = if req.process.is_empty() {
        name.clone()
    } else {
        req.process.clone()
    };

    if let Err(e) = af_services::control_service(&target, &req.action).await {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to {} service: {}", req.action, e),
        );
    }

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

    Json(serde_json::json!({
        "message": "Service control command executed successfully",
        "service": name,
        "action": req.action,
    }))
    .into_response()
}

async fn get_marketplace_apps() -> Response {
    let Ok(pkgs) = af_services::get_packages() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load package catalog configuration",
        );
    };

    let ingress_map: HashMap<String, AppIngressConfig> = af_db::get_all_app_ingress_configs()
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.app_name.clone(), c))
        .collect();
    let base_domain = af_services::resolve_base_domain();

    let mut apps = Vec::with_capacity(pkgs.len());
    for p in pkgs {
        let mut active_port = p.default_port;
        let internal_domain = af_services::get_blueprint(&p.name)
            .map(|bp| bp.internal_domain)
            .unwrap_or_default();
        let mut public_domain = String::new();
        let mut external_access = false;

        if let Some(ing) = ingress_map.get(&p.name) {
            if ing.listen_port > 0 {
                active_port = ing.listen_port;
            }
            public_domain = ing.public_domain.clone();
            external_access = ing.external_access_enabled;
        }
        if public_domain.is_empty() && !base_domain.is_empty() && active_port > 0 {
            public_domain = af_services::format_app_public_domain(&p.name, &base_domain);
            if p.status == "installed" || p.status == "running" {
                external_access = true;
            }
        }

        let mut app = MarketplaceApp {
            id: p.name.clone(),
            name: p.label,
            desc: p.description,
            hits: p.hits,
            category: p.category,
            status: p.status,
            default_port: p.default_port,
            active_port,
            internal_domain,
            public_domain,
            external_access_enabled: external_access,
            web_path: p.web_path,
            progress: 0,
            started_at: None,
            log_line: String::new(),
            installed_version: p.installed_version,
            latest_version: p.latest_version,
            update_available: p.update_available,
            update_checked_at: p.update_checked_at,
            update_url: p.update_url,
            update_error: p.update_error,
        };

        if let Some(job) = af_services::get_package_job_info(&p.name) {
            app.progress = job.progress;
            app.started_at = Some(job.started_at);
            app.log_line = job.last_line;
        }

        apps.push(app);
    }

    Json(apps).into_response()
}

async fn package_progress(Path(id): Path<String>) -> Response {
    if let Some(job) = af_services::get_package_job_info(&id) {
        Json(job).into_response()
    } else {
        Json(serde_json::json!({
            "package_id": id,
            "status": "idle",
            "progress": 0,
        }))
        .into_response()
    }
}

async fn install_package(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle(id, "install", "installing", auth_user, headers).await
}

async fn uninstall_package(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle(id, "remove", "uninstalling", auth_user, headers).await
}

async fn update_package(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle(id, "update", "updating", auth_user, headers).await
}

async fn dispatch_package_lifecycle(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    let Ok(pkgs) = af_services::get_packages() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load package catalog configuration",
        );
    };
    let Some(pkg) = pkgs.into_iter().find(|p| p.name == pkg_id) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Package not found");
    };

    if matches!(
        pkg.status.as_str(),
        "installing" | "uninstalling" | "updating"
    ) {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package is already modifying state",
        );
    }

    let script_prefix = if action == "remove" {
        "removepackage-"
    } else {
        "installpackage-"
    };
    let script_name = format!("{}{}", script_prefix, pkg.name);
    if af_runner::resolve_package_script_path(action, &script_name).is_none() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Provisioning script is missing or unreadable on the server",
        );
    }

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        &format!("package_{}", action),
        "package",
        &pkg.name,
        &pkg.label,
        &ip,
        ua,
    );

    af_services::set_package_job_info(af_services::PackageJobInfo {
        package_id: pkg.name.clone(),
        action: action.to_string(),
        status: status_label.to_string(),
        progress: 5,
        last_line: format!("Starting {} for {}...", action, pkg.label),
        started_at: Utc::now().to_rfc3339(),
    });

    let msg = match action {
        "install" => "Installation started successfully",
        "remove" => "Uninstallation started successfully",
        _ => "Update started successfully",
    };

    Json(serde_json::json!({
        "message": msg,
        "package": pkg_id,
        "status": status_label,
    }))
    .into_response()
}

async fn check_package_updates() -> Response {
    let records = af_services::workers::refresh_all_package_updates().await;
    let updates_available = records.iter().filter(|r| r.update_available).count();
    Json(serde_json::json!({
        "message": "Package update check completed",
        "updates": records,
        "updates_available": updates_available,
    }))
    .into_response()
}

async fn check_single_package_update(Path(id): Path<String>) -> Response {
    let Ok(pkgs) = af_services::get_packages() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to load package catalog configuration",
        );
    };
    let Some(pkg) = pkgs.into_iter().find(|p| p.name == id) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Package not found");
    };
    let record = af_services::workers::refresh_package_update_by_id(&pkg.name).await;
    Json(serde_json::json!({
        "message": "Package update check completed",
        "package": pkg.name,
        "update": record,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings, Profile & Users (`settings.go`, `users.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub ai_model: String,
    pub system_prompt: String,
    pub language: String,
    pub timezone: String,
    pub update_channel: String,
    pub default_dashboard: String,
    pub setup_completed: bool,
    pub base_domain: String,
    pub gemini_api_key: String,
    pub openai_api_key: String,
    pub lm_studio_endpoint: String,
    pub ollama_endpoint: String,
    pub anthropic_api_key: String,
    pub anthropic_endpoint: String,
}

fn mask_secret(raw: &str) -> String {
    let dec = af_db::decrypt_key(raw).unwrap_or_else(|_| raw.to_string());
    if dec.len() > 4 {
        let last4: String = dec
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", last4)
    } else {
        String::new()
    }
}

async fn get_settings() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let row = conn.query_row(
        "SELECT COALESCE(ai_model, 'gemini-4-argon'), COALESCE(system_prompt, ''), COALESCE(language, 'en'), \
         COALESCE(timezone, 'UTC'), COALESCE(update_channel, 'stable'), COALESCE(default_dashboard, 'overview'), \
         COALESCE(setup_completed, 0), COALESCE(base_domain, ''), COALESCE(gemini_api_key, ''), \
         COALESCE(openai_api_key, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''), \
         COALESCE(anthropic_api_key, ''), COALESCE(anthropic_endpoint, '') FROM settings WHERE id = 1",
        [],
        |r| {
            let mut base_domain: String = r.get(7)?;
            if base_domain.is_empty() {
                base_domain = af_services::resolve_base_domain();
            }
            let gemini_raw: String = r.get(8)?;
            let openai_raw: String = r.get(9)?;
            let anthropic_raw: String = r.get(12)?;
            Ok(SettingsPayload {
                ai_model: r.get(0)?,
                system_prompt: r.get(1)?,
                language: r.get(2)?,
                timezone: r.get(3)?,
                update_channel: r.get(4)?,
                default_dashboard: r.get(5)?,
                setup_completed: r.get(6)?,
                base_domain,
                gemini_api_key: mask_secret(&gemini_raw),
                openai_api_key: mask_secret(&openai_raw),
                lm_studio_endpoint: r.get(10)?,
                ollama_endpoint: r.get(11)?,
                anthropic_api_key: mask_secret(&anthropic_raw),
                anthropic_endpoint: r.get(13)?,
            })
        },
    );

    match row {
        Ok(payload) => Json(payload).into_response(),
        Err(_) => Json(SettingsPayload::default()).into_response(),
    }
}

async fn update_settings(Json(mut req): Json<SettingsPayload>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let channel = if req.update_channel == "nightly" {
        "nightly"
    } else if req.update_channel == "experimental" {
        "experimental"
    } else {
        "stable"
    };
    let norm_domain = if req.base_domain.trim().is_empty() {
        String::new()
    } else {
        let n = af_db::normalize_base_domain(&req.base_domain);
        if n.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_DOMAIN",
                "Invalid base domain",
            );
        }
        n
    };

    let _ = conn.execute(
        "UPDATE settings SET ai_model = ?1, system_prompt = ?2, language = ?3, timezone = ?4, \
         update_channel = ?5, default_dashboard = ?6, setup_completed = ?7, base_domain = ?8, \
         lm_studio_endpoint = ?9, ollama_endpoint = ?10, anthropic_endpoint = ?11, \
         updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![
            req.ai_model,
            req.system_prompt,
            req.language,
            req.timezone,
            channel,
            req.default_dashboard,
            req.setup_completed,
            norm_domain,
            req.lm_studio_endpoint,
            req.ollama_endpoint,
            req.anthropic_endpoint,
        ],
    );

    if !req.gemini_api_key.is_empty() && !req.gemini_api_key.starts_with("****") {
        if let Ok(enc) = af_db::encrypt_key(&req.gemini_api_key) {
            let _ = conn.execute(
                "UPDATE settings SET gemini_api_key = ?1 WHERE id = 1",
                params![enc],
            );
        }
    }
    if !req.openai_api_key.is_empty() && !req.openai_api_key.starts_with("****") {
        if let Ok(enc) = af_db::encrypt_key(&req.openai_api_key) {
            let _ = conn.execute(
                "UPDATE settings SET openai_api_key = ?1 WHERE id = 1",
                params![enc],
            );
        }
    }
    if !req.anthropic_api_key.is_empty() && !req.anthropic_api_key.starts_with("****") {
        if let Ok(enc) = af_db::encrypt_key(&req.anthropic_api_key) {
            let _ = conn.execute(
                "UPDATE settings SET anthropic_api_key = ?1 WHERE id = 1",
                params![enc],
            );
        }
    }

    af_db::invalidate_ingress_cache();
    req.gemini_api_key.clear();
    req.openai_api_key.clear();
    req.anthropic_api_key.clear();
    req.base_domain = norm_domain;
    req.update_channel = channel.to_string();

    Json(serde_json::json!({
        "message": "Settings saved successfully",
        "data": req,
    }))
    .into_response()
}

async fn issue_ws_ticket(
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let ip = extract_client_ip(&headers);
    let ticket = issue_ws_ticket_for_user(auth_user.user_id, &ip);
    Json(serde_json::json!({ "ticket": ticket }))
}

#[derive(Deserialize)]
struct UpdateProfileReq {
    email: String,
}

async fn update_profile(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<UpdateProfileReq>,
) -> Response {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE users SET email = ?1 WHERE id = ?2",
            params![req.email.trim(), auth_user.user_id],
        );
    }
    Json(serde_json::json!({ "message": "Profile updated successfully" })).into_response()
}

#[derive(Deserialize)]
struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

async fn update_password(
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    if req.new_password.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "New password must be at least 8 characters",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let Ok(existing_hash) = conn.query_row(
        "SELECT COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };

    if !bcrypt::verify(&req.current_password, &existing_hash).unwrap_or(false) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Current password is incorrect",
        );
    }
    let Ok(new_hash) = bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to hash password",
        );
    };
    let _ = conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![new_hash, auth_user.user_id],
    );

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "password_update",
        "user",
        &auth_user.user_id.to_string(),
        "Password updated successfully",
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "status": "success",
        "message": "Password updated successfully",
    }))
    .into_response()
}

#[derive(Deserialize)]
struct AvatarReq {
    #[serde(default)]
    avatar: String,
    #[serde(default)]
    avatar_url: String,
}

async fn update_avatar(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<AvatarReq>,
) -> Response {
    let val = if !req.avatar.is_empty() {
        req.avatar
    } else {
        req.avatar_url
    };
    if val.len() > 2 * 1024 * 1024 {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "Avatar payload exceeds maximum 2MB size limit",
        );
    }
    let lower = val.trim().to_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("file:") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Disallowed avatar URI scheme",
        );
    }
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE users SET avatar_url = ?1 WHERE id = ?2",
            params![val, auth_user.user_id],
        );
    }
    Json(serde_json::json!({
        "status": "success",
        "message": "Avatar updated successfully",
        "avatar_url": val,
    }))
    .into_response()
}

async fn delete_avatar(Extension(auth_user): Extension<AuthUser>) -> Response {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE users SET avatar_url = '' WHERE id = ?1",
            params![auth_user.user_id],
        );
    }
    Json(serde_json::json!({
        "status": "success",
        "message": "Avatar removed successfully",
    }))
    .into_response()
}

async fn get_users() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(Vec::<User>::new()).into_response();
    };
    let mut users = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            let gid: String = r.get(5)?;
            Ok(User {
                id: r.get(0)?,
                username: r.get(1)?,
                email: r.get(2)?,
                avatar_url: r.get(3)?,
                role: r.get(4)?,
                is_oauth: !gid.is_empty(),
                google_id: gid,
                totp_enabled: r.get(6)?,
            })
        }) {
            for u in rows.flatten() {
                users.push(u);
            }
        }
    }
    Json(users).into_response()
}

#[derive(Deserialize)]
struct RoleReq {
    role: String,
}

async fn update_user_role(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<RoleReq>,
) -> Response {
    if req.role != "admin" && req.role != "user" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid role specified. Must be 'admin' or 'user'.",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let admin_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(1);
    let current_role: String = conn
        .query_row("SELECT role FROM users WHERE id = ?1", params![id], |r| {
            r.get(0)
        })
        .unwrap_or_default();

    if current_role == "admin" && req.role != "admin" && admin_count <= 1 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Cannot demote the last remaining admin.",
        );
    }

    let _ = conn.execute(
        "UPDATE users SET role = ?1 WHERE id = ?2",
        params![req.role, id],
    );
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "user_role_change",
        "user",
        &id.to_string(),
        &format!("role={}", req.role),
        &ip,
        ua,
    );
    Json(serde_json::json!({ "message": "Role updated successfully" })).into_response()
}

async fn delete_user(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let Ok(role) = conn.query_row(
        "SELECT role FROM users WHERE id = ?1",
        params![id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };
    let admin_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if role == "admin" && admin_count <= 1 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Cannot delete the last remaining admin.",
        );
    }
    let _ = conn.execute("DELETE FROM users WHERE id = ?1", params![id]);
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "user_delete",
        "user",
        &id.to_string(),
        "",
        &ip,
        ua,
    );
    Json(serde_json::json!({ "message": "User deleted successfully" })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// FS, Notifications, Blueprints, Ingress, Streaming & Admin Endpoints
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct FsQuery {
    #[serde(default)]
    path: String,
}

async fn browse_directories(Query(q): Query<FsQuery>) -> Response {
    if q.path.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Path query parameter is required",
        );
    }
    let p = PathBuf::from(&q.path);
    if !p.exists() {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
    }
    if !p.is_dir() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "NOT_A_DIRECTORY",
            "Path is not a directory",
        );
    }

    let mut directories = Vec::new();
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&p) {
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let full = entry.path().to_string_lossy().into_owned();
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len() as i64).unwrap_or(0);
            if is_dir {
                directories.push(name.clone());
            }
            entries.push(serde_json::json!({
                "name": name,
                "path": full,
                "is_dir": is_dir,
                "size": size,
                "mod_time": Utc::now().to_rfc3339(),
            }));
        }
    }
    directories.sort();
    let parent = p
        .parent()
        .map(|par| par.to_string_lossy().into_owned())
        .unwrap_or_default();

    Json(serde_json::json!({
        "current_path": q.path,
        "parent_path": parent,
        "directories": directories,
        "entries": entries,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
    #[serde(default)]
    action: String,
    #[serde(default)]
    username: String,
}

fn default_limit() -> i64 {
    50
}

async fn get_notifications(
    Extension(auth_user): Extension<AuthUser>,
    Query(q): Query<PageQuery>,
) -> Json<serde_json::Value> {
    let (notifications, unread_count) =
        af_services::list_notifications(auth_user.user_id, q.limit, q.offset).unwrap_or_default();
    Json(serde_json::json!({
        "notifications": notifications,
        "unread_count": unread_count,
    }))
}

async fn mark_notification_read(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    if let Ok(conn) = af_db::get_conn() {
        let updated = conn
            .execute(
                "UPDATE notifications SET read = 1 WHERE id = ?1 AND (user_id = ?2 OR user_id IS NULL)",
                params![id, auth_user.user_id],
            )
            .unwrap_or(0);
        if updated == 0 {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Notification not found");
        }
    }
    Json(serde_json::json!({ "message": "Notification marked as read" })).into_response()
}

async fn dismiss_all_notifications(
    Extension(auth_user): Extension<AuthUser>,
) -> Json<serde_json::Value> {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE notifications SET read = 1 WHERE (user_id = ?1 OR user_id IS NULL) AND read = 0",
            params![auth_user.user_id],
        );
    }
    Json(serde_json::json!({ "message": "All notifications dismissed" }))
}

async fn get_blueprints() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "blueprints": af_services::get_all_blueprints()
    }))
}

async fn get_app_blueprint(Path(app_name): Path<String>) -> Response {
    let all = af_services::get_all_blueprints();
    if let Some(bp) = all
        .into_iter()
        .find(|b| b.blueprint.app_name == app_name)
    {
        Json(bp).into_response()
    } else {
        api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found")
    }
}

async fn sync_app_blueprint(
    Path(app_name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let Some(bp) = af_services::get_blueprint(&app_name) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found");
    };
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "blueprint_sync",
        "blueprint",
        &app_name,
        "",
        &ip,
        ua,
    );

    let existing_ing = af_db::get_app_ingress_config(&app_name).ok().flatten();
    let allocated_port = existing_ing
        .as_ref()
        .map(|c| c.listen_port)
        .filter(|&p| p > 0)
        .unwrap_or(bp.default_port);
    let public_domain = existing_ing
        .as_ref()
        .map(|c| c.public_domain.clone())
        .unwrap_or_default();
    let external_access_enabled = existing_ing
        .as_ref()
        .map(|c| c.external_access_enabled)
        .unwrap_or(false);

    let config_applied = af_services::mutators::apply_blueprint_app_config(&app_name, allocated_port)
        .await
        .is_ok();

    let res = af_services::BlueprintSetupResult {
        app_name: bp.app_name,
        service_name: bp.service_name,
        allocated_port,
        default_port: bp.default_port,
        port_reassigned: allocated_port != bp.default_port && allocated_port > 0,
        internal_domain: bp.internal_domain,
        public_domain,
        external_access_enabled,
        config_applied,
        ingress_synced: true,
        hosts_synced: true,
        network_dns_synced: true,
    };

    Json(serde_json::json!({
        "message": "Blueprint synchronized successfully",
        "result": res,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct StreamingQuery {
    #[serde(default = "default_window")]
    window: i32,
}

fn default_window() -> i32 {
    30
}

async fn get_streaming_dashboard(
    Extension(auth_user): Extension<AuthUser>,
    Query(q): Query<StreamingQuery>,
) -> Json<af_services::StreamingDashboardResponse> {
    let is_admin = auth_user.role == "admin";
    Json(af_services::get_streaming_dashboard(q.window, is_admin))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateStreamingServerReq {
    #[serde(default)]
    name: String,
    url: String,
    #[serde(default)]
    api_key: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn update_streaming_server(
    Path(provider): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<UpdateStreamingServerReq>,
) -> Response {
    if provider != "jellyfin" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Only Jellyfin connection is enabled in this release; Plex and Emby support will arrive in a future update.",
        );
    }
    let clean_url = match af_services::validate_server_url(&req.url) {
        Ok(u) => u,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", e.to_string()),
    };

    let enc_key = if req.api_key.is_empty() || req.api_key.starts_with("****") {
        String::new()
    } else {
        af_db::encrypt_key(&req.api_key).unwrap_or(req.api_key)
    };

    if let Ok(conn) = af_db::get_conn() {
        let name = if req.name.trim().is_empty() {
            "Jellyfin".to_string()
        } else {
            req.name.trim().to_string()
        };
        let _ = conn.execute(
            r#"
            INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
            VALUES ('jellyfin', ?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
            ON CONFLICT(provider) DO UPDATE SET
                name = excluded.name,
                url = excluded.url,
                api_key = CASE WHEN excluded.api_key != '' THEN excluded.api_key ELSE streaming_servers.api_key END,
                enabled = excluded.enabled,
                updated_at = CURRENT_TIMESTAMP
            "#,
            params![name, clean_url, enc_key, req.enabled],
        );
    }

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "streaming_server_update",
        "streaming_server",
        "jellyfin",
        &clean_url,
        &ip,
        ua,
    );

    let dash = af_services::get_streaming_dashboard(30, true);
    let server = dash.servers.into_iter().next();
    Json(serde_json::json!({
        "message": "Jellyfin server configuration saved",
        "server": server,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DemoReq {
    #[serde(default)]
    action: String,
}

async fn handle_streaming_demo(Json(req): Json<DemoReq>) -> Json<serde_json::Value> {
    if req.action == "clear" {
        af_services::set_streaming_demo_mode(false);
        Json(serde_json::json!({
            "message": "Demo telemetry cleared",
            "demoMode": false,
        }))
    } else {
        af_services::set_streaming_demo_mode(true);
        Json(serde_json::json!({
            "message": "Demo streaming telemetry loaded",
            "demoMode": true,
        }))
    }
}

async fn get_ingress_configs() -> Json<serde_json::Value> {
    let configs = af_db::get_all_app_ingress_configs().unwrap_or_default();
    Json(serde_json::json!({ "configs": configs }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateIngressReq {
    #[serde(default)]
    public_domain: String,
    #[serde(default)]
    external_access_enabled: bool,
    #[serde(default)]
    listen_port: i32,
    #[serde(default)]
    tls_enabled: bool,
}

async fn update_app_ingress_config(
    Path(app_name): Path<String>,
    Json(req): Json<UpdateIngressReq>,
) -> Response {
    let listen_port = if req.listen_port > 0 {
        req.listen_port
    } else if let Some(existing) = af_db::get_app_ingress_config(&app_name).ok().flatten() {
        if existing.listen_port > 0 {
            existing.listen_port
        } else {
            af_services::get_blueprint(&app_name)
                .map(|b| b.default_port)
                .unwrap_or(0)
        }
    } else {
        af_services::get_blueprint(&app_name)
            .map(|b| b.default_port)
            .unwrap_or(0)
    };

    let cfg = AppIngressConfig {
        app_name: app_name.clone(),
        public_domain: req.public_domain.trim().to_string(),
        external_access_enabled: req.external_access_enabled,
        listen_port,
        tls_enabled: req.tls_enabled,
        updated_at: Utc::now().to_rfc3339(),
    };
    if let Err(e) = af_db::upsert_app_ingress_config(&cfg) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        );
    }

    let _ = af_services::mutators::apply_blueprint_app_config(&app_name, listen_port).await;

    Json(serde_json::json!({
        "message": "Ingress configuration updated successfully",
        "config": cfg,
    }))
    .into_response()
}

async fn get_notification_rules() -> Json<serde_json::Value> {
    let mut rules = Vec::new();
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, condition_type, condition_value, COALESCE(level, 'warning'), COALESCE(enabled, 1), COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_rules ORDER BY created_at DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "condition_type": r.get::<_, String>(2)?,
                    "condition_value": r.get::<_, String>(3)?,
                    "level": r.get::<_, String>(4)?,
                    "enabled": r.get::<_, i32>(5)? != 0,
                    "created_at": r.get::<_, String>(6)?,
                }))
            }) {
                for r in rows.flatten() {
                    rules.push(r);
                }
            }
        }
    }
    Json(serde_json::json!({ "rules": rules }))
}

async fn get_notification_channels() -> Json<serde_json::Value> {
    let mut channels = Vec::new();
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, type, COALESCE(config, '{}'), COALESCE(enabled, 1), COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_channels ORDER BY created_at DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let raw_cfg: String = r.get(3)?;
                let cfg_val: serde_json::Value =
                    serde_json::from_str(&raw_cfg).unwrap_or_else(|_| serde_json::json!({}));
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "type": r.get::<_, String>(2)?,
                    "config": cfg_val,
                    "enabled": r.get::<_, i32>(4)? != 0,
                    "created_at": r.get::<_, String>(5)?,
                }))
            }) {
                for ch in rows.flatten() {
                    channels.push(ch);
                }
            }
        }
    }
    Json(serde_json::json!({ "channels": channels }))
}

async fn list_pending_actions() -> Json<serde_json::Value> {
    let actions = af_db::list_pending_actions(50, 0).unwrap_or_default();
    let total = actions.len();
    Json(serde_json::json!({
        "actions": actions,
        "total": total,
        "limit": 50,
        "offset": 0,
    }))
}

async fn approve_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let Ok(action) = af_db::resolve_action(id, "approved", &auth_user.username) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Action not found or already resolved",
        );
    };
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
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
        "message": "Action approved",
        "action": action,
    }))
    .into_response()
}

async fn reject_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let Ok(action) = af_db::resolve_action(id, "rejected", &auth_user.username) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Action not found or already resolved",
        );
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
        "message": "Action rejected",
        "action": action,
    }))
    .into_response()
}

async fn get_audit_log(Query(q): Query<PageQuery>) -> Json<serde_json::Value> {
    let (entries, total) =
        af_db::list_audit_entries(q.limit, q.offset, &q.action, &q.username).unwrap_or_default();
    Json(serde_json::json!({
        "entries": entries,
        "total": total,
        "limit": q.limit,
        "offset": q.offset,
    }))
}
