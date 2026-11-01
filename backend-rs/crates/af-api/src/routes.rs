use futures::StreamExt;
use crate::auth::{
    admin_only_middleware, api_error, auth_middleware, check_setup_needed, csrf_middleware,
    disable_2fa, get_session, issue_csrf_token, list_active_sessions, local_login, logout,
    mfa_login_verify, mint_plugin_jwt, refresh_session, revoke_session, setup_2fa, setup_admin,
    verify_2fa, verify_proxy_auth, AuthUser,
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
    clear_streaming_demo_data, control_streaming_session, get_streaming_artwork,
    get_streaming_dashboard_handler, seed_streaming_demo_data, sync_streaming_server_history,
    test_streaming_server,
};
use crate::ws::{
    broadcast_ws_message, extract_client_ip, handle_log_websocket, handle_websocket,
    issue_ws_ticket_for_user,
};
use af_models::{AppIngressConfig, MarketplaceApp, User};
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{any, delete, get, post, put};
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

    let top_level_plugin_proxy = Router::new()
        .route("/plugins/:id", any(proxy_plugin_root_request))
        .route("/plugins/:id/*path", any(proxy_plugin_request))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .nest("/api/v1", v1)
        .nest("/api", legacy)
        .merge(top_level_plugin_proxy)
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
        .route("/plugins", get(list_plugins_handler))
        .route("/plugins/:id/proxy", any(proxy_plugin_root_request))
        .route("/plugins/:id/proxy/*path", any(proxy_plugin_request))
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
        .route("/plugins", get(list_plugins_handler))
        .route("/plugins/:id/token", post(mint_plugin_token_handler))
        .layer(middleware::from_fn(admin_only_middleware))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    let compat_routes = Router::new()
        .route("/deploy/stream", get(handle_deploy_stream))
        .route("/fs", get(browse_directories))
        .layer(middleware::from_fn(auth_middleware));

    let ingress_compat_routes = Router::new()
        .route("/ingress/configs", get(get_ingress_configs))
        .route("/ingress/apps/:appName", put(update_app_ingress_config))
        .layer(middleware::from_fn(admin_only_middleware))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .nest("/public", public_routes)
        .nest("/auth", auth_routes)
        .nest("/admin", admin_routes)
        .merge(compat_routes)
        .merge(ingress_compat_routes)
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
        "version": "4.0.0",
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
         aetherflow_build_info{{runtime=\"rust\",version=\"4.0.0\",os=\"{}\",arch=\"{}\"}} 1\n",
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
    let target = if req.process.trim().is_empty() {
        name.clone()
    } else {
        req.process.trim().to_string()
    };

    let result = if req.managed_by.trim().is_empty() {
        af_services::control_service(&target, &req.action).await
    } else {
        af_services::control_service_with_manager(&target, &req.action, req.managed_by.trim()).await
    };

    if let Err(e) = result {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to {} service: {}", req.action, e),
        );
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

fn allocate_or_resolve_app_port(app_name: &str, default_port: i32) -> i32 {
    if let Ok(Some(existing)) = af_db::get_app_ingress_config(app_name) {
        if existing.listen_port > 0 {
            return existing.listen_port;
        }
    }
    let bp = af_services::get_blueprint(app_name);
    let candidate = bp.as_ref().map(|b| b.default_port).unwrap_or(default_port);
    if candidate <= 0 {
        return 0;
    }
    if std::net::TcpListener::bind(("127.0.0.1", candidate as u16)).is_ok() {
        return candidate;
    }
    // These applications do not expose a configurable native listen port.
    if matches!(app_name, "plex" | "calibreweb") {
        return 0;
    }
    let range = bp
        .as_ref()
        .map(|b| b.fallback_port_range)
        .unwrap_or([17000, 19999]);
    let start = range[0].max(1024);
    let end = range[1].max(start);
    for port in start..=end {
        if std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok() {
            return port;
        }
    }
    0
}

fn emit_package_progress(
    pkg_id: &str,
    action: &str,
    status: &str,
    progress: i32,
    line: &str,
    started_at: &str,
) {
    let info = af_services::PackageJobInfo {
        package_id: pkg_id.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        progress,
        last_line: line.to_string(),
        started_at: started_at.to_string(),
    };
    af_services::set_package_job_info(info);
    broadcast_ws_message(&serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": status,
        "progress": progress,
        "line": line,
        "started_at": started_at,
    }));
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

    if action == "update" && pkg.status != "installed" {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package must be installed before it can be updated",
        );
    }

    let script_prefix = if action == "remove" {
        "removepackage-"
    } else {
        "installpackage-"
    };
    let script_name = format!("{}{}", script_prefix, pkg.name);
    let Some(_script_path) = af_runner::resolve_package_script_path(action, &script_name) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Provisioning script is missing or unreadable on the server",
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
        &format!("package_{}", action),
        "package",
        &pkg.name,
        &pkg.label,
        &ip,
        ua,
    );

    let started_at = Utc::now().to_rfc3339();
    if !af_services::try_start_package_job(af_services::PackageJobInfo {
        package_id: pkg.name.clone(),
        action: action.to_string(),
        status: status_label.to_string(),
        progress: 5,
        last_line: format!("Starting {} for {}...", action, pkg.label),
        started_at: started_at.clone(),
    }) {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Package is already modifying state",
        );
    }
    emit_package_progress(
        &pkg.name,
        action,
        status_label,
        5,
        &format!("Starting {} for {}...", action, pkg.label),
        &started_at,
    );

    let clean_id = pkg.name.clone();
    let pkg_label = pkg.label.clone();
    let pkg_default_port = pkg.default_port;
    let pkg_lock_file = pkg.lock_file.clone();

    tokio::spawn(async move {
        let _lifecycle_guard = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        // Read native configuration before stopping the application. An update
        // must keep its port even while that port is owned by the old process.
        let configured_port = if action == "update" {
            af_services::mutators::get_app_runtime_meta(&clean_id).configured_port
        } else {
            0
        };

        emit_package_progress(
            &clean_id,
            action,
            status_label,
            10,
            &format!("Preparing environment for {}...", pkg_label),
            &started_at,
        );

        let mut stopped_units: Vec<String> = Vec::new();
        if action == "update"
            && env::var("AETHERFLOW_FS_ROOT")
                .unwrap_or_default()
                .trim()
                .is_empty()
        {
            let mut units = af_services::resolve_service_units(&clean_id);
            units.sort_by_key(|unit| !unit.ends_with(".timer"));
            for u in units {
                let (st, _, _) = af_services::get_systemd_unit_info(&u);
                if st == "running" {
                    if let Err(error) =
                        af_services::control_service_with_manager(&u, "stop", "systemd-unit").await
                    {
                        for unit in &stopped_units {
                            let _ = af_services::control_service_with_manager(
                                unit,
                                "start",
                                "systemd-unit",
                            )
                            .await;
                        }
                        emit_package_progress(
                            &clean_id,
                            action,
                            "failed",
                            10,
                            &format!("Could not stop {}: {}", u, error),
                            &started_at,
                        );
                        af_services::clear_package_job_info(&clean_id);
                        return;
                    }
                    stopped_units.push(u);
                }
            }
        }

        let allocated_port = if action == "update" {
            let ingress_port = af_db::get_app_ingress_config(&clean_id)
                .ok()
                .flatten()
                .map(|c| c.listen_port)
                .unwrap_or(0);
            if configured_port > 0 {
                configured_port
            } else if ingress_port > 0 {
                ingress_port
            } else {
                pkg_default_port
            }
        } else if action == "install" {
            allocate_or_resolve_app_port(&clean_id, pkg_default_port)
        } else {
            pkg_default_port
        };
        if pkg_default_port > 0 && allocated_port <= 0 && action == "install" {
            emit_package_progress(
                &clean_id,
                action,
                "failed",
                10,
                "No supported listen port is available for this application",
                &started_at,
            );
            af_services::clear_package_job_info(&clean_id);
            return;
        }

        emit_package_progress(
            &clean_id,
            action,
            status_label,
            25,
            &format!("Executing {} script for {}...", action, pkg_label),
            &started_at,
        );

        let fs_root_override = env::var("AETHERFLOW_FS_ROOT")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let can_run_bash =
            cfg!(unix) && fs_root_override.is_none() && std::path::Path::new("/bin/bash").exists();

        let execution_result = if can_run_bash && af_runner::is_runner_available() {
            af_runner::dispatch_package_stream(
                action,
                &clean_id,
                &script_name,
                allocated_port,
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
                    );
                },
            )
            .await
        } else if can_run_bash {
            let request = af_models::PackageRunnerRequest {
                action: action.to_string(),
                package_id: clean_id.clone(),
                script_name: script_name.clone(),
                app_port: allocated_port,
            };
            let stream = af_runner::execute_package_request_stream(request);
            tokio::pin!(stream);
            let mut result = Ok(());
            while let Some(item) = stream.next().await {
                match item {
                    Ok(line) => {
                        if let Some(error) = line.trim().strip_prefix("__RUNNER_EXIT_ERROR__:") {
                            result = Err(anyhow::anyhow!("{}", error));
                        } else {
                            let (pct, msg) = af_runner::parse_progress_line(&line)
                                .map(|(p, m)| (p as i32, m))
                                .unwrap_or_else(|| (60, line));
                            emit_package_progress(
                                &clean_id,
                                action,
                                status_label,
                                pct,
                                msg.trim(),
                                &started_at,
                            );
                        }
                    }
                    Err(error) => {
                        result = Err(error.into());
                        break;
                    }
                }
            }
            result
        } else {
            emit_package_progress(
                &clean_id,
                action,
                status_label,
                60,
                &format!("Applying package state changes for {}...", pkg_label),
                &started_at,
            );
            if !pkg_lock_file.is_empty() {
                let lock_path = if let Some(ref root) = fs_root_override {
                    std::path::Path::new(root.trim())
                        .join(pkg_lock_file.trim_start_matches(['/', '\\']))
                } else {
                    PathBuf::from(&pkg_lock_file)
                };
                if action == "remove" {
                    let _ = fs::remove_file(&lock_path);
                } else if fs_root_override.is_some() {
                    if let Some(parent) = lock_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&lock_path, b"installed\n");
                }
            }
            Ok(())
        };

        if let Err(error) = execution_result {
            for unit in &stopped_units {
                let _ =
                    af_services::control_service_with_manager(unit, "start", "systemd-unit").await;
            }
            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            emit_package_progress(
                &clean_id,
                action,
                "failed",
                60,
                &error.to_string(),
                &started_at,
            );
            af_services::clear_package_job_info(&clean_id);
            return;
        }

        emit_package_progress(
            &clean_id,
            action,
            status_label,
            85,
            &format!("Synchronizing blueprint & ingress for {}...", pkg_label),
            &started_at,
        );

        if action == "install" || action == "update" {
            let _ =
                af_services::mutators::apply_blueprint_app_config(&clean_id, allocated_port).await;

            if allocated_port > 0 {
                let base_domain = af_services::resolve_base_domain();
                let existing = af_db::get_app_ingress_config(&clean_id).ok().flatten();
                let public_domain = existing
                    .as_ref()
                    .map(|c| c.public_domain.clone())
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| {
                        if base_domain.is_empty() {
                            String::new()
                        } else {
                            af_services::format_app_public_domain(&clean_id, &base_domain)
                        }
                    });
                let external_access = existing
                    .as_ref()
                    .map(|c| c.external_access_enabled)
                    .unwrap_or(!public_domain.is_empty());
                let tls_enabled = existing
                    .as_ref()
                    .map(|c| c.tls_enabled)
                    .unwrap_or(!public_domain.is_empty());
                let now = Utc::now();
                let cfg = AppIngressConfig {
                    app_name: clean_id.clone(),
                    public_domain,
                    external_access_enabled: external_access,
                    listen_port: allocated_port,
                    tls_enabled,
                    created_at: existing.as_ref().map(|c| c.created_at).unwrap_or(now),
                    updated_at: now,
                };
                let _ = af_db::set_app_ingress_config(&cfg);
            }

            let (master_user, master_pass, _) = af_services::mutators::load_master_credentials();
            if !master_user.is_empty() && !master_pass.is_empty() {
                af_services::mutators::sync_master_credentials_to_installed_apps(
                    &master_user,
                    &master_pass,
                );
            }

            if action == "update" {
                for u in stopped_units {
                    let _ = af_services::control_service_with_manager(&u, "start", "systemd-unit")
                        .await;
                }
                let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
            }
        } else if action == "remove" {
            let _ = af_db::delete_app_ingress_config(&clean_id);
            if let Ok(conn) = af_db::get_conn() {
                let _ = conn.execute(
                    "DELETE FROM app_updates WHERE package_name = ?1",
                    params![clean_id],
                );
            }
            let _ = af_services::mutators::sync_network_dns_providers().await;
        }

        af_services::clear_service_status_cache();
        af_services::mutators::clear_app_runtime_meta_cache();

        emit_package_progress(
            &clean_id,
            action,
            "completed",
            100,
            &format!("Completed {} for {}", action, pkg_label),
            &started_at,
        );
        af_services::clear_package_job_info(&clean_id);
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
            let base_domain: String = r.get(7)?;
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

    drop(conn);
    match row {
        Ok(mut payload) => {
            if payload.base_domain.is_empty() {
                payload.base_domain = af_services::resolve_base_domain();
            }
            Json(payload).into_response()
        }
        Err(_) => Json(SettingsPayload::default()).into_response(),
    }
}

async fn update_settings(Json(mut req): Json<SettingsPayload>) -> Response {
    let prev_base_domain = af_db::get_base_domain();

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

    drop(conn);
    af_db::invalidate_ingress_cache();

    if !norm_domain.is_empty() && norm_domain != prev_base_domain {
        let now = Utc::now();
        let old_suffix = if prev_base_domain.is_empty() {
            String::new()
        } else {
            format!(".{}", prev_base_domain)
        };

        let mut handled_apps = std::collections::HashSet::new();
        for mut cfg in af_db::get_all_app_ingress_configs().unwrap_or_default() {
            handled_apps.insert(cfg.app_name.clone());
            let should_auto_update = cfg.public_domain.trim().is_empty()
                || (!old_suffix.is_empty() && cfg.public_domain.ends_with(&old_suffix));
            if should_auto_update {
                if cfg.listen_port <= 0 {
                    cfg.listen_port = af_services::get_blueprint(&cfg.app_name)
                        .map(|b| b.default_port)
                        .unwrap_or(0);
                }
                if cfg.listen_port > 0 {
                    cfg.public_domain =
                        af_services::format_app_public_domain(&cfg.app_name, &norm_domain);
                    cfg.external_access_enabled = true;
                    cfg.tls_enabled = true;
                    cfg.updated_at = now;
                    let _ = af_db::set_app_ingress_config(&cfg);
                    let _ = af_services::mutators::apply_blueprint_app_config(
                        &cfg.app_name,
                        cfg.listen_port,
                    )
                    .await;
                }
            }
        }

        if let Ok(pkgs) = af_services::get_packages() {
            for p in pkgs {
                if p.status == "installed" && p.default_port > 0 && !handled_apps.contains(&p.name)
                {
                    let pub_dom = af_services::format_app_public_domain(&p.name, &norm_domain);
                    let cfg = AppIngressConfig {
                        app_name: p.name.clone(),
                        public_domain: pub_dom,
                        external_access_enabled: true,
                        listen_port: p.default_port,
                        tls_enabled: true,
                        created_at: now,
                        updated_at: now,
                    };
                    let _ = af_db::set_app_ingress_config(&cfg);
                    let _ = af_services::mutators::apply_blueprint_app_config(
                        &p.name,
                        p.default_port,
                    )
                    .await;
                }
            }
        }

        let _ = af_services::mutators::sync_network_dns_providers().await;
        af_services::mutators::trigger_apache_cert_sync().await;
    }

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
    drop(conn);

    let current_password = req.current_password.clone();
    let new_password = req.new_password.clone();
    let hash_for_verify = existing_hash.clone();
    let hashed = tokio::task::spawn_blocking(move || -> Result<String, &'static str> {
        if !bcrypt::verify(&current_password, &hash_for_verify).unwrap_or(false) {
            return Err("bad");
        }
        bcrypt::hash(&new_password, bcrypt::DEFAULT_COST).map_err(|_| "hash")
    })
    .await;
    let new_hash = match hashed {
        Ok(Ok(hash)) => hash,
        Ok(Err("bad")) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Current password is incorrect",
            );
        }
        _ => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to hash password",
            );
        }
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let changed = conn
        .execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![new_hash, auth_user.user_id],
        )
        .unwrap_or(0);
    drop(conn);
    if changed == 0 {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update password",
        );
    }

    if auth_user.role == "admin" {
        let _ = af_services::mutators::save_master_credentials(
            &auth_user.username,
            &req.new_password,
        );
        af_services::mutators::sync_master_credentials_to_installed_apps(
            &auth_user.username,
            &req.new_password,
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
    let Ok(current_role) = conn.query_row(
        "SELECT role FROM users WHERE id = ?1",
        params![id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };

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
    drop(conn);
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
    let _ = conn.execute("DELETE FROM active_sessions WHERE user_id = ?1", params![id]);
    let _ = conn.execute("DELETE FROM oidc_refresh_tokens WHERE user_id = ?1", params![id]);
    let _ = conn.execute("DELETE FROM oidc_consents WHERE user_id = ?1", params![id]);
    let _ = conn.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![id]);
    let _ = conn.execute("DELETE FROM user_quotas WHERE user_id = ?1", params![id]);
    let _ = conn.execute("DELETE FROM users WHERE id = ?1", params![id]);
    drop(conn);
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

fn get_allowed_fs_roots() -> Vec<PathBuf> {
    let mut raw_roots: Vec<PathBuf> = Vec::new();
    let has_env_override = if let Ok(env_roots) = env::var("AF_ALLOWED_FS_ROOTS") {
        for part in env_roots.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                raw_roots.push(PathBuf::from(trimmed));
            }
        }
        !raw_roots.is_empty()
    } else {
        false
    };

    if !has_env_override {
        for def in [
            "/mnt",
            "/media",
            "/home",
            "/opt/AetherFlow",
            "/var/lib/aetherflow",
        ] {
            raw_roots.push(PathBuf::from(def));
        }
        raw_roots.push(env::temp_dir());
    }

    if let Ok(cwd) = env::current_dir() {
        raw_roots.push(cwd);
    }

    let mut resolved = Vec::with_capacity(raw_roots.len());
    for root in raw_roots {
        if let Ok(canon) = fs::canonicalize(&root) {
            resolved.push(canon);
        } else {
            resolved.push(root);
        }
    }
    resolved
}

fn is_fs_path_allowed(target: &std::path::Path, allowed_roots: &[PathBuf]) -> bool {
    for root in allowed_roots {
        if target == root || target.starts_with(root) {
            return true;
        }
    }
    false
}

async fn browse_directories(Query(q): Query<FsQuery>) -> Response {
    let raw_path = q.path.trim();
    if raw_path.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Path query parameter is required",
        );
    }
    let p = PathBuf::from(raw_path);
    if !p.exists() && fs::symlink_metadata(&p).is_err() {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
    }

    let resolved_path = match fs::canonicalize(&p) {
        Ok(rp) => rp,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
        }
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_PATH",
                "Could not resolve directory path",
            );
        }
    };

    let allowed_roots = get_allowed_fs_roots();
    if !is_fs_path_allowed(&resolved_path, &allowed_roots) {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Access denied: path is outside allowed sandbox",
        );
    }

    let Ok(dir_meta) = fs::metadata(&resolved_path) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Directory not found");
    };
    if !dir_meta.is_dir() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "NOT_A_DIRECTORY",
            "Path is not a directory",
        );
    }

    let Ok(read_dir) = fs::read_dir(&resolved_path) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to read directory",
        );
    };

    let mut directories = Vec::new();
    let mut entries = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let entry_path = entry.path();
        let full = entry_path.to_string_lossy().into_owned();

        let sym_meta = fs::symlink_metadata(&entry_path).ok();
        let size = sym_meta.as_ref().map(|m| m.len() as i64).unwrap_or(0);
        let mod_time = sym_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        let mut is_dir = sym_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        if !is_dir
            && sym_meta
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            if let Ok(target_meta) = fs::metadata(&entry_path) {
                if target_meta.is_dir() {
                    if let Ok(canon_target) = fs::canonicalize(&entry_path) {
                        if is_fs_path_allowed(&canon_target, &allowed_roots) {
                            is_dir = true;
                        }
                    }
                }
            }
        }

        if is_dir {
            directories.push(name.clone());
        }
        entries.push(serde_json::json!({
            "name": name,
            "path": full,
            "is_dir": is_dir,
            "size": size,
            "mod_time": mod_time,
        }));
    }

    directories.sort();
    entries.sort_by(|a, b| {
        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        na.cmp(nb)
    });

    let parent = resolved_path
        .parent()
        .filter(|par| *par != resolved_path && is_fs_path_allowed(par, &allowed_roots))
        .map(|par| par.to_string_lossy().into_owned())
        .unwrap_or_default();

    Json(serde_json::json!({
        "current_path": resolved_path.to_string_lossy().into_owned(),
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
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let updated = conn
        .execute(
            "UPDATE notifications SET read = 1 WHERE id = ?1 AND (user_id = ?2 OR user_id IS NULL)",
            params![id, auth_user.user_id],
        )
        .unwrap_or(0);
    if updated == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Notification not found");
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
    let configured_port = af_services::mutators::get_app_runtime_meta(&app_name).configured_port;
    let allocated_port = existing_ing
        .as_ref()
        .map(|c| c.listen_port)
        .filter(|&p| p > 0)
        .unwrap_or(if configured_port > 0 { configured_port } else { bp.default_port });
    let base_domain = af_services::resolve_base_domain();
    let public_domain = existing_ing
        .as_ref()
        .map(|c| c.public_domain.clone())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| {
            if base_domain.is_empty() || allocated_port <= 0 {
                String::new()
            } else {
                af_services::format_app_public_domain(&app_name, &base_domain)
            }
        });
    let external_access_enabled = existing_ing
        .as_ref()
        .map(|c| c.external_access_enabled)
        .unwrap_or(!public_domain.is_empty());
    let tls_enabled = existing_ing
        .as_ref()
        .map(|c| c.tls_enabled)
        .unwrap_or(!public_domain.is_empty());

    let config_applied = af_services::mutators::apply_blueprint_app_config(&app_name, allocated_port)
        .await
        .is_ok();

    let now = Utc::now();
    let ingress_cfg = AppIngressConfig {
        app_name: bp.app_name.clone(),
        public_domain: public_domain.clone(),
        external_access_enabled,
        listen_port: allocated_port,
        tls_enabled,
        created_at: existing_ing.as_ref().map(|c| c.created_at).unwrap_or(now),
        updated_at: now,
    };
    let ingress_synced = if allocated_port > 0 {
        let ok = af_db::set_app_ingress_config(&ingress_cfg).is_ok();
        af_db::invalidate_ingress_cache();
        ok
    } else {
        false
    };

    let mut dns_domains = Vec::new();
    if !bp.internal_domain.trim().is_empty() {
        dns_domains.push(bp.internal_domain.clone());
    }
    if !public_domain.is_empty() && !dns_domains.contains(&public_domain) {
        dns_domains.push(public_domain.clone());
    }
    let hosts_synced = if dns_domains.is_empty() {
        true
    } else {
        af_services::mutators::sync_local_dns_domains(&dns_domains)
            .await
            .is_ok()
    };
    let network_dns_synced = af_services::mutators::sync_network_dns_providers()
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
        ingress_synced,
        hosts_synced,
        network_dns_synced,
    };

    Json(serde_json::json!({
        "message": "Blueprint synchronized successfully",
        "result": res,
    }))
    .into_response()
}

async fn get_streaming_dashboard(
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    get_streaming_dashboard_handler(Query(q), req).await
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

    let saved = if let Ok(conn) = af_db::get_conn() {
        let name = if req.name.trim().is_empty() {
            "Jellyfin".to_string()
        } else {
            req.name.trim().to_string()
        };
        conn.execute(
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
        ).is_ok()
    } else {
        false
    };
    if !saved {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Jellyfin server configuration",
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

    let dash = crate::streaming_ext::build_streaming_dashboard("30", "all", "all", true).await;
    let server = dash.servers.first().cloned();
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

async fn handle_streaming_demo(
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<DemoReq>,
) -> Response {
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if req.action.eq_ignore_ascii_case("clear") || req.action.eq_ignore_ascii_case("disable") {
        let _ = clear_streaming_demo_data();
        af_db::record_audit(
            auth_user.user_id,
            &auth_user.username,
            "streaming_demo_clear",
            "streaming_demo",
            "jellyfin",
            "cleared",
            &ip,
            ua,
        );
        Json(serde_json::json!({
            "message": "Demo telemetry cleared",
            "demoMode": false,
        }))
        .into_response()
    } else {
        let history_seeded = match seed_streaming_demo_data() {
            Ok(count) => count,
            Err(error) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    error.to_string(),
                );
            }
        };
        af_db::record_audit(
            auth_user.user_id,
            &auth_user.username,
            "streaming_demo_seed",
            "streaming_demo",
            "jellyfin",
            "seeded",
            &ip,
            ua,
        );
        Json(serde_json::json!({
            "message": "Demo streaming telemetry loaded",
            "demoMode": true,
            "historySeeded": history_seeded,
            "predictionsSeeded": 0,
        }))
        .into_response()
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
    let clean_app = app_name.trim().to_lowercase();
    if clean_app.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "App name is required",
        );
    }
    if req.listen_port < 0 || req.listen_port > 65535 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "listenPort must be between 0 and 65535",
        );
    }

    let clean_public_domain = if req.public_domain.trim().is_empty() {
        String::new()
    } else {
        let norm = af_db::normalize_base_domain(&req.public_domain);
        if norm.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_DOMAIN",
                "Invalid publicDomain",
            );
        }
        norm
    };

    let existing = af_db::get_app_ingress_config(&clean_app).ok().flatten();
    let listen_port = if req.listen_port > 0 {
        req.listen_port
    } else if let Some(ref ex) = existing {
        if ex.listen_port > 0 {
            ex.listen_port
        } else {
            af_services::get_blueprint(&clean_app)
                .map(|b| b.default_port)
                .unwrap_or(0)
        }
    } else {
        af_services::get_blueprint(&clean_app)
            .map(|b| b.default_port)
            .unwrap_or(0)
    };

    let now = Utc::now();
    let cfg = AppIngressConfig {
        app_name: clean_app.clone(),
        public_domain: clean_public_domain.clone(),
        external_access_enabled: req.external_access_enabled,
        listen_port,
        tls_enabled: req.tls_enabled,
        created_at: existing.as_ref().map(|c| c.created_at).unwrap_or(now),
        updated_at: now,
    };
    if let Err(e) = af_db::set_app_ingress_config(&cfg) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        );
    }
    af_db::invalidate_ingress_cache();

    let _ = af_services::mutators::apply_blueprint_app_config(&clean_app, listen_port).await;

    let internal_domain = af_services::get_blueprint(&clean_app)
        .map(|bp| bp.internal_domain)
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| format!("{}.aether.local", clean_app));
    let mut dns_domains = vec![internal_domain];
    if !clean_public_domain.is_empty() && !dns_domains.contains(&clean_public_domain) {
        dns_domains.push(clean_public_domain);
    }
    let _ = af_services::mutators::sync_local_dns_domains(&dns_domains).await;
    let _ = af_services::mutators::sync_network_dns_providers().await;

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

async fn list_pending_actions(Query(q): Query<HashMap<String, String>>) -> Response {
    let status_filter = q
        .get("status")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("pending");

    if !matches!(
        status_filter,
        "pending" | "approved" | "rejected" | "executed" | "failed" | "all"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid status filter. Use: pending, approved, rejected, executed, failed, all",
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
        .unwrap_or(0);

    let all_actions = af_db::list_pending_actions(500, 0).unwrap_or_default();
    let filtered: Vec<_> = if status_filter == "all" {
        all_actions
    } else {
        all_actions
            .into_iter()
            .filter(|a| a.status == status_filter)
            .collect()
    };
    let total = filtered.len();
    let actions: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();
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

fn parse_action_gate_service_command(raw_action: &str) -> Option<(String, String)> {
    let trimmed = raw_action.trim();
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
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let svc = rest.trim();
            if !svc.is_empty() {
                return Some((svc.to_string(), act.to_string()));
            }
        }
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() == 2 && matches!(parts[0], "restart" | "start" | "stop") {
        return Some((parts[1].to_string(), parts[0].to_string()));
    }
    if parts.len() == 3
        && parts[0] == "systemctl"
        && matches!(parts[1], "restart" | "start" | "stop")
    {
        return Some((parts[2].to_string(), parts[1].to_string()));
    }
    None
}

async fn approve_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    match af_db::get_pending_action_by_id(id) {
        Ok(Some(existing)) => {
            if existing.status != "pending" {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    format!("Action already resolved: {}", existing.status),
                );
            }
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
    }

    let Ok(mut action) = af_db::resolve_action(id, "approved", &auth_user.username) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Action not found or already resolved",
        );
    };

    if let Some((svc_name, svc_act)) = parse_action_gate_service_command(&action.action) {
        match af_services::control_service(&svc_name, &svc_act).await {
            Ok(()) => {
                let log_msg = format!(
                    "Service '{}' {} executed successfully by {}",
                    svc_name, svc_act, auth_user.username
                );
                af_db::mark_action_executed(id, &log_msg);
            }
            Err(e) => {
                let err_msg = format!("Failed to {} service '{}': {}", svc_act, svc_name, e);
                af_db::mark_action_failed(id, &err_msg);
            }
        }
        if let Ok(Some(updated)) = af_db::get_pending_action_by_id(id) {
            action = updated;
        }
    }

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
        "status": "approved",
        "message": "Action approved. The originating subsystem will execute it.",
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
        "status": "rejected",
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

// ──────────────────────────────────────────────────────────────────────────────
// Plugin Discovery, Scoped Token Minting & Streaming Reverse Proxy Endpoints
// ──────────────────────────────────────────────────────────────────────────────

static PLUGIN_PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

#[derive(Deserialize, Default)]
struct ListPluginsQuery {
    #[serde(default)]
    include_templates: Option<bool>,
}

async fn list_plugins_handler(Query(q): Query<ListPluginsQuery>) -> Json<serde_json::Value> {
    let all = af_services::plugins::discover_installed_plugins();
    let include_templates = q.include_templates.unwrap_or(true);
    let plugins: Vec<af_services::plugins::PluginInstanceView> = all
        .into_iter()
        .filter(|p| include_templates || !p.is_template)
        .collect();
    let count = plugins.len();
    Json(serde_json::json!({
        "plugins": plugins,
        "count": count,
    }))
}

#[derive(Deserialize, Default)]
struct MintPluginTokenReq {
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

async fn mint_plugin_token_handler(
    Path(plugin_id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: Option<Json<MintPluginTokenReq>>,
) -> Response {
    let clean_id = plugin_id.trim().to_lowercase();
    let discovered = af_services::plugins::discover_installed_plugins();
    let Some(plugin) = discovered.into_iter().find(|p| p.id == clean_id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "PLUGIN_NOT_FOUND",
            format!("Plugin '{}' not found", clean_id),
        );
    };

    if plugin.status == "invalid" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PLUGIN_MANIFEST",
            plugin
                .validation_error
                .unwrap_or_else(|| "Plugin manifest failed validation".to_string()),
        );
    }

    let ttl = body
        .and_then(|Json(r)| r.ttl_seconds)
        .unwrap_or(900)
        .clamp(60, 86400);

    let Ok((token, claims)) =
        mint_plugin_jwt(auth_user.user_id, &plugin.id, &plugin.api_scopes, ttl)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to mint plugin token",
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
        "plugin_token_mint",
        "plugin",
        &plugin.id,
        &format!("scopes={}", plugin.api_scopes.join(",")),
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "plugin_id": plugin.id,
        "token": token,
        "scopes": plugin.api_scopes,
        "allocated_port": plugin.allocated_port,
        "expires_at": claims.exp,
    }))
    .into_response()
}

fn is_plugin_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "host"
    )
}

fn is_plugin_sensitive_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-csrf-token"
    )
}

async fn proxy_plugin_root_request(
    Path(plugin_id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    forward_plugin_proxy_request(plugin_id, String::new(), auth_user, req).await
}

async fn proxy_plugin_request(
    Path((plugin_id, sub_path)): Path<(String, String)>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    forward_plugin_proxy_request(plugin_id, sub_path, auth_user, req).await
}

async fn forward_plugin_proxy_request(
    plugin_id: String,
    sub_path: String,
    auth_user: AuthUser,
    req: Request,
) -> Response {
    let clean_id = plugin_id.trim().to_lowercase();
    if let Some(ref caller_plugin_id) = auth_user.plugin_id {
        if !caller_plugin_id.is_empty() && !caller_plugin_id.eq_ignore_ascii_case(&clean_id) {
            return api_error(
                StatusCode::FORBIDDEN,
                "PLUGIN_SCOPE_DENIED",
                format!(
                    "Plugin '{}' token cannot proxy requests to plugin '{}'",
                    caller_plugin_id, clean_id
                ),
            );
        }
    }

    if sub_path.contains("..")
        || sub_path.contains('\\')
        || sub_path.contains('?')
        || sub_path.contains('#')
        || sub_path.chars().any(|c| c.is_control())
        || std::path::Path::new(&sub_path)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PROXY_PATH",
            "Disallowed path traversal or control characters in plugin proxy route",
        );
    }

    let discovered = af_services::plugins::discover_installed_plugins();
    let Some(plugin) = discovered.into_iter().find(|p| p.id == clean_id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "PLUGIN_NOT_FOUND",
            format!("Plugin '{}' not found", clean_id),
        );
    };

    if plugin.status == "invalid" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PLUGIN_MANIFEST",
            plugin
                .validation_error
                .unwrap_or_else(|| "Plugin manifest failed validation".to_string()),
        );
    }

    let clean_sub = sub_path.trim_start_matches('/');
    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let target_url = if clean_sub.is_empty() {
        format!("http://127.0.0.1:{}/{}", plugin.allocated_port, query_suffix)
    } else {
        format!(
            "http://127.0.0.1:{}/{}{}",
            plugin.allocated_port, clean_sub, query_suffix
        )
    };

    let method_str = req.method().as_str().to_string();
    let incoming_headers = req.headers().clone();
    let Ok(body_bytes) = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await else {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "Plugin proxy request body exceeds 16MB limit",
        );
    };

    let connection_nominated: std::collections::HashSet<String> = incoming_headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();

    let reqwest_method =
        reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream_req = PLUGIN_PROXY_HTTP_CLIENT.request(reqwest_method, &target_url);

    for (k, v) in incoming_headers.iter() {
        let name_str = k.as_str();
        let name_lower = name_str.to_ascii_lowercase();
        if is_plugin_hop_by_hop_header(name_str)
            || is_plugin_sensitive_auth_header(name_str)
            || connection_nominated.contains(&name_lower)
            || name_str.eq_ignore_ascii_case("x-aetherflow-user")
            || name_str.eq_ignore_ascii_case("x-aetherflow-plugin-id")
        {
            continue;
        }
        if let (Ok(rk), Ok(rv)) = (
            reqwest::header::HeaderName::from_bytes(name_str.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            upstream_req = upstream_req.header(rk, rv);
        }
    }

    upstream_req = upstream_req
        .header("X-Aetherflow-User", &auth_user.username)
        .header("X-Aetherflow-Plugin-Id", &plugin.id);

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    match upstream_req.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let upstream_headers = upstream_resp.headers().clone();
            let stream = upstream_resp.bytes_stream();
            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;

            let resp_headers = response.headers_mut();
            for (k, v) in upstream_headers.iter() {
                if is_plugin_hop_by_hop_header(k.as_str()) {
                    continue;
                }
                if let (Ok(hk), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    resp_headers.append(hk, hv);
                }
            }
            response
        }
        Err(err) => api_error(
            StatusCode::BAD_GATEWAY,
            "PLUGIN_UPSTREAM_UNAVAILABLE",
            format!(
                "Companion plugin '{}' on port {} is unavailable: {}",
                plugin.id, plugin.allocated_port, err
            ),
        ),
    }
}

