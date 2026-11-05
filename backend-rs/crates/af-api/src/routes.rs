use crate::auth::{
    admin_only_middleware, api_error, auth_middleware, check_setup_needed, csrf_middleware,
    disable_2fa, get_session, issue_csrf_token, list_active_sessions, local_login, logout,
    mfa_login_verify, refresh_session, revoke_session, setup_2fa, setup_admin, verify_2fa,
    verify_proxy_auth, AuthUser,
};
use crate::embed::spa_fallback_handler;
use crate::intelligence::{
    ai_chat, ai_support, analyze_predictions, approve_mediaflow_item, bandwidth_analyze,
    bandwidth_apply, bookmark_log, decline_mediaflow_item, enroll_worker, get_auth_metrics_history,
    get_bookmarks, get_cluster_nodes, get_log_sources, get_logs, get_mediaflow_queue,
    get_metrics_history, get_predictions, get_system_topology, get_worker_metrics,
    metadata_results, metadata_scan, metadata_status, remove_worker, test_ai_connection,
    trigger_mediaflow_scan,
};
use crate::middlewares::{
    ai_rate_limit_middleware, auth_rate_limit_middleware, host_validation_middleware,
    oidc_rate_limit_middleware, quota_upload_guard_middleware,
};
use crate::network::{
    add_wireguard_peer, advertise_tailscale_routes, generate_wireguard_keys, get_network_status,
    get_tailscale_peers, get_tailscale_status, get_wireguard_peers, network_diagnostics,
    network_service, remove_wireguard_peer, tailscale_connect, tailscale_disconnect,
    tailscale_logout, tailscale_routes, tailscale_settings, update_wireguard_peer,
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
use crate::plugins::{
    control_plugin_handler, list_plugins_handler, mint_plugin_token_handler,
    proxy_plugin_root_handler, proxy_plugin_wildcard_handler, serve_plugin_ui_handler,
};
use crate::storage::{
    check_update, delete_shared_file, download_backup, download_file, get_backups_list,
    get_files_list, get_optimal_backup_window, get_own_quota, get_system_update_status,
    handle_deploy_process, handle_deploy_stream, list_user_quotas, prepare_backup_download,
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
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use chrono::Utc;
use futures::StreamExt;
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

const OPENAPI_YAML: &str = include_str!("../../../../config/openapi-v1.yaml");

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

    let is_legacy_api =
        req.uri().path().starts_with("/api/") && !req.uri().path().starts_with("/api/v1/");
    let req_path = req.uri().path().to_string();

    req.headers_mut().insert(
        "X-Request-ID",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    let is_plugin_ui = req_path.contains("/plugins/") && req_path.ends_with("/ui");

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    if is_plugin_ui {
        h.insert("X-Frame-Options", HeaderValue::from_static("SAMEORIGIN"));
    } else {
        h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    }
    h.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    h.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    if !is_plugin_ui {
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
            ),
        );
    }
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
    let top_level_plugins = Router::new()
        .route("/plugins/:id/ui", get(serve_plugin_ui_handler))
        .route(
            "/plugins/:id/proxy",
            get(proxy_plugin_root_handler)
                .post(proxy_plugin_root_handler)
                .put(proxy_plugin_root_handler)
                .delete(proxy_plugin_root_handler),
        )
        .route(
            "/plugins/:id/proxy/*rest",
            get(proxy_plugin_wildcard_handler)
                .post(proxy_plugin_wildcard_handler)
                .put(proxy_plugin_wildcard_handler)
                .delete(proxy_plugin_wildcard_handler),
        )
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .nest("/api/v1", v1)
        .nest("/api", legacy)
        .merge(top_level_plugins)
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

    let public_routes = Router::new()
        .merge(crate::mcbrowser::public_router())
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
        .merge(oidc_limited_public);

    let ai_limited_auth = Router::new()
        .route("/ai/chat", post(ai_chat))
        .route("/ai/support", post(ai_support))
        .layer(middleware::from_fn(ai_rate_limit_middleware));

    let auth_routes = Router::new()
        .merge(crate::mcbrowser::router())
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
        .route(
            "/fileshare",
            get(get_files_list).layer(middleware::from_fn(quota_upload_guard_middleware)),
        )
        .route(
            "/fileshare/download/:filename",
            get(download_file).layer(middleware::from_fn(quota_upload_guard_middleware)),
        )
        .route("/services", get(get_services))
        .route("/packages/:id/progress", get(package_progress))
        .route("/system/update/check", get(check_update))
        .route("/system/update/status", get(get_system_update_status))
        .route("/system/metrics", get(get_system_metrics))
        .route("/system/metrics/history", get(get_auth_metrics_history))
        .route("/system/hardware", get(get_hardware_info))
        .route("/notifications", get(get_notifications))
        .route("/notifications/:id/read", put(mark_notification_read))
        .route(
            "/notifications/dismiss-all",
            post(dismiss_all_notifications),
        )
        .route("/deploy/stream", get(handle_deploy_stream))
        .route("/deploy/:appName", post(handle_deploy_process))
        .route("/blueprints", get(get_blueprints))
        .route("/blueprints/:appName", get(get_app_blueprint))
        .route("/streaming/dashboard", get(get_streaming_dashboard))
        .route(
            "/streaming/history",
            get(crate::streaming_history::history_handler),
        )
        .route(
            "/streaming/history/export",
            get(crate::streaming_history::history_export_handler),
        )
        .route(
            "/streaming/patterns",
            get(crate::streaming_patterns::patterns_handler),
        )
        .route(
            "/streaming/patterns/activity",
            get(crate::streaming_patterns::activity_handler),
        )
        .route(
            "/streaming/patterns/concurrency",
            get(crate::streaming_patterns::concurrency_handler),
        )
        .route(
            "/streaming/drilldown",
            get(crate::streaming_patterns::drilldown_handler),
        )
        .route(
            "/streaming/drilldown/users",
            get(crate::streaming_patterns::drilldown_users_handler),
        )
        .route(
            "/streaming/drilldown/clients",
            get(crate::streaming_patterns::drilldown_clients_handler),
        )
        .route(
            "/streaming/drilldown/items",
            get(crate::streaming_patterns::drilldown_items_handler),
        )
        .route(
            "/streaming/drilldown/libraries",
            get(crate::streaming_patterns::drilldown_libraries_handler),
        )
        .route(
            "/streaming/drilldown/genres",
            get(crate::streaming_patterns::drilldown_genres_handler),
        )
        .route("/streaming/artwork/:itemId", get(get_streaming_artwork))
        .route("/plugins", get(list_plugins_handler))
        .route("/plugins/:id/ui", get(serve_plugin_ui_handler))
        .route(
            "/plugins/:id/proxy",
            get(proxy_plugin_root_handler)
                .post(proxy_plugin_root_handler)
                .put(proxy_plugin_root_handler)
                .delete(proxy_plugin_root_handler),
        )
        .route(
            "/plugins/:id/proxy/*rest",
            get(proxy_plugin_wildcard_handler)
                .post(proxy_plugin_wildcard_handler)
                .put(proxy_plugin_wildcard_handler)
                .delete(proxy_plugin_wildcard_handler),
        )
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    let quota_guarded_upload = Router::new()
        .route("/fileshare/upload", post(upload_file))
        // Allow multipart framing above the 50 MiB legacy whole-file cap.
        // The handler separately enforces 5 MiB chunks and 50 MiB total files.
        .layer(axum::extract::DefaultBodyLimit::max(51 * 1024 * 1024))
        .layer(middleware::from_fn(quota_upload_guard_middleware));

    let admin_routes = Router::new()
        .route("/plugins", get(list_plugins_handler))
        .route("/plugins/:id/control", post(control_plugin_handler))
        .route("/plugins/:id/token", post(mint_plugin_token_handler))
        .route("/backup/run", post(run_backup))
        .route("/backup/list", get(get_backups_list))
        .route(
            "/backup/download/:filename",
            get(download_backup).post(prepare_backup_download),
        )
        .route("/backup/upload/:filename", post(upload_backup_chunk))
        .route("/settings", get(get_settings).put(update_settings))
        .route("/settings/test-ai", post(test_ai_connection))
        .route("/users", get(get_users))
        .route("/users/:id/role", put(update_user_role))
        .route("/users/:id", delete(delete_user))
        .route("/quotas", get(list_user_quotas))
        .route("/quotas/:id", put(update_user_quota))
        .route("/quotas/:id/refresh", post(refresh_user_quota))
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
        .route("/system/update/status", get(get_system_update_status))
        .route("/system/metrics", get(get_system_metrics))
        .merge(quota_guarded_upload)
        .route(
            "/fileshare/download/:filename",
            get(download_file).layer(middleware::from_fn(quota_upload_guard_middleware)),
        )
        .route(
            "/fileshare/:filename",
            delete(delete_shared_file).layer(middleware::from_fn(quota_upload_guard_middleware)),
        )
        .route("/cluster/nodes", get(get_cluster_nodes))
        .route("/cluster/enroll", post(enroll_worker))
        .route("/cluster/nodes/:id", delete(remove_worker))
        .route("/cluster/nodes/:id/metrics", get(get_worker_metrics))
        .route(
            "/oidc/clients",
            get(get_oidc_clients).post(create_oidc_client),
        )
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
        .route(
            "/ai/backup/schedule",
            post(set_backup_schedule).put(set_backup_schedule),
        )
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
            delete(remove_wireguard_peer).put(update_wireguard_peer),
        )
        .route("/network/wireguard/keygen", post(generate_wireguard_keys))
        .route("/network/tailscale/status", get(get_tailscale_status))
        .route("/network/tailscale/peers", get(get_tailscale_peers))
        .route(
            "/network/tailscale/routes",
            get(tailscale_routes).post(advertise_tailscale_routes),
        )
        .route("/network/tailscale/connect", post(tailscale_connect))
        .route("/network/tailscale/disconnect", post(tailscale_disconnect))
        .route("/network/tailscale/logout", post(tailscale_logout))
        .route("/network/tailscale/settings", post(tailscale_settings))
        .route("/network/:provider/service", post(network_service))
        .route("/network/diagnostics", get(network_diagnostics))
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
            crate::streaming_portability::EXPORT_ROUTE,
            get(crate::streaming_portability::export_handler),
        )
        .route(
            crate::streaming_portability::PREVIEW_ROUTE,
            post(crate::streaming_portability::preview_handler),
        )
        .route(
            crate::streaming_portability::RESTORE_ROUTE,
            post(crate::streaming_portability::restore_handler),
        )
        .route(
            "/streaming/imports/status",
            get(crate::streaming_import::get_streaming_import_status_handler),
        )
        .route(
            "/streaming/imports/events",
            post(crate::streaming_import::import_streaming_events_handler),
        )
        .route(
            "/streaming/imports/upstream-probe",
            post(crate::streaming_import::probe_upstream_event_source_handler),
        )
        .route(
            "/streaming/policies",
            get(crate::streaming_import::get_streaming_policy_handler)
                .put(crate::streaming_import::update_streaming_policy_handler),
        )
        .route(
            "/streaming/user-links",
            get(crate::streaming_import::list_streaming_user_links_handler)
                .put(crate::streaming_import::upsert_streaming_user_link_handler)
                .delete(crate::streaming_import::delete_streaming_user_link_handler),
        )
        .route(
            "/streaming/reconciliation/preview",
            post(crate::streaming_import::preview_legacy_reconciliation_handler),
        )
        .route(
            "/streaming/reconciliation/apply",
            post(crate::streaming_import::apply_legacy_reconciliation_handler),
        )
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
            "version": af_runner::af_release::runtime::runtime_identity().version,
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
    let manager = req.managed_by.trim();
    if manager != "systemd-unit"
        && af_services::resolve_service_control_scope(&name) == "shared-vhost"
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "SHARED_VHOST_CONTROL_UNSUPPORTED",
            format!(
                "{} is hosted as a shared Apache vhost; use the Apache2 Web Server card for daemon-wide controls",
                name
            ),
        );
    }

    let target = if req.process.trim().is_empty() {
        name.clone()
    } else {
        req.process.trim().to_string()
    };

    if manager != "systemd-unit"
        && af_services::resolve_service_control_scope(&target) == "shared-vhost"
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "SHARED_VHOST_CONTROL_UNSUPPORTED",
            format!(
                "{} is hosted as a shared Apache vhost; use the Apache2 Web Server card for daemon-wide controls",
                target
            ),
        );
    }

    let result = if manager.is_empty() {
        af_services::control_service(&target, &req.action).await
    } else {
        af_services::control_service_with_manager(&target, &req.action, manager).await
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
        let mut tls_enabled = true;

        if let Some(ing) = ingress_map.get(&p.name) {
            if ing.listen_port > 0 {
                active_port = ing.listen_port;
            }
            public_domain = ing.public_domain.clone();
            external_access = ing.external_access_enabled;
            tls_enabled = ing.tls_enabled;
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
            tls_enabled,
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

async fn pre_stop_units_for_package_update_with<ResolveFn, StatusFn, ControlFn, ControlFut>(
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
    if action == "update"
        && af_services::should_pre_stop_on_update(clean_id)
        && fs_root_override.trim().is_empty()
    {
        let mut units = resolve_units(clean_id);
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        for unit_name in units {
            if query_status(&unit_name) == "running" {
                if let Err(error) = control_unit(unit_name.clone(), "stop").await {
                    for stopped_unit in &stopped_units {
                        let _ = control_unit(stopped_unit.clone(), "start").await;
                    }
                    return Err((unit_name, error.to_string()));
                }
                stopped_units.push(unit_name);
            }
        }
    }
    Ok(stopped_units)
}

fn load_authoritative_app_ingress_config(
    app_name: &str,
) -> anyhow::Result<Option<AppIngressConfig>> {
    af_db::invalidate_ingress_cache();
    af_db::get_app_ingress_config(app_name)
}

fn resolve_existing_update_port_with<LoadIngressFn>(
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

fn resolve_package_lifecycle_port_with<RuntimePortFn, LoadIngressFn, AllocateInstallPortFn>(
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
        let ingress_port = load_ingress_config(clean_id)
            .ok()
            .flatten()
            .map(|c| c.listen_port)
            .unwrap_or(0);
        let resolved_port = if configured_port > 0 {
            configured_port
        } else if ingress_port > 0 {
            ingress_port
        } else {
            pkg_default_port
        };
        Ok(resolved_port)
    } else if action == "install" {
        let allocated_port = allocate_install_port(clean_id, pkg_default_port);
        if pkg_default_port > 0 && allocated_port <= 0 {
            return Err("No supported listen port is available for this application".to_string());
        }
        Ok(allocated_port)
    } else {
        Ok(pkg_default_port)
    }
}

async fn run_package_lifecycle_dispatch_gate_with<
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

async fn finalize_post_script_lifecycle_with<
    LoadIngressFn,
    SaveIngressFn,
    ControlFn,
    ControlFut,
    RefreshUpdateFn,
    RefreshUpdateFut,
>(
    action: &str,
    clean_id: &str,
    allocated_port: i32,
    stopped_units: Vec<String>,
    base_domain: &str,
    mut load_ingress: LoadIngressFn,
    mut save_ingress: SaveIngressFn,
    mut control_unit: ControlFn,
    mut refresh_update: RefreshUpdateFn,
) -> Result<(), String>
where
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    SaveIngressFn: FnMut(&AppIngressConfig) -> anyhow::Result<()>,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    RefreshUpdateFn: FnMut(String) -> RefreshUpdateFut,
    RefreshUpdateFut: std::future::Future<Output = ()>,
{
    if action != "install" && action != "update" {
        return Ok(());
    }

    let mut required_errors: Vec<String> = Vec::new();

    if allocated_port > 0 {
        match load_ingress(clean_id) {
            Ok(existing) => {
                let public_domain = existing
                    .as_ref()
                    .map(|c| c.public_domain.clone())
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| {
                        if base_domain.is_empty() {
                            String::new()
                        } else {
                            af_services::format_app_public_domain(clean_id, base_domain)
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
                    app_name: clean_id.to_string(),
                    public_domain,
                    external_access_enabled: external_access,
                    listen_port: allocated_port,
                    tls_enabled,
                    created_at: existing.as_ref().map(|c| c.created_at).unwrap_or(now),
                    updated_at: now,
                };
                if let Err(e) = save_ingress(&cfg) {
                    required_errors.push(format!("Failed to persist ingress configuration: {}", e));
                }
            }
            Err(error) => {
                required_errors.push(format!("Failed to load ingress configuration: {}", error))
            }
        }
    }

    if action == "update" && af_services::should_pre_stop_on_update(clean_id) {
        for u in stopped_units {
            if let Err(e) = control_unit(u.clone(), "start").await {
                required_errors.push(format!("Failed to restart stopped unit {}: {}", u, e));
            }
        }
    }

    refresh_update(clean_id.to_string()).await;

    if required_errors.is_empty() {
        Ok(())
    } else {
        Err(required_errors.join("; "))
    }
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
        emit_package_progress(
            &clean_id,
            action,
            status_label,
            10,
            &format!("Preparing environment for {}...", pkg_label),
            &started_at,
        );

        let fs_root_override_raw = env::var("AETHERFLOW_FS_ROOT").unwrap_or_default();
        let fs_root_override =
            Option::from(fs_root_override_raw.clone()).filter(|s| !s.trim().is_empty());
        let can_run_bash =
            cfg!(unix) && fs_root_override.is_none() && std::path::Path::new("/bin/bash").exists();

        let (allocated_port, stopped_units, execution_result) =
            match run_package_lifecycle_dispatch_gate_with(
                action,
                &clean_id,
                pkg_default_port,
                &fs_root_override_raw,
                |app_id| af_services::mutators::get_app_runtime_meta(app_id).configured_port,
                load_authoritative_app_ingress_config,
                allocate_or_resolve_app_port,
                |app_id| af_services::resolve_controllable_service_units(app_id, "restart"),
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
                    let fs_root_override = fs_root_override.clone();
                    async move {
                        emit_package_progress(
                            &clean_id,
                            action,
                            status_label,
                            25,
                            &format!("Executing {} script for {}...", action, pkg_label),
                            &started_at,
                        );

                        if can_run_bash && af_runner::is_runner_available() {
                            af_runner::dispatch_package_stream(
                                action,
                                &clean_id,
                                &script_name,
                                resolved_port,
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
                                app_port: resolved_port,
                            };
                            let stream = af_runner::execute_package_request_stream(request);
                            tokio::pin!(stream);
                            let mut result = Ok(());
                            while let Some(item) = stream.next().await {
                                match item {
                                    Ok(line) => {
                                        if let Some(error) =
                                            line.trim().strip_prefix("__RUNNER_EXIT_ERROR__:")
                                        {
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
                        }
                    }
                },
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error_message) => {
                    emit_package_progress(
                        &clean_id,
                        action,
                        "failed",
                        10,
                        &error_message,
                        &started_at,
                    );
                    af_services::clear_package_job_info(&clean_id);
                    return;
                }
            };

        if let Err(error) = execution_result {
            if af_services::should_pre_stop_on_update(&clean_id) {
                for unit in &stopped_units {
                    let _ =
                        af_services::control_service_with_manager(unit, "start", "systemd-unit")
                            .await;
                }
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
            if let Err(e) =
                af_services::mutators::apply_blueprint_app_config(&clean_id, allocated_port).await
            {
                tracing::warn!(
                    package = %clean_id,
                    port = allocated_port,
                    error = %e,
                    "Optional blueprint app config synchronization warning"
                );
            }

            let (master_user, master_pass, _) = af_services::mutators::load_master_credentials();
            if !master_user.is_empty() && !master_pass.is_empty() {
                af_services::mutators::sync_master_credentials_to_installed_apps(
                    &master_user,
                    &master_pass,
                );
            }

            let base_domain = af_services::resolve_base_domain();
            if let Err(required_err) = finalize_post_script_lifecycle_with(
                action,
                &clean_id,
                allocated_port,
                stopped_units,
                &base_domain,
                |app_id| af_db::get_app_ingress_config(app_id),
                |cfg| af_db::set_app_ingress_config(cfg),
                |unit_name, ctrl_action| async move {
                    af_services::control_service_with_manager(
                        &unit_name,
                        ctrl_action,
                        "systemd-unit",
                    )
                    .await
                },
                |app_id| async move {
                    let _ = af_services::workers::refresh_package_update_by_id(&app_id).await;
                },
            )
            .await
            {
                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                emit_package_progress(&clean_id, action, "failed", 90, &required_err, &started_at);
                af_services::clear_package_job_info(&clean_id);
                return;
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
    Json(build_single_package_update_response(&pkg.name, record)).into_response()
}

fn build_single_package_update_response(
    pkg_name: &str,
    record: Option<af_services::workers::PackageUpdateRecord>,
) -> serde_json::Value {
    let update_available = record.as_ref().map(|r| r.update_available).unwrap_or(false);
    let installed_version = record.as_ref().map(|r| r.installed_version.clone());
    let latest_version = record.as_ref().map(|r| r.latest_version.clone());
    let update_url = record.as_ref().map(|r| r.release_url.clone());
    let checked_at = record.as_ref().map(|r| r.checked_at.clone());
    let last_error = record
        .as_ref()
        .map(|r| r.error.clone())
        .filter(|e| !e.trim().is_empty());
    serde_json::json!({
        "message": "Package update check completed",
        "package": pkg_name,
        "update_available": update_available,
        "installed_version": installed_version,
        "latest_version": latest_version,
        "update_url": update_url,
        "checked_at": checked_at,
        "last_error": last_error,
        "error": last_error,
        "update": record,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings, Profile & Users (`settings.go`, `users.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub ai_model: String,
    #[serde(default)]
    pub local_provider: String,
    #[serde(default)]
    pub local_model: String,
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
    if raw.is_empty() {
        return String::new();
    }
    let dec = match af_db::decrypt_key(raw) {
        Ok(value) if !value.starts_with("enc:v1:") => value,
        _ => return "****".to_string(),
    };
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

fn redact_settings_for_role(payload: &mut SettingsPayload, role: &str) {
    if role != "admin" {
        payload.gemini_api_key.clear();
        payload.openai_api_key.clear();
        payload.anthropic_api_key.clear();
        payload.lm_studio_endpoint.clear();
        payload.ollama_endpoint.clear();
        payload.anthropic_endpoint.clear();
    }
}

async fn get_settings(Extension(user): Extension<AuthUser>) -> Response {
    crate::auth::blocking_response(move || get_settings_for_role(&user.role)).await
}

fn get_settings_for_role(role: &str) -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
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
         COALESCE(anthropic_api_key, ''), COALESCE(anthropic_endpoint, ''), \
         COALESCE(local_provider, ''), COALESCE(local_model, '') FROM settings WHERE id = 1",
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
                local_provider: r.get(14)?,
                local_model: r.get(15)?,
            })
        },
    );

    drop(conn);
    match row {
        Ok(mut payload) => {
            if payload.base_domain.is_empty() {
                payload.base_domain = af_services::resolve_base_domain();
            }
            redact_settings_for_role(&mut payload, role);
            Json(payload).into_response()
        }
        Err(_) => Json(SettingsPayload::default()).into_response(),
    }
}

async fn update_settings(Json(mut req): Json<SettingsPayload>) -> Response {
    req.ai_model = req.ai_model.trim().to_owned();
    req.local_provider = req.local_provider.trim().to_owned();
    req.local_model = req.local_model.trim().to_owned();
    if (!req.local_provider.is_empty()
        && !matches!(
            req.local_provider.as_str(),
            "lm-studio" | "ollama" | "anthropic-local"
        ))
        || (!req.local_model.is_empty()
            && !crate::intelligence::is_valid_local_model_id(&req.local_model))
        || crate::intelligence::is_forbidden_model_alias(&req.ai_model)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AI_SETTINGS",
            "Use a local runtime and an installed model identifier, not a provider alias",
        );
    }
    for endpoint in [
        &mut req.lm_studio_endpoint,
        &mut req.ollama_endpoint,
        &mut req.anthropic_endpoint,
    ] {
        if !endpoint.trim().is_empty() {
            match af_services::validate_server_url(endpoint) {
                Ok(clean) => *endpoint = clean,
                Err(_) => {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_ENDPOINT",
                        "Invalid or disallowed AI endpoint URL",
                    )
                }
            }
        } else {
            endpoint.clear();
        }
    }
    let prev_base_domain = af_db::get_base_domain();

    let Ok(mut conn) = af_db::get_conn() else {
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

    let saved = (|| -> anyhow::Result<()> {
        let transaction =
            conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE settings SET ai_model = ?1, system_prompt = ?2, language = ?3, timezone = ?4, \
         update_channel = ?5, default_dashboard = ?6, setup_completed = ?7, base_domain = ?8, \
         lm_studio_endpoint = ?9, ollama_endpoint = ?10, anthropic_endpoint = ?11, \
         local_provider = ?12, local_model = ?13, \
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
                req.local_provider,
                req.local_model,
            ],
        )?;
        anyhow::ensure!(updated == 1, "Settings row is missing");
        for (column, value) in [
            ("gemini_api_key", &req.gemini_api_key),
            ("openai_api_key", &req.openai_api_key),
            ("anthropic_api_key", &req.anthropic_api_key),
        ] {
            if !value.is_empty() && !value.starts_with("****") {
                let encrypted = af_db::encrypt_key(value)?;
                transaction.execute(
                    &format!("UPDATE settings SET {column} = ?1 WHERE id = 1"),
                    params![encrypted],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    })();
    if let Err(error) = saved {
        tracing::warn!(%error, "Settings update was rolled back");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SETTINGS_SAVE_FAILED",
            "Settings could not be saved",
        );
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
                    let _ =
                        af_services::mutators::apply_blueprint_app_config(&p.name, p.default_port)
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
                StatusCode::FORBIDDEN,
                "INVALID_CURRENT_PASSWORD",
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
        let _ =
            af_services::mutators::save_master_credentials(&auth_user.username, &req.new_password);
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
    if let Err(error) =
        crate::mcbrowser::lifecycle::update_account_role(auth_user.clone(), id, req.role.clone())
            .await
    {
        return error.into_response();
    }
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
    if let Err(error) = crate::mcbrowser::lifecycle::delete_account(auth_user.clone(), id).await {
        return error.into_response();
    }
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

async fn browse_directories(
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<FsQuery>,
) -> Response {
    if auth_user.role != "admin" || crate::mcbrowser::validate_mcbrowser_user(&auth_user).is_err() {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Host filesystem browsing requires admin access",
        );
    }
    tokio::task::spawn_blocking(move || {
        let Ok(connection) = af_db::get_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        };
        let live_admin = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM users AS account
                LEFT JOIN user_quotas AS quota ON quota.user_id = account.id
                WHERE account.id = ?1 AND account.role = 'admin'
                AND account.username NOT LIKE 'plugin:%'
                AND LOWER(TRIM(COALESCE(quota.status, ''))) IN ('', 'active')
            )",
            [auth_user.user_id],
            |row| row.get::<_, bool>(0),
        );
        drop(connection);
        match live_admin {
            Ok(true) => browse_host_directories(query),
            Ok(false) => api_error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Host filesystem browsing requires active admin access",
            ),
            Err(_) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Account authorization unavailable",
            ),
        }
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Filesystem worker failed",
        )
    })
}

fn browse_host_directories(q: FsQuery) -> Response {
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
    if let Some(bp) = all.into_iter().find(|b| b.blueprint.app_name == app_name) {
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
        .unwrap_or(if configured_port > 0 {
            configured_port
        } else {
            bp.default_port
        });
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

    let config_applied =
        af_services::mutators::apply_blueprint_app_config(&app_name, allocated_port)
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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateStreamingServerReq {
    #[serde(default)]
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

pub(crate) async fn update_streaming_server(
    Path(provider): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<UpdateStreamingServerReq>,
) -> Response {
    let norm_provider = provider.trim().to_ascii_lowercase();
    if norm_provider != "jellyfin" && norm_provider != crate::streaming_emby::EMBY_PROVIDER_ID {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Only Jellyfin and Emby connections are supported in this release; Plex support will arrive in a future update.",
        );
    }
    let clean_url = if norm_provider == crate::streaming_emby::EMBY_PROVIDER_ID {
        match crate::streaming_ext::save_emby_server_configuration(
            &req.name,
            &req.url,
            &req.api_key,
            req.enabled,
        ) {
            Ok(u) => u,
            Err(resp) => return resp,
        }
    } else {
        let clean_url = match af_services::validate_server_url(&req.url) {
            Ok(u) => u,
            Err(e) => return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", e.to_string()),
        };

        let trimmed_key = req.api_key.trim();
        let is_masked = trimmed_key.starts_with("****");
        let enc_key = if req.api_key.is_empty() || is_masked {
            String::new()
        } else {
            match af_db::encrypt_key(&req.api_key) {
                Ok(key) => key,
                Err(_) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "STREAMING_KEY_STORAGE_FAILED",
                        "Failed to encrypt provider credential; configuration was not changed",
                    )
                }
            }
        };

        let saved = if let Ok(conn) = af_db::get_conn() {
            if enc_key.is_empty() {
                if let Ok(previous_url) = conn.query_row(
                    "SELECT url FROM streaming_servers WHERE provider = 'jellyfin'",
                    [],
                    |row| row.get::<_, String>(0),
                ) {
                    if previous_url.trim_end_matches('/') != clean_url {
                        return api_error(StatusCode::BAD_REQUEST, "STREAMING_KEY_REQUIRED", "Provide a new API key when changing the provider URL; stored credentials cannot be transferred to another server");
                    }
                }
            }
            let name = if req.name.trim().is_empty() {
                "Jellyfin".to_string()
            } else {
                req.name.trim().to_string()
            };
            conn.execute(
                r#"
                INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
                ON CONFLICT(provider) DO UPDATE SET
                    name = excluded.name,
                    server_id = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_id END,
                    server_version = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_version END,
                    last_connected_at = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN NULL ELSE streaming_servers.last_connected_at END,
                    url = excluded.url,
                    api_key = CASE WHEN excluded.api_key != '' THEN excluded.api_key ELSE streaming_servers.api_key END,
                    enabled = excluded.enabled,
                    updated_at = CURRENT_TIMESTAMP
                "#,
                params![norm_provider, name, clean_url, enc_key, req.enabled],
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
        clean_url
    };

    let provider_label = if norm_provider == crate::streaming_emby::EMBY_PROVIDER_ID {
        "Emby"
    } else {
        "Jellyfin"
    };

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
        &norm_provider,
        &clean_url,
        &ip,
        ua,
    );

    let dash = crate::streaming_ext::build_streaming_dashboard("30", "all", "all", true).await;
    let server = dash
        .servers
        .into_iter()
        .find(|s| s.provider.eq_ignore_ascii_case(&norm_provider));
    Json(serde_json::json!({
        "message": format!("{} server configuration saved", provider_label),
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
    public_domain: Option<String>,
    #[serde(default)]
    external_access_enabled: Option<bool>,
    #[serde(default)]
    listen_port: Option<i32>,
    #[serde(default)]
    tls_enabled: Option<bool>,
}

fn resolve_patched_ingress_config(
    clean_app: &str,
    req: &UpdateIngressReq,
    existing: Option<&AppIngressConfig>,
    blueprint_default_port: i32,
    now: chrono::DateTime<Utc>,
) -> Result<AppIngressConfig, (StatusCode, &'static str, &'static str)> {
    let current_effective_port = existing
        .map(|ex| ex.listen_port)
        .filter(|&p| p > 0)
        .unwrap_or(blueprint_default_port);

    if let Some(requested_port) = req.listen_port {
        if !(0..=65535).contains(&requested_port) {
            return Err((
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "listenPort must be between 0 and 65535",
            ));
        }
        if requested_port > 0
            && current_effective_port > 0
            && requested_port != current_effective_port
        {
            return Err((
                StatusCode::CONFLICT,
                "PORT_RECONFIGURATION_UNSUPPORTED",
                "Changing listenPort via ingress configuration is not supported without native service rebinding and readiness verification",
            ));
        }
        if requested_port > 0 && current_effective_port <= 0 {
            return Err((
                StatusCode::CONFLICT,
                "PORT_RECONFIGURATION_UNSUPPORTED",
                "This application does not support custom ingress listenPort assignment",
            ));
        }
    }

    let clean_public_domain = match req.public_domain.as_ref() {
        Some(raw_domain) => {
            if raw_domain.trim().is_empty() {
                String::new()
            } else {
                let norm = af_db::normalize_base_domain(raw_domain);
                if norm.is_empty() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "INVALID_DOMAIN",
                        "Invalid publicDomain",
                    ));
                }
                norm
            }
        }
        None => existing
            .map(|ex| ex.public_domain.clone())
            .unwrap_or_default(),
    };

    let listen_port = req
        .listen_port
        .filter(|&p| p > 0)
        .unwrap_or(current_effective_port);

    let external_access_enabled = req
        .external_access_enabled
        .or_else(|| existing.map(|ex| ex.external_access_enabled))
        .unwrap_or(!clean_public_domain.is_empty());

    if !(1..=65535).contains(&listen_port) {
        return Err((
            StatusCode::BAD_REQUEST,
            "INVALID_PORT",
            "No valid native listen port is configured for this application",
        ));
    }
    if external_access_enabled && clean_public_domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "INVALID_DOMAIN",
            "A public domain is required to enable external access",
        ));
    }

    let tls_enabled = req
        .tls_enabled
        .or_else(|| existing.map(|ex| ex.tls_enabled))
        .unwrap_or(!clean_public_domain.is_empty());

    Ok(AppIngressConfig {
        app_name: clean_app.to_string(),
        public_domain: clean_public_domain,
        external_access_enabled,
        listen_port,
        tls_enabled,
        created_at: existing.map(|c| c.created_at).unwrap_or(now),
        updated_at: now,
    })
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
    let existing = match af_db::get_app_ingress_config(&clean_app) {
        Ok(config) => config,
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                error.to_string(),
            )
        }
    };
    let runtime_port = af_services::mutators::get_app_runtime_meta(&clean_app).configured_port;
    let blueprint_default_port = if runtime_port > 0 {
        runtime_port
    } else {
        af_services::get_blueprint(&clean_app)
            .map(|blueprint| blueprint.default_port)
            .unwrap_or(0)
    };

    let now = Utc::now();
    let cfg = match resolve_patched_ingress_config(
        &clean_app,
        &req,
        existing.as_ref(),
        blueprint_default_port,
        now,
    ) {
        Ok(cfg) => cfg,
        Err((status, code, msg)) => return api_error(status, code, msg),
    };
    if let Err(e) = af_db::set_app_ingress_config(&cfg) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        );
    }
    af_db::invalidate_ingress_cache();

    let internal_domain = af_services::get_blueprint(&clean_app)
        .map(|bp| bp.internal_domain)
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| format!("{}.aether.local", clean_app));
    let mut dns_domains = vec![internal_domain];
    if !cfg.public_domain.is_empty() && !dns_domains.contains(&cfg.public_domain) {
        dns_domains.push(cfg.public_domain.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_settings_hide_provider_keys_and_private_endpoints() {
        let original = SettingsPayload {
            ai_model: "model".into(),
            language: "en".into(),
            gemini_api_key: "****last".into(),
            openai_api_key: "****tail".into(),
            anthropic_api_key: "****more".into(),
            lm_studio_endpoint: "http://internal:1234".into(),
            ollama_endpoint: "http://internal:11434".into(),
            anthropic_endpoint: "http://private".into(),
            ..Default::default()
        };
        let mut member = original.clone();
        redact_settings_for_role(&mut member, "user");
        for value in [
            &member.gemini_api_key,
            &member.openai_api_key,
            &member.anthropic_api_key,
            &member.lm_studio_endpoint,
            &member.ollama_endpoint,
            &member.anthropic_endpoint,
        ] {
            assert!(value.is_empty());
        }
        assert_eq!(member.ai_model, original.ai_model);
        assert_eq!(member.language, original.language);
        let mut admin = original.clone();
        redact_settings_for_role(&mut admin, "admin");
        assert_eq!(admin.lm_studio_endpoint, original.lm_studio_endpoint);
        assert_eq!(mask_secret("enc:v1:not-decryptable-ciphertext"), "****");
    }

    #[tokio::test]
    async fn wrong_current_password_is_forbidden_without_expiring_session() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let hash = bcrypt::hash("correct-password", 4).unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute("INSERT INTO users (id, username, password_hash, role) VALUES (876, 'password-contract', ?1, 'user')", params![hash]).unwrap();
        drop(conn);
        let response = update_password(
            Extension(AuthUser {
                user_id: 876,
                username: "password-contract".into(),
                role: "user".into(),
                jti: "current-session".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            }),
            HeaderMap::new(),
            Json(ChangePasswordReq {
                current_password: "wrong".into(),
                new_password: "new-password".into(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response
            .headers()
            .contains_key(axum::http::header::SET_COOKIE));
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], "INVALID_CURRENT_PASSWORD");
    }

    #[tokio::test]
    async fn test_dispatch_package_update_pre_stop_skips_maintainerr_and_stops_radarr() {
        use std::sync::{Arc, Mutex};

        let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let maintainerr_recorder = Arc::clone(&recorded_control_actions);

        let maintainerr_stopped = pre_stop_units_for_package_update_with(
            "update",
            "maintainerr",
            "",
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder_handle = Arc::clone(&maintainerr_recorder);
                async move {
                    recorder_handle
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
        )
        .await
        .expect("maintainerr pre-stop decision should succeed");
        assert!(
            maintainerr_stopped.is_empty(),
            "maintainerr must not be pre-stopped by API update dispatcher"
        );
        assert!(
            recorded_control_actions.lock().unwrap().is_empty(),
            "control callback must not receive stop for maintainerr"
        );

        let radarr_recorder = Arc::clone(&recorded_control_actions);
        let radarr_stopped = pre_stop_units_for_package_update_with(
            "update",
            "radarr",
            "",
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder_handle = Arc::clone(&radarr_recorder);
                async move {
                    recorder_handle
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
        )
        .await
        .expect("radarr pre-stop decision should succeed");

        assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
        assert_eq!(
            *recorded_control_actions.lock().unwrap(),
            vec!["stop radarr".to_string()]
        );

        recorded_control_actions.lock().unwrap().clear();
        for shared_app in ["nextcloud", "rutorrent", "organizr"] {
            let recorder = Arc::clone(&recorded_control_actions);
            let stopped = pre_stop_units_for_package_update_with(
                "update",
                shared_app,
                "",
                af_services::resolve_service_units,
                |_unit_name| "running".to_string(),
                move |unit_name, control_action| {
                    let recorder_handle = Arc::clone(&recorder);
                    async move {
                        recorder_handle
                            .lock()
                            .unwrap()
                            .push(format!("{} {}", control_action, unit_name));
                        Ok(())
                    }
                },
            )
            .await
            .expect("shared-vhost pre-stop decision should succeed");
            assert!(
                stopped.is_empty(),
                "{} must not pre-stop shared apache2 on update",
                shared_app
            );
        }
        assert!(
            recorded_control_actions.lock().unwrap().is_empty(),
            "shared-vhost updates must not invoke stop on apache2"
        );
    }

    #[tokio::test]
    async fn test_dispatch_package_update_maintainerr_port_preservation_and_fail_closed() {
        use std::sync::{Arc, Mutex};

        let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_dispatch_ports: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
        let queried_apps: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        for alias_id in ["maintainerr", "af-maintainerr", "af-maintainerr.service"] {
            recorded_control_actions.lock().unwrap().clear();
            recorded_dispatch_ports.lock().unwrap().clear();
            queried_apps.lock().unwrap().clear();

            let control_recorder = Arc::clone(&recorded_control_actions);
            let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
            let app_recorder = Arc::clone(&queried_apps);

            let (allocated_port, stopped_units, dispatch_res) =
                run_package_lifecycle_dispatch_gate_with(
                    "update",
                    alias_id,
                    6246,
                    "",
                    |_app_id| 0,
                    move |app_id| {
                        app_recorder.lock().unwrap().push(app_id.to_string());
                        Ok(Some(AppIngressConfig {
                            app_name: app_id.to_string(),
                            listen_port: 17420,
                            ..Default::default()
                        }))
                    },
                    |_app_id, _default_port| 6246,
                    af_services::resolve_service_units,
                    |_unit_name| "running".to_string(),
                    move |unit_name, control_action| {
                        let recorder = Arc::clone(&control_recorder);
                        async move {
                            recorder
                                .lock()
                                .unwrap()
                                .push(format!("{} {}", control_action, unit_name));
                            Ok(())
                        }
                    },
                    move |port| {
                        let recorder = Arc::clone(&dispatch_recorder);
                        async move {
                            recorder.lock().unwrap().push(port);
                            Ok(())
                        }
                    },
                )
                .await
                .expect("maintainerr update with valid non-default port should succeed");

            assert!(dispatch_res.is_ok());
            assert_eq!(allocated_port, 17420);
            assert!(stopped_units.is_empty());
            assert_eq!(
                *queried_apps.lock().unwrap(),
                vec!["maintainerr".to_string()]
            );
            assert!(
                recorded_control_actions.lock().unwrap().is_empty(),
                "maintainerr update must not invoke unit control for {}",
                alias_id
            );
            assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
        }

        // Missing ingress row must fail closed before any unit control or package dispatch
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let missing_err = run_package_lifecycle_dispatch_gate_with(
            "update",
            "maintainerr",
            6246,
            "",
            |_app_id| 0,
            |_app_id| Ok(None),
            |_app_id, _default_port| 6246,
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder = Arc::clone(&control_recorder);
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
            move |port| {
                let recorder = Arc::clone(&dispatch_recorder);
                async move {
                    recorder.lock().unwrap().push(port);
                    Ok(())
                }
            },
        )
        .await
        .expect_err("missing ingress mapping must fail closed");
        assert!(
            missing_err.contains("missing persisted ingress port mapping for maintainerr update"),
            "unexpected missing-mapping error: {}",
            missing_err
        );
        assert!(recorded_control_actions.lock().unwrap().is_empty());
        assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

        // Unreadable DB / query error must fail closed without falling back to 6246
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let db_err = run_package_lifecycle_dispatch_gate_with(
            "update",
            "maintainerr",
            6246,
            "",
            |_app_id| 0,
            |_app_id| Err(anyhow::anyhow!("sqlite disk I/O error")),
            |_app_id, _default_port| 6246,
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder = Arc::clone(&control_recorder);
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
            move |port| {
                let recorder = Arc::clone(&dispatch_recorder);
                async move {
                    recorder.lock().unwrap().push(port);
                    Ok(())
                }
            },
        )
        .await
        .expect_err("unreadable ingress DB must fail closed");
        assert!(
            db_err.contains("cannot read existing configured port for maintainerr")
                && db_err.contains("sqlite disk I/O error"),
            "unexpected DB error: {}",
            db_err
        );
        assert!(recorded_control_actions.lock().unwrap().is_empty());
        assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

        // Out-of-range / invalid ports must fail closed with zero control or dispatch calls
        for invalid_port in [0, -1, 80, 1023, 65536, 70000] {
            recorded_control_actions.lock().unwrap().clear();
            recorded_dispatch_ports.lock().unwrap().clear();
            let control_recorder = Arc::clone(&recorded_control_actions);
            let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
            let port_err = run_package_lifecycle_dispatch_gate_with(
                "update",
                "maintainerr",
                6246,
                "",
                |_app_id| 0,
                move |app_id| {
                    Ok(Some(AppIngressConfig {
                        app_name: app_id.to_string(),
                        listen_port: invalid_port,
                        ..Default::default()
                    }))
                },
                |_app_id, _default_port| 6246,
                af_services::resolve_service_units,
                |_unit_name| "running".to_string(),
                move |unit_name, control_action| {
                    let recorder = Arc::clone(&control_recorder);
                    async move {
                        recorder
                            .lock()
                            .unwrap()
                            .push(format!("{} {}", control_action, unit_name));
                        Ok(())
                    }
                },
                move |port| {
                    let recorder = Arc::clone(&dispatch_recorder);
                    async move {
                        recorder.lock().unwrap().push(port);
                        Ok(())
                    }
                },
            )
            .await
            .expect_err("invalid persisted port must fail closed");
            assert!(
                port_err.contains(&format!(
                    "invalid persisted listen port {} for maintainerr update",
                    invalid_port
                )),
                "unexpected error for invalid port {}: {}",
                invalid_port,
                port_err
            );
            assert!(recorded_control_actions.lock().unwrap().is_empty());
            assert!(recorded_dispatch_ports.lock().unwrap().is_empty());
        }

        // Unrelated package update (radarr) preserves fallback to default_port and pre-stops unit
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let (radarr_port, radarr_stopped, radarr_res) = run_package_lifecycle_dispatch_gate_with(
            "update",
            "radarr",
            7878,
            "",
            |_app_id| 0,
            |_app_id| Ok(None),
            |_app_id, _default_port| 7878,
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder = Arc::clone(&control_recorder);
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
            move |port| {
                let recorder = Arc::clone(&dispatch_recorder);
                async move {
                    recorder.lock().unwrap().push(port);
                    Ok(())
                }
            },
        )
        .await
        .expect("radarr update should fall back to default port when unconfigured");
        assert!(radarr_res.is_ok());
        assert_eq!(radarr_port, 7878);
        assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
        assert_eq!(
            *recorded_control_actions.lock().unwrap(),
            vec!["stop radarr".to_string()]
        );
        assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![7878]);

        // Fresh install of maintainerr preserves install port allocation without pre-existing ingress
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let (install_port, install_stopped, install_res) =
            run_package_lifecycle_dispatch_gate_with(
                "install",
                "maintainerr",
                6246,
                "",
                |_app_id| 0,
                |_app_id| Ok(None),
                |_app_id, _default_port| 17420,
                af_services::resolve_service_units,
                |_unit_name| "running".to_string(),
                move |unit_name, control_action| {
                    let recorder = Arc::clone(&control_recorder);
                    async move {
                        recorder
                            .lock()
                            .unwrap()
                            .push(format!("{} {}", control_action, unit_name));
                        Ok(())
                    }
                },
                move |port| {
                    let recorder = Arc::clone(&dispatch_recorder);
                    async move {
                        recorder.lock().unwrap().push(port);
                        Ok(())
                    }
                },
            )
            .await
            .expect("fresh maintainerr install should allocate port");
        assert!(install_res.is_ok());
        assert_eq!(install_port, 17420);
        assert!(install_stopped.is_empty());
        assert!(recorded_control_actions.lock().unwrap().is_empty());
        assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
    }

    #[test]
    fn test_single_package_update_response_flattens_contract_fields() {
        let rec = af_services::workers::PackageUpdateRecord {
            package_id: "radarr".to_string(),
            installed: true,
            installed_version: "5.14.0".to_string(),
            latest_version: "5.15.0".to_string(),
            update_available: true,
            checked_at: "2026-11-02T12:00:00Z".to_string(),
            release_url: "https://github.com/Radarr/Radarr/releases/tag/v5.15.0".to_string(),
            error: "github rate limit warning".to_string(),
        };
        let body = build_single_package_update_response("radarr", Some(rec));
        assert_eq!(body["package"], "radarr");
        assert_eq!(body["update_available"], true);
        assert_eq!(body["installed_version"], "5.14.0");
        assert_eq!(body["latest_version"], "5.15.0");
        assert_eq!(
            body["update_url"],
            "https://github.com/Radarr/Radarr/releases/tag/v5.15.0"
        );
        assert_eq!(body["checked_at"], "2026-11-02T12:00:00Z");
        assert_eq!(body["last_error"], "github rate limit warning");
        assert_eq!(body["error"], "github rate limit warning");
        assert_eq!(body["update"]["package_id"], "radarr");
    }

    #[tokio::test]
    async fn test_finalize_post_script_lifecycle_required_failures_and_install_refresh() {
        use std::sync::{Arc, Mutex};

        let refreshed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let refresh_handle = Arc::clone(&refreshed);

        let ok_res = finalize_post_script_lifecycle_with(
            "install",
            "radarr",
            7878,
            Vec::new(),
            "example.com",
            |_app_id| Ok(None),
            |_cfg| Ok(()),
            |_unit, _action| async move { Ok(()) },
            move |app_id| {
                let r = Arc::clone(&refresh_handle);
                async move {
                    r.lock().unwrap().push(app_id);
                }
            },
        )
        .await;
        assert!(ok_res.is_ok());
        assert_eq!(*refreshed.lock().unwrap(), vec!["radarr".to_string()]);

        let err_ingress = finalize_post_script_lifecycle_with(
            "install",
            "radarr",
            7878,
            Vec::new(),
            "example.com",
            |_app_id| Ok(None),
            |_cfg| Err(anyhow::anyhow!("sqlite locked")),
            |_unit, _action| async move { Ok(()) },
            |_app_id| async move {},
        )
        .await
        .expect_err("ingress persistence failure must fail required post-script stage");
        assert!(err_ingress.contains("Failed to persist ingress configuration"));

        let restored = Arc::new(Mutex::new(Vec::new()));
        let restore_handle = Arc::clone(&restored);
        let err_read = finalize_post_script_lifecycle_with(
            "update",
            "radarr",
            7878,
            vec!["radarr".to_string()],
            "example.com",
            |_app_id| Err(anyhow::anyhow!("sqlite read failed")),
            |_cfg| panic!("failed read must not overwrite ingress"),
            move |unit, _action| {
                restore_handle.lock().unwrap().push(unit);
                async { Ok(()) }
            },
            |_app_id| async {},
        )
        .await
        .expect_err("failed ingress read must fail required synchronization");
        assert!(err_read.contains("Failed to load ingress configuration"));
        assert_eq!(*restored.lock().unwrap(), vec!["radarr".to_string()]);

        let err_restart = finalize_post_script_lifecycle_with(
            "update",
            "radarr",
            7878,
            vec!["radarr".to_string()],
            "example.com",
            |_app_id| Ok(None),
            |_cfg| Ok(()),
            |unit, _action| async move { Err(anyhow::anyhow!("{} failed to start", unit)) },
            |_app_id| async move {},
        )
        .await
        .expect_err("stopped unit restart failure must fail required post-script stage");
        assert!(err_restart.contains("Failed to restart stopped unit radarr"));
    }

    #[test]
    fn test_resolve_patched_ingress_config_preserves_omitted_fields_and_rejects_port_change() {
        let now = Utc::now();
        let existing = AppIngressConfig {
            app_name: "radarr".to_string(),
            public_domain: "radarr.example.com".to_string(),
            external_access_enabled: true,
            listen_port: 17878,
            tls_enabled: true,
            created_at: now,
            updated_at: now,
        };

        let req_patch: UpdateIngressReq = serde_json::from_value(serde_json::json!({
            "publicDomain": "movies.example.com",
            "externalAccessEnabled": false
        }))
        .unwrap();

        let patched =
            resolve_patched_ingress_config("radarr", &req_patch, Some(&existing), 7878, now)
                .expect("omitted listenPort and tlsEnabled should be preserved");
        assert_eq!(patched.public_domain, "movies.example.com");
        assert!(!patched.external_access_enabled);
        assert_eq!(patched.listen_port, 17878);
        assert!(patched.tls_enabled);

        let req_port_change: UpdateIngressReq = serde_json::from_value(serde_json::json!({
            "listenPort": 18999
        }))
        .unwrap();
        let err =
            resolve_patched_ingress_config("radarr", &req_port_change, Some(&existing), 7878, now)
                .expect_err("changing listenPort via ingress config must fail closed");
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1, "PORT_RECONFIGURATION_UNSUPPORTED");
    }
    #[tokio::test]
    async fn test_update_prestop_uses_daemon_and_timer_policy_not_jobs_or_unconfigured_mounts() {
        for (app, expected) in [
            ("recyclarr", vec!["recyclarr.timer".to_string()]),
            ("rclone", vec!["rclone".to_string()]),
        ] {
            let stopped = pre_stop_units_for_package_update_with(
                "update",
                app,
                "",
                |app_id| {
                    af_services::resolve_controllable_service_units_with(app_id, "restart", false)
                },
                |_unit| "running".to_string(),
                |_unit, _action| async { Ok(()) },
            )
            .await
            .unwrap();
            assert_eq!(stopped, expected);
        }
    }
}

#[cfg(test)]
mod hillclimb_tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn local_ai_settings_round_trip_runtime_and_installed_model_without_overriding_cloud_selection(
    ) {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        af_db::get_conn().unwrap().execute("INSERT INTO users(id, username, role) VALUES(678, 'local-settings-contract', 'admin')", []).unwrap();
        let (token, _) = crate::auth::create_standard_jwt(678, &HeaderMap::new()).unwrap();
        let app = build_router();
        for runtime in ["lm-studio", "ollama", "anthropic-local"] {
            for model in ["qwen2.5:14b", "gemini-4-argon"] {
                let payload = SettingsPayload {
                    ai_model: model.to_owned(),
                    local_provider: runtime.to_owned(),
                    local_model: "qwen2.5:14b".to_owned(),
                    ..Default::default()
                };
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .method("PUT")
                            .uri("/api/v1/admin/settings")
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(axum::body::Body::from(
                                serde_json::to_vec(&payload).unwrap(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{runtime} {model}");
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/api/v1/auth/settings")
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                let returned: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(returned["aiModel"], model);
                assert_eq!(returned["localProvider"], runtime);
                assert_eq!(returned["localModel"], "qwen2.5:14b");
                let provider = crate::intelligence::resolve_provider_settings();
                assert_eq!(provider.default_model, model);
                assert_eq!(provider.local_model, "qwen2.5:14b");
                assert_eq!(
                    provider.local_provider,
                    if model == "gemini-4-argon" {
                        ""
                    } else {
                        runtime
                    }
                );
            }
        }
        let mut legacy_payload = serde_json::to_value(SettingsPayload::default()).unwrap();
        legacy_payload
            .as_object_mut()
            .unwrap()
            .remove("localProvider");
        legacy_payload.as_object_mut().unwrap().remove("localModel");
        let legacy: SettingsPayload = serde_json::from_value(legacy_payload).unwrap();
        assert!(legacy.local_provider.is_empty() && legacy.local_model.is_empty());
    }

    #[tokio::test]
    async fn settings_persistence_failure_does_not_report_success_or_change_saved_fields() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET ai_model='gemini-4-argon', system_prompt='preserved' WHERE id=1",
            [],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER fail_settings_update BEFORE UPDATE OF local_provider ON settings BEGIN SELECT RAISE(FAIL, 'forced persistence failure'); END;").unwrap();
        drop(conn);
        let payload = SettingsPayload {
            ai_model: "qwen2.5:14b".to_owned(),
            local_provider: "ollama".to_owned(),
            local_model: "qwen2.5:14b".to_owned(),
            system_prompt: "not-saved".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            update_settings(Json(payload)).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let conn = af_db::get_conn().unwrap();
        let saved: (String, String) = conn
            .query_row(
                "SELECT ai_model, system_prompt FROM settings WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(saved, ("gemini-4-argon".to_owned(), "preserved".to_owned()));
    }

    #[tokio::test]
    async fn role_routes_reject_last_usable_admin_demotion_and_failed_writes_without_success_audit()
    {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("INSERT INTO users(id, username, role) VALUES(679, 'role-operator', 'admin'), (680, 'role-target', 'user'), (681, 'disabled-role-admin', 'admin'); INSERT INTO user_quotas(user_id,username,status) VALUES(681, 'disabled-role-admin', 'suspended'); CREATE TRIGGER fail_role_update BEFORE UPDATE OF role ON users WHEN NEW.id=680 BEGIN SELECT RAISE(FAIL, 'forced persistence failure'); END;").unwrap();
        drop(conn);
        let (token, _) = crate::auth::create_standard_jwt(679, &HeaderMap::new()).unwrap();
        let app = build_router();
        for (target, role, expected) in [
            (679, "user", StatusCode::BAD_REQUEST),
            (680, "admin", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("PUT")
                        .uri(format!("/api/v1/admin/users/{target}/role"))
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(
                            serde_json::json!({"role":role}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let conn = af_db::get_conn().unwrap();
        let success_audits: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM admin_audit_log WHERE action='user_role_change'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(success_audits, 0);
        let role: String = conn
            .query_row("SELECT role FROM users WHERE id=680", [], |row| row.get(0))
            .unwrap();
        assert_eq!(role, "user");
    }

    #[tokio::test]
    async fn ai_endpoint_settings_reject_invalid_targets_before_persistence() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users(id, username, role) VALUES(677, 'settings-contract', 'admin')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE settings SET lm_studio_endpoint='http://localhost:1234' WHERE id=1",
            [],
        )
        .unwrap();
        drop(conn);
        let (token, _) = crate::auth::create_standard_jwt(677, &HeaderMap::new()).unwrap();
        let app = build_router();
        for (name, invalid) in [
            ("lmStudioEndpoint", "file:///etc/unused"),
            ("ollamaEndpoint", "http://169.254.169.254"),
            ("anthropicEndpoint", "https://fixture:password@example.test"),
        ] {
            let mut payload = serde_json::to_value(SettingsPayload::default()).unwrap();
            payload[name] = invalid.into();
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("PUT")
                        .uri("/api/v1/admin/settings")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let stored: String = af_db::get_conn()
                .unwrap()
                .query_row(
                    "SELECT lm_studio_endpoint FROM settings WHERE id=1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stored, "http://localhost:1234");
        }
    }
}
