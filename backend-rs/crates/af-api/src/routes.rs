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
        .route("/ready", get(authenticated_ready))
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
        .route("/services/restart/status", get(get_core_restart_status))
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

async fn authenticated_ready() -> Response {
    let ready = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(|| -> anyhow::Result<()> {
            let conn = af_db::get_conn()?;
            let value: i32 = conn.query_row("SELECT 1", [], |row| row.get(0))?;
            anyhow::ensure!(value == 1, "database readiness probe failed");
            Ok(())
        }),
    )
    .await;
    let healthy = matches!(ready, Ok(Ok(Ok(()))));
    (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "service": "aetherflow-api",
            "status": if healthy { "ready" } else { "not_ready" },
            "database": if healthy { "ok" } else { "unreachable" },
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

async fn get_services(Extension(auth_user): Extension<AuthUser>) -> Response {
    let diagnostics_allowed = crate::ws::package_diagnostics_allowed(&auth_user);
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let jobs = af_services::package_job_snapshot()?;
            af_services::get_active_services_with_jobs(&jobs)
        }),
    )
    .await
    {
        Ok(Ok(Ok(services))) => {
            let mut services = serde_json::to_value(services).unwrap_or_default();
            if !diagnostics_allowed {
                crate::ws::sanitize_services_for_viewer(&mut services);
            }
            Json(services).into_response()
        }
        _ => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Service status could not be confirmed; retry shortly",
        ),
    }
}

#[derive(Clone, Deserialize)]
struct ServiceControlReq {
    action: String,
    #[serde(default)]
    managed_by: String,
    #[serde(default)]
    process: String,
}

/// Validates a Services control request before any privileged command runs.
/// Returns the exact target to control, or an `(status, code, message)` error.
fn validate_service_control_request(
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

fn service_control_failure_response(error: &anyhow::Error, target: &str, action: &str) -> Response {
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

async fn control_service_handler(
    Path(name): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<ServiceControlReq>,
) -> Response {
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

async fn get_core_restart_status(Query(query): Query<HashMap<String, String>>) -> Response {
    let unit = query.get("job_unit").map(String::as_str).unwrap_or("");
    if !unit.starts_with("aetherflow-self-update-restart-")
        || !af_models::is_valid_self_update_job_unit_name(unit)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RESTART_RECEIPT",
            "A valid core restart receipt is required",
        );
    }
    crate::storage::get_system_update_status(Query(query)).await
}

async fn get_marketplace_apps() -> Response {
    tokio::task::spawn_blocking(get_marketplace_apps_blocking)
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Marketplace status unavailable",
            )
        })
}

fn get_marketplace_apps_blocking() -> Response {
    let Ok(jobs) = af_services::package_job_snapshot() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Lifecycle status could not be confirmed; retry shortly",
        );
    };
    let Ok(pkgs) = af_services::get_packages_with_jobs(&jobs) else {
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
            job_id: None,
            log_line: String::new(),
            installed_version: p.installed_version,
            latest_version: p.latest_version,
            update_available: p.update_available,
            update_checked_at: p.update_checked_at,
            update_url: p.update_url,
            update_error: af_services::workers::public_update_error(&p.update_error),
            last_job: jobs.outcomes.get(&p.name).cloned().map(public_job_outcome),
        };

        if let Some(job) = jobs.active.get(&p.name).cloned() {
            app.progress = job.progress;
            app.job_id = Some(job.job_id);
            app.started_at = Some(job.started_at);
            app.log_line = format!("{} application…", job.status);
        }

        apps.push(app);
    }

    Json(apps).into_response()
}

fn public_job_outcome(outcome: af_services::PackageJobOutcome) -> af_models::MarketplaceJobOutcome {
    af_models::MarketplaceJobOutcome {
        job_id: outcome.job_id,
        action: outcome.action,
        status: outcome.status,
        started_at: outcome.started_at,
        finished_at: outcome.finished_at,
    }
}

fn package_progress_payload(
    id: &str,
    active: Option<af_services::PackageJobInfo>,
    outcome: Option<af_services::PackageJobOutcome>,
    diagnostics_allowed: bool,
) -> serde_json::Value {
    if let Some(mut job) = active {
        if !diagnostics_allowed {
            job.last_line = af_services::package_job_progress_summary(&job.status).into();
        }
        return serde_json::to_value(job).unwrap_or_default();
    }
    if let Some(mut outcome) = outcome {
        // Authenticated view: include the terminal failure message so clients
        // can report why a job failed after the active entry is gone.
        if !diagnostics_allowed {
            outcome.message = af_services::package_job_progress_summary(&outcome.status).into();
        }
        return serde_json::json!({
            "package_id": id,
            "job_id": outcome.job_id,
            "action": outcome.action,
            "status": outcome.status,
            "progress": if outcome.status == "completed" { 100 } else { 0 },
            "last_line": outcome.message,
            "message": outcome.message,
            "started_at": outcome.started_at,
            "finished_at": outcome.finished_at,
            "last_job": outcome,
        });
    }
    serde_json::json!({
        "package_id": id,
        "status": "idle",
        "progress": 0,
    })
}

async fn package_progress(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let diagnostics_allowed = crate::ws::package_diagnostics_allowed(&auth_user);
    tokio::task::spawn_blocking(move || {
        let Ok(jobs) = af_services::package_job_snapshot() else {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Lifecycle status could not be confirmed; retry shortly",
            );
        };
        Json(package_progress_payload(
            &id,
            jobs.active.get(&id).cloned(),
            jobs.outcomes.get(&id).cloned(),
            diagnostics_allowed,
        ))
        .into_response()
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STATUS_UNAVAILABLE",
            "Lifecycle status could not be confirmed; retry shortly",
        )
    })
}

async fn install_package(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle(id, "install", "installing", false, auth_user, headers).await
}

#[derive(Debug, Default, Deserialize)]
struct UninstallQuery {
    #[serde(default)]
    purge: Option<String>,
}

/// Removal is data-preserving unless the caller explicitly asks for a purge
/// with `?purge=true`. Any other value is rejected rather than guessed.
fn parse_uninstall_purge(query: &UninstallQuery) -> Result<bool, String> {
    match query.purge.as_deref().map(str::trim) {
        None | Some("") | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => Err(format!(
            "Invalid purge value {:?}; use purge=true for an explicit data purge",
            other
        )),
    }
}

async fn uninstall_package(
    Path(id): Path<String>,
    Query(query): Query<UninstallQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    let purge = match parse_uninstall_purge(&query) {
        Ok(purge) => purge,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message),
    };
    dispatch_package_lifecycle(id, "remove", "uninstalling", purge, auth_user, headers).await
}

async fn update_package(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle(id, "update", "updating", false, auth_user, headers).await
}

/// Ends a lifecycle job: records the terminal outcome (so polling clients can
/// distinguish failure from success) and broadcasts the terminal event.
fn finish_package_lifecycle(
    pkg_id: &str,
    action: &str,
    failure: Option<af_services::PackageJobFailure>,
    progress: i32,
    message: &str,
    started_at: &str,
    job_id: &str,
) {
    let succeeded = failure.is_none();
    let outcome = match failure {
        Some(failure) => af_services::fail_package_job(pkg_id, action, failure, job_id),
        None => af_services::finish_package_job(pkg_id, action, true, message, job_id),
    };
    let Some(outcome) = outcome else {
        return;
    };
    broadcast_ws_message(&serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": outcome.status,
        "progress": if succeeded { 100 } else { progress },
        "line": message,
        "started_at": started_at,
        "job_id": outcome.job_id,
        "finished_at": outcome.finished_at,
    }));
}

struct SystemUpdateLifecycleBlock {
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
async fn system_update_lifecycle_block_with<QueryFn, QueryFut>(
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

async fn system_update_lifecycle_block() -> Option<SystemUpdateLifecycleBlock> {
    system_update_lifecycle_block_with(|| async {
        af_runner::dispatch_self_update_status_request(&af_models::SelfUpdateStatusRequest {
            job_unit: String::new(),
        })
        .await
    })
    .await
}

fn allocate_or_resolve_app_port(app_name: &str, default_port: i32) -> i32 {
    if let Ok(Some(existing)) = load_authoritative_app_ingress_config(app_name) {
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
    job_id: &str,
) {
    let info = af_services::PackageJobInfo {
        job_id: job_id.to_string(),
        package_id: pkg_id.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        progress,
        last_line: line.to_string(),
        started_at: started_at.to_string(),
    };
    let Some(info) = af_services::set_package_job_info(info) else {
        return;
    };
    let progress = info.progress;
    broadcast_ws_message(&serde_json::json!({
        "type": "package:progress",
        "package_id": pkg_id,
        "action": action,
        "status": status,
        "job_id": job_id,
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
        units.sort();
        units.dedup();
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        let mut running_units = Vec::new();
        for unit_name in units {
            match query_status(&unit_name).as_str() {
                "running" => running_units.push(unit_name),
                "stopped" | "failed" | "idle" => {},
                observation => return Err((unit_name, format!("Required service state is unconfirmed ({observation}); update was not started"))),
            }
        }
        for unit_name in running_units {
            stopped_units.push(unit_name.clone());
            if let Err(error) = control_unit(unit_name.clone(), "stop").await {
                let mut errors = vec![error.to_string()];
                for stopped_unit in stopped_units.iter().rev() {
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

fn load_authoritative_app_ingress_config(
    app_name: &str,
) -> anyhow::Result<Option<AppIngressConfig>> {
    af_db::invalidate_ingress_cache();
    let conn = af_db::get_conn()?;
    af_db::load_lifecycle_ingress(&conn, app_name)
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
        let ingress = load_ingress_config(clean_id).map_err(|error| {
            format!("cannot read existing configured port for {clean_id}: {error}")
        })?;
        let ingress_port = ingress.map(|config| config.listen_port).unwrap_or(0);
        let resolved_port = if (1..=65535).contains(&configured_port) {
            configured_port
        } else if (1..=65535).contains(&ingress_port) {
            ingress_port
        } else if pkg_default_port <= 0 {
            0
        } else {
            return Err(format!(
                "existing configured port for {clean_id} update is unavailable"
            ));
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

#[derive(Debug)]
struct PackageLifecycleFailure {
    kind: af_services::PackageJobFailure,
    message: String,
}

fn merge_blueprint_finalization(
    finalization: Result<(), PackageLifecycleFailure>,
    blueprint_error: Option<String>,
) -> Result<(), PackageLifecycleFailure> {
    match (finalization, blueprint_error) {
        (result, None) => result,
        (Ok(()), Some(error)) => Err(PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::Configuration,
            message: format!("Required blueprint configuration synchronization failed: {error}"),
        }),
        (Err(mut failure), Some(error)) => {
            if failure.kind == af_services::PackageJobFailure::ServiceRestore {
                failure.kind = af_services::PackageJobFailure::ConfigurationAndServiceRestore;
            }
            failure.message.push_str(&format!(
                "; Required blueprint configuration synchronization failed: {error}"
            ));
            Err(failure)
        }
    }
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
) -> Result<(), PackageLifecycleFailure>
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
    let mut configuration_failed = false;
    let mut service_restore_failed = false;

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
                    configuration_failed = true;
                    required_errors.push(format!("Failed to persist ingress configuration: {}", e));
                }
            }
            Err(error) => {
                configuration_failed = true;
                required_errors.push(format!("Failed to load ingress configuration: {}", error))
            }
        }
    }

    if action == "update" && af_services::should_pre_stop_on_update(clean_id) {
        for u in stopped_units {
            if let Err(e) = control_unit(u.clone(), "start").await {
                service_restore_failed = true;
                required_errors.push(format!("Failed to restart stopped unit {}: {}", u, e));
            }
        }
    }

    refresh_update(clean_id.to_string()).await;

    if required_errors.is_empty() {
        Ok(())
    } else {
        let kind = match (configuration_failed, service_restore_failed) {
            (true, true) => af_services::PackageJobFailure::ConfigurationAndServiceRestore,
            (false, true) => af_services::PackageJobFailure::ServiceRestore,
            _ => af_services::PackageJobFailure::Configuration,
        };
        Err(PackageLifecycleFailure {
            kind,
            message: required_errors.join("; "),
        })
    }
}

async fn dispatch_package_lifecycle(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    delete_data: bool,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    if delete_data && action != "remove" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Data purge is only valid for package removal",
        );
    }
    let (pkgs, admission_guard) = match tokio::task::spawn_blocking(|| {
        let guard = af_runner::acquire_lifecycle_admission_lock(None).map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                "LIFECYCLE_ADMISSION_UNAVAILABLE",
                format!("Cannot reserve application lifecycle admission: {}", error),
            )
        })?;
        af_services::package_job_snapshot()
            .and_then(|_| af_services::reconcile_package_jobs_under_admission())
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STATUS_UNAVAILABLE",
                    "Lifecycle status could not be reconciled; retry shortly",
                )
            })?;
        af_services::get_packages()
            .map(|packages| (packages, guard))
            .map_err(|_| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "STATUS_UNAVAILABLE",
                    "Package catalog and lifecycle status could not be confirmed; retry shortly",
                )
            })
    })
    .await
    {
        Ok(Ok(admission)) => admission,
        Ok(Err(response)) => return response,
        _ => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Package catalog and lifecycle status could not be confirmed; retry shortly",
            )
        }
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

    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
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
    let audit_action = if delete_data {
        "package_purge".to_string()
    } else {
        format!("package_{}", action)
    };
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        &audit_action,
        "package",
        &pkg.name,
        &pkg.label,
        &ip,
        ua,
    );

    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }

    // This value is also the job identity clients use to match a terminal
    // outcome to the job they started; jobs for one package are sequential.
    let job_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    if !af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.clone(),
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
    drop(admission_guard);
    emit_package_progress(
        &pkg.name,
        action,
        status_label,
        5,
        &format!("Starting {} for {}...", action, pkg.label),
        &started_at,
        &job_id,
    );

    let response_job_id = job_id.clone();
    let response_started_at = started_at.clone();
    let clean_id = pkg.name.clone();
    let pkg_label = pkg.label.clone();
    let pkg_default_port = pkg.default_port;
    let pkg_lock_file = pkg.lock_file.clone();
    let job_lease = af_services::take_package_job_lease(&clean_id, &job_id);

    tokio::spawn(af_runner::PACKAGE_JOB_ID.scope(job_id.clone(), async move {
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
        // Re-check under the lifecycle mutex: a system update may have been
        // launched while this job was queued (run_update holds this mutex
        // while launching, so the check cannot race with the launch).
        if let Some(message) = system_update_lifecycle_block().await {
            finish_package_lifecycle(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::Preparation),
                5,
                &message.to_string(),
                &started_at,
                &job_id,
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
                    let job_id = job_id.clone();
                    let fs_root_override = fs_root_override.clone();
                    async move {
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
                            af_runner::dispatch_package_action_with_options(
                                action,
                                &clean_id,
                                &script_name,
                                resolved_port,
                                delete_data,
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
                            let request = af_models::PackageRunnerRequest {
                                action: action.to_string(),
                                package_id: clean_id.clone(),
                                script_name: script_name.clone(),
                                lifecycle_job_id: job_id.clone(),
                                app_port: resolved_port,
                                delete_data,
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
                                                &job_id,
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
                                &job_id,
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
                    finish_package_lifecycle(
                        &clean_id,
                        action,
                        Some(af_services::PackageJobFailure::Preparation),
                        10,
                        &error_message,
                        &started_at,
                        &job_id,
                    );
                    return;
                }
            };

        if let Err(error) = execution_result {
            af_services::mutators::clear_app_runtime_meta_cache();
            let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
            if af_services::should_pre_stop_on_update(&clean_id) {
                for unit in &stopped_units {
                    let _ =
                        af_services::control_service_with_manager(unit, "start", "systemd-unit")
                            .await;
                }
            }
            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle(
                &clean_id,
                action,
                Some(af_services::PackageJobFailure::Installer),
                60,
                &error.to_string(),
                &started_at,
                &job_id,
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

        if action == "install" || action == "update" {
            let blueprint_error =
                af_services::mutators::apply_blueprint_app_config(&clean_id, allocated_port)
                    .await
                    .err();

            let base_domain = af_services::resolve_base_domain();
            let finalization = finalize_post_script_lifecycle_with(
                action,
                &clean_id,
                allocated_port,
                stopped_units,
                &base_domain,
                |app_id| load_authoritative_app_ingress_config(app_id),
                |_cfg| {
                    let mut conn = af_db::get_conn()?;
                    af_db::synchronize_lifecycle_ingress(
                        &mut conn,
                        &clean_id,
                        action,
                        &job_id,
                        allocated_port,
                        false,
                        &base_domain,
                    )
                },
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
            .await;
            let finalization = merge_blueprint_finalization(finalization, blueprint_error);
            if let Err(required_err) = finalization {
                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle(
                    &clean_id,
                    action,
                    Some(required_err.kind),
                    90,
                    &required_err.message,
                    &started_at,
                    &job_id,
                );
                return;
            }
        } else if action == "remove" {
            let retained = af_db::get_conn().and_then(|mut conn| {
                af_db::synchronize_lifecycle_ingress(
                    &mut conn,
                    &clean_id,
                    action,
                    &job_id,
                    0,
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
                );
                return;
            }
            let _ = af_services::mutators::sync_network_dns_providers().await;
        }

        af_services::clear_service_status_cache();
        af_services::mutators::clear_app_runtime_meta_cache();

        finish_package_lifecycle(
            &clean_id,
            action,
            None,
            100,
            &format!("Completed {} for {}", action, pkg_label),
            &started_at,
            &job_id,
        );
    }));

    let msg = match action {
        "install" => "Installation started successfully",
        "remove" => "Uninstallation started successfully",
        _ => "Update started successfully",
    };

    Json(serde_json::json!({
        "message": msg,
        "package": pkg_id,
        "status": status_label,
        "action": action,
        "started_at": response_started_at,
        "job_id": response_job_id,
        "purge": delete_data,
    }))
    .into_response()
}

async fn check_package_updates() -> Response {
    let records = match af_services::workers::refresh_all_package_updates().await {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(error = %error, "package update check inventory unavailable");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Application inventory could not be confirmed; retry the update check shortly",
            );
        }
    };
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
    mut record: Option<af_services::workers::PackageUpdateRecord>,
) -> serde_json::Value {
    if let Some(record) = record.as_mut() {
        record.error = af_services::workers::public_update_error(&record.error);
    }
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
        let synchronized = af_services::mutators::with_blueprint_admission(async {
            let now = Utc::now();
            let old_suffix = if prev_base_domain.is_empty() {
                String::new()
            } else {
                format!(".{}", prev_base_domain)
            };

            let mut handled_apps = std::collections::HashSet::new();
            for mut cfg in af_db::get_all_app_ingress_configs()? {
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
                        af_services::mutators::with_blueprint_mutation(&cfg.app_name, async {
                            af_db::set_app_ingress_config(&cfg)?;
                            af_services::mutators::apply_blueprint_app_config(
                                &cfg.app_name,
                                cfg.listen_port,
                            )
                            .await
                            .map_err(anyhow::Error::msg)?;
                            Ok(())
                        })
                        .await?;
                    }
                }
            }

            let pkgs = af_services::get_packages()?;
            {
                for p in pkgs {
                    if p.status == "installed"
                        && p.default_port > 0
                        && !handled_apps.contains(&p.name)
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
                        af_services::mutators::with_blueprint_mutation(&p.name, async {
                            af_db::set_app_ingress_config(&cfg)?;
                            af_services::mutators::apply_blueprint_app_config(
                                &p.name,
                                p.default_port,
                            )
                            .await
                            .map_err(anyhow::Error::msg)?;
                            Ok(())
                        })
                        .await?;
                    }
                }
            }

            af_services::mutators::sync_network_dns_providers()
                .await
                .map_err(anyhow::Error::msg)?;
            af_services::mutators::trigger_apache_cert_sync().await;
            Ok(())
        })
        .await;
        if let Err(error) = synchronized {
            return blueprint_sync_failure_response(&error);
        }
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
) -> Response {
    if auth_user.plugin_id.is_some()
        || !auth_user.plugin_scopes.is_empty()
        || auth_user.role == "plugin"
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_WEBSOCKET_FORBIDDEN",
            "Scoped plugins cannot create operator WebSocket sessions; use scoped telemetry reads",
        );
    }
    let ip = extract_client_ip(&headers);
    let ticket = issue_ws_ticket_for_user(auth_user.user_id, &ip);
    Json(serde_json::json!({ "ticket": ticket })).into_response()
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
    if af_services::get_blueprint(&app_name).is_none() {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Blueprint not found");
    }
    let guarded_app = app_name.clone();
    match af_services::mutators::with_blueprint_mutation(&guarded_app, async move {
        Ok(sync_app_blueprint_admitted(Path(app_name), Extension(auth_user), headers).await)
    })
    .await
    {
        Ok(response) => response,
        Err(error) => blueprint_sync_failure_response(&error),
    }
}

fn blueprint_sync_failure_response(error: &anyhow::Error) -> Response {
    let error_id = uuid::Uuid::new_v4().to_string();
    tracing::error!(%error_id, detail = %format!("{error:#}"), "blueprint synchronization failed");
    let (status, code, message) = if af_runner::is_lifecycle_busy(error) {
        (StatusCode::CONFLICT, "LIFECYCLE_BUSY", "Application configuration is reserved by another lifecycle operation; retry after it completes")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "BLUEPRINT_SYNC_FAILED", "Blueprint synchronization could not be completed; inspect authorized diagnostics before retrying")
    };
    (
        status,
        Json(serde_json::json!({"code":code,"message":message,"error_id":error_id})),
    )
        .into_response()
}

async fn sync_app_blueprint_admitted(
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

    let existing_ing = match load_authoritative_app_ingress_config(&app_name) {
        Ok(existing) => existing,
        Err(error) => return blueprint_sync_failure_response(&error),
    };
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

    if let Err(error) =
        af_services::mutators::apply_blueprint_app_config(&app_name, allocated_port).await
    {
        return blueprint_sync_failure_response(&anyhow::Error::msg(error));
    }
    let config_applied = true;

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
        if let Err(error) = af_db::set_app_ingress_config(&ingress_cfg) {
            return blueprint_sync_failure_response(&error);
        }
        af_db::invalidate_ingress_cache();
        true
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
        if let Err(error) = af_services::mutators::sync_local_dns_domains(&dns_domains).await {
            return blueprint_sync_failure_response(&anyhow::Error::msg(error));
        }
        true
    };
    if let Err(error) = af_services::mutators::sync_network_dns_providers().await {
        return blueprint_sync_failure_response(&anyhow::Error::msg(error));
    }
    let network_dns_synced = true;

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
#[path = "http_lifecycle_regressions.rs"]
mod http_lifecycle_regressions;

#[cfg(all(test, unix))]
#[path = "services_readiness_regressions.rs"]
mod services_readiness_regressions;

#[cfg(all(test, unix))]
#[path = "update_error_regressions.rs"]
mod update_error_regressions;

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

        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let (radarr_port, radarr_stopped, radarr_res) = run_package_lifecycle_dispatch_gate_with(
            "update",
            "radarr",
            7878,
            "",
            |_app_id| 17878,
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
        .expect("radarr update must preserve its authoritative native port");
        assert!(radarr_res.is_ok());
        assert_eq!(radarr_port, 17878);
        assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
        assert_eq!(
            *recorded_control_actions.lock().unwrap(),
            vec!["stop radarr".to_string()]
        );
        assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17878]);

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
        assert_eq!(body["last_error"], "Update status could not be confirmed");
        assert_eq!(body["error"], "Update status could not be confirmed");
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
        assert!(err_ingress
            .message
            .contains("Failed to persist ingress configuration"));
        assert_eq!(
            err_ingress.kind,
            af_services::PackageJobFailure::Configuration
        );

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
        assert!(err_read
            .message
            .contains("Failed to load ingress configuration"));
        assert_eq!(err_read.kind, af_services::PackageJobFailure::Configuration);
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
        assert!(err_restart
            .message
            .contains("Failed to restart stopped unit radarr"));
        assert_eq!(
            err_restart.kind,
            af_services::PackageJobFailure::ServiceRestore
        );

        let both = finalize_post_script_lifecycle_with(
            "update",
            "radarr",
            7878,
            vec!["radarr".into()],
            "example.com",
            |_| Err(anyhow::anyhow!("secret ingress failure")),
            |_| Ok(()),
            |_, _| async { Err(anyhow::anyhow!("secret service failure")) },
            |_| async {},
        )
        .await
        .unwrap_err();
        assert_eq!(
            both.kind,
            af_services::PackageJobFailure::ConfigurationAndServiceRestore
        );
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
    fn control_req(action: &str, managed_by: &str, process: &str) -> ServiceControlReq {
        ServiceControlReq {
            action: action.to_string(),
            managed_by: managed_by.to_string(),
            process: process.to_string(),
        }
    }

    #[test]
    fn test_service_control_rejects_foreign_units_and_unknown_managers() {
        let err = validate_service_control_request(
            "sonarr",
            &control_req("stop", "systemd-unit", "sshd"),
        )
        .expect_err("a package card must not stop an unrelated host unit");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert_eq!(err.1, "SERVICE_CONTROL_FORBIDDEN");
        let err = validate_service_control_request(
            "sonarr",
            &control_req("restart", "systemd", "aetherflow-runner"),
        )
        .expect_err("process override must stay within the card");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let err =
            validate_service_control_request("sonarr", &control_req("restart", "shell", "sonarr"))
                .expect_err("unknown managers are rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err =
            validate_service_control_request("sonarr", &control_req("enable", "systemd", "sonarr"))
                .expect_err("only start/stop/restart are allowed");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = validate_service_control_request(
            "AetherFlow Frontend",
            &control_req("restart", "embedded", "aetherflow-frontend"),
        )
        .expect_err("embedded frontend has no daemon");
        assert_eq!(err.1, "EMBEDDED_SERVICE_CONTROL_UNSUPPORTED");
        let err = validate_service_control_request(
            "nextcloud",
            &control_req("restart", "systemd", "nextcloud"),
        )
        .expect_err("shared vhost controls stay blocked");
        assert_eq!(err.1, "SHARED_VHOST_CONTROL_UNSUPPORTED");
        assert_eq!(
            validate_service_control_request(
                "sonarr",
                &control_req("restart", "systemd", "sonarr")
            )
            .unwrap(),
            "sonarr"
        );
    }

    #[test]
    fn test_service_control_is_serialized_with_active_lifecycle_job() {
        // Regression: manual restarts during an update raced the installer's
        // own stop/replace/start sequence.
        let started_at = "hillclimb-control-lock";
        assert!(af_services::try_start_package_job(
            af_services::PackageJobInfo {
                job_id: started_at.to_string(),
                package_id: "lidarr".into(),
                action: "update".into(),
                status: "updating".into(),
                progress: 25,
                last_line: String::new(),
                started_at: started_at.into(),
            }
        ));
        let err = validate_service_control_request(
            "lidarr",
            &control_req("restart", "systemd", "lidarr"),
        )
        .expect_err("controls must wait for the lifecycle job");
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
        af_services::finish_package_job("lidarr", "update", true, "done", started_at);
        assert_eq!(
            validate_service_control_request(
                "lidarr",
                &control_req("restart", "systemd", "lidarr")
            )
            .unwrap(),
            "lidarr"
        );
    }

    #[test]
    fn test_uninstall_purge_requires_explicit_true() {
        let parse = |value: Option<&str>| {
            parse_uninstall_purge(&UninstallQuery {
                purge: value.map(str::to_string),
            })
        };
        assert_eq!(parse(None), Ok(false));
        assert_eq!(parse(Some("")), Ok(false));
        assert_eq!(parse(Some("false")), Ok(false));
        assert_eq!(parse(Some("true")), Ok(true));
        assert_eq!(parse(Some("1")), Ok(true));
        assert!(parse(Some("yes")).is_err());
        assert!(parse(Some("TRUE ; rm")).is_err());
    }

    #[test]
    fn test_progress_reports_failed_outcome_after_job_clears_but_public_view_has_no_detail() {
        let outcome = af_services::PackageJobOutcome {
            job_id: "test-job".into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "failed".into(),
            message: "Could not stop sonarr: exit status 5".into(),
            started_at: "2026-11-05T20:00:00.000Z".into(),
            finished_at: "2026-11-05T20:01:00Z".into(),
        };
        let payload = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
        assert_eq!(payload["status"], "failed");
        assert_eq!(payload["action"], "update");
        assert_eq!(payload["message"], "Could not stop sonarr: exit status 5");
        assert_eq!(payload["started_at"], "2026-11-05T20:00:00.000Z");
        let idle = package_progress_payload("sonarr", None, None, false);
        assert_eq!(idle["status"], "idle");

        let public = serde_json::to_value(public_job_outcome(outcome.clone())).unwrap();
        assert_eq!(public["status"], "failed");
        assert_eq!(public["started_at"], "2026-11-05T20:00:00.000Z");
        assert!(
            public.get("message").is_none(),
            "unauthenticated catalog must not leak errors"
        );
        let ordinary = package_progress_payload("sonarr", None, Some(outcome), false);
        assert!(!ordinary.to_string().contains("exit status"));
        assert_eq!(ordinary["last_job"]["job_id"], "test-job");
    }

    fn lifecycle_status_fixture() -> (std::path::PathBuf, rusqlite::Connection) {
        let root = std::env::temp_dir().join(format!("af-api-status-{}", uuid::Uuid::new_v4()));
        let path = root.join("backend/data/aetherflow.sqlite");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::env::set_var("AETHERFLOW_FS_ROOT", &root);
        std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        std::env::set_var("DB_PATH", &path);
        af_services::initialize_package_jobs(rusqlite::Connection::open(&path).unwrap()).unwrap();
        (root, rusqlite::Connection::open(path).unwrap())
    }

    fn progress_test_user(role: &str, plugin: Option<&str>) -> AuthUser {
        AuthUser {
            user_id: 1,
            username: "progress-fixture".into(),
            role: role.into(),
            jti: "progress-fixture".into(),
            plugin_id: plugin.map(str::to_owned),
            plugin_scopes: plugin
                .map(|_| vec!["telemetry:read".into()])
                .unwrap_or_default(),
        }
    }

    #[tokio::test]
    async fn routine_service_control_failures_are_sanitized_and_correlated() {
        for timed_out in [false, true] {
            let detail = "SYNTHETIC_PRIVATE_DETAIL /private/review/secret.json";
            let error = if timed_out {
                anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, detail))
                    .context("control failed")
            } else {
                anyhow::anyhow!(detail)
            };
            let response = service_control_failure_response(&error, "sonarr", "restart");
            assert_eq!(
                response.status(),
                if timed_out {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(!body.to_string().contains("SYNTHETIC_PRIVATE_DETAIL"));
            assert!(!body.to_string().contains("/private/"));
            assert!(uuid::Uuid::parse_str(body["error_id"].as_str().unwrap()).is_ok());
            assert_eq!(
                body["code"],
                if timed_out {
                    "SERVICE_CONTROL_TIMEOUT"
                } else {
                    "SERVICE_CONTROL_FAILED"
                }
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bulk_update_inventory_errors_are_unavailable_without_success_counts() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, blocker) = lifecycle_status_fixture();
        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
        std::fs::write(&automation, "{}").unwrap();
        let package = af_models::Package {
            name: "sonarr".into(),
            lock_file: "/install/.sonarr.lock".into(),
            ..Default::default()
        };
        let valid_catalog = serde_json::to_vec(&vec![package]).unwrap();
        for failure in ["catalog", "lock", "journal"] {
            std::fs::write(&catalog, &valid_catalog).unwrap();
            match failure {
                "catalog" => std::fs::write(&catalog, "{corrupt").unwrap(),
                "lock" => std::fs::create_dir_all(root.join("install/.sonarr.lock")).unwrap(),
                "journal" => blocker.execute_batch("BEGIN EXCLUSIVE").unwrap(),
                _ => unreachable!(),
            }
            let response = check_package_updates().await;
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{failure}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["code"], "STATUS_UNAVAILABLE");
            assert!(body.get("updates").is_none());
            assert!(body.get("updates_available").is_none());
            assert!(!body.to_string().contains(root.to_str().unwrap()));
            if failure == "lock" {
                std::fs::remove_dir(root.join("install/.sonarr.lock")).unwrap();
            }
            if failure == "journal" {
                blocker.execute_batch("ROLLBACK").unwrap();
            }
        }
        std::fs::write(&catalog, "[]").unwrap();
        let response = check_package_updates().await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["updates"], serde_json::json!([]));
        assert_eq!(body["updates_available"], 0);
        drop(blocker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn services_credentials_require_a_human_admin_for_http_views() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();
        std::fs::create_dir_all(root.join("install")).unwrap();
        std::fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
        std::fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
        std::fs::write(
            root.join("var/lib/sonarr/config.xml"),
            "<Config><ApiKey>synthetic-service-credential</ApiKey><Port>18989</Port></Config>",
        )
        .unwrap();
        let package = af_models::Package {
            name: "sonarr".into(),
            label: "Sonarr".into(),
            service_name: "sonarr".into(),
            lock_file: "/install/.sonarr.lock".into(),
            ..Default::default()
        };
        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
        std::fs::write(&automation, "{}").unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
        for (role, plugin, allowed) in [
            ("user", None, false),
            ("plugin", Some("status-reader"), false),
            ("admin", Some("status-reader"), false),
            ("admin", None, true),
        ] {
            let response = get_services(Extension(progress_test_user(role, plugin))).await;
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body["Sonarr"].get("api_key").is_some(),
                allowed,
                "{role} {plugin:?}"
            );
            assert_eq!(
                body.to_string().contains("synthetic-service-credential"),
                allowed
            );
            assert_eq!(body["Sonarr"]["id"], "sonarr");
        }
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn package_progress_sanitizes_users_and_plugins_but_keeps_admin_diagnostics() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        assert!(af_services::try_start_package_job(
            af_services::PackageJobInfo {
                job_id: "privileged-output-job".into(),
                package_id: "sonarr".into(),
                action: "update".into(),
                status: "updating".into(),
                progress: 42,
                last_line: "PASSWORD=private-installer-output".into(),
                started_at: "fixture-start".into(),
            }
        ));
        for (role, plugin, raw_expected) in [
            ("user", None, false),
            ("plugin", Some("telemetry-client"), false),
            ("admin", Some("telemetry-client"), false),
            ("admin", None, true),
        ] {
            let user = progress_test_user(role, plugin);
            let response = package_progress(Path("sonarr".into()), Extension(user.clone())).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["job_id"], "privileged-output-job");
            assert_eq!(payload["progress"], 42);
            assert_eq!(payload["status"], "updating");
            assert_eq!(
                payload.to_string().contains("private-installer-output"),
                raw_expected
            );
            if plugin.is_some() {
                assert_eq!(
                    issue_ws_ticket(Extension(user), HeaderMap::new())
                        .await
                        .status(),
                    StatusCode::FORBIDDEN
                );
            }
        }
        af_services::fail_package_job(
            "sonarr",
            "update",
            af_services::PackageJobFailure::Installer,
            "privileged-output-job",
        )
        .unwrap();
        let response = package_progress(
            Path("sonarr".into()),
            Extension(progress_test_user("admin", None)),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let outcome: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            outcome["message"],
            af_services::PackageJobFailure::Installer.summary()
        );
        assert!(!outcome.to_string().contains("private-installer-output"));
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn package_admission_reconciles_dead_same_package_before_catalog_validation() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        let package_id = "lifecycle-admission-fixture";
        let package = af_models::Package {
            name: package_id.into(),
            label: "Lifecycle admission fixture".into(),
            service_name: package_id.into(),
            lock_file: "/install/.lifecycle-admission-fixture.lock".into(),
            ..Default::default()
        };
        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
        std::fs::write(&automation, "{}").unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
        std::env::set_var(
            "AETHERFLOW_RUNNER_SOCK",
            format!(
                "/tmp/afr-{}.sock",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ),
        );
        af_db::init_db().unwrap();
        let scripts = root.join("packages/package/install");
        std::fs::create_dir_all(&scripts).unwrap();
        let script_name = format!("installpackage-{package_id}");
        let script = scripts.join(&script_name);
        std::fs::write(&script, "#!/bin/sh\nexit 91\n").unwrap();
        let previous_directory = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        assert_eq!(
            af_runner::resolve_package_script_path("install", &script_name),
            Some(std::path::PathBuf::from("packages/package/install").join(&script_name))
        );
        assert!(af_services::try_start_package_job(
            af_services::PackageJobInfo {
                job_id: "abandoned-install".into(),
                package_id: package_id.into(),
                action: "install".into(),
                status: "installing".into(),
                progress: 20,
                last_line: String::new(),
                started_at: "fixture-start".into(),
            }
        ));
        drop(af_services::take_package_job_lease(package_id, "abandoned-install").unwrap());
        assert_eq!(
            af_services::package_job_snapshot().unwrap().active[package_id].status,
            "installing"
        );
        let execution_blocked = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        let response = dispatch_package_lifecycle(
            package_id.into(),
            "install",
            "installing",
            false,
            progress_test_user("admin", None),
            HeaderMap::new(),
        )
        .await;
        let response_status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_status, StatusCode::OK, "{payload}");
        let identity = payload["job_id"].as_str().unwrap();
        assert_ne!(identity, "abandoned-install");
        assert_eq!(
            af_services::package_job_snapshot().unwrap().active[package_id].job_id,
            identity
        );
        let rejected = dispatch_package_lifecycle(
            package_id.into(),
            "install",
            "installing",
            false,
            progress_test_user("admin", None),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::CONFLICT);
        assert!(af_services::finish_package_job(
            package_id,
            "install",
            true,
            "late",
            "abandoned-install"
        )
        .is_none());
        af_services::finish_package_job(package_id, "install", true, "fixture done", identity)
            .unwrap();
        drop(connection);
        std::env::set_current_dir(previous_directory).unwrap();
        std::fs::remove_dir_all(root).unwrap();
        drop(execution_blocked);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn package_ingress_callbacks_require_the_current_lifecycle_owner() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();
        let job = |identity: &str, action: &str, status: &str| af_services::PackageJobInfo {
            job_id: identity.into(),
            package_id: "sonarr".into(),
            action: action.into(),
            status: status.into(),
            progress: 20,
            last_line: String::new(),
            started_at: "fixture-start".into(),
        };
        assert!(af_services::try_start_package_job(job(
            "ingress-install",
            "install",
            "installing"
        )));
        finalize_post_script_lifecycle_with(
            "install",
            "sonarr",
            18989,
            Vec::new(),
            "example.com",
            load_authoritative_app_ingress_config,
            |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, "ingress-install", "install"),
            |_, _| async { Ok(()) },
            |_| async {},
        )
        .await
        .unwrap();
        let ingress = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
        assert_eq!(ingress.listen_port, 18989);
        assert!(af_db::set_app_ingress_config(&ingress).is_err());
        assert!(
            af_db::set_app_ingress_config_for_lifecycle(&ingress, "wrong-owner", "install")
                .is_err()
        );
        af_services::finish_package_job("sonarr", "install", true, "done", "ingress-install")
            .unwrap();
        assert!(af_services::try_start_package_job(job(
            "ingress-remove",
            "remove",
            "uninstalling"
        )));
        assert!(af_db::archive_app_ingress_config("sonarr", false).is_err());
        assert!(af_db::archive_app_ingress_config_for_lifecycle(
            "sonarr",
            false,
            "ingress-install"
        )
        .is_err());
        af_db::archive_app_ingress_config_for_lifecycle("sonarr", false, "ingress-remove").unwrap();
        assert!(af_db::get_app_ingress_config("sonarr").unwrap().is_none());
        assert_eq!(
            load_authoritative_app_ingress_config("sonarr")
                .unwrap()
                .unwrap()
                .listen_port,
            18989
        );
        af_services::finish_package_job("sonarr", "remove", true, "done", "ingress-remove")
            .unwrap();
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn package_progress_yields_and_fails_closed_on_blocked_journal() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, blocker) = lifecycle_status_fixture();
        blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let mut response = Box::pin(package_progress(
            Path("sonarr".into()),
            Extension(progress_test_user("user", None)),
        ));
        assert!(
            futures::poll!(&mut response).is_pending(),
            "journal status must not block the async runtime or return idle on read failure"
        );
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), response)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["code"], "STATUS_UNAVAILABLE");
        assert!(af_runner::acquire_lifecycle_admission_lock(Some(&root)).is_ok());
        let mut admission = Box::pin(dispatch_package_lifecycle(
            "sonarr".into(),
            "install",
            "installing",
            false,
            AuthUser {
                user_id: 1,
                username: "isolated-admin".into(),
                role: "admin".into(),
                jti: "isolated-session".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            },
            HeaderMap::new(),
        ));
        assert!(
            futures::poll!(&mut admission).is_pending(),
            "admission status lookup must yield before reading the journal"
        );
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), admission)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        blocker.execute_batch("ROLLBACK").unwrap();
        blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','matching-receipt','update','completed','fixture')", []).unwrap();
        let response = package_progress(
            Path("sonarr".into()),
            Extension(progress_test_user("user", None)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["job_id"], "matching-receipt");
        assert_eq!(payload["status"], "completed");
        drop(blocker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_control_fails_closed_for_unreadable_or_unknown_journal() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, blocker) = lifecycle_status_fixture();
        blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let unavailable = validate_service_control_request(
            "sonarr",
            &control_req("restart", "systemd", "sonarr"),
        );
        blocker.execute_batch("ROLLBACK").unwrap();
        blocker.execute("INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','unknown-receipt','update','unrecognized-phase','fixture')", []).unwrap();
        let unknown = validate_service_control_request(
            "sonarr",
            &control_req("restart", "systemd", "sonarr"),
        );
        assert_eq!(unavailable.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unknown.unwrap_err().1, "PACKAGE_LIFECYCLE_IN_PROGRESS");
        drop(blocker);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_control_contention_returns_409_without_lock_details() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, _connection) = lifecycle_status_fixture();
        let socket =
            std::env::temp_dir().join(format!("c-{}.sock", &uuid::Uuid::new_v4().to_string()[..8]));
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
        let guard = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
        let request = |name: &str| {
            control_service_handler(
                Path(name.to_string()),
                Extension(AuthUser {
                    user_id: 1,
                    username: "fixture".into(),
                    role: "admin".into(),
                    jti: "fixture".into(),
                    plugin_id: None,
                    plugin_scopes: Vec::new(),
                }),
                HeaderMap::new(),
                Json(control_req("restart", "systemd", name)),
            )
        };
        // With no runner, the fallback must fail before invoking a real command.
        let local = request("aetherflow-frontend").await;
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let fake_runner = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    continue;
                } // runner availability probe
                let request = String::from_utf8_lossy(&buffer[..count]);
                let (status, response) = if request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .ends_with("/v1/self-update/status")
                {
                    ("200 OK", af_models::RunnerResponse { success: true, output: serde_json::json!({"status":"succeeded","completed":true,"success":true,"job_unit":"","error":"","exit_code":null}).to_string(), error: String::new() })
                } else {
                    assert!(request
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .ends_with("/v1/systemctl"));
                    (
                        "409 Conflict",
                        af_models::RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: "release lock contention at /private/fixture.lock".into(),
                        },
                    )
                };
                let body = serde_json::to_string(&response).unwrap();
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let remote = request("aetherflow-frontend").await;
        let core = request("aetherflow-api").await;
        fake_runner.abort();
        for response in [local, remote, core] {
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["code"], "LIFECYCLE_BUSY");
            assert!(payload["message"].as_str().unwrap().contains("Retry"));
            assert!(!String::from_utf8_lossy(&body).contains(".lock"));
        }
        drop(guard);
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn test_system_update_blocks_package_lifecycle_until_terminal() {
        let status = |completed: bool| af_models::SelfUpdateJobStatus {
            status: if completed { "succeeded" } else { "running" }.to_string(),
            completed,
            success: completed,
            job_unit: "aetherflow-self-update-deploy-nightly-0123abcd.service".to_string(),
            error: String::new(),
            exit_code: if completed { Some(0) } else { None },
        };
        assert!(
            system_update_lifecycle_block_with(|| async { Ok(status(false)) })
                .await
                .is_some()
        );
        let running = system_update_lifecycle_block_with(|| async { Ok(status(false)) })
            .await
            .expect("running updater must block lifecycle jobs");
        assert!(running.to_string().contains("in progress"));
        let unavailable = system_update_lifecycle_block_with(|| async {
            Err(anyhow::anyhow!("runner socket connection refused"))
        })
        .await
        .expect("unknown status for a launched updater fails closed");
        assert!(unavailable.to_string().contains("unavailable"));
        assert!(
            system_update_lifecycle_block_with(|| async { Ok(status(true)) })
                .await
                .is_none()
        );
        assert!(system_update_lifecycle_block_with(|| async {
            Err(anyhow::anyhow!("self-update job 'x' not found"))
        })
        .await
        .is_some());
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
