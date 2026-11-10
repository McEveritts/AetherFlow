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
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
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
        .route("/packages/:id/reinstall", post(reinstall_package))
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

#[derive(Debug, Default, Deserialize)]
struct MarketplaceQuery {
    #[serde(default)]
    require_auth: Option<String>,
}

fn parse_require_auth(query: &MarketplaceQuery) -> bool {
    matches!(
        query.require_auth.as_deref().map(str::trim),
        Some("1") | Some("true") | Some("yes")
    )
}

async fn get_marketplace_apps(
    Query(query): Query<MarketplaceQuery>,
    headers: HeaderMap,
) -> Response {
    let require_auth = parse_require_auth(&query);
    tokio::task::spawn_blocking(move || get_marketplace_apps_blocking(headers, require_auth))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STATUS_UNAVAILABLE",
                "Marketplace status unavailable",
            )
        })
}

fn get_marketplace_auth_info(headers: &HeaderMap) -> (bool, bool) {
    let Some(token) = crate::auth::resolve_raw_token(headers) else {
        return (false, false);
    };
    if let Ok(plugin_claims) = crate::plugins::decode_and_verify_plugin_token(&token) {
        let is_authed = crate::plugins::plugin_claims_allow_request(
            &plugin_claims,
            &axum::http::Method::GET,
            "/api/v1/public/marketplace",
        ) || crate::plugins::plugin_claims_allow_request(
            &plugin_claims,
            &axum::http::Method::GET,
            "/api/v1/admin/packages",
        );
        return (is_authed, false);
    }
    if let Ok(claims) = crate::auth::decode_session_claims(&token, false) {
        if !matches!(af_db::token_revocation_status(&claims.jti), Ok(false)) {
            return (false, false);
        }
        if !claims.plugin_id.is_empty() || !claims.plugin_scopes.is_empty() {
            if crate::plugins::is_plugin_request_denied(
                &axum::http::Method::GET,
                "/api/v1/public/marketplace",
            ) {
                return (false, false);
            }
            let is_authed = af_services::plugins::verify_plugin_route_scope(
                &claims.plugin_scopes,
                "/api/v1/public/marketplace",
            ) || af_services::plugins::verify_plugin_route_scope(
                &claims.plugin_scopes,
                "/api/v1/admin/packages",
            );
            return (is_authed, false);
        }
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let client_ip = extract_client_ip(headers);
        if !crate::auth::matches_client_fingerprint(&claims.cfp, &client_ip, ua) {
            return (false, false);
        }
        let Ok(conn) = af_db::get_conn() else {
            return (false, false);
        };
        let role: Result<String, _> = conn.query_row(
            "SELECT role FROM users WHERE id = ?1",
            rusqlite::params![claims.user_id],
            |row| row.get(0),
        );
        if let Ok(r) = role {
            let is_admin = r.trim().eq_ignore_ascii_case("admin");
            return (true, is_admin);
        }
    }
    (false, false)
}

#[allow(dead_code)]
fn has_valid_marketplace_auth(headers: &HeaderMap) -> bool {
    get_marketplace_auth_info(headers).0
}

fn get_marketplace_apps_blocking(headers: HeaderMap, require_auth: bool) -> Response {
    let (is_authenticated, diagnostics_allowed) = get_marketplace_auth_info(&headers);
    if require_auth && !is_authenticated {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required for marketplace inventory",
        );
    }
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

    if !is_authenticated {
        let public_apps: Vec<serde_json::Value> = pkgs
            .into_iter()
            .map(|p| {
                let mut map = serde_json::Map::new();
                map.insert("id".to_string(), serde_json::Value::String(p.name));
                map.insert("name".to_string(), serde_json::Value::String(p.label));
                map.insert("desc".to_string(), serde_json::Value::String(p.description));
                map.insert("hits".to_string(), serde_json::json!(p.hits));
                map.insert("category".to_string(), serde_json::Value::String(p.category));
                map.insert("status".to_string(), serde_json::Value::String("not_installed".to_string()));
                if p.default_port > 0 {
                    map.insert("default_port".to_string(), serde_json::json!(p.default_port));
                }
                if !p.web_path.is_empty() {
                    map.insert("web_path".to_string(), serde_json::Value::String(p.web_path));
                }
                map.insert("inventory_known".to_string(), serde_json::Value::Bool(false));
                map.insert("inventory_authenticated".to_string(), serde_json::Value::Bool(false));
                map.insert(
                    "inventory_mode".to_string(),
                    serde_json::Value::String(af_models::INVENTORY_MODE_PUBLIC_REDACTED.to_string()),
                );
                serde_json::Value::Object(map)
            })
            .collect();

        return (
            [
                (
                    axum::http::header::HeaderName::from_static("x-aetherflow-inventory-mode"),
                    axum::http::HeaderValue::from_static(af_models::INVENTORY_MODE_PUBLIC_REDACTED),
                ),
                (
                    axum::http::header::HeaderName::from_static("x-aetherflow-inventory-authenticated"),
                    axum::http::HeaderValue::from_static("false"),
                ),
            ],
            Json(public_apps),
        )
            .into_response();
    }

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
            installed_version: sanitize_url_or_source_key_for_api(&p.installed_version),
            latest_version: sanitize_url_or_source_key_for_api(&p.latest_version),
            update_available: p.update_available,
            update_checked_at: p.update_checked_at,
            update_url: sanitize_url_or_source_key_for_api(&p.update_url),
            update_error: sanitize_url_or_source_key_for_api(&af_services::workers::public_update_error(&p.update_error)),
            inventory_known: true,
            inventory_authenticated: is_authenticated,
            inventory_mode: if is_authenticated {
                af_models::INVENTORY_MODE_AUTHENTICATED.to_string()
            } else {
                af_models::INVENTORY_MODE_PUBLIC_REDACTED.to_string()
            },
            last_job: jobs.outcomes.get(&p.name).cloned().map(|outcome| {
                if is_authenticated {
                    af_models::MarketplaceJobOutcome {
                        job_id: outcome.job_id,
                        action: outcome.action,
                        status: outcome.status,
                        started_at: outcome.started_at,
                        finished_at: outcome.finished_at,
                        expected_target_version: outcome.expected_target_version.map(|v| sanitize_url_or_source_key_for_api(&v)),
                        achieved_version: outcome.achieved_version.map(|v| sanitize_url_or_source_key_for_api(&v)),
                        failed_stage: if diagnostics_allowed { outcome.failed_stage.map(|s| sanitize_url_or_source_key_for_api(&s)) } else { None },
                        exit_code: if diagnostics_allowed { outcome.exit_code } else { None },
                        sanitized_summary: if diagnostics_allowed {
                            outcome.sanitized_summary.map(|s| sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&s)))
                        } else {
                            None
                        },
                    }
                } else {
                    public_job_outcome(outcome)
                }
            }),
        };

        if let Some(job) = jobs.active.get(&p.name).cloned() {
            app.progress = job.progress;
            app.job_id = Some(job.job_id);
            app.started_at = Some(job.started_at);
            app.log_line = sanitize_url_or_source_key_for_api(&af_services::package_job_progress_summary(&job.status));
        }

        apps.push(app);
    }

    let inv_mode = if is_authenticated {
        af_models::INVENTORY_MODE_AUTHENTICATED
    } else {
        af_models::INVENTORY_MODE_PUBLIC_REDACTED
    };
    let inv_auth = if is_authenticated { "true" } else { "false" };
    (
        [
            (
                axum::http::header::HeaderName::from_static("x-aetherflow-inventory-mode"),
                axum::http::HeaderValue::from_static(inv_mode),
            ),
            (
                axum::http::header::HeaderName::from_static("x-aetherflow-inventory-authenticated"),
                axum::http::HeaderValue::from_static(inv_auth),
            ),
        ],
        Json(apps),
    )
        .into_response()
}

fn public_job_outcome(outcome: af_services::PackageJobOutcome) -> af_models::MarketplaceJobOutcome {
    af_models::MarketplaceJobOutcome {
        job_id: outcome.job_id,
        action: outcome.action,
        status: outcome.status,
        started_at: outcome.started_at,
        finished_at: outcome.finished_at,
        expected_target_version: None,
        achieved_version: None,
        failed_stage: None,
        exit_code: None,
        sanitized_summary: None,
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
        } else {
            job.last_line = sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&job.last_line));
        }
        return serde_json::to_value(job).unwrap_or_default();
    }
    if let Some(mut outcome) = outcome {
        // Authenticated view: include the terminal failure message so clients
        // can report why a job failed after the active entry is gone.
        if !diagnostics_allowed {
            outcome.message = af_services::package_job_progress_summary(&outcome.status).into();
            outcome.failed_stage = None;
            outcome.exit_code = None;
            outcome.sanitized_summary = None;
        } else {
            outcome.message = sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&outcome.message));
            outcome.sanitized_summary =
                outcome.sanitized_summary.map(|s| sanitize_url_or_source_key_for_api(&af_services::redact_secrets(&s)));
            outcome.failed_stage = outcome.failed_stage.map(|s| sanitize_url_or_source_key_for_api(&s));
            outcome.expected_target_version = outcome.expected_target_version.map(|v| sanitize_url_or_source_key_for_api(&v));
            outcome.achieved_version = outcome.achieved_version.map(|v| sanitize_url_or_source_key_for_api(&v));
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PackageActionQuery {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PackageTargetPayload {
    #[serde(default)]
    expected_target_version: Option<String>,
    #[serde(default)]
    target_version: Option<String>,
}

fn extract_expected_target_version(bytes: &[u8]) -> Result<Option<String>, StatusCode> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let val: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let obj = val.as_object().ok_or(StatusCode::BAD_REQUEST)?;

    if let Some(target_val) = obj.get("expected_target_version") {
        if !target_val.is_null() && !target_val.is_string() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(target_val) = obj.get("target_version") {
        if !target_val.is_null() && !target_val.is_string() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let parsed: PackageTargetPayload = serde_json::from_value(serde_json::Value::Object(obj.clone()))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let res = parsed
        .expected_target_version
        .or(parsed.target_version)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(res)
}

async fn install_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => return api_error(code, "BAD_REQUEST", "Malformed JSON or invalid expected_target_version"),
    };
    let clean_id = id.trim_start_matches("package-");
    let action = if af_services::is_package_installed(clean_id) {
        "reinstall"
    } else {
        "install"
    };
    dispatch_package_lifecycle_with_target(id, action, "installing", false, target, auth_user, headers).await
}

pub(crate) async fn reinstall_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => return api_error(code, "BAD_REQUEST", "Malformed JSON or invalid expected_target_version"),
    };
    dispatch_package_lifecycle_with_target(id, "reinstall", "installing", false, target, auth_user, headers).await
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
    dispatch_package_lifecycle_with_target(id, "remove", "uninstalling", purge, None, auth_user, headers).await
}

async fn update_package(
    Path(id): Path<String>,
    Query(query): Query<PackageActionQuery>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let target = match extract_expected_target_version(&body) {
        Ok(t) => t
            .or_else(|| query.expected_target_version.or(query.target_version))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Err(code) => return api_error(code, "BAD_REQUEST", "Malformed JSON or invalid expected_target_version"),
    };
    dispatch_package_lifecycle_with_target(id, "update", "updating", false, target, auth_user, headers).await
}

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

/// Ends a lifecycle job: records the terminal outcome (so polling clients can
/// distinguish failure from success) and broadcasts the terminal event.
fn finish_package_lifecycle(
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

    let outcome = af_services::finish_package_job_with_diagnostics(
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
    allocate_or_resolve_app_port_with(
        app_name,
        default_port,
        load_authoritative_app_ingress_config,
        af_db::get_reserved_ports_excluding,
    )
}

fn allocate_or_resolve_app_port_with<LoadExistingFn, LoadReservedFn>(
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
    if candidate <= 0 {
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
    let range = bp
        .as_ref()
        .map(|b| b.fallback_port_range)
        .unwrap_or([17000, 19999]);
    let start = range[0].max(1024);
    let end = range[1].max(start);
    for port in start..=end {
        if !reserved.contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok()
        {
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

fn is_oneshot_service_unit(unit: &str) -> bool {
    let lower = unit.trim().trim_end_matches(".service").to_ascii_lowercase();
    matches!(lower.as_str(), "recyclarr" | "scrutiny-collector")
}

fn is_restart_eligible_unit(unit: &str) -> bool {
    !is_oneshot_service_unit(unit)
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
    let is_reinstall =
        action == "reinstall" || (action == "install" && af_services::is_package_installed(clean_id));
    if (action == "update" || is_reinstall)
        && af_services::should_pre_stop_on_update(clean_id)
        && fs_root_override.trim().is_empty()
    {
        let mut units = resolve_units(clean_id);
        units.sort();
        units.dedup();
        units.sort_by_key(|unit| !unit.ends_with(".timer"));
        let mut running_units = Vec::new();
        for unit_name in units {
            let is_oneshot = is_oneshot_service_unit(&unit_name);
            match query_status(&unit_name).as_str() {
                "running" => running_units.push(unit_name),
                "restarting" if is_oneshot => running_units.push(unit_name),
                "stopped" | "failed" | "idle" => {},
                observation => return Err((unit_name, format!("Required service state is unconfirmed ({observation}); update was not started"))),
            }
        }
        for unit_name in running_units {
            if is_restart_eligible_unit(&unit_name) {
                stopped_units.push(unit_name.clone());
            }
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

#[derive(Debug, Clone)]
pub(crate) struct PackageLifecycleFailure {
    pub(crate) kind: af_services::PackageJobFailure,
    pub(crate) message: String,
}

fn merge_blueprint_finalization(
    finalization: Result<(), PackageLifecycleFailure>,
    blueprint_error: Option<String>,
) -> Result<(), PackageLifecycleFailure> {
    match (finalization, blueprint_error) {
        (result, None) => result,
        (Ok(_), Some(error)) => Err(PackageLifecycleFailure {
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

pub(crate) trait PostOperationRefreshResult {
    fn into_installed_version(self) -> Option<String>;
}

impl PostOperationRefreshResult for () {
    fn into_installed_version(self) -> Option<String> {
        None
    }
}

impl PostOperationRefreshResult for Option<String> {
    fn into_installed_version(self) -> Option<String> {
        self
    }
}

impl PostOperationRefreshResult for Option<af_services::workers::PackageUpdateRecord> {
    fn into_installed_version(self) -> Option<String> {
        self.map(|r| r.installed_version).filter(|s| !s.trim().is_empty())
    }
}

pub fn versions_match_target(achieved: &str, expected: &str) -> bool {
    af_runner::af_release::lifecycle::versions_match_target(achieved, expected)
}

pub fn target_version_matches(expected: &str, achieved: &str) -> bool {
    versions_match_target(achieved, expected)
}

fn resolve_candidate_receipt_paths(pkg_name: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let fs_root = std::env::var("AETHERFLOW_FS_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("AF_PACKAGE_ROOT").ok().filter(|s| !s.trim().is_empty()))
        .map(PathBuf::from);

    let resolve = |rel: &str| -> PathBuf {
        let rel_trimmed = rel.trim_start_matches(['/', '\\']);
        if let Some(ref root) = fs_root {
            root.join(rel_trimmed)
        } else {
            PathBuf::from(rel)
        }
    };

    for prefix in ["/var/lib", "/etc", "/opt"] {
        if prefix == "/opt" && pkg_name.eq_ignore_ascii_case("filebot") {
            let p = resolve("/opt/filebot-node/.af-version");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
            let candidate = format!("{}/{}/.af-version", prefix, candidate_name);
            let p = resolve(&candidate);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    if pkg_name.eq_ignore_ascii_case("piped") {
        for extra in ["/opt/piped/.af-components.json", "/var/lib/piped/.af-components.json"] {
            let p = resolve(extra);
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    for candidate_name in [pkg_name, &pkg_name.to_lowercase()] {
        if let Some(bp) = af_services::get_blueprint(candidate_name) {
            let cfg = bp.config_file_path.trim();
            if !cfg.is_empty() {
                let p = resolve(cfg);
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    paths
}

#[allow(dead_code)]
pub(crate) fn candidate_receipt_paths_for_package(pkg_name: &str) -> Vec<PathBuf> {
    resolve_candidate_receipt_paths(pkg_name)
}

fn open_dir_nofollow_stepwise_ext(
    dir_path: &std::path::Path,
    create_missing: bool,
) -> Result<Option<OwnedFd>, String> {
    if !dir_path.is_absolute() {
        return Err(format!("Directory path {} is not absolute", dir_path.display()));
    }

    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("Failed to open root directory '/': {}", err));
    }
    let mut curr_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    let mut current_path = PathBuf::from("/");
    for comp in dir_path.components() {
        match comp {
            std::path::Component::Prefix(_) => {
                return Err(format!("Unsupported prefix component in path {}", dir_path.display()));
            }
            std::path::Component::RootDir => {
                continue;
            }
            std::path::Component::CurDir => {
                continue;
            }
            std::path::Component::ParentDir => {
                return Err(format!(
                    "Directory path {} contains invalid '..' parent directory component",
                    dir_path.display()
                ));
            }
            std::path::Component::Normal(part) => {
                current_path.push(part);
                let part_bytes = part.as_bytes();
                let part_cstr = std::ffi::CString::new(part_bytes).map_err(|e| {
                    format!("Invalid directory component {:?}: {}", part, e)
                })?;

                let next_fd = unsafe {
                    libc::openat(
                        curr_fd.as_raw_fd(),
                        part_cstr.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    let raw = err.raw_os_error();
                    if raw == Some(libc::ENOENT) {
                        if !create_missing {
                            return Ok(None);
                        }
                        let mkdir_res = unsafe {
                            libc::mkdirat(curr_fd.as_raw_fd(), part_cstr.as_ptr(), 0o755)
                        };
                        if mkdir_res != 0 {
                            let mk_err = std::io::Error::last_os_error();
                            if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                return Err(format!(
                                    "Failed to create directory component {}: {}",
                                    current_path.display(),
                                    mk_err
                                ));
                            }
                        }
                        let opened_fd = unsafe {
                            libc::openat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                            )
                        };
                        if opened_fd < 0 {
                            let open_err = std::io::Error::last_os_error();
                            return Err(format!(
                                "Failed to open directory component {}: {}",
                                current_path.display(),
                                open_err
                            ));
                        }
                        curr_fd = unsafe { OwnedFd::from_raw_fd(opened_fd) };
                        continue;
                    }
                    if raw == Some(libc::ELOOP) || raw == Some(libc::ENOTDIR) {
                        let mut comp_st: libc::stat = unsafe { std::mem::zeroed() };
                        let stat_res = unsafe {
                            libc::fstatat(
                                curr_fd.as_raw_fd(),
                                part_cstr.as_ptr(),
                                &mut comp_st,
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        };
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        if stat_res == 0 && (comp_st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
                            return Err(format!(
                                "Candidate receipt ancestor {} is not a directory",
                                current_path.display()
                            ));
                        }
                        if raw == Some(libc::ELOOP) {
                            return Err(format!(
                                "Candidate receipt ancestor {} is a symlink",
                                current_path.display()
                            ));
                        }
                        return Err(format!(
                            "Candidate receipt ancestor {} is not a directory",
                            current_path.display()
                        ));
                    }
                    return Err(format!(
                        "Failed to open directory component {}: {}",
                        current_path.display(),
                        err
                    ));
                }
                curr_fd = unsafe { OwnedFd::from_raw_fd(next_fd) };
            }
        }
    }

    Ok(Some(curr_fd))
}

#[allow(dead_code)]
fn open_dir_nofollow_stepwise(dir_path: &std::path::Path) -> Result<OwnedFd, String> {
    match open_dir_nofollow_stepwise_ext(dir_path, false)? {
        Some(fd) => Ok(fd),
        None => Err(format!(
            "ENOENT: Directory component {} does not exist",
            dir_path.display()
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptSnapshotEntry {
    pub bytes: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl std::ops::Deref for ReceiptSnapshotEntry {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for ReceiptSnapshotEntry {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for ReceiptSnapshotEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

impl From<&[u8]> for ReceiptSnapshotEntry {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            mode: 0o600,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }
}

fn snapshot_candidate_receipts(
    pkg_name: &str,
) -> Result<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>, String> {
    let paths = resolve_candidate_receipt_paths(pkg_name);
    let mut snapshots = Vec::new();
    for path in paths {
        let parent = path.parent().ok_or_else(|| {
            format!("Candidate receipt {} has no parent directory", path.display())
        })?;

        let file_name = path.file_name().ok_or_else(|| {
            format!("Candidate receipt {} has no file name", path.display())
        })?;
        let file_cstr = std::ffi::CString::new(file_name.as_bytes()).map_err(|e| {
            format!("Invalid receipt filename {}: {}", path.display(), e)
        })?;

        let is_version_or_components = matches!(
            file_name.to_str(),
            Some(".af-version") | Some(".af-components.json")
        );
        let max_size: i64 = if is_version_or_components {
            64 * 1024
        } else {
            1024 * 1024
        };
        let limit_label = if is_version_or_components {
            "64 KiB"
        } else {
            "1 MiB"
        };

        // 1. Open parent using open_dir_nofollow_stepwise_ext(parent, false)
        let dir_fd = match open_dir_nofollow_stepwise_ext(parent, false) {
            Ok(Some(fd)) => fd,
            Ok(None) => {
                snapshots.push((path, None));
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        };

        // 2. Stat candidate receipt entry relative to dir_fd with AT_SYMLINK_NOFOLLOW
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to stat receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if st.st_size > max_size || st.st_size < 0 {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        // 3. Open receipt file relative to dir_fd
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                snapshots.push((path, None));
                continue;
            }
            return Err(format!(
                "Failed to open receipt {}: {}",
                path.display(),
                err
            ));
        }

        // 4. Verify libc::fstat matches (st.st_dev, st.st_ino) and S_IFREG and <= max_size
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        let fstat_res = unsafe { libc::fstat(fd, &mut opened_st) };
        if fstat_res != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!(
                "Failed to stat opened receipt {}: {}",
                path.display(),
                err
            ));
        }

        if (opened_st.st_dev, opened_st.st_ino) != (st.st_dev, st.st_ino) {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} changed during open",
                path.display()
            ));
        }

        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} is a symlink or non-regular file",
                path.display()
            ));
        }

        if opened_st.st_size > max_size || opened_st.st_size < 0 {
            unsafe { libc::close(fd) };
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        let mode = (opened_st.st_mode & 0o7777) as u32;
        let uid = opened_st.st_uid as u32;
        let gid = opened_st.st_gid as u32;

        // 5. Read bounded at most max_size
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = Vec::new();
        file.by_ref().take((max_size as u64) + 1).read_to_end(&mut buf).map_err(|e| {
            format!("Failed to read receipt {}: {}", path.display(), e)
        })?;

        if buf.len() > max_size as usize {
            return Err(format!(
                "Candidate receipt {} exceeds {} limit",
                path.display(),
                limit_label
            ));
        }

        snapshots.push((
            path,
            Some(ReceiptSnapshotEntry {
                bytes: buf,
                mode,
                uid,
                gid,
            }),
        ));
    }
    Ok(snapshots)
}

fn restore_candidate_receipts(
    snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (path, prev_entry_opt) in snapshots {
        let parent = match path.parent() {
            Some(p) => p,
            None => {
                errors.push(format!("Receipt path has no parent: {}", path.display()));
                continue;
            }
        };

        let file_name = match path.file_name() {
            Some(name) => name,
            None => {
                errors.push(format!("Receipt path has no file name: {}", path.display()));
                continue;
            }
        };
        let file_cstr = match std::ffi::CString::new(file_name.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("Invalid receipt filename {}: {}", path.display(), e));
                continue;
            }
        };

        let dir_fd = if prev_entry_opt.is_some() {
            match open_dir_nofollow_stepwise_ext(parent, true) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    errors.push(format!(
                        "Failed to create or open parent directory for receipt {}",
                        path.display()
                    ));
                    continue;
                }
                Err(e) => {
                    errors.push(format!("Refusing to restore receipt {}: {}", path.display(), e));
                    continue;
                }
            }
        } else {
            match open_dir_nofollow_stepwise_ext(parent, false) {
                Ok(Some(fd)) => fd,
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    errors.push(format!(
                        "Refusing to remove uncertified receipt {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            }
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                file_cstr.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_res == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            errors.push(format!(
                "Refusing to overwrite directory at receipt path {}",
                path.display()
            ));
            continue;
        }

        if let Some(entry) = prev_entry_opt {
            let tmp_name = format!(
                ".af-tmp-receipt-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            );
            let tmp_cstr = match std::ffi::CString::new(tmp_name.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("Invalid temporary receipt filename: {}", e));
                    continue;
                }
            };

            let tmp_fd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if tmp_fd < 0 {
                let err = std::io::Error::last_os_error();
                errors.push(format!(
                    "Failed to create temporary receipt for {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let write_res = (|| -> Result<(), std::io::Error> {
                let mut written = 0;
                while written < entry.bytes.len() {
                    let res = unsafe {
                        libc::write(
                            tmp_fd,
                            entry.bytes[written..].as_ptr() as *const libc::c_void,
                            entry.bytes.len() - written,
                        )
                    };
                    if res < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    written += res as usize;
                }
                Ok(())
            })();

            if let Err(e) = write_res {
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to write temporary receipt for {}: {}",
                    path.display(),
                    e
                ));
                continue;
            }

            let chown_res = unsafe { libc::fchown(tmp_fd, entry.uid as libc::uid_t, entry.gid as libc::gid_t) };
            if chown_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore ownership for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let chmod_res = unsafe { libc::fchmod(tmp_fd, (entry.mode & 0o7777) as libc::mode_t) };
            if chmod_res < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to restore mode for temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            let sync_res = unsafe { libc::fsync(tmp_fd) };
            if sync_res != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(tmp_fd);
                    libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0);
                }
                errors.push(format!(
                    "Failed to fsync temporary receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }

            unsafe { libc::close(tmp_fd) };

            let rename_res = unsafe {
                libc::renameat(
                    dir_fd.as_raw_fd(),
                    tmp_cstr.as_ptr(),
                    dir_fd.as_raw_fd(),
                    file_cstr.as_ptr(),
                )
            };
            if rename_res != 0 {
                let err = std::io::Error::last_os_error();
                let _ = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), tmp_cstr.as_ptr(), 0) };
                errors.push(format!(
                    "Failed to atomically restore receipt {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        } else {
            let unlink_res = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), file_cstr.as_ptr(), 0) };
            if unlink_res != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    errors.push(format!(
                        "Failed to remove uncertified receipt {}: {}",
                        path.display(),
                        err
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}

async fn finalize_post_script_lifecycle_with<
    LoadIngressFn,
    SaveIngressFn,
    ControlFn,
    ControlFut,
    RefreshUpdateFn,
    RefreshUpdateFut,
    RefreshOutput,
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
) -> Result<Option<String>, PackageLifecycleFailure>
where
    LoadIngressFn: FnMut(&str) -> anyhow::Result<Option<AppIngressConfig>>,
    SaveIngressFn: FnMut(&AppIngressConfig) -> anyhow::Result<()>,
    ControlFn: FnMut(String, &'static str) -> ControlFut,
    ControlFut: std::future::Future<Output = anyhow::Result<()>>,
    RefreshUpdateFn: FnMut(String) -> RefreshUpdateFut,
    RefreshUpdateFut: std::future::Future<Output = RefreshOutput>,
    RefreshOutput: PostOperationRefreshResult,
{
    if !matches!(action, "install" | "reinstall" | "update") {
        return Ok(None);
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

    if matches!(action, "update" | "install" | "reinstall")
        && af_services::should_pre_stop_on_update(clean_id)
    {
        for u in stopped_units.iter().rev() {
            if let Err(e) = control_unit(u.clone(), "start").await {
                service_restore_failed = true;
                required_errors.push(format!("Failed to restart stopped unit {}: {}", u, e));
            }
        }
    }

    let refreshed = refresh_update(clean_id.to_string()).await;
    let achieved_version = refreshed.into_installed_version();

    if required_errors.is_empty() {
        Ok(achieved_version)
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

fn is_incomplete_rollback_error(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("incomplete rollback")
        || lower.contains("incomplete_rollback")
        || lower.contains("incomplete recovery")
        || lower.contains("recovery backup preserved")
        || lower.contains("failed to stop")
}

#[allow(dead_code)]
async fn restore_pre_stopped_units_after_installer_failure_with<ControlFn, ControlFut>(
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
            for unit in stopped_units.iter().rev() {
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

fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rest.rfind('#') {
        let before = &rest[..idx];
        let after = &rest[idx + 1..];
        if before.ends_with("?q") || before.ends_with("&q") {
            return (rest, None);
        }
        if before.ends_with("cred") && after.contains('@') {
            return (rest, None);
        }
        (before, Some(after))
    } else {
        (rest, None)
    }
}

fn sanitize_git_repo_remote(remote: &str) -> String {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    static HEX_12_QUERY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"^\?q#[0-9a-fA-F]{12}$").unwrap()
    });

    // Mask cred#<12-hex> and ?q#<12-hex> so Url::parse does not treat '#' as URL fragment delimiter
    let masked = if trimmed.contains("cred#") || trimmed.contains("?q#") {
        let m1 = regex::Regex::new(r"cred#([0-9a-fA-F]{12})@")
            .unwrap()
            .replace_all(trimmed, "cred__AFTOKEN__$1@")
            .into_owned();
        regex::Regex::new(r"\?q#([0-9a-fA-F]{12})")
            .unwrap()
            .replace_all(&m1, "?q__AFTOKEN__$1")
            .into_owned()
    } else {
        trimmed.to_string()
    };

    if let Ok(mut parsed) = reqwest::Url::parse(&masked) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        if let Some(q) = parsed.query() {
            let full_q = format!("?{q}");
            if !full_q.starts_with("?q__AFTOKEN__") && !HEX_12_QUERY_RE.is_match(&full_q) {
                parsed.set_query(None);
            }
        }
        parsed.set_fragment(None);

        let user = parsed.username().to_string();
        let pass = parsed.password().map(|p| p.to_string());

        if pass.is_some() {
            let _ = parsed.set_password(None);
            if (scheme == "http" || scheme == "https") && !user.starts_with("cred__AFTOKEN__") {
                let _ = parsed.set_username("");
            }
        } else if !user.is_empty()
            && (scheme == "http" || scheme == "https")
            && !user.starts_with("cred__AFTOKEN__")
        {
            let _ = parsed.set_username("");
        }

        let mut out = parsed.to_string();
        if !masked.ends_with('/') && out.ends_with('/') && parsed.path() == "/" {
            out.pop();
        }
        // Unmask
        out = out.replace("cred__AFTOKEN__", "cred#");
        out = out.replace("?q__AFTOKEN__", "?q#");
        out
    } else if trimmed.contains(':') {
        let (without_frag, _) = split_git_repo_remote_and_branch(trimmed);
        let (without_q, query_part) = if let Some((base, q)) = without_frag.split_once('?') {
            let full_q = format!("?{q}");
            if HEX_12_QUERY_RE.is_match(&full_q) {
                (base, format!("?{q}"))
            } else {
                (base, String::new())
            }
        } else {
            (without_frag, String::new())
        };

        if let Some((user_host, path)) = without_q.split_once(':') {
            if let Some((user, host)) = user_host.split_once('@') {
                let clean_user = if let Some((u, _pass)) = user.split_once(':') {
                    u
                } else {
                    user
                };
                format!("{clean_user}@{host}:{path}{query_part}")
            } else {
                format!("{user_host}:{path}{query_part}")
            }
        } else {
            format!("{without_q}{query_part}")
        }
    } else {
        trimmed.to_string()
    }
}

pub fn sanitize_url_or_source_key_for_api(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.contains('|') {
        let parts: Vec<String> = trimmed
            .split('|')
            .map(sanitize_url_or_source_key_for_api)
            .collect();
        return parts.join("|");
    }

    if let Some(rest) = trimmed.strip_prefix("git-repo:") {
        let (remote, branch) = split_git_repo_remote_and_branch(rest);
        let sanitized_remote = sanitize_git_repo_remote(remote);
        return match branch {
            Some(b) => format!("git-repo:{sanitized_remote}#{b}"),
            None => format!("git-repo:{sanitized_remote}"),
        };
    }

    static URL_USERINFO_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/?#@\s]+@").unwrap()
    });
    static SENSITIVE_QUERY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"(?i)([?&;])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|credential(?:s)?|passphrase|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass|jwt[_-]?secret)[A-Za-z0-9_.-]*|\b(?:[A-Za-z0-9]*[_.-])?pass(?:[_.-][A-Za-z0-9]*)*\b)=([^&#|\s]+)"#).unwrap()
    });

    let stripped = URL_USERINFO_RE.replace_all(trimmed, "$1");

    // If reqwest::Url::parse succeeds on a display URL, strip credentials, query string, and fragment.
    if let Ok(mut parsed) = reqwest::Url::parse(&stripped) {
        let scheme = parsed.scheme();
        if (scheme == "http" || scheme == "https" || scheme == "ssh" || scheme == "git" || scheme == "ftp")
            && parsed.has_host()
        {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            let mut out = parsed.to_string();
            let base_before = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
            if !trimmed.ends_with('/') && out.ends_with('/') && !base_before.ends_with('/') {
                if parsed.path() == "/" {
                    out.pop();
                }
            }
            return out;
        }
    }

    // SCP-style remotes: e.g. git@github.com:org/repo.git?token=x#frag or user:pass@host:path?q#frag
    if !trimmed.contains("://") {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let without_q = without_frag.split('?').next().unwrap_or(without_frag);
        if let Some((userinfo, host_path)) = without_q.split_once('@') {
            if host_path.contains(':') || trimmed.starts_with("git@") {
                let clean_user = userinfo.split(':').next().unwrap_or(userinfo);
                return format!("{clean_user}@{host_path}");
            }
        }
    }

    let query_sanitized = SENSITIVE_QUERY_RE.replace_all(&stripped, "$1$2=[REDACTED]");
    let sanitized = af_runner::package_lifecycle::sanitize_lifecycle_field(&query_sanitized);
    URL_USERINFO_RE.replace_all(&sanitized, "$1").into_owned()
}

pub fn sanitize_package_update_record(
    mut record: af_services::workers::PackageUpdateRecord,
) -> af_services::workers::PackageUpdateRecord {
    record.release_url = sanitize_url_or_source_key_for_api(&record.release_url);
    record.source_key = sanitize_url_or_source_key_for_api(&record.source_key);
    record.installed_version = sanitize_url_or_source_key_for_api(&record.installed_version);
    record.latest_version = sanitize_url_or_source_key_for_api(&record.latest_version);
    record.error = sanitize_url_or_source_key_for_api(&af_services::workers::public_update_error(&record.error));
    record
}

pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime_with<ControlFn, ControlFut, StatusFn>(
    clean_id: &str,
    quiesce_units: &[String],
    restart_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    mut runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
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
        for unit in quiesce_units {
            if let Err(e) = control_unit(unit.clone(), "stop").await {
                let err_str = e.to_string();
                let err_lower = err_str.to_ascii_lowercase();
                let is_absent_err = err_lower.contains("not loaded")
                    || err_lower.contains("not-found")
                    || err_lower.contains("no such file")
                    || err_lower.contains("could not be found")
                    || err_lower.contains("exit status: 5")
                    || err_lower.contains("exit code 5");

                if is_absent_err && matches!(query_status(unit).as_str(), "stopped" | "idle") {
                    tracing::info!(
                        unit = %unit,
                        error = %e,
                        "Absent unit not loaded during stop before restoration, confirmed quiescent"
                    );
                } else {
                    tracing::error!(unit = %unit, error = %e, "Failed to quiesce unit before receipt restoration");
                    quiesce_failures.push(format!("Failed to quiesce unit '{unit}' before receipt restoration: {e}"));
                }
            }
        }
    }

    if !quiesce_failures.is_empty() {
        return (
            Some("Skipped candidate receipt restoration because service quiescence failed (incomplete-rollback)".to_string()),
            quiesce_failures,
        );
    }

    // Incomplete rollback did not recover runtime. Leave candidate receipts on
    // disk so a NEW runtime is not paired with a rewound .af-version.
    let mut restart_failures: Vec<String> = Vec::new();
    if refuse_restart {
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

    // Step 2: Restore runtime snapshot if present
    if let Some(ref mut rt) = runtime_snapshot {
        if let Err(rt_err) = rt.restore() {
            if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
                restart_failures.push(
                    "Refusing to restart pre-stopped service after runtime restoration failure".to_string(),
                );
            }
            return (Some(rt_err), restart_failures);
        }
    }

    // Step 3: Restore candidate receipts
    let receipt_restore_error = if !receipt_snapshots.is_empty() {
        restore_candidate_receipts(receipt_snapshots).err()
    } else {
        None
    };

    // Step 4: Restart restart_units AFTER restore_candidate_receipts completes
    if receipt_restore_error.is_some() {
        if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
            restart_failures.push(
                "Refusing to restart pre-stopped service after receipt restoration failure".to_string(),
            );
        }
        return (receipt_restore_error, restart_failures);
    }

    if af_services::should_pre_stop_on_update(clean_id) && !restart_units.is_empty() {
        for unit in restart_units.iter().rev() {
            if let Err(e) = control_unit(unit.clone(), "start").await {
                tracing::error!(unit = %unit, error = %e, "Application service restart failed after receipt restoration");
                restart_failures.push(format!("{unit}: {e}"));
            }
        }

        // Step 5: Verify restart_units active
        for unit in restart_units {
            let st = query_status(unit);
            if st != "running" && st != "idle" {
                if !restart_failures.iter().any(|f| f.starts_with(unit)) {
                    restart_failures.push(format!("{unit} is {st}"));
                }
            }
        }
    }

    (receipt_restore_error, restart_failures)
}

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
static CANDIDATE_QUIESCE_RECORDER: std::sync::Mutex<Option<Vec<String>>> =
    std::sync::Mutex::new(None);

pub(crate) async fn quiesce_and_restore_candidate_receipts_and_runtime(
    clean_id: &str,
    stopped_units: &[String],
    receipt_snapshots: &[(PathBuf, Option<ReceiptSnapshotEntry>)],
    refuse_restart: bool,
    runtime_snapshot: Option<&mut af_runner::package_lifecycle::PackageRuntimeSnapshot>,
) -> (Option<String>, Vec<String>) {
    let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
    let mut quiesce_units = stopped_units.to_vec();
    for u in all_controllable {
        if !quiesce_units.contains(&u) {
            quiesce_units.push(u);
        }
    }
    quiesce_units.sort_by_key(|u| !u.ends_with(".timer"));
    let restart_units: Vec<String> = stopped_units
        .iter()
        .filter(|u| is_restart_eligible_unit(u))
        .cloned()
        .collect();
    quiesce_and_restore_candidate_receipts_and_runtime_with(
        clean_id,
        &quiesce_units,
        &restart_units,
        receipt_snapshots,
        refuse_restart,
        runtime_snapshot,
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

pub(crate) fn should_rollback_post_certification_failure(action: &str, kind: af_services::PackageJobFailure) -> bool {
    matches!(action, "install" | "reinstall" | "update")
        && matches!(
            kind,
            af_services::PackageJobFailure::Configuration
                | af_services::PackageJobFailure::ServiceRestore
                | af_services::PackageJobFailure::ConfigurationAndServiceRestore
        )
}

pub(crate) async fn handle_post_certification_finalization_failure_with<ControlFn, ControlFut, StatusFn>(
    action: &str,
    mut required_err: PackageLifecycleFailure,
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
    if should_rollback_post_certification_failure(action, required_err.kind) {
        let all_controllable = af_services::resolve_controllable_service_units(clean_id, "stop");
        let mut quiesce_units = stopped_units.to_vec();
        for u in all_controllable {
            if !quiesce_units.contains(&u) {
                quiesce_units.push(u);
            }
        }
        quiesce_units.sort_by_key(|u| !u.ends_with(".timer"));
        let restart_units: Vec<String> = stopped_units
            .iter()
            .filter(|u| is_restart_eligible_unit(u))
            .cloned()
            .collect();
        let (receipt_restore_error, restart_failures) =
            quiesce_and_restore_candidate_receipts_and_runtime_with(
                clean_id,
                &quiesce_units,
                &restart_units,
                receipt_snapshots,
                refuse_restart,
                runtime_snapshot,
                control_unit,
                query_status,
            )
            .await;
        if let Some(ref r_err) = receipt_restore_error {
            required_err.message.push_str(&format!("; receipt restoration error: {}", r_err));
        }
        if !restart_failures.is_empty() {
            required_err.message.push_str(&format!("; post-restoration restart failures: {}", restart_failures.join("; ")));
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

#[allow(dead_code)]
fn resolve_confirmed_latest_version(clean_id: &str) -> Option<String> {
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(ver) = conn.query_row(
            "SELECT latest_version FROM app_updates WHERE package_name = ?1",
            rusqlite::params![clean_id],
            |r| r.get::<_, String>(0),
        ) {
            let trimmed = ver.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub(crate) async fn dispatch_package_lifecycle(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    delete_data: bool,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    dispatch_package_lifecycle_with_target(
        pkg_id,
        action,
        status_label,
        delete_data,
        None,
        auth_user,
        headers,
    )
    .await
}

async fn dispatch_package_lifecycle_with_target(
    pkg_id: String,
    action: &'static str,
    status_label: &'static str,
    delete_data: bool,
    mut expected_target_version: Option<String>,
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

    let clean_id = pkg.name.clone();
    let is_retired = pkg.update_source == "retired" || pkg.name == "readarr";

    if let Some(ref target) = expected_target_version {
        if !af_runner::af_release::lifecycle::is_valid_target_version_token(target) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid target version token format",
            );
        }
    }

    if is_retired {
        if let Some(ref explicit_target) = expected_target_version {
            if !af_runner::af_release::lifecycle::versions_match_target(explicit_target, "0.4.18.2805")
                && !af_runner::af_release::lifecycle::versions_match_target("0.4.18.2805", explicit_target)
            {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Retired package can only target pinned version 0.4.18.2805",
                );
            }
        }
    }

    if action == "remove" {
        expected_target_version = None;
    } else if action == "update" {
        if is_retired && expected_target_version.is_none() {
            expected_target_version = Some("0.4.18.2805".to_string());
        }

        af_services::workers::ensure_app_updates_columns();
        let db_update: Option<(String, String, bool, String, String, String)> = if let Ok(conn) = af_db::get_conn() {
            conn.query_row(
                "SELECT COALESCE(installed_version, ''), COALESCE(latest_version, ''), COALESCE(update_available, 0), COALESCE(checked_at, ''), COALESCE(last_error, ''), COALESCE(source_key, '') FROM app_updates WHERE package_name = ?1",
                rusqlite::params![&clean_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok()
        } else {
            None
        };

        let Some((installed, latest, update_available, checked_at, err, source_key)) = db_update else {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        };

        let db_latest = latest.trim();
        if db_latest.is_empty() {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        }

        if is_retired {
            if !af_runner::af_release::lifecycle::versions_match_target(db_latest, "0.4.18.2805")
                && !af_runner::af_release::lifecycle::versions_match_target("0.4.18.2805", db_latest)
            {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Retired package can only target pinned version 0.4.18.2805",
                );
            }
        }

        let github_api_base = std::env::var("AETHERFLOW_GITHUB_API_BASE_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.github.com".to_string());
        let expected_source_key = af_services::workers::canonical_update_source_key(&github_api_base, &pkg);

        if source_key.trim().is_empty() || source_key.trim() != expected_source_key {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: package update source is unconfirmed or mismatched",
            );
        }

        let has_valid_checked_at = !checked_at.trim().is_empty()
            && chrono::DateTime::parse_from_rfc3339(checked_at.trim()).is_ok();
        let db_installed = installed.trim();
        let installed_confirmed = !db_installed.is_empty()
            && !db_installed.eq_ignore_ascii_case("unknown")
            && !err.to_ascii_lowercase().contains("installed version");
        let has_provenance = has_valid_checked_at
            && installed_confirmed
            && update_available;

        if !installed_confirmed {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: installed version could not be confirmed",
            );
        }
        if !has_provenance {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version lacks prior confirmation provenance",
            );
        }

        if !err.trim().is_empty() {
            let Some(ref explicit_target) = expected_target_version else {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Cannot start update: upstream update check reported error",
                );
            };
            if !af_runner::af_release::lifecycle::versions_match_target(explicit_target, db_latest)
                && !af_runner::af_release::lifecycle::versions_match_target(db_latest, explicit_target)
            {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    "Explicit target version conflicts with confirmed upstream latest version",
                );
            }
        } else {
            if let Some(ref explicit_target) = expected_target_version {
                if !af_runner::af_release::lifecycle::versions_match_target(explicit_target, db_latest)
                    && !af_runner::af_release::lifecycle::versions_match_target(db_latest, explicit_target)
                {
                    return api_error(
                        StatusCode::CONFLICT,
                        "CONFLICT",
                        "Explicit target version conflicts with confirmed upstream latest version",
                    );
                }
            } else {
                expected_target_version = Some(db_latest.to_string());
            }
        }

        if expected_target_version.as_deref().unwrap_or("").trim().is_empty() {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot start update: target version is unconfirmed",
            );
        }
    } else {
        // Install or Reinstall: do not block on app_updates errors or missing records
        if is_retired && expected_target_version.is_none() {
            expected_target_version = Some("0.4.18.2805".to_string());
        }
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
        expected_target_version: expected_target_version.clone(),
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
                expected_target_version.as_deref(),
                None,
                &[],
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

        let expected_target_for_runner = expected_target_version.clone();
        let captured_receipt_snapshots: std::sync::Arc<
            std::sync::Mutex<Vec<(PathBuf, Option<ReceiptSnapshotEntry>)>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let snapshots_slot = captured_receipt_snapshots.clone();
        let captured_runtime_snapshot: std::sync::Arc<
            std::sync::Mutex<Option<af_runner::package_lifecycle::PackageRuntimeSnapshot>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let runtime_snapshot_slot = captured_runtime_snapshot.clone();
        let (allocated_port, stopped_units, execution_result) =
            match run_package_lifecycle_dispatch_gate_with(
                action,
                &clean_id,
                pkg_default_port,
                &fs_root_override_raw,
                |app_id| af_services::mutators::get_app_runtime_meta(app_id).configured_port,
                load_authoritative_app_ingress_config,
                allocate_or_resolve_app_port,
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
                    let runtime_snapshot_slot = runtime_snapshot_slot.clone();
                    async move {
                        if matches!(action, "install" | "reinstall" | "update") {
                            match snapshot_candidate_receipts(&clean_id) {
                                Ok(s) => *snapshots_slot.lock().unwrap() = s,
                                Err(err) => {
                                    return Err(anyhow::anyhow!("Preparation: {err}"));
                                }
                            }
                            let mut env_cfg = af_runner::PackageExecutionEnv::default();
                            env_cfg.fs_root = fs_root_override
                                .as_ref()
                                .map(|s| PathBuf::from(s.trim()))
                                .or_else(|| af_runner::PackageExecutionEnv::default().fs_root);
                            // The privileged af-runner daemon captures its own root snapshot
                            // when it will execute the installer. A second unprivileged
                            // capture here would either fail or record a partial tree.
                            let capture_locally = env_cfg.fs_root.is_some()
                                || !(can_run_bash && af_runner::is_runner_available());
                            if capture_locally {
                            let mut capture_units = af_services::resolve_controllable_service_units(&clean_id, "stop");
                            if let Ok(pkgs) = af_services::get_packages() {
                                if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_id) {
                                    let svc = p.service_name.trim().to_string();
                                    if !svc.is_empty()
                                        && !matches!(svc.as_str(), "apache2" | "nginx" | "apache2.service" | "nginx.service")
                                        && !capture_units.contains(&svc)
                                    {
                                        capture_units.push(svc);
                                    }
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
                        expected_target_version.as_deref(),
                        None,
                        &[],
                    );
                    return;
                }
            };

        let receipt_snapshots = captured_receipt_snapshots.lock().unwrap().clone();
        let mut runtime_snapshot = captured_runtime_snapshot.lock().unwrap().take();

        if let Err(error) = execution_result {
            af_services::mutators::clear_app_runtime_meta_cache();
            let _ = af_services::workers::refresh_package_update_by_id(&clean_id).await;
            let err_str = error.to_string();
            let is_prep_err = err_str.starts_with("Preparation: ");
            let refuse_restart = is_incomplete_rollback_error(&err_str);
            let (receipt_restore_error, restart_failures) =
                if matches!(action, "install" | "reinstall" | "update") {
                    quiesce_and_restore_candidate_receipts_and_runtime(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        refuse_restart,
                        if refuse_restart { None } else { runtime_snapshot.as_mut() },
                    )
                    .await
                } else {
                    let mut restart_failures = Vec::new();
                    if refuse_restart {
                        restart_failures.push("Refusing to restart pre-stopped service after incomplete rollback".to_string());
                    } else if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
                        for unit in stopped_units.iter().rev() {
                            if let Err(e) = af_services::control_service_with_manager(unit, "start", "systemd-unit").await {
                                restart_failures.push(format!("{unit}: {e}"));
                            }
                        }
                    }
                    (None, restart_failures)
                };

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
            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle(
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
            );
            return;
        }

        let mut achieved_ver: Option<String> = None;

        if matches!(action, "install" | "reinstall" | "update") {
            let mut restart_failures: Vec<String> = Vec::new();
            if af_services::should_pre_stop_on_update(&clean_id) && !stopped_units.is_empty() {
                for unit in stopped_units.iter().rev() {
                    if let Err(e) = af_services::control_service_with_manager(unit, "start", "systemd-unit").await {
                        tracing::error!(unit, error = %e, "Application service restoration failed after script execution");
                        restart_failures.push(format!("{unit}: {e}"));
                    }
                }
                for unit in &stopped_units {
                    let (st, _, _) = af_services::get_systemd_unit_info(unit);
                    if st != "running" && st != "idle" {
                        if !restart_failures.iter().any(|f| f.starts_with(unit)) {
                            restart_failures.push(format!("{unit} is {st}"));
                        }
                    }
                }
            }

            if !restart_failures.is_empty() {
                let (receipt_restore_error, post_restore_failures) =
                    quiesce_and_restore_candidate_receipts_and_runtime(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
                    )
                    .await;
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

                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle(
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
                let (receipt_restore_error, post_restore_failures) =
                    quiesce_and_restore_candidate_receipts_and_runtime(
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
                    )
                    .await;
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

                af_services::clear_service_status_cache();
                af_services::mutators::clear_app_runtime_meta_cache();
                finish_package_lifecycle(
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

            let blueprint_error =
                af_services::mutators::apply_blueprint_app_config(&clean_id, allocated_port)
                    .await
                    .err();

            let base_domain = af_services::resolve_base_domain();
            let finalization = finalize_post_script_lifecycle_with(
                action,
                &clean_id,
                allocated_port,
                stopped_units.clone(),
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
                    let pkgs = af_services::get_packages().unwrap_or_default();
                    if let Some(pkg) = pkgs.into_iter().find(|p| p.name == app_id) {
                        af_services::workers::probe_installed_package_version_strict(&pkg)
                            .await
                            .ok()
                            .filter(|s| !s.trim().is_empty())
                    } else {
                        None
                    }
                },
            )
            .await;
            let finalization_check = finalization.as_ref().map(|_| ()).map_err(|e| PackageLifecycleFailure {
                kind: e.kind,
                message: e.message.clone(),
            });
            if let Err(required_err) = merge_blueprint_finalization(finalization_check, blueprint_error) {
                let (required_err, receipt_restore_error, _restart_failures) =
                    handle_post_certification_finalization_failure_with(
                        action,
                        required_err,
                        &clean_id,
                        &stopped_units,
                        &receipt_snapshots,
                        false,
                        runtime_snapshot.as_mut(),
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
                if let Some(r_err) = receipt_restore_error {
                    tracing::error!(
                        package = %clean_id,
                        error = %r_err,
                        "Failed to restore candidate receipts after service restoration failure"
                    );
                    append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
                }
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
                    expected_target_version.as_deref(),
                    None,
                    &stopped_units,
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
                    None,
                    None,
                    &stopped_units,
                );
                return;
            }
            if let Err(dns_err) = af_services::mutators::sync_network_dns_providers().await {
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

        let mut unresumed_units = Vec::new();
        for unit in &stopped_units {
            let (st, _, _) = af_services::get_systemd_unit_info(unit);
            if st != "running" && st != "idle" {
                unresumed_units.push(format!("{unit} ({st})"));
            }
        }
        if !unresumed_units.is_empty() {
            let (receipt_restore_error, restart_failures) =
                quiesce_and_restore_candidate_receipts_and_runtime(
                    &clean_id,
                    &stopped_units,
                    &receipt_snapshots,
                    false,
                    runtime_snapshot.as_mut(),
                )
                .await;
            if let Some(ref r_err) = receipt_restore_error {
                tracing::error!(
                    package = %clean_id,
                    error = %r_err,
                    "Failed to restore candidate receipts after service inactive verification"
                );
                append_package_job_output(&job_id, &format!("receipt restoration error: {r_err}"));
            }
            let mut msg = format!(
                "Application service failed to remain active after execution: {}",
                unresumed_units.join("; ")
            );
            if !restart_failures.is_empty() {
                msg.push_str(&format!("; post-restoration restart failures: {}", restart_failures.join("; ")));
            }
            if let Some(ref r_err) = receipt_restore_error {
                msg.push_str(&format!("; receipt restoration error: {}", r_err));
            }
            af_services::clear_service_status_cache();
            af_services::mutators::clear_app_runtime_meta_cache();
            finish_package_lifecycle(
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
            );
            return;
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
            expected_target_version.as_deref(),
            achieved_ver.as_deref(),
            &stopped_units,
        );
    }));

    let msg = match action {
        "install" | "reinstall" => "Installation started successfully",
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
    let pkg_repo_urls: HashMap<String, String> = af_services::get_packages()
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.name, sanitize_url_or_source_key_for_api(&p.update_repo_url)))
        .collect();

    let updates: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            let sanitized = sanitize_package_update_record(r);
            let mut val = serde_json::to_value(&sanitized).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let repo_url = pkg_repo_urls.get(&sanitized.package_id).cloned().unwrap_or_default();
                if !repo_url.is_empty() {
                    obj.insert("update_repo_url".to_string(), serde_json::Value::String(repo_url));
                }
                if !sanitized.source_key.is_empty() {
                    obj.insert(
                        "update_source_key".to_string(),
                        serde_json::Value::String(sanitized.source_key.clone()),
                    );
                }
                if !sanitized.release_url.is_empty() {
                    obj.insert(
                        "update_url".to_string(),
                        serde_json::Value::String(sanitized.release_url.clone()),
                    );
                }
            }
            val
        })
        .collect();

    Json(serde_json::json!({
        "message": "Package update check completed",
        "updates": updates,
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
    let record = record.map(sanitize_package_update_record);
    Json(build_single_package_update_response(&pkg.name, record)).into_response()
}

fn build_single_package_update_response(
    pkg_name: &str,
    mut record: Option<af_services::workers::PackageUpdateRecord>,
) -> serde_json::Value {
    if let Some(record) = record.as_mut() {
        record.error = af_services::workers::public_update_error(&record.error);
        *record = sanitize_package_update_record(record.clone());
    }
    let update_available = record.as_ref().map(|r| r.update_available).unwrap_or(false);
    let installed_version = record.as_ref().map(|r| r.installed_version.clone());
    let latest_version = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.latest_version));
    let update_url = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.release_url));
    let release_url = update_url.clone();
    let update_source_key = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.source_key));
    let update_repo_url = af_services::get_packages()
        .ok()
        .and_then(|pkgs| pkgs.into_iter().find(|p| p.name == pkg_name))
        .map(|p| sanitize_url_or_source_key_for_api(&p.update_repo_url))
        .filter(|u| !u.is_empty());
    let checked_at = record.as_ref().map(|r| r.checked_at.clone());
    let last_error = record
        .as_ref()
        .map(|r| sanitize_url_or_source_key_for_api(&r.error))
        .filter(|e| !e.trim().is_empty());
    serde_json::json!({
        "message": "Package update check completed",
        "package": pkg_name,
        "update_available": update_available,
        "installed_version": installed_version,
        "latest_version": latest_version,
        "update_url": update_url,
        "release_url": release_url,
        "update_repo_url": update_repo_url,
        "update_source_key": update_source_key,
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
    let guarded_app = clean_app.clone();
    match af_services::mutators::with_blueprint_mutation(&guarded_app, async move {
        let existing = match af_db::get_app_ingress_config(&clean_app) {
            Ok(config) => config,
            Err(error) => {
                return Ok(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    error.to_string(),
                ))
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
            Err((status, code, msg)) => return Ok(api_error(status, code, msg)),
        };
        if let Err(e) = af_db::set_app_ingress_config(&cfg) {
            return Ok(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            ));
        }
        af_db::invalidate_ingress_cache();

        let internal_domain = af_services::get_blueprint(&clean_app)
            .map(|bp| bp.internal_domain)
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| format!("{}.aether.local", clean_app));
        if let Err(error) = af_services::mutators::sync_apache_app_vhost(
            &cfg.app_name,
            cfg.listen_port,
            &internal_domain,
            &cfg.public_domain,
            cfg.external_access_enabled,
        ) {
            tracing::warn!(app = %cfg.app_name, detail = %error, "Apache vhost sync skipped or failed during ingress update");
        }
        if cfg.tls_enabled {
            af_services::mutators::trigger_apache_cert_sync().await;
        }
        let mut dns_domains = vec![internal_domain];
        if !cfg.public_domain.is_empty() && !dns_domains.contains(&cfg.public_domain) {
            dns_domains.push(cfg.public_domain.clone());
        }
        let _ = af_services::mutators::sync_local_dns_domains(&dns_domains).await;
        let _ = af_services::mutators::sync_network_dns_providers().await;

        Ok(Json(serde_json::json!({
            "message": "Ingress configuration updated successfully",
            "config": cfg,
        }))
        .into_response())
    })
    .await
    {
        Ok(response) => response,
        Err(error) => blueprint_sync_failure_response(&error),
    }
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
mod update_error_regressions {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_and_historical_update_diagnostics_never_reach_status_consumers() {
        let name = "routes::update_error_regressions::raw_and_historical_update_diagnostics_never_reach_status_consumers";
        if env::var("AF_UPDATE_ERROR_CHILD").as_deref() != Ok(name) {
            assert!(std::process::Command::new(env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("AF_UPDATE_ERROR_CHILD", name)
                .status()
                .unwrap()
                .success());
            return;
        }
        let root = env::temp_dir().join(format!("ue-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        for key in [
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_CONFIG_ROOT",
            "AETHERFLOW_RELEASE_ROOT",
        ] {
            env::set_var(key, &root);
        }
        let db = root.join("fixture.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db);
        }
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
        env::set_var(
            "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
            root.join("automation.json"),
        );
        env::set_var(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                env::var("PATH").unwrap()
            ),
        );
        let command = root.join("bin/systemctl");
        fs::write(
            &command,
            "#!/bin/sh\ntest \"$1\" = show || exit 99\nprintf 'ActiveState=active\\nSubState=running\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&command, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("install/.fixture.lock"), "installed").unwrap();
        fs::write(
            root.join("packages.json"),
            r#"[{"name":"fixture","label":"Fixture","description":"isolated fixture","category":"test","service_type":"systemd","service_name":"fixture","lock_file":"/install/.fixture.lock"}]"#,
        )
        .unwrap();
        fs::write(
            root.join("automation.json"),
            r#"{"fixture":{"update_source":"command","version_command":["/bin/sh","-c","printf 'SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config' >&2; exit 27"]}}"#,
        )
        .unwrap();
        af_db::init_db().unwrap();
        af_services::initialize_package_jobs(rusqlite::Connection::open(&db).unwrap()).unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users(id,username,role) VALUES(1,'status-viewer','user')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_updates(package_name,installed_version,latest_version,update_available,last_error) VALUES('fixture','1.0','1.1',1,'SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config')",
            [],
        )
        .unwrap();
        drop(conn);
        let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
        let router = build_router();

        // 1. Unauthenticated /api/v1/public/marketplace redacts update_error completely.
        let unauth_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/public/marketplace")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_resp.status(), StatusCode::OK);
        let unauth_body = to_bytes(unauth_resp.into_body(), 1024 * 1024).await.unwrap();
        let unauth_text = String::from_utf8(unauth_body.to_vec()).unwrap();
        assert!(!unauth_text.contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
        assert!(!unauth_text.contains("/etc/private/config"));
        assert!(!unauth_text.contains("Update status could not be confirmed"));

        // 2. Authenticated status consumers receive sanitized public_update_error, never raw diagnostics.
        for path in ["/api/v1/public/marketplace", "/api/v1/auth/services"] {
            let request = Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"));
            let response = router
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(
                !text.contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
                "{path}: {text}"
            );
            assert!(!text.contains("/etc/private/config"), "{path}: {text}");
            assert!(
                text.contains("Update status could not be confirmed"),
                "{path}: {text}"
            );
        }
        let record = af_services::workers::refresh_package_update_by_id("fixture")
            .await
            .unwrap();
        assert_eq!(
            record.error,
            "Installed version could not be confirmed; Latest version could not be confirmed"
        );
        let persisted: String = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT last_error FROM app_updates WHERE package_name='fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, record.error);
        let response = build_single_package_update_response(
            "fixture",
            Some(af_services::workers::PackageUpdateRecord {
                error: "SYNTHETIC_PRIVATE_DIAGNOSTIC".into(),
                ..record
            }),
        );
        assert_eq!(
            response["last_error"],
            "Update status could not be confirmed"
        );
        assert!(!response
            .to_string()
            .contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
        fs::remove_dir_all(root).unwrap();
    }
}

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
            source_key: "github:Radarr/Radarr".to_string(),
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
        assert_eq!(body["last_error"], "GitHub API rate limit reached; retaining last confirmed version");
        assert_eq!(body["error"], "GitHub API rate limit reached; retaining last confirmed version");
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

        let reinstall_restored = Arc::new(Mutex::new(Vec::new()));
        let reinstall_restore_handle = Arc::clone(&reinstall_restored);
        finalize_post_script_lifecycle_with(
            "install",
            "radarr",
            7878,
            vec!["radarr".into()],
            "example.com",
            |_| Ok(None),
            |_| Ok(()),
            move |unit, action| {
                reinstall_restore_handle
                    .lock()
                    .unwrap()
                    .push(format!("{action} {unit}"));
                async { Ok(()) }
            },
            |_| async {},
        )
        .await
        .expect("in-place reinstall must restart pre-stopped units");
        assert_eq!(
            *reinstall_restored.lock().unwrap(),
            vec!["start radarr".to_string()]
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
                expected_target_version: None,
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
            ..Default::default()
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

    #[tokio::test(flavor = "current_thread")]
    async fn marketplace_inventory_requires_human_admin_for_lifecycle_diagnostics() {
        use tower::ServiceExt;

        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();
        std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        let package = af_models::Package {
            name: "fixture".into(),
            label: "Fixture".into(),
            lock_file: "/install/.fixture.lock".into(),
            ..Default::default()
        };
        std::fs::write(
            &catalog,
            serde_json::to_vec(&vec![package]).unwrap(),
        )
        .unwrap();
        std::fs::write(&automation, "{}").unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "INSERT INTO users(id, username, role) VALUES (1, 'operator', 'admin'), (2, 'viewer', 'user');
             INSERT INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status)
             VALUES ('inventory-reader', 1, 0, 1, 'running');",
        )
        .unwrap();
        drop(conn);
        assert!(af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: "inventory-privilege-fixture".into(),
            package_id: "fixture".into(),
            expected_target_version: Some("2.0.0".into()),
            action: "update".into(),
            status: "updating".into(),
            progress: 42,
            started_at: chrono::Utc::now().to_rfc3339(),
            last_line: "PRIVATE_INSTALLER_DETAILS".into(),
        }));
        af_services::finish_package_job_with_diagnostics(
            "fixture",
            "update",
            false,
            Some(af_services::PackageJobFailure::Installer),
            "inventory-privilege-fixture",
            Some("private-fixture-stage".into()),
            Some(41),
            Some("PRIVATE_INSTALLER_DETAILS /home/fixture/internal-path".into()),
            Some("2.0.0".into()),
            Some("1.0.0".into()),
        )
        .unwrap();
        let (admin_token, admin_claims) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
        let (user_token, _) = crate::auth::create_standard_jwt(2, &HeaderMap::new()).unwrap();
        let mut cases = vec![
            ("human-admin".to_string(), admin_token, true, true),
            ("human-user".to_string(), user_token, true, false),
            ("invalid".to_string(), "invalid-token".to_string(), false, false),
        ];
        for (scope, authenticated) in [
            ("/api/v1/admin/packages", true),
            ("/api/v1/public/marketplace", true),
            ("/api/v1/auth/system/metrics", false),
        ] {
            let manifest = crate::plugins::ValidatedPluginManifest {
                id: "inventory-reader".into(),
                name: "Inventory reader".into(),
                version: "1.0.0".into(),
                sdk: String::new(),
                contract_version: String::new(),
                runtime_status: String::new(),
                description: String::new(),
                author: String::new(),
                permissions: Vec::new(),
                granted_scopes: vec![crate::plugins::PluginScopeRule {
                    method: "GET".into(),
                    route: scope.into(),
                }],
                lifecycle_hooks: Default::default(),
                backend: Default::default(),
                frontend: Default::default(),
                plugin_dir: root.join("plugins/inventory-reader"),
            };
            let (token, _) = crate::plugins::mint_scoped_plugin_token(&manifest, Some(300)).unwrap();
            assert!(crate::plugins::decode_and_verify_plugin_token(&token).is_ok());
            cases.push((format!("dedicated {scope}"), token, authenticated, false));
            for plugin_id in ["inventory-reader", ""] {
                let mut claims = admin_claims.clone();
                claims.plugin_id = plugin_id.into();
                claims.plugin_scopes = vec![scope.into()];
                claims.jti = uuid::Uuid::new_v4().to_string();
                let token = jsonwebtoken::encode(
                    &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                    &claims,
                    &jsonwebtoken::EncodingKey::from_secret(&crate::auth::jwt_secret_bytes()),
                )
                .unwrap();
                assert!(crate::auth::decode_session_claims(&token, false).is_ok());
                cases.push((format!("legacy {plugin_id:?} {scope}"), token, authenticated, false));
            }
        }
        let router = build_router();
        for (label, token, authenticated, diagnostics_allowed) in cases {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
            assert_eq!(
                get_marketplace_auth_info(&headers),
                (authenticated, diagnostics_allowed),
                "{label}"
            );
            for require_auth in [false, true] {
                let response = router
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(if require_auth {
                                "/api/v1/public/marketplace?require_auth=1"
                            } else {
                                "/api/v1/public/marketplace"
                            })
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if require_auth && !authenticated {
                    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK, "{label}");
                assert_eq!(
                    response.headers()["x-aetherflow-inventory-authenticated"],
                    if authenticated { "true" } else { "false" },
                    "{label}"
                );
                let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
                let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let app = &payload[0];
                assert_eq!(app["inventory_known"], authenticated, "{label}");
                if authenticated {
                    assert_eq!(app["last_job"]["job_id"], "inventory-privilege-fixture", "{label}");
                    assert_eq!(app["last_job"]["status"], "failed", "{label}");
                    assert_eq!(app["last_job"]["expected_target_version"], "2.0.0", "{label}");
                }
                for field in ["failed_stage", "exit_code", "sanitized_summary"] {
                    assert_eq!(app["last_job"].get(field).is_some(), diagnostics_allowed, "{label} {field}");
                }
                assert_eq!(payload.to_string().contains("PRIVATE_INSTALLER_DETAILS"), diagnostics_allowed, "{label}");
                assert_eq!(payload.to_string().contains("/home/fixture/internal-path"), diagnostics_allowed, "{label}");
            }
        }
        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
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
                last_line: "step_output=private-installer-output".into(),
                started_at: "fixture-start".into(),
                expected_target_version: None,
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

    fn short_test_socket_path(filename: &str) -> std::path::PathBuf {
        if let Some(tmpdir) = std::env::var_os("TMPDIR") {
            if !tmpdir.is_empty() {
                let candidate = std::path::PathBuf::from(tmpdir).join(filename);
                if candidate.as_os_str().len() < 95 {
                    return candidate;
                }
            }
        }
        let candidate = std::env::temp_dir().join(filename);
        if candidate.as_os_str().len() < 95 {
            candidate
        } else {
            std::path::PathBuf::from("/tmp").join(filename)
        }
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
            short_test_socket_path(&format!(
                "afr-{}.sock",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            )),
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
                expected_target_version: None,
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
            expected_target_version: None,
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
        let socket = short_test_socket_path(&format!(
            "c-{}.sock",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
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

    #[test]
    fn test_port_reservation_lookup_failure_fails_closed() {
        let port_when_reserved_err = allocate_or_resolve_app_port_with(
            "sonarr",
            8989,
            |_| Ok(None),
            |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
        );
        assert_eq!(
            port_when_reserved_err, 0,
            "reserved-port query failure must return 0 instead of handing out default port"
        );

        let port_when_existing_err = allocate_or_resolve_app_port_with(
            "sonarr",
            8989,
            |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
            |_| Ok(std::collections::BTreeSet::new()),
        );
        assert_eq!(
            port_when_existing_err, 0,
            "existing ingress lookup failure must return 0 instead of falling through"
        );

        let resolved = resolve_package_lifecycle_port_with(
            "install",
            "sonarr",
            8989,
            |_| 0,
            |_| Ok(None),
            |app, def| {
                allocate_or_resolve_app_port_with(
                    app,
                    def,
                    |_| Ok(None),
                    |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
                )
            },
        );
        assert!(
            resolved.is_err(),
            "resolve_package_lifecycle_port_with must fail closed when reserved-port lookup fails"
        );
    }

    #[tokio::test]
    async fn test_incomplete_rollback_refuses_to_restart_pre_stopped_units_in_api() {
        let restarted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let restarted_clone = restarted.clone();
        let stopped = vec!["sonarr".to_string(), "sonarr.timer".to_string()];
        let (kind, msg) = restore_pre_stopped_units_after_installer_failure_with(
            "sonarr",
            &stopped,
            "Package update failed; incomplete rollback: recovery backup preserved at /var/lib/sonarr.bak",
            move |unit, action| {
                let restarted_clone = restarted_clone.clone();
                async move {
                    restarted_clone
                        .lock()
                        .unwrap()
                        .push(format!("{action} {unit}"));
                    Ok(())
                }
            },
        )
        .await;
        assert_eq!(kind, af_services::PackageJobFailure::ServiceRestore);
        assert!(
            msg.contains("Refusing to restart pre-stopped service after incomplete rollback"),
            "unexpected message: {msg}"
        );
        assert!(
            restarted.lock().unwrap().is_empty(),
            "pre-stopped units must NOT be started when rollback is incomplete"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_lifecycle_action_dispatch_does_not_block_install_reinstall_or_remove_on_update_errors_or_retirement() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();

        let test_pkg = af_models::Package {
            name: "test-err-pkg".into(),
            label: "Test Error Pkg".into(),
            service_name: "test-err-pkg".into(),
            lock_file: "/install/.test-err-pkg.lock".into(),
            status: "installed".into(),
            ..Default::default()
        };
        let retired_pkg = af_models::Package {
            name: "readarr".into(),
            label: "Readarr".into(),
            service_name: "readarr".into(),
            lock_file: "/install/.readarr.lock".into(),
            status: "installed".into(),
            update_source: "retired".into(),
            ..Default::default()
        };
        let uninstalled_pkg = af_models::Package {
            name: "test-fresh-pkg".into(),
            label: "Test Fresh Pkg".into(),
            service_name: "test-fresh-pkg".into(),
            lock_file: "/install/.test-fresh-pkg.lock".into(),
            status: "not_installed".into(),
            ..Default::default()
        };

        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        std::fs::write(
            &catalog,
            serde_json::to_vec(&vec![test_pkg.clone(), retired_pkg.clone(), uninstalled_pkg.clone()]).unwrap(),
        )
        .unwrap();
        std::fs::write(&automation, "{}").unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
        std::env::set_var(
            "AETHERFLOW_RUNNER_SOCK",
            short_test_socket_path(&format!(
                "afr-{}.sock",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            )),
        );

        let install_scripts = root.join("packages/package/install");
        let remove_scripts = root.join("packages/package/remove");
        let update_scripts = root.join("packages/package/update");
        std::fs::create_dir_all(&install_scripts).unwrap();
        std::fs::create_dir_all(&remove_scripts).unwrap();
        std::fs::create_dir_all(&update_scripts).unwrap();
        for id in ["test-err-pkg", "readarr", "test-fresh-pkg"] {
            let inst_file = install_scripts.join(format!("installpackage-{id}"));
            let rem_file = remove_scripts.join(format!("removepackage-{id}"));
            let upd_file = update_scripts.join(format!("updatepackage-{id}"));
            std::fs::write(&inst_file, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::write(&rem_file, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::write(&upd_file, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&inst_file, std::fs::Permissions::from_mode(0o755));
                let _ = std::fs::set_permissions(&rem_file, std::fs::Permissions::from_mode(0o755));
                let _ = std::fs::set_permissions(&upd_file, std::fs::Permissions::from_mode(0o755));
            }
        }
        let previous_directory = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();

        // Seed app_updates with an upstream error for test-err-pkg
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, latest_version, last_error) VALUES ('test-err-pkg', '', 'GitHub rate limit exceeded')",
                [],
            ).unwrap();
        }

        let admin = progress_test_user("admin", None);

        // A. Verify 'remove' succeeds even when app_updates has a last_error
        let res_remove = dispatch_package_lifecycle_with_target(
            "test-err-pkg".into(),
            "remove",
            "uninstalling",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_remove.status(), StatusCode::OK, "remove must not be blocked by app_updates last_error");
        af_services::clear_package_job_info("test-err-pkg");

        // B. Verify 'install' succeeds on uninstalled package without app_updates record
        let res_install = dispatch_package_lifecycle_with_target(
            "test-fresh-pkg".into(),
            "install",
            "installing",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_install.status(), StatusCode::OK, "install must not require app_updates or confirmed target");
        af_services::clear_package_job_info("test-fresh-pkg");

        // C. Verify 'reinstall' succeeds even when app_updates has last_error
        let res_reinstall = dispatch_package_lifecycle_with_target(
            "test-err-pkg".into(),
            "reinstall",
            "installing",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_reinstall.status(), StatusCode::OK, "reinstall must not be blocked by app_updates last_error");
        af_services::clear_package_job_info("test-err-pkg");

        // D. Verify 'remove' succeeds unconditionally on a retired package (readarr)
        let res_retired_remove = dispatch_package_lifecycle_with_target(
            "readarr".into(),
            "remove",
            "uninstalling",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_retired_remove.status(), StatusCode::OK, "remove on retired package must succeed unconditionally");
        af_services::clear_package_job_info("readarr");

        // E. Verify 'update' on test-err-pkg IS blocked by app_updates last_error
        let res_update_blocked = dispatch_package_lifecycle_with_target(
            "test-err-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_update_blocked.status(), StatusCode::CONFLICT, "update MUST be blocked by app_updates error");

        drop(connection);
        std::env::set_current_dir(previous_directory).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_explicit_target_confirmation_and_stale_error_policy() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();

        let pkg = af_models::Package {
            name: "test-target-pkg".into(),
            label: "Test Target Pkg".into(),
            service_name: "test-target-pkg".into(),
            lock_file: "/install/.test-target-pkg.lock".into(),
            status: "installed".into(),
            ..Default::default()
        };
        let rem_pkg = af_models::Package {
            name: "test-remove-pkg".into(),
            label: "Test Remove Pkg".into(),
            service_name: "test-remove-pkg".into(),
            lock_file: "/install/.test-remove-pkg.lock".into(),
            status: "installed".into(),
            ..Default::default()
        };
        let reinst_pkg = af_models::Package {
            name: "test-reinstall-pkg".into(),
            label: "Test Reinstall Pkg".into(),
            service_name: "test-reinstall-pkg".into(),
            lock_file: "/install/.test-reinstall-pkg.lock".into(),
            status: "installed".into(),
            ..Default::default()
        };
        let inst_pkg = af_models::Package {
            name: "test-install-pkg".into(),
            label: "Test Install Pkg".into(),
            service_name: "test-install-pkg".into(),
            lock_file: "/install/.test-install-pkg.lock".into(),
            status: "not_installed".into(),
            ..Default::default()
        };
        let readarr_pkg = af_models::Package {
            name: "readarr".into(),
            label: "Readarr".into(),
            service_name: "readarr".into(),
            lock_file: "/install/.readarr.lock".into(),
            status: "installed".into(),
            update_source: "retired".into(),
            ..Default::default()
        };
        let catalog = root.join("catalog.json");
        let automation = root.join("automation.json");
        std::fs::write(
            &catalog,
            serde_json::to_vec(&vec![pkg.clone(), rem_pkg.clone(), reinst_pkg.clone(), inst_pkg.clone(), readarr_pkg.clone()]).unwrap(),
        )
        .unwrap();
        std::fs::write(&automation, "{}").unwrap();
        std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
        std::env::set_var(
            "AETHERFLOW_RUNNER_SOCK",
            short_test_socket_path(&format!(
                "afr-{}.sock",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            )),
        );

        let update_scripts = root.join("packages/package/update");
        let install_scripts = root.join("packages/package/install");
        let remove_scripts = root.join("packages/package/remove");
        std::fs::create_dir_all(&update_scripts).unwrap();
        std::fs::create_dir_all(&install_scripts).unwrap();
        std::fs::create_dir_all(&remove_scripts).unwrap();
        for id in ["test-target-pkg", "test-remove-pkg", "test-reinstall-pkg", "test-install-pkg", "readarr"] {
            for dir in [&update_scripts, &install_scripts, &remove_scripts] {
                let script = dir.join(format!("updatepackage-{id}"));
                let _ = std::fs::write(&script, "#!/bin/sh\nexit 0\n");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
                }
            }
            let inst_script = install_scripts.join(format!("installpackage-{id}"));
            let rem_script = remove_scripts.join(format!("removepackage-{id}"));
            std::fs::write(&inst_script, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::write(&rem_script, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&inst_script, std::fs::Permissions::from_mode(0o755));
                let _ = std::fs::set_permissions(&rem_script, std::fs::Permissions::from_mode(0o755));
            }
        }

        std::fs::create_dir_all(root.join("install")).unwrap();
        std::fs::write(root.join("install/.test-target-pkg.lock"), "installed").unwrap();
        std::fs::write(root.join("install/.test-remove-pkg.lock"), "installed").unwrap();
        std::fs::write(root.join("install/.test-reinstall-pkg.lock"), "installed").unwrap();
        std::fs::write(root.join("install/.readarr.lock"), "installed").unwrap();

        let previous_directory = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();

        let admin = progress_test_user("admin", None);

        // 1. Update with explicit target when app_updates row is missing -> 409 Conflict
        let res_missing = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            Some("v1.2.0".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_missing.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        let expected_source = af_services::workers::canonical_update_source_key("https://api.github.com", &pkg);
        // Seed app_updates with db_latest = "v1.2.0" and last_error non-empty but WITHOUT prior confirmation provenance (checked_at = "", update_available = 0)
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
        }

        // 2a. Update with matching explicit target when app_updates has last_error and NO prior confirmation provenance -> 409 Conflict
        let res_unproven = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            Some("v1.2.0".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_unproven.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // Now seed app_updates with proven prior confirmation provenance and subsequent rate limit error
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
        }

        // 2b. Implicit update (no explicit target) when last_error is present -> 409 Conflict
        let res_implicit = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_implicit.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 2c. Update with explicit unconfirmed target ("v9.9.9") when app_updates has db_latest = "v1.2.0" -> 409 Conflict
        let res_mismatch = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            Some("v9.9.9".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_mismatch.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 3. Update with explicit target matching previously confirmed db_latest = "v1.2.0" with proven provenance -> succeeds (200)
        let res_matching = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            Some("v1.2.0".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_matching.status(), StatusCode::OK);
        af_services::clear_package_job_info("test-target-pkg");

        // 4. Install, reinstall, and remove still succeed when app_updates has last_error
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-remove-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-reinstall-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-install-pkg', '', '', 'Upstream repository unreachable')",
                [],
            ).unwrap();
        }

        let res_rem = dispatch_package_lifecycle_with_target(
            "test-remove-pkg".into(),
            "remove",
            "uninstalling",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_rem.status(), StatusCode::OK);
        af_services::clear_package_job_info("test-remove-pkg");

        let res_reinst = dispatch_package_lifecycle_with_target(
            "test-reinstall-pkg".into(),
            "reinstall",
            "installing",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_reinst.status(), StatusCode::OK);
        af_services::clear_package_job_info("test-reinstall-pkg");

        let res_inst = dispatch_package_lifecycle_with_target(
            "test-install-pkg".into(),
            "install",
            "installing",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_inst.status(), StatusCode::OK);
        af_services::clear_package_job_info("test-install-pkg");

        // 5. Update with explicit target when last_error is present and update_available = 0 (even with valid checked_at and matching target) -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '2.0.0', '1.0.0', 0, '2026-11-08T10:00:00Z', 'Latest version could not be confirmed: 500', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_unavail = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            Some("1.0.0".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_unavail.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 6. Update on retired package (readarr) when app_updates is missing -> 409 Conflict
        let res_retired_missing = dispatch_package_lifecycle_with_target(
            "readarr".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_retired_missing.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("readarr");

        let readarr_source = af_services::workers::canonical_update_source_key("https://api.github.com", &readarr_pkg);
        // 7. Update on retired package (readarr) when app_updates has unconfirmed last_error -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('readarr', '0.4.17.2700', '0.4.18.2805', 0, '2026-11-08T10:00:00Z', 'Upstream repository unreachable', ?1)",
                [&readarr_source],
            ).unwrap();
        }
        let res_retired_err = dispatch_package_lifecycle_with_target(
            "readarr".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_retired_err.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("readarr");

        let res_retired_err_explicit = dispatch_package_lifecycle_with_target(
            "readarr".into(),
            "update",
            "updating",
            false,
            Some("0.4.18.2805".to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_retired_err_explicit.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("readarr");

        // 8. Enforce confirmed provenance & source_key validation on EVERY update path (empty last_error)
        // 8a. Update with empty last_error and valid provenance & source_key -> 200 OK
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_clean_update = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_clean_update.status(), StatusCode::OK);
        af_services::clear_package_job_info("test-target-pkg");

        // 8b. action == "update" with empty last_error and empty checked_at -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '', '', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_empty_checked_at = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_empty_checked_at.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 8c. action == "update" with empty last_error and empty/unknown installed_version -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_empty_installed = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_empty_installed.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'unknown', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_unknown_installed = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_unknown_installed.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 8d. action == "update" with empty last_error and update_available = 0 -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
        }
        let res_unavail_no_err = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_unavail_no_err.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        // 8e. action == "update" with legacy empty source_key = '' or mismatched source_key -> 409 Conflict
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', '')",
                [],
            ).unwrap();
        }
        let res_legacy_empty_source = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_legacy_empty_source.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', 'mismatched:source:key')",
                [],
            ).unwrap();
        }
        let res_mismatched_source = dispatch_package_lifecycle_with_target(
            "test-target-pkg".into(),
            "update",
            "updating",
            false,
            None,
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(res_mismatched_source.status(), StatusCode::CONFLICT);
        af_services::clear_package_job_info("test-target-pkg");

        drop(connection);
        std::env::set_current_dir(previous_directory).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_progress_ingestion_and_projections_redact_secrets() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();

        // Test emit_package_progress ingests and stores redacted line
        let job_id = "secret-prog-job";
        assert!(af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }));

        emit_package_progress(
            "sonarr",
            "update",
            "updating",
            50,
            "Executing script with user_password=\"secret_pass_123\" and db_secret=secret_db_456",
            "test-time",
            job_id,
        );

        let info = af_services::get_package_job_info("sonarr").unwrap();
        assert!(!info.last_line.contains("secret_pass_123"));
        assert!(!info.last_line.contains("secret_db_456"));
        assert!(info.last_line.contains("[REDACTED]"));

        for line in [
            r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
            "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
            "Authorization: [REDACTED] FRAGMENT_CANARY",
        ] {
            emit_package_progress("sonarr", "update", "updating", 50, line, "test-time", job_id);
            let current = af_services::get_package_job_info("sonarr").unwrap();
            assert!(!current.last_line.contains("FRAGMENT_CANARY"));
            let projected = package_progress_payload("sonarr", Some(current), None, true);
            assert!(!projected.to_string().contains("FRAGMENT_CANARY"));
        }

        // Test finish_package_lifecycle ingests and stores redacted message and summary
        finish_package_lifecycle(
            "sonarr",
            "update",
            Some(af_services::PackageJobFailure::TargetVerification),
            95,
            "Target mismatch with github_token=secret_gh_tok_789 and api_key=secret_api_key_000",
            "test-time",
            job_id,
            Some("v2.0.0"),
            Some("v1.0.0"),
            &[],
        );

        let outcome = af_services::get_package_job_outcome("sonarr").unwrap();
        assert!(!outcome.message.contains("secret_gh_tok_789"));
        assert!(!outcome.message.contains("secret_api_key_000"));
        if let Some(ref summary) = outcome.sanitized_summary {
            assert!(!summary.contains("secret_gh_tok_789"));
            assert!(!summary.contains("secret_api_key_000"));
            assert!(summary.contains("[REDACTED]"));
        }

        // Test package_progress_payload redacts secrets for admin view
        let progress_json = package_progress_payload("sonarr", None, Some(outcome.clone()), true);
        assert!(!progress_json.to_string().contains("secret_gh_tok_789"));
        assert!(!progress_json.to_string().contains("secret_api_key_000"));

        // Test Authorization: Basic, curl -u, --pass, and JSON boundary redaction
        let job_id2 = "secret-prog-job-2";
        assert!(af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: job_id2.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: None,
        }));
        emit_package_progress(
            "sonarr",
            "update",
            "updating",
            60,
            "Running curl -u admin:mysecret123 http://target.local with --pass pass_val_456 and Authorization: Basic dXNlcjpwYXNz and password={\"raw\":\"boundary_secret_789\"}",
            "test-time",
            job_id2,
        );
        let info2 = af_services::get_package_job_info("sonarr").unwrap();
        assert!(!info2.last_line.contains("mysecret123"));
        assert!(!info2.last_line.contains("pass_val_456"));
        assert!(!info2.last_line.contains("dXNlcjpwYXNz"));
        assert!(!info2.last_line.contains("boundary_secret_789"));
        assert!(info2.last_line.contains("curl -u [REDACTED]"));
        assert!(info2.last_line.contains("--pass [REDACTED]"));
        assert!(info2.last_line.contains("Basic [REDACTED]"));
        assert!(info2.last_line.contains("[REDACTED]"));

        finish_package_lifecycle(
            "sonarr",
            "update",
            Some(af_services::PackageJobFailure::Installer),
            60,
            "Failed running curl -u admin:mysecret123 http://target with --pass pass_val_456 and Basic dXNlcjpwYXNz",
            "test-time",
            job_id2,
            Some("v2.0.0"),
            None,
            &[],
        );
        let outcome2 = af_services::get_package_job_outcome("sonarr").unwrap();
        assert!(!outcome2.message.contains("mysecret123"));
        assert!(!outcome2.message.contains("pass_val_456"));
        assert!(!outcome2.message.contains("dXNlcjpwYXNz"));
        if let Some(ref sum) = outcome2.sanitized_summary {
            assert!(!sum.contains("mysecret123"));
            assert!(!sum.contains("pass_val_456"));
            assert!(!sum.contains("dXNlcjpwYXNz"));
        }
        let progress_json2 = package_progress_payload("sonarr", None, Some(outcome2), true);
        assert!(!progress_json2.to_string().contains("mysecret123"));
        assert!(!progress_json2.to_string().contains("pass_val_456"));
        assert!(!progress_json2.to_string().contains("dXNlcjpwYXNz"));

        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_public_unauthenticated_catalog_strips_all_private_fields() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let (root, connection) = lifecycle_status_fixture();
        af_db::init_db().unwrap();

        let response = get_marketplace_apps_blocking(HeaderMap::new(), false);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-aetherflow-inventory-mode")
                .unwrap()
                .to_str()
                .unwrap(),
            "public_redacted"
        );
        assert_eq!(
            response
                .headers()
                .get("x-aetherflow-inventory-authenticated")
                .unwrap()
                .to_str()
                .unwrap(),
            "false"
        );

        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = payload.as_array().expect("public response must be an array");
        assert!(!apps.is_empty(), "public catalog should return packages");

        for app in apps {
            let obj = app.as_object().expect("each item must be a JSON object");
            // Public fields that may be present:
            assert!(obj.contains_key("id"));
            assert!(obj.contains_key("name"));
            assert!(obj.contains_key("desc"));
            assert!(obj.contains_key("category"));
            assert_eq!(obj.get("status").unwrap(), "not_installed");
            assert_eq!(obj.get("inventory_known").unwrap(), false);
            assert_eq!(obj.get("inventory_authenticated").unwrap(), false);
            assert_eq!(obj.get("inventory_mode").unwrap(), "public_redacted");

            // Private inventory and ingress fields that MUST be omitted:
            assert!(!obj.contains_key("internal_domain"), "internal_domain must be omitted");
            assert!(!obj.contains_key("external_access_enabled"), "external_access_enabled must be omitted");
            assert!(!obj.contains_key("tls_enabled"), "tls_enabled must be omitted");
            assert!(!obj.contains_key("latest_version"), "latest_version must be omitted");
            assert!(!obj.contains_key("installed_version"), "installed_version must be omitted");
            assert!(!obj.contains_key("checked_at"), "checked_at must be omitted");
            assert!(!obj.contains_key("update_checked_at"), "update_checked_at must be omitted");
            assert!(!obj.contains_key("update_url"), "update_url must be omitted");
            assert!(!obj.contains_key("update_error"), "update_error must be omitted");
            assert!(!obj.contains_key("update_available"), "update_available must be omitted");
            assert!(!obj.contains_key("active_port"), "active_port must be omitted");
            assert!(!obj.contains_key("public_domain"), "public_domain must be omitted");
            assert!(!obj.contains_key("active_job"), "active_job must be omitted");
            assert!(!obj.contains_key("last_job"), "last_job must be omitted");
            assert!(!obj.contains_key("last_job_outcome"), "last_job_outcome must be omitted");
            assert!(!obj.contains_key("progress"), "progress must be omitted");
            assert!(!obj.contains_key("log_line"), "log_line must be omitted");
            assert!(!obj.contains_key("started_at"), "started_at must be omitted");
            assert!(!obj.contains_key("job_id"), "job_id must be omitted");
        }

        drop(connection);
        std::fs::remove_dir_all(root).unwrap();
    }

    static RECEIPT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_candidate_receipt_snapshot_and_restoration_with_target_certification_failure() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-receipt-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
        let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
        std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

        let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

        // 1. Snapshot candidate receipts
        let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
        assert!(snapshots.iter().any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
        assert!(snapshots.iter().any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

        // 2. Simulate installer making changes (overwriting existing, creating new)
        std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
        let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
        std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

        // 3. Target certification fails -> restore candidate receipts
        restore_candidate_receipts(&snapshots).unwrap();

        // 4. Verify previous receipt is restored and new receipt was removed
        assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
        assert!(!opt_syncthing.exists(), "uncertified new receipt must be removed");

        // 5. Verify TargetVerification reports stage target_certification_after_install_commit
        let job_id = "test-target-cert-job";
        let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "syncthing".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: Some("v3.0.0".into()),
        });
        finish_package_lifecycle(
            "syncthing",
            "update",
            Some(af_services::PackageJobFailure::TargetVerification),
            95,
            "Target certification failed after installer execution (runtime state may be partially committed): expected v3.0.0, achieved v2.0.0",
            "test-time",
            job_id,
            Some("v3.0.0"),
            Some("v2.0.0"),
            &[],
        );
        let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
        assert_eq!(outcome.status, "failed");
        assert_eq!(
            outcome.failed_stage.as_deref(),
            Some("target_certification_after_install_commit")
        );
        assert!(outcome
            .sanitized_summary
            .as_ref()
            .unwrap()
            .contains("Target certification failed after installer execution"));
        assert_eq!(
            outcome.message,
            af_services::PackageJobFailure::TargetVerification.summary()
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_symlink_swap_restoration_does_not_overwrite_victim() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-symlink-swap-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_path = temp_dir.join("var/lib/radarr/.af-version");
        std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
        std::fs::write(&receipt_path, b"1.0.0").unwrap();

        let victim_file = temp_dir.join("victim");
        std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

        // 1. Snapshot candidate receipts
        let snapshots = snapshot_candidate_receipts("radarr").unwrap();
        assert!(snapshots.iter().any(|(p, bytes)| p == &receipt_path && bytes.as_deref() == Some(b"1.0.0")));

        // 2. Attacker swaps receipt for a symlink pointing to /tmp/victim
        std::fs::remove_file(&receipt_path).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

        // 3. Restore candidate receipts
        let restore_res = restore_candidate_receipts(&snapshots);
        assert!(restore_res.is_ok(), "Restoration should succeed: {:?}", restore_res);

        // 4. Victim file must NOT be overwritten!
        let victim_content = std::fs::read(&victim_file).unwrap();
        assert_eq!(victim_content, b"VICTIM_INTACT_CONTENT");

        // 5. Receipt file must be restored as a regular file (not a symlink) with original bytes
        let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
        assert!(meta.file_type().is_file(), "Receipt must be restored as a regular file");
        assert!(!meta.file_type().is_symlink(), "Receipt must not be a symlink");
        assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_snapshot_fails_closed_on_symlink_fifo_or_oversized() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-bad-receipt-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_path = temp_dir.join("var/lib/sonarr/.af-version");
        std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();

        // 1. Symlink at receipt path fails closed
        let dummy_target = temp_dir.join("dummy_target");
        std::fs::write(&dummy_target, b"test").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&dummy_target, &receipt_path).unwrap();
        let sym_err = snapshot_candidate_receipts("sonarr");
        assert!(sym_err.is_err(), "Snapshot must fail closed on symlink receipt");
        assert!(sym_err.unwrap_err().contains("symlink or non-regular file"));
        let _ = std::fs::remove_file(&receipt_path);

        // 2. FIFO at receipt path fails closed
        #[cfg(unix)]
        {
            let cstr = std::ffi::CString::new(receipt_path.as_os_str().as_bytes()).unwrap();
            let res = unsafe { libc::mkfifo(cstr.as_ptr(), 0o644) };
            assert_eq!(res, 0);
            let fifo_err = snapshot_candidate_receipts("sonarr");
            assert!(fifo_err.is_err(), "Snapshot must fail closed on FIFO receipt");
            assert!(fifo_err.unwrap_err().contains("symlink or non-regular file"));
            let _ = std::fs::remove_file(&receipt_path);
        }

        // 3. File > 64 KiB at receipt path fails closed
        let oversized = vec![b'X'; 64 * 1024 + 1];
        std::fs::write(&receipt_path, &oversized).unwrap();
        let size_err = snapshot_candidate_receipts("sonarr");
        assert!(size_err.is_err(), "Snapshot must fail closed on oversized receipt");
        assert!(size_err.unwrap_err().contains("exceeds 64 KiB limit"));
        let _ = std::fs::remove_file(&receipt_path);

        // 4. Ancestor directory being a symlink fails closed
        let ancestor_link = temp_dir.join("var/lib/sonarr");
        let _ = std::fs::remove_dir(&ancestor_link);
        let real_dir = temp_dir.join("real_sonarr");
        std::fs::create_dir_all(&real_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, &ancestor_link).unwrap();
        std::fs::write(ancestor_link.join(".af-version"), b"1.0.0").unwrap();
        let ancestor_err = snapshot_candidate_receipts("sonarr");
        assert!(ancestor_err.is_err(), "Snapshot must fail closed on symlink ancestor");
        assert!(ancestor_err.unwrap_err().contains("is a symlink"));

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_intermediate_ancestor_symlink_fails_closed() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-intermediate-symlink-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        // Intermediate ancestor "var/lib" is a symlink to "real_lib"
        let real_lib = temp_dir.join("real_lib");
        std::fs::create_dir_all(real_lib.join("syncthing")).unwrap();
        std::fs::write(real_lib.join("syncthing/.af-version"), b"1.0.0").unwrap();

        let var_dir = temp_dir.join("var");
        std::fs::create_dir_all(&var_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_lib, var_dir.join("lib")).unwrap();

        // 1. Snapshot must fail closed because intermediate ancestor "lib" is a symlink
        let snap_err = snapshot_candidate_receipts("syncthing");
        assert!(snap_err.is_err(), "Snapshot must fail closed when intermediate ancestor is a symlink");
        assert!(snap_err.unwrap_err().contains("is a symlink"));

        // 2. Restore must also fail closed
        let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
        let fake_snapshot: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
            vec![(receipt_path.clone(), Some(ReceiptSnapshotEntry::from(b"2.0.0".to_vec())))];
        let restore_err = restore_candidate_receipts(&fake_snapshot);
        assert!(restore_err.is_err(), "Restore must fail closed when intermediate ancestor is a symlink");
        assert!(restore_err.unwrap_err().contains("is a symlink"));

        // 3. Restore None (uncertified receipt removal) must also fail closed on symlink ancestor
        let fake_snapshot_none: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(receipt_path, None)];
        let restore_none_err = restore_candidate_receipts(&fake_snapshot_none);
        assert!(restore_none_err.is_err(), "Restore None must fail closed when intermediate ancestor is a symlink");
        assert!(restore_none_err.unwrap_err().contains("is a symlink"));

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_lifecycle_job_fails_closed_and_restores_receipts_on_service_restart_failure() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-service-restart-fail-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
        let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
        std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

        let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

        // 1. Snapshot candidate receipts
        let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
        assert!(snapshots.iter().any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
        assert!(snapshots.iter().any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

        // 2. Simulate installer making changes
        std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
        let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
        std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

        // 3. Service restart failed: stopped unit is inactive
        let stopped_units = vec!["nonexistent-restart-fail.service".to_string()];

        // Receipts are rolled back
        restore_candidate_receipts(&snapshots).unwrap();
        assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
        assert!(!opt_syncthing.exists());

        // 4. Job lifecycle finishes with finish_package_lifecycle
        let job_id = "test-service-restart-fail-job";
        let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "syncthing".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "init".into(),
            started_at: "test-time".into(),
            expected_target_version: Some("v2.0.0".into()),
        });

        // Even if the caller passed failure: None and progress: 100,
        // finish_package_lifecycle must verify stopped_units and fail closed!
        finish_package_lifecycle(
            "syncthing",
            "update",
            None,
            100,
            "Completed update for syncthing",
            "test-time",
            job_id,
            Some("v2.0.0"),
            Some("v2.0.0"),
            &stopped_units,
        );

        let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
        assert_ne!(outcome.status, "completed", "Job must NEVER be completed if stopped unit failed to restart");
        assert_eq!(outcome.status, "failed");
        assert_eq!(
            outcome.failed_stage.as_deref(),
            Some("service_restore")
        );
        assert!(
            outcome.message.contains("service")
                || outcome.message.contains("stopped")
                || outcome.sanitized_summary.as_ref().map(|s| s.contains("service") || s.contains("stopped")).unwrap_or(false)
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_sanitize_url_or_source_key_for_api_strips_credentials() {
        let sample_url = "https://user:super_secret@git.example.com/team/App.git";
        assert_eq!(
            sanitize_url_or_source_key_for_api(sample_url),
            "https://git.example.com/team/App.git"
        );

        let url_with_query = "https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main";
        assert_eq!(
            sanitize_url_or_source_key_for_api(url_with_query),
            "https://git.example.com/team/App.git"
        );

        let release_url_with_query = "https://github.com/org/repo/releases/v1.1.0?download=true&token=xyz";
        assert_eq!(
            sanitize_url_or_source_key_for_api(release_url_with_query),
            "https://github.com/org/repo/releases/v1.1.0"
        );

        let sample_key = "git_head:https://user:super_secret@git.example.com/team/App.git|team/App";
        assert_eq!(
            sanitize_url_or_source_key_for_api(sample_key),
            "git_head:https://git.example.com/team/App.git|team/App"
        );

        let key_with_query = "git_head:https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main|team/App";
        assert_eq!(
            sanitize_url_or_source_key_for_api(key_with_query),
            "git_head:https://git.example.com/team/App.git?token=[REDACTED]&branch=main|team/App"
        );

        let ssh_url = "ssh://user:super_secret@git.example.com/team/App.git";
        assert_eq!(
            sanitize_url_or_source_key_for_api(ssh_url),
            "ssh://git.example.com/team/App.git"
        );

        let token_url = "https://ghp_supersecret12345@github.com/org/repo.git";
        assert_eq!(
            sanitize_url_or_source_key_for_api(token_url),
            "https://github.com/org/repo.git"
        );

        let err_diagnostic = "Clone failed for https://user:pass@host/repo: password=\"secret123\"";
        let sanitized_err = sanitize_url_or_source_key_for_api(err_diagnostic);
        assert!(!sanitized_err.contains("user:pass@"));
        assert!(!sanitized_err.contains("secret123"));
        assert_eq!(
            sanitized_err,
            "Clone failed for https://host/repo: password=[REDACTED]"
        );
    }

    #[tokio::test]
    async fn test_candidate_receipt_restoration_quiesces_stopped_units_before_restoring_and_restarts_afterward() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-quiesce-order-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_file = temp_dir.join("opt/syncthing/.af-version");
        let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
        std::fs::write(&receipt_file, b"v1.0.0").unwrap();

        // 1. Create snapshot
        let snapshots = vec![(
            receipt_file.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        // 2. Simulate installer having overwritten the receipt to v2.0.0
        std::fs::write(&receipt_file, b"v2.0.0").unwrap();

        let stopped_units = vec!["syncthing.service".to_string()];
        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let receipt_at_stop = std::sync::Arc::new(std::sync::Mutex::new(None));
        let receipt_at_start = std::sync::Arc::new(std::sync::Mutex::new(None));

        let t_clone = timeline.clone();
        let r_stop_clone = receipt_at_stop.clone();
        let r_start_clone = receipt_at_start.clone();
        let receipt_file_clone = receipt_file.clone();

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "syncthing",
            &stopped_units,
            &stopped_units,
            &snapshots,
            false,
            move |unit, action| {
                let t_clone = t_clone.clone();
                let r_stop_clone = r_stop_clone.clone();
                let r_start_clone = r_start_clone.clone();
                let r_file = receipt_file_clone.clone();
                async move {
                    let cur_content = std::fs::read_to_string(&r_file).unwrap_or_default();
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    if action == "stop" {
                        *r_stop_clone.lock().unwrap() = Some(cur_content);
                    } else if action == "start" {
                        *r_start_clone.lock().unwrap() = Some(cur_content);
                    }
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(restore_err.is_none(), "Receipt restoration should succeed");
        assert!(restart_fails.is_empty(), "Service restart should succeed");

        let events = timeline.lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["stop syncthing.service", "start syncthing.service"],
            "Must stop (quiesce) unit BEFORE restoration, and start unit AFTER restoration"
        );

        // Crucial verification: at time of "stop", the receipt was un-restored (v2.0.0)
        assert_eq!(
            receipt_at_stop.lock().unwrap().as_deref(),
            Some("v2.0.0"),
            "Unit must be stopped BEFORE receipt is restored"
        );

        // At time of "start", the receipt was restored (v1.0.0)
        assert_eq!(
            receipt_at_start.lock().unwrap().as_deref(),
            Some("v1.0.0"),
            "Unit must be started AFTER receipt is restored"
        );

        // Final disk state
        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"v1.0.0");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_candidate_receipt_quiesce_failure_skips_restoration_and_restart() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-quiesce-fail-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_file = temp_dir.join("opt/syncthing/.af-version");
        let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
        std::fs::write(&receipt_file, b"v2.0.0").unwrap();

        let snapshots = vec![(
            receipt_file.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        let stopped_units = vec!["syncthing.service".to_string()];
        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t_clone = timeline.clone();

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "syncthing",
            &stopped_units,
            &stopped_units,
            &snapshots,
            false,
            move |unit, action| {
                let t_clone = t_clone.clone();
                async move {
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    if action == "stop" {
                        anyhow::bail!("systemctl stop failed: device or resource busy");
                    }
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(restore_err.is_some(), "Must return error when quiescence fails");
        let err_msg = restore_err.unwrap();
        assert!(err_msg.contains("Skipped candidate receipt restoration because service quiescence failed"));
        assert_eq!(restart_fails.len(), 1);
        assert!(restart_fails[0].contains("Failed to quiesce unit 'syncthing.service'"));

        let events = timeline.lock().unwrap().clone();
        assert_eq!(events, vec!["stop syncthing.service"], "Must not attempt to start after quiesce failure");

        // Crucial: restore_candidate_receipts must NOT have been called, receipt remains v2.0.0
        assert_eq!(
            std::fs::read(&receipt_file).unwrap(),
            b"v2.0.0",
            "Receipt must NOT be modified when quiescence fails"
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_quiesce_and_restore_candidate_receipts_absent_unit_allows_restoration() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-absent-unit-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_file = temp_dir.join("opt/radarr/.af-version");
        let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
        std::fs::write(&receipt_file, b"v2.0.0").unwrap();

        let snapshots = vec![(
            receipt_file.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        let stopped_units = vec!["radarr.service".to_string()];

        // Case 1: Stop fails with not loaded error AND query_status returns "stopped"
        // Receipt restoration should succeed and restore to v1.0.0.
        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "radarr",
            &stopped_units,
            &[],
            &snapshots,
            false,
            move |_unit, action| async move {
                if action == "stop" {
                    anyhow::bail!("systemctl stop radarr.service failed: Unit radarr.service not loaded. (exit status: 5)");
                }
                Ok(())
            },
            |_unit| "stopped".to_string(),
        )
        .await;

        assert!(
            restore_err.is_none(),
            "Receipt restoration should succeed when absent unit is confirmed stopped: {restore_err:?}"
        );
        assert!(restart_fails.is_empty(), "Expected no restart failures: {restart_fails:?}");
        assert_eq!(
            std::fs::read(&receipt_file).unwrap(),
            b"v1.0.0",
            "Receipt must be restored to v1.0.0 when absent unit is quiescent"
        );

        // Reset receipt back to v2.0.0
        std::fs::write(&receipt_file, b"v2.0.0").unwrap();

        // Case 2: Stop fails with not loaded error BUT query_status returns "running"
        // Should fail closed, return error, and leave receipt at v2.0.0.
        let (restore_err_fail, restart_fails_fail) = quiesce_and_restore_candidate_receipts_with(
            "radarr",
            &stopped_units,
            &[],
            &snapshots,
            false,
            move |_unit, action| async move {
                if action == "stop" {
                    anyhow::bail!("systemctl stop radarr.service failed: Unit radarr.service not loaded. (exit status: 5)");
                }
                Ok(())
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(
            restore_err_fail.is_some(),
            "Candidate receipt restoration must fail when query_status reports running"
        );
        let err_msg = restore_err_fail.unwrap();
        assert!(err_msg.contains("Skipped candidate receipt restoration because service quiescence failed"));
        assert_eq!(restart_fails_fail.len(), 1);
        assert!(restart_fails_fail[0].contains("Failed to quiesce unit 'radarr.service'"));

        assert_eq!(
            std::fs::read(&receipt_file).unwrap(),
            b"v2.0.0",
            "Receipt must NOT be modified when service quiescence fails"
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_candidate_receipt_restoration_failure_skips_service_restart() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-restore-fail-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        // Snapshot with invalid path (e.g. root "/") so restore_candidate_receipts fails
        let invalid_path = PathBuf::from("/");
        let snapshots = vec![(invalid_path, None)];

        let stopped_units = vec!["syncthing.service".to_string()];
        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t_clone = timeline.clone();

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "syncthing",
            &stopped_units,
            &stopped_units,
            &snapshots,
            false,
            move |unit, action| {
                let t_clone = t_clone.clone();
                async move {
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(restore_err.is_some(), "Receipt restoration should fail");
        assert_eq!(restart_fails.len(), 1);
        assert_eq!(
            restart_fails[0],
            "Refusing to restart pre-stopped service after receipt restoration failure"
        );

        let events = timeline.lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["stop syncthing.service"],
            "Must stop unit during quiescence, but NEVER start unit when restoration fails"
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_admin_update_response_sanitizes_credentials() {
        let rec = af_services::workers::PackageUpdateRecord {
            package_id: "testapp".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
            update_available: true,
            checked_at: "2026-11-09T10:00:00Z".to_string(),
            release_url: "https://user:secret_token@git.example.com/org/testapp/releases/v1.1.0".to_string(),
            error: "connection failed with password=\"super_secret_pw\" to https://admin:pwd@host/repo".to_string(),
            source_key: "git_head:https://user:secret_token@git.example.com/org/testapp.git|main".to_string(),
        };

        let sanitized_rec = sanitize_package_update_record(rec.clone());
        assert_eq!(
            sanitized_rec.release_url,
            "https://git.example.com/org/testapp/releases/v1.1.0"
        );
        assert_eq!(
            sanitized_rec.source_key,
            "git_head:https://git.example.com/org/testapp.git|main"
        );
        assert!(!sanitized_rec.error.contains("super_secret_pw"));
        assert!(!sanitized_rec.error.contains("pwd@"));

        let body = build_single_package_update_response("testapp", Some(rec));
        let body_str = body.to_string();
        assert!(!body_str.contains("secret_token"));
        assert!(!body_str.contains("super_secret_pw"));
        assert!(!body_str.contains("pwd@"));
        assert_eq!(
            body["update_url"],
            "https://git.example.com/org/testapp/releases/v1.1.0"
        );
        assert_eq!(
            body["release_url"],
            "https://git.example.com/org/testapp/releases/v1.1.0"
        );
        assert_eq!(
            body["update_source_key"],
            "git_head:https://git.example.com/org/testapp.git|main"
        );
    }

    #[test]
    fn test_sanitize_package_update_record_redacts_installed_version() {
        let rec = af_services::workers::PackageUpdateRecord {
            package_id: "testapp".to_string(),
            installed: true,
            installed_version: "https://user:leak_token@git.example.com/app/v1.0.0?token=leak#secret-frag".to_string(),
            latest_version: "https://user:leak_token@git.example.com/app/v2.0.0?token=leak#secret-frag".to_string(),
            update_available: true,
            checked_at: "2026-11-09T10:00:00Z".to_string(),
            release_url: "https://user:leak_token@git.example.com/org/testapp/releases/v2.0.0?token=leak#secret-frag".to_string(),
            error: "failure with password=\"leak_pw\"".to_string(),
            source_key: "git_head:https://user:leak_token@git.example.com/org/testapp.git|main".to_string(),
        };

        let sanitized_rec = sanitize_package_update_record(rec);
        assert_eq!(
            sanitized_rec.installed_version,
            "https://git.example.com/app/v1.0.0"
        );
        assert!(!sanitized_rec.installed_version.contains("leak_token"));
        assert!(!sanitized_rec.installed_version.contains("secret-frag"));
        assert!(!sanitized_rec.installed_version.contains("token=leak"));

        let rec_kv = af_services::workers::PackageUpdateRecord {
            package_id: "testapp".to_string(),
            installed: true,
            installed_version: "1.2.3 token=leak_secret_token_123".to_string(),
            latest_version: "1.2.4".to_string(),
            update_available: true,
            checked_at: "2026-11-09T10:00:00Z".to_string(),
            release_url: "https://github.com/org/repo".to_string(),
            error: String::new(),
            source_key: "github:org/repo".to_string(),
        };
        let sanitized_kv = sanitize_package_update_record(rec_kv);
        assert_eq!(sanitized_kv.installed_version, "1.2.3 token=[REDACTED]");
        assert!(!sanitized_kv.installed_version.contains("leak_secret_token_123"));
    }

    #[test]
    fn test_sanitize_url_or_source_key_for_api_strips_fragments_and_queries() {
        assert_eq!(
            sanitize_url_or_source_key_for_api("https://user:pass@github.com/org/repo?token=1#secret-frag"),
            "https://github.com/org/repo"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("git@github.com:org/repo.git?token=1#secret-frag"),
            "git@github.com:org/repo.git"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("user:pass@host:path?token=1#secret-frag"),
            "user@host:path"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("https://example.com/download#hash"),
            "https://example.com/download"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("git-repo:ssh://Deploy@git.example.com/Team/App.git#main"),
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"),
            "git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"
        );
        assert_eq!(
            sanitize_url_or_source_key_for_api("git-repo:https://user:pass@github.com/org/repo?bad_query#main"),
            "git-repo:https://github.com/org/repo#main"
        );
    }

    #[tokio::test]
    async fn test_quiesce_and_restore_stops_inactive_units_and_restarts_only_active_units() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-quiesce-inactive-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_file = temp_dir.join("opt/syncthing/.af-version");
        let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
        std::fs::write(&receipt_file, b"v2.0.0").unwrap();

        let snapshots = vec![(
            receipt_file.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        let quiesce_units = vec![
            "syncthing.service".to_string(),
            "syncthing-helper.service".to_string(),
        ];
        let restart_units = vec!["syncthing.service".to_string()];

        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t_clone = timeline.clone();

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "syncthing",
            &quiesce_units,
            &restart_units,
            &snapshots,
            false,
            move |unit, action| {
                let t_clone = t_clone.clone();
                async move {
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(restore_err.is_none());
        assert!(restart_fails.is_empty());

        let events = timeline.lock().unwrap().clone();
        assert!(events.contains(&"stop syncthing.service".to_string()));
        assert!(events.contains(&"stop syncthing-helper.service".to_string()));
        assert!(events.contains(&"start syncthing.service".to_string()));
        assert!(!events.contains(&"start syncthing-helper.service".to_string()));

        assert_eq!(
            events,
            vec![
                "stop syncthing.service".to_string(),
                "stop syncthing-helper.service".to_string(),
                "start syncthing.service".to_string(),
            ]
        );

        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"v1.0.0");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_quiesce_and_restore_candidate_receipts_quiesces_oneshots_without_restart() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-oneshot-quiesce-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        // Case 1: recyclarr (has timer recyclarr.timer and oneshot recyclarr)
        let recyclarr_receipt = temp_dir.join("opt/recyclarr/.af-version");
        let _ = std::fs::create_dir_all(recyclarr_receipt.parent().unwrap());
        std::fs::write(&recyclarr_receipt, b"v2.0.0").unwrap();
        let snapshots = vec![(
            recyclarr_receipt.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        *CANDIDATE_QUIESCE_RECORDER.lock().unwrap() = Some(Vec::new());

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts(
            "recyclarr",
            &["recyclarr.timer".to_string()],
            &snapshots,
            false,
        )
        .await;

        assert!(restore_err.is_none());
        assert!(restart_fails.is_empty());
        assert_eq!(std::fs::read(&recyclarr_receipt).unwrap(), b"v1.0.0");

        let recorded = CANDIDATE_QUIESCE_RECORDER.lock().unwrap().take().unwrap_or_default();
        // Quiescence must stop both timer and oneshot service, with timer first
        assert!(recorded.contains(&"stop recyclarr.timer".to_string()));
        assert!(recorded.contains(&"stop recyclarr".to_string()));
        let stop_timer_idx = recorded.iter().position(|r| r == "stop recyclarr.timer").unwrap();
        let stop_service_idx = recorded.iter().position(|r| r == "stop recyclarr").unwrap();
        assert!(stop_timer_idx < stop_service_idx, "timer must be stopped before oneshot");
        // Restart must only restart the timer, NEVER the oneshot
        assert!(recorded.contains(&"start recyclarr.timer".to_string()));
        assert!(!recorded.contains(&"start recyclarr".to_string()));

        // Case 2: scrutiny (has scrutiny-collector.timer, scrutiny-collector [oneshot], scrutiny)
        let scrutiny_receipt = temp_dir.join("opt/scrutiny/.af-version");
        let _ = std::fs::create_dir_all(scrutiny_receipt.parent().unwrap());
        std::fs::write(&scrutiny_receipt, b"v2.0.0").unwrap();
        let scrutiny_snapshots = vec![(
            scrutiny_receipt.clone(),
            Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
        )];

        *CANDIDATE_QUIESCE_RECORDER.lock().unwrap() = Some(Vec::new());

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts(
            "scrutiny",
            &["scrutiny-collector.timer".to_string(), "scrutiny".to_string()],
            &scrutiny_snapshots,
            false,
        )
        .await;

        assert!(restore_err.is_none());
        assert!(restart_fails.is_empty());
        assert_eq!(std::fs::read(&scrutiny_receipt).unwrap(), b"v1.0.0");

        let recorded = CANDIDATE_QUIESCE_RECORDER.lock().unwrap().take().unwrap_or_default();
        // Quiescence must stop scrutiny-collector.timer, scrutiny, and oneshot scrutiny-collector
        assert!(recorded.contains(&"stop scrutiny-collector.timer".to_string()));
        assert!(recorded.contains(&"stop scrutiny-collector".to_string()));
        assert!(recorded.contains(&"stop scrutiny".to_string()));
        let stop_timer_idx = recorded.iter().position(|r| r == "stop scrutiny-collector.timer").unwrap();
        let stop_collector_idx = recorded.iter().position(|r| r == "stop scrutiny-collector").unwrap();
        assert!(stop_timer_idx < stop_collector_idx, "timer must be stopped before collector oneshot");
        // Restart must only restart scrutiny and timer, NEVER the oneshot collector
        assert!(recorded.contains(&"start scrutiny-collector.timer".to_string()));
        assert!(recorded.contains(&"start scrutiny".to_string()));
        assert!(!recorded.contains(&"start scrutiny-collector".to_string()));

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_run_package_lifecycle_dispatch_gate_with_quiesces_oneshots_and_excludes_from_restart() {
        use std::sync::{Arc, Mutex};

        // 1. Recyclarr: pre-stop quiesces timer + oneshot, but stopped_units excludes oneshot
        let recorded_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let control_rec = recorded_controls.clone();

        let (_port, stopped_units, dispatch_res) = run_package_lifecycle_dispatch_gate_with(
            "update",
            "recyclarr",
            0,
            "",
            |_app_id| 0,
            |_app_id| Ok(None),
            |_app_id, _port| 0,
            |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
            |_unit| "running".to_string(),
            move |unit, action| {
                let rec = control_rec.clone();
                async move {
                    rec.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_port| async move { Err(anyhow::anyhow!("simulated script failure to trigger rollback")) },
        )
        .await
        .expect("dispatch gate itself should complete");

        assert!(dispatch_res.is_err());
        // Stopped units must ONLY contain restart-eligible units (timer), excluding oneshot
        assert_eq!(stopped_units, vec!["recyclarr.timer".to_string()]);

        let pre_controls = recorded_controls.lock().unwrap().clone();
        assert!(pre_controls.contains(&"stop recyclarr.timer".to_string()));
        assert!(pre_controls.contains(&"stop recyclarr".to_string()));

        // Rollback quiescence test: quiesce_units gets both from resolve("stop"), restart gets stopped_units
        let rollback_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let rb_rec = rollback_controls.clone();
        let all_quiesce = af_services::resolve_controllable_service_units("recyclarr", "stop");
        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "recyclarr",
            &all_quiesce,
            &stopped_units,
            &[],
            false,
            move |unit, action| {
                let rec = rb_rec.clone();
                async move {
                    rec.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;
        assert!(restore_err.is_none());
        assert!(restart_fails.is_empty());

        let rb_events = rollback_controls.lock().unwrap().clone();
        assert!(rb_events.contains(&"stop recyclarr.timer".to_string()));
        assert!(rb_events.contains(&"stop recyclarr".to_string()));
        assert!(rb_events.contains(&"start recyclarr.timer".to_string()));
        assert!(!rb_events.contains(&"start recyclarr".to_string()));

        // 2. Scrutiny: pre-stop quiesces collector timer + collector oneshot + service, excludes collector oneshot from restart
        recorded_controls.lock().unwrap().clear();
        let control_rec = recorded_controls.clone();

        let (_port, stopped_units, dispatch_res) = run_package_lifecycle_dispatch_gate_with(
            "update",
            "scrutiny",
            8080,
            "",
            |_app_id| 8080,
            |_app_id| Ok(None),
            |_app_id, _port| 8080,
            |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
            |_unit| "running".to_string(),
            move |unit, action| {
                let rec = control_rec.clone();
                async move {
                    rec.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_port| async move { Err(anyhow::anyhow!("simulated script failure")) },
        )
        .await
        .expect("dispatch gate should complete");

        assert!(dispatch_res.is_err());
        assert!(!stopped_units.contains(&"scrutiny-collector".to_string()));
        assert!(stopped_units.contains(&"scrutiny-collector.timer".to_string()));
        assert!(stopped_units.contains(&"scrutiny".to_string()));

        let pre_controls = recorded_controls.lock().unwrap().clone();
        assert!(pre_controls.contains(&"stop scrutiny-collector.timer".to_string()));
        assert!(pre_controls.contains(&"stop scrutiny".to_string()));
        assert!(pre_controls.contains(&"stop scrutiny-collector".to_string()));

        // Rollback quiescence test for scrutiny
        let rollback_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let rb_rec = rollback_controls.clone();
        let all_quiesce = af_services::resolve_controllable_service_units("scrutiny", "stop");
        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "scrutiny",
            &all_quiesce,
            &stopped_units,
            &[],
            false,
            move |unit, action| {
                let rec = rb_rec.clone();
                async move {
                    rec.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;
        assert!(restore_err.is_none());
        assert!(restart_fails.is_empty());

        let rb_events = rollback_controls.lock().unwrap().clone();
        assert!(rb_events.contains(&"stop scrutiny-collector.timer".to_string()));
        assert!(rb_events.contains(&"stop scrutiny".to_string()));
        assert!(rb_events.contains(&"stop scrutiny-collector".to_string()));
        assert!(rb_events.contains(&"start scrutiny-collector.timer".to_string()));
        assert!(rb_events.contains(&"start scrutiny".to_string()));
        assert!(!rb_events.contains(&"start scrutiny-collector".to_string()));
    }

    #[test]
    fn test_restore_candidate_receipts_creates_missing_directories_via_stepwise_mkdirat() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-mkdirat-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        // Nested parent directory does NOT exist initially
        let nested_receipt = temp_dir.join("var/lib/syncthing/.af-version");
        assert!(!nested_receipt.parent().unwrap().exists());

        let snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
            vec![(nested_receipt.clone(), Some(ReceiptSnapshotEntry::from(b"1.5.0".to_vec())))];
        // Must succeed using stepwise descriptor-relative mkdirat + openat without std::fs::create_dir_all
        let res = restore_candidate_receipts(&snapshots);
        assert!(res.is_ok(), "Restoration must create missing directories safely: {:?}", res);
        assert_eq!(std::fs::read(&nested_receipt).unwrap(), b"1.5.0");

        // None case where parent does not exist should cleanly succeed as no-op
        let non_existent_file = temp_dir.join("opt/nonexistent/.af-version");
        let none_snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(non_existent_file.clone(), None)];
        let none_res = restore_candidate_receipts(&none_snapshots);
        assert!(none_res.is_ok(), "None restoration with ENOENT parent must succeed as no-op");
        assert!(!non_existent_file.exists());

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_finish_package_lifecycle_appends_inactive_stopped_units_diagnostics_when_failure_already_present() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let job_id = "test-inactive-diag-job";
        let pkg_id = "syncthing";
        af_services::clear_package_job_info(pkg_id);
        let started = af_services::try_start_package_job(af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: pkg_id.into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 10,
            last_line: "initial state".into(),
            started_at: "test-time".into(),
            expected_target_version: Some("v2.0.0".into()),
        });
        assert!(started, "Job must start");

        let stopped_units = vec!["nonexistent-inactive-dummy.service".to_string()];

        // Failure is already set (e.g. TargetVerification)
        finish_package_lifecycle(
            pkg_id,
            "update",
            Some(af_services::PackageJobFailure::TargetVerification),
            95,
            "Target certification failed: expected v2.0.0, achieved v1.0.0",
            "test-time",
            job_id,
            Some("v2.0.0"),
            Some("v1.0.0"),
            &stopped_units,
        );

        let outcome = af_services::get_package_job_outcome(pkg_id).unwrap();
        assert_eq!(outcome.status, "failed");
        let summary = outcome.sanitized_summary.as_deref().unwrap_or("");
        assert!(
            summary.contains("nonexistent-inactive-dummy.service") || summary.contains("stopped services failed to resume"),
            "Sanitized summary must contain inactive unit diagnostics: {summary}"
        );
    }

    #[test]
    fn test_candidate_receipt_paths_includes_blueprint_config_and_restores_atomically() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-bp-config-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let (pkg, cfg_path) = if let Some(bp) = af_services::get_blueprint("radarr").filter(|b| !b.config_file_path.trim().is_empty()) {
            ("radarr", bp.config_file_path.clone())
        } else if let Some(bp) = af_services::get_blueprint("sonarr").filter(|b| !b.config_file_path.trim().is_empty()) {
            ("sonarr", bp.config_file_path.clone())
        } else {
            ("radarr", "/etc/radarr/config.xml".to_string())
        };

        let paths = candidate_receipt_paths_for_package(pkg);
        let rel_trimmed = cfg_path.trim_start_matches(['/', '\\']);
        let expected_cfg = temp_dir.join(rel_trimmed);
        assert!(
            paths.contains(&expected_cfg),
            "Candidate receipt paths must include blueprint config {expected_cfg:?}, got: {paths:?}"
        );

        let _ = std::fs::create_dir_all(expected_cfg.parent().unwrap());
        std::fs::write(&expected_cfg, b"<Config><Port>7878</Port></Config>").unwrap();

        let snapshots = snapshot_candidate_receipts(pkg).unwrap();
        assert!(
            snapshots.iter().any(|(p, b)| p == &expected_cfg && b.as_deref() == Some(b"<Config><Port>7878</Port></Config>")),
            "Blueprint config must be snapshotted"
        );

        std::fs::write(&expected_cfg, b"<Config><Port>9999</Port><Corrupted/></Config>").unwrap();

        restore_candidate_receipts(&snapshots).unwrap();

        assert_eq!(
            std::fs::read(&expected_cfg).unwrap(),
            b"<Config><Port>7878</Port></Config>",
            "Blueprint config must be rolled back on certification or restart failure"
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_candidate_receipt_preserves_mode_and_ownership_on_restoration() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-mode-restore-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
        std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
        std::fs::write(&receipt_path, b"v1.0.0-secret").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let initial_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
        #[cfg(unix)]
        let (initial_mode, initial_uid, initial_gid) = {
            use std::os::unix::fs::MetadataExt;
            (initial_meta.mode() & 0o7777, initial_meta.uid(), initial_meta.gid())
        };
        #[cfg(unix)]
        assert_eq!(initial_mode, 0o600);

        // 1. Snapshot candidate receipts
        let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
        let snap_entry = snapshots
            .iter()
            .find(|(p, _)| p == &receipt_path)
            .and_then(|(_, e)| e.as_ref())
            .expect("receipt must be snapshotted");

        assert_eq!(snap_entry.bytes, b"v1.0.0-secret");
        #[cfg(unix)]
        {
            assert_eq!(snap_entry.mode, 0o600);
            assert_eq!(snap_entry.uid, initial_uid);
            assert_eq!(snap_entry.gid, initial_gid);
        }

        // 2. Simulate installer/attacker clobbering the file: modifying bytes and changing permissions to 0o644
        std::fs::write(&receipt_path, b"v2.0.0-clobbered").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let clobbered_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(clobbered_meta.mode() & 0o7777, 0o644);
        }

        // 3. Call restore_candidate_receipts
        restore_candidate_receipts(&snapshots).unwrap();

        // 4. Verify exact bytes restored
        assert_eq!(std::fs::read(&receipt_path).unwrap(), b"v1.0.0-secret");

        // 5. Verify mode is 0600 (NEVER 0644) and uid/gid preserved
        let restored_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                restored_meta.mode() & 0o7777,
                0o600,
                "Mode must be restored to 0600, never left as 0644"
            );
            assert_eq!(restored_meta.uid(), initial_uid, "UID must be preserved");
            assert_eq!(restored_meta.gid(), initial_gid, "GID must be preserved");
        }

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave22_api_sanitize_scalar_credentials_and_filebot_receipts() {
        let paths = candidate_receipt_paths_for_package("filebot");
        assert!(
            paths.iter().any(|p| p.to_string_lossy().contains("filebot-node")),
            "candidate_receipt_paths_for_package('filebot') must include opt/filebot-node/.af-version: {paths:?}"
        );

        let cases = [
            "Cookie: session=CANARY_COOKIE",
            "session=CANARY_SESSION",
            "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
            "pass=CANARY_PASSWORD",
            "https://example.test/cb?session=CANARY_Q1&pass=CANARY_Q2&webhook_url=CANARY_Q3",
        ];
        for case in cases {
            let sanitized = sanitize_url_or_source_key_for_api(case);
            assert!(
                !sanitized.contains("CANARY_"),
                "CANARY_ leaked in sanitize_url_or_source_key_for_api for input: {case:?}, got: {sanitized:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_wave22_quiesce_and_restore_runtime_snapshot_restores_binary_and_state() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-w22-rt-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let bin_file = temp_dir.join("opt/syncthing/syncthing");
        let state_file = temp_dir.join("var/lib/syncthing/state.txt");
        let receipt_file = temp_dir.join("opt/syncthing/.af-version");

        std::fs::create_dir_all(bin_file.parent().unwrap()).unwrap();
        std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();

        std::fs::write(&bin_file, b"bin-1.22.0").unwrap();
        std::fs::write(&state_file, b"state-1.22.0").unwrap();
        std::fs::write(&receipt_file, b"1.22.0").unwrap();

        // 1. Snapshot candidate receipts
        let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
        assert!(
            snapshots.iter().any(|(p, bytes)| p == &receipt_file && bytes.as_deref() == Some(b"1.22.0")),
            "receipt must be snapshotted"
        );

        // 2. Snapshot package runtime
        let mut env_cfg = af_runner::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());
        let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
            "syncthing",
            &["syncthing.service".to_string()],
            &env_cfg,
            false,
        )
        .expect("Runtime snapshot must capture successfully");

        // 3. Overwrite files to 1.23.4
        std::fs::write(&bin_file, b"bin-1.23.4").unwrap();
        std::fs::write(&state_file, b"state-1.23.4").unwrap();
        std::fs::write(&receipt_file, b"1.23.4").unwrap();

        // 4. Quiesce, restore runtime and receipts, and restart
        let stopped_units = vec!["syncthing.service".to_string()];
        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t_clone = timeline.clone();

        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_and_runtime_with(
            "syncthing",
            &stopped_units,
            &stopped_units,
            &snapshots,
            false,
            Some(&mut rt_snap),
            move |unit, action| {
                let t_clone = t_clone.clone();
                async move {
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

        assert!(restore_err.is_none(), "Expected no restore error: {restore_err:?}");
        assert!(restart_fails.is_empty(), "Expected no restart failures: {restart_fails:?}");

        let events = timeline.lock().unwrap().clone();
        assert_eq!(
            events,
            vec!["stop syncthing.service", "start syncthing.service"],
            "Must stop unit before restore, and start unit after restore"
        );

        // 5. Assert disk contents restored to 1.22.0
        assert_eq!(std::fs::read(&bin_file).unwrap(), b"bin-1.22.0");
        assert_eq!(std::fs::read(&state_file).unwrap(), b"state-1.22.0");
        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"1.22.0");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_wave23_configuration_only_failure_triggers_runtime_and_receipt_rollback() {
        // 1. Verify should_rollback_post_certification_failure returns true for Configuration
        assert!(should_rollback_post_certification_failure("update", af_services::PackageJobFailure::Configuration));
        assert!(should_rollback_post_certification_failure("install", af_services::PackageJobFailure::Configuration));
        assert!(should_rollback_post_certification_failure("reinstall", af_services::PackageJobFailure::Configuration));
        assert!(should_rollback_post_certification_failure("update", af_services::PackageJobFailure::ServiceRestore));
        assert!(should_rollback_post_certification_failure("update", af_services::PackageJobFailure::ConfigurationAndServiceRestore));
        assert!(!should_rollback_post_certification_failure("remove", af_services::PackageJobFailure::Configuration));
        assert!(!should_rollback_post_certification_failure("update", af_services::PackageJobFailure::Installer));

        // 2. Exercise handle_post_certification_finalization_failure_with with PackageJobFailure::Configuration
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-w23-cfg-rb-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let bin_file = temp_dir.join("opt/sonarr/Sonarr");
        let db_file = temp_dir.join("var/lib/sonarr/sonarr.db");
        let receipt_file = temp_dir.join("opt/sonarr/.af-version");

        std::fs::create_dir_all(bin_file.parent().unwrap()).unwrap();
        std::fs::create_dir_all(db_file.parent().unwrap()).unwrap();

        std::fs::write(&bin_file, b"bin-old").unwrap();
        std::fs::write(&db_file, b"db-old").unwrap();
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let snapshots = snapshot_candidate_receipts("sonarr").unwrap();

        let mut env_cfg = af_runner::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());
        let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
            "sonarr",
            &["sonarr.service".to_string()],
            &env_cfg,
            false,
        )
        .expect("Runtime snapshot must capture");

        // Simulate installer mutating binary, DB, and receipt
        std::fs::write(&bin_file, b"bin-candidate").unwrap();
        std::fs::write(&db_file, b"db-mutated").unwrap();
        std::fs::write(&receipt_file, b"2.0.0\n").unwrap();

        let stopped_units = vec!["sonarr.service".to_string()];
        let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t_clone = timeline.clone();

        let failure = PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::Configuration,
            message: "Failed to persist ingress configuration".into(),
        };

        let (final_err, receipt_restore_error, restart_failures) =
            handle_post_certification_finalization_failure_with(
                "update",
                failure,
                "sonarr",
                &stopped_units,
                &snapshots,
                false,
                Some(&mut rt_snap),
                move |unit, action| {
                    let t_clone = t_clone.clone();
                    async move {
                        t_clone.lock().unwrap().push(format!("{action} {unit}"));
                        Ok(())
                    }
                },
                |_unit| "running".to_string(),
            )
            .await;

        assert!(receipt_restore_error.is_none(), "receipt_restore_error should be None: {:?}", receipt_restore_error);
        assert!(restart_failures.is_empty(), "restart_failures should be empty: {:?}", restart_failures);
        assert_eq!(final_err.kind, af_services::PackageJobFailure::Configuration);

        // Verify units quiesced and restarted
        let events = timeline.lock().unwrap().clone();
        assert!(events.contains(&"stop sonarr.service".to_string()));
        assert_eq!(events.last().map(|s| s.as_str()), Some("start sonarr.service"));

        // Verify disk files rolled back
        assert_eq!(std::fs::read(&bin_file).unwrap(), b"bin-old");
        assert_eq!(std::fs::read(&db_file).unwrap(), b"db-old");
        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"1.0.0\n");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
        let clean_plex = "plex";
        let mut plex_units = af_services::resolve_controllable_service_units(clean_plex, "stop");
        if let Ok(pkgs) = af_services::get_packages() {
            if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_plex) {
                let svc = p.service_name.trim().to_string();
                if !svc.is_empty()
                    && !matches!(svc.as_str(), "apache2" | "nginx" | "apache2.service" | "nginx.service")
                    && !plex_units.contains(&svc)
                {
                    plex_units.push(svc);
                }
            }
        }
        let clean_mcvnc = "mcvnc";
        let mut mcvnc_units = af_services::resolve_controllable_service_units(clean_mcvnc, "stop");
        if let Ok(pkgs) = af_services::get_packages() {
            if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_mcvnc) {
                let svc = p.service_name.trim().to_string();
                if !svc.is_empty()
                    && !matches!(svc.as_str(), "apache2" | "nginx" | "apache2.service" | "nginx.service")
                    && !mcvnc_units.contains(&svc)
                {
                    mcvnc_units.push(svc);
                }
            }
        }

        let temp_dir = std::env::temp_dir().join(format!("af-test-w23-api-footprint-{}", uuid::Uuid::new_v4()));
        let mut env_cfg = af_runner::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());

        let sysd = temp_dir.join("etc/systemd/system");
        std::fs::create_dir_all(&sysd).unwrap();
        let mcvnc_file = sysd.join("af-mcvnc.service");
        std::fs::write(&mcvnc_file, b"OLD_MCVNC").unwrap();

        let mut mcvnc_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
            clean_mcvnc,
            &mcvnc_units,
            &env_cfg,
            false,
        )
        .unwrap();

        std::fs::write(&mcvnc_file, b"NEW_MCVNC").unwrap();
        mcvnc_snap.restore().unwrap();
        assert_eq!(std::fs::read(&mcvnc_file).unwrap(), b"OLD_MCVNC");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_wave24_incomplete_rollback_keeps_candidate_receipt() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-w24-receipt-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let receipt_file = temp_dir.join("opt/sonarr/.af-version");
        std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
        std::fs::write(&receipt_file, b"1.0.0").unwrap();
        let snapshots = snapshot_candidate_receipts("sonarr").unwrap();
        std::fs::write(&receipt_file, b"2.0.0").unwrap();

        let units = vec!["sonarr.service".to_string()];
        let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_and_runtime_with(
            "sonarr",
            &units,
            &units,
            &snapshots,
            true,
            None,
            |_unit, _action| async { Ok(()) },
            |_unit| "running".to_string(),
        )
        .await;

        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"2.0.0");
        let err = restore_err.expect("incomplete rollback reports skipped receipt restoration");
        assert!(
            err.contains("Skipped candidate receipt restoration after incomplete rollback"),
            "{err}"
        );
        assert!(
            restart_fails.iter().any(|f| f.contains("Refusing to restart pre-stopped service after incomplete rollback")),
            "{restart_fails:?}"
        );

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_wave24_configuration_restore_error_upgrades_failure_kind() {
        let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
        let temp_dir = std::env::temp_dir().join(format!("af-test-w24-kind-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
        std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

        let etc_cfg = temp_dir.join("etc/maintainerr/config");
        std::fs::create_dir_all(etc_cfg.parent().unwrap()).unwrap();
        std::fs::write(&etc_cfg, b"OLD_CFG").unwrap();
        let receipt_file = temp_dir.join("opt/maintainerr/.af-version");
        std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
        std::fs::write(&receipt_file, b"1.0.0").unwrap();

        let snapshots = snapshot_candidate_receipts("maintainerr").unwrap();
        let mut env_cfg = af_runner::PackageExecutionEnv::default();
        env_cfg.fs_root = Some(temp_dir.clone());
        let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
            "maintainerr",
            &[],
            &env_cfg,
            false,
        )
        .expect("maintainerr runtime capture");

        std::fs::write(&receipt_file, b"2.0.0").unwrap();
        std::fs::write(&etc_cfg, b"NEW_CFG").unwrap();
        std::fs::remove_dir_all(temp_dir.join("etc")).unwrap();
        std::fs::write(temp_dir.join("etc"), b"blocker").unwrap();

        let failure = PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::Configuration,
            message: "Failed to persist ingress configuration".into(),
        };
        let (final_err, receipt_restore_error, restart_failures) =
            handle_post_certification_finalization_failure_with(
                "update",
                failure,
                "maintainerr",
                &[],
                &snapshots,
                false,
                Some(&mut rt_snap),
                |_unit, _action| async { Ok(()) },
                |_unit| "running".to_string(),
            )
            .await;

        assert!(receipt_restore_error.is_some(), "runtime restore failure must surface");
        assert!(restart_failures.is_empty(), "{restart_failures:?}");
        assert_eq!(
            final_err.kind,
            af_services::PackageJobFailure::ConfigurationAndServiceRestore
        );
        assert_eq!(std::fs::read(&receipt_file).unwrap(), b"2.0.0");

        if let Some(r) = orig_root {
            std::env::set_var("AETHERFLOW_FS_ROOT", r);
        } else {
            std::env::remove_var("AETHERFLOW_FS_ROOT");
        }
        let _ = std::fs::remove_file(temp_dir.join("etc"));
        let _ = std::fs::remove_dir_all(&temp_dir);
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

    #[tokio::test]
    async fn afmp003_allocate_or_resolve_app_port_skips_ports_persisted_for_stopped_apps() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
        drop(conn);

        // Persist Sonarr's default port (8989) and fallback port 17000 as owned by other stopped apps
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "stopped-owner-default".into(),
            listen_port: 8989,
            ..Default::default()
        })
        .unwrap();
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "stopped-owner-fallback".into(),
            listen_port: 17000,
            ..Default::default()
        })
        .unwrap();

        let allocated = allocate_or_resolve_app_port("sonarr", 8989);
        assert_ne!(allocated, 8989, "must not steal stopped app's persisted default port");
        assert_ne!(allocated, 17000, "must not steal stopped app's persisted fallback port");
        assert!(
            (17001..=19999).contains(&allocated),
            "expected fallback port >= 17001, got {allocated}"
        );
    }

    #[tokio::test]
    async fn test_marketplace_auth_modes_and_target_version_matching() {
        use axum::http::Request;

        // Test target_version_matches logic
        assert!(target_version_matches("1.2.3", "1.2.3"));
        assert!(target_version_matches("v1.2.3", "1.2.3"));
        assert!(target_version_matches("1.2.3", "v1.2.3"));
        assert!(target_version_matches("Release-1.2.3", "1.2.3"));
        assert!(target_version_matches("abc1234", "abc123456789"));
        assert!(!target_version_matches("1.2.3", "1.2.4"));
        assert!(!target_version_matches("1.2.3", ""));
        assert!(!target_version_matches("1.2.3", "1.2.3-rc1"));
        assert!(!target_version_matches("1.2.3", "1.2.3.4"));
        assert!(target_version_matches(
            "frontend:abc1234,backend:def5678,proxy:0123456",
            "frontend:abc1234,backend:def5678,proxy:0123456"
        ));
        assert!(!target_version_matches(
            "frontend:abc1234,backend:def5678",
            "frontend:abc1234,backend:def5678"
        ));

        // Build router and test get_marketplace endpoint
        let app = build_router();

        // 1. Unauthenticated with require_auth=1 must return 401 UNAUTHORIZED
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/public/marketplace?require_auth=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // 2. Unauthenticated without require_auth must return 200 with public_redacted mode
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/public/marketplace")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-aetherflow-inventory-mode").unwrap(),
            "public_redacted"
        );
        assert_eq!(
            res.headers().get("x-aetherflow-inventory-authenticated").unwrap(),
            "false"
        );
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
        if let Some(item) = items.first() {
            assert_eq!(item["inventory_known"], false);
            assert_eq!(item["inventory_authenticated"].as_bool().unwrap_or(false), false);
        }
    }
}
