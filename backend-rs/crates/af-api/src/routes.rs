use crate::auth::{
    admin_only_middleware, api_error, auth_middleware, check_setup_needed, csrf_middleware,
    disable_2fa, get_session, issue_csrf_token, list_active_sessions, local_login, logout,
    mfa_login_verify, refresh_session_with_peer, revoke_session, setup_2fa, setup_admin,
    verify_2fa, verify_proxy_auth, AuthUser,
};
use crate::embed::spa_fallback_handler;
use crate::intelligence::{
    ai_chat, ai_support, analyze_predictions, approve_mediaflow_item, bandwidth_analyze,
    bandwidth_apply, bookmark_log, decline_mediaflow_item, dispatch_worker_command, enroll_worker,
    get_auth_metrics_history, get_bookmarks, get_cluster_nodes, get_log_sources,
    get_mediaflow_queue, get_metrics_history, get_predictions, get_system_topology,
    get_worker_metrics, list_worker_commands, metadata_results, metadata_scan, metadata_status,
    remove_worker, test_ai_connection, trigger_mediaflow_scan,
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
    ProxiedPluginResponse,
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
    broadcast_ws_message, extract_client_ip, extract_client_ip_for_peer, handle_log_websocket,
    handle_websocket, issue_ws_ticket_for_session, normalize_request_forwarding_for_peer, PeerIp,
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

mod marketplace;
#[cfg(test)]
use marketplace::{
    allocate_or_resolve_app_port, allocate_or_resolve_app_port_with,
    build_single_package_update_response, dispatch_package_lifecycle_with_target,
    emit_package_progress, finalize_post_script_lifecycle_with, finish_package_lifecycle,
    get_marketplace_apps_blocking, get_marketplace_auth_info, package_progress_payload,
    parse_uninstall_purge, pre_stop_units_for_package_update_with, public_job_outcome,
    resolve_package_lifecycle_port_with, restore_candidate_receipts,
    restore_pre_stopped_units_after_installer_failure_with,
    run_package_lifecycle_dispatch_gate_with, snapshot_candidate_receipts,
    system_update_lifecycle_block_with, UninstallQuery, CANDIDATE_QUIESCE_RECORDER,
};
// Keep the existing crate::routes paths for lifecycle callers.
#[allow(unused_imports)]
pub(crate) use marketplace::{
    append_package_job_output, reinstall_package, should_rollback_post_certification_failure,
    PackageActionQuery, PackageLifecycleFailure, ReceiptSnapshotEntry,
};
use marketplace::{
    check_package_updates, check_single_package_update, get_marketplace_apps, install_package,
    load_authoritative_app_ingress_config, package_progress, system_update_lifecycle_block,
    uninstall_package, update_package,
};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use marketplace::{
    dispatch_package_lifecycle, handle_post_certification_finalization_failure_with,
    quiesce_and_restore_candidate_receipts, quiesce_and_restore_candidate_receipts_and_runtime,
    quiesce_and_restore_candidate_receipts_and_runtime_with,
    quiesce_and_restore_candidate_receipts_with,
};
pub use marketplace::{
    sanitize_package_update_record, sanitize_url_or_source_key_for_api, target_version_matches,
    versions_match_target,
};

static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

pub(crate) const OPENAPI_YAML: &str = include_str!("../../../../config/openapi-v1.yaml");

// Keep these hashes in sync with the bundled viewer in openapi_ui.rs. The
// Swagger route test verifies them against the served HTML and its script.
const OPENAPI_VIEWER_CSP: &str = concat!(
    "default-src 'none'; ",
    "script-src 'sha256-jyJt4RwhcAIhFYY+cKeNwROF+/g73E7Z48dgwfww3qI='; ",
    "style-src 'sha256-uFkWmHkrhhU0j08xygBL6L+ApAEWzPHOdAssSQkGcTg='; ",
    "style-src-attr 'unsafe-hashes'",
    " 'sha256-5Fsk84KIR+lDiNQtvNos/9DJZDA1zI/lJleV8flEcUw='", // border-color: rgba(244, 63, 94, 0.45);
    " 'sha256-vlLHoHEFMi9eDFnAmMWaNmB2X3mX3y8/KrTJRwQ5Zgk='", // color:var(--rose);
    " 'sha256-MspoDULVvFUu+EGVwxzfwJrhcBGpJbJUVylwYlqFut0='", // display:flex;align-items:center;justify-content:space-between;gap:12px;
    " 'sha256-xC8juOyOcGVG0BdxV2vy4LlzWOZfFlsV82FV45f1hTY='", // font-size:12px;
    " 'sha256-ZbR7rNLB0eDq+536A9faDgt/COmrZCwPOXqeYb+72AY='", // font-size:12px;margin-top:4px;
    " 'sha256-RjZ3C0loqJUpHnVjvylsB/gI+/jzWQZIje5lII5BhvA='", // margin-bottom:12px;
    " 'sha256-PEo9RAB0C7Pw0EzsgS+HuVOHFPZRr93dZNJ9mYzz95A='", // margin-bottom:20px;
    " 'sha256-xQAVW2K0oJOkay83e4mq0DkGen61FPvjkekwHB20JNk='", // margin-bottom:8px;
    " 'sha256-GVP6eWzzxD9xO2PlBQF9gO5MWEE1dewvo/XOfKaRI/k='", // margin-left:8px;
    " 'sha256-qTg+SZK3Zo3bBUqZqmXpk0+a1nRHw5ojp7cXL9n4z4o='", // margin-left:8px;font-size:12px;
    " 'sha256-cm6LMX8ymN9S2NZIl6bkdxkDVg8qKWjN9YrULeIqytI='", // margin-top:10px;
    " 'sha256-NugfhhJHFN8ab5ins9DoUFIX7i7OhkkvaH+nh6H6Y3M='", // margin-top:4px;
    " 'sha256-HUNu/B+IX8Ijz50biWW0v3RjXHoGSCMlzH2BnOV0TJc='", // margin-top:6px;
    " 'sha256-ozuPwv93gGhip1xyJjz11Brp9Kvn+VSA8OluSNIDrx8='", // margin-top:8px;
    " 'sha256-iAn7EfFRiJ0vGVgxvjrTlA52i5pGG79OKBU/qKXAdOg='", // max-height:70vh;
    " 'sha256-cfmEFAlZNrRhDsLv6ZB7Pzg2EggYbJJ4l1wTyOZW7Cg='", // width:90px;
    "; img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
);

// ─────────────────────────────────────────────────────────────────────────────
// Security Headers, Request ID & API Versioning Middlewares
// ─────────────────────────────────────────────────────────────────────────────

pub async fn security_headers_middleware(mut req: Request, next: Next) -> Response {
    normalize_request_forwarding_for_peer(&mut req);
    let req_id = req
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));

    let is_legacy_api =
        req.uri().path().starts_with("/api/") && !req.uri().path().starts_with("/api/v1/");
    let req_path = req.uri().path().to_string();
    let req_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 255
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
                })
        })
        .map(str::to_string);

    req.headers_mut().insert(
        "X-Request-ID",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    let is_plugin_ui = req_path.contains("/plugins/") && req_path.ends_with("/ui");
    let mut resp = next.run(req).await;
    let is_plugin_proxy = resp.extensions().get::<ProxiedPluginResponse>().is_some();
    let is_openapi_viewer = (req_path.starts_with("/api/v1/public/swagger/")
        || req_path.starts_with("/api/public/swagger/"))
        && resp.status() == StatusCode::OK
        && resp
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|mime| mime == "text/html; charset=utf-8");
    let h = resp.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    if matches!(
        req_path.as_str(),
        "/api/v1/auth/plugins" | "/api/auth/plugins"
    ) {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
    if is_plugin_ui && !is_plugin_proxy {
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
    if is_plugin_proxy {
        // Plugins are untrusted and can emit public cache directives. Replace
        // them for every proxied response, irrespective of path, status or MIME.
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        h.insert(header::EXPIRES, HeaderValue::from_static("0"));
        h.remove("surrogate-control");
        h.remove("cdn-cache-control");
        h.remove("cloudflare-cdn-cache-control");
        // Apply to every upstream representation, including JSON and scripts:
        // MIME types, route suffixes and URL encodings do not reliably identify
        // documents. Fetch callers can still consume the unchanged response.
        // No sandbox allowances means opaque origin and no plugin script, even
        // when an operator opens a proxy URL as a top-level document.
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static(
                "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        );
    } else if is_plugin_ui {
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static(
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts",
            ),
        );
    } else if is_openapi_viewer {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(OPENAPI_VIEWER_CSP),
        );
    } else if req_path.starts_with("/api/") {
        h.insert(
            "Content-Security-Policy",
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        );
    } else {
        let connect_src = match req_host.as_deref() {
            Some(host) => format!("'self' ws://{host} wss://{host}"),
            None => "'self'".to_string(),
        };
        let csp = format!(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data: blob: https:; media-src 'self' blob:; connect-src {connect_src}; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        );
        if let Ok(hv) = HeaderValue::from_str(&csp) {
            h.insert("Content-Security-Policy", hv);
        }
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
        let raw_successor = req_path.replacen("/api/", "/api/v1/", 1);
        let safe_successor: String = raw_successor
            .chars()
            .filter(|&c| !c.is_control() && !matches!(c, ';' | '>' | '<' | '"' | '\\' | ' '))
            .collect();
        if safe_successor.starts_with("/api/v1/") {
            if let Ok(link_hv) =
                HeaderValue::from_str(&format!("<{}>; rel=\"successor-version\"", safe_successor))
            {
                h.insert("Link", link_hv);
            }
        }
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Router Construction
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
                .patch(proxy_plugin_root_handler)
                .delete(proxy_plugin_root_handler),
        )
        .route(
            "/plugins/:id/proxy/*rest",
            get(proxy_plugin_wildcard_handler)
                .post(proxy_plugin_wildcard_handler)
                .put(proxy_plugin_wildcard_handler)
                .patch(proxy_plugin_wildcard_handler)
                .delete(proxy_plugin_wildcard_handler),
        )
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(auth_middleware));

    let public_well_known =
        Router::new().route("/.well-known/openid-configuration", get(oidc_discovery));

    Router::new()
        .nest("/api/v1", v1)
        .nest("/api", legacy)
        .merge(top_level_plugins)
        .merge(public_well_known)
        .route("/health", get(health_check))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(prometheus_metrics))
        .fallback(spa_fallback_handler)
        .layer(middleware::from_fn(host_validation_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
}

fn build_v1_router() -> Router {
    let auth_limited_public = Router::new()
        .route("/auth/login", post(local_login))
        .route("/auth/mfa/verify", post(mfa_login_verify))
        .route("/auth/setup", post(setup_admin))
        .route("/auth/refresh", post(refresh_session_with_peer))
        .layer(middleware::from_fn(auth_rate_limit_middleware));

    let oidc_limited_public = Router::new()
        .route("/auth/google/login", get(google_login))
        .route("/auth/google/callback", get(google_callback))
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
        .route("/swagger", get(crate::openapi_ui::swagger_redirect))
        .route("/swagger/", get(crate::openapi_ui::swagger_index))
        .route("/swagger/*any", get(crate::openapi_ui::swagger_asset))
        .route("/csrf-token", get(issue_csrf_token))
        .route("/auth/verify", get(verify_proxy_auth))
        .route("/auth/setup/check", get(check_setup_needed))
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
        .route("/refresh", post(refresh_session_with_peer))
        .route("/sessions", get(list_active_sessions))
        .route("/sessions/:jti", delete(revoke_session))
        .route("/logout", post(logout))
        .route("/profile", put(update_profile))
        .route("/profile/password", put(update_password))
        .route("/profile/avatar", put(update_avatar).delete(delete_avatar))
        .route("/system/topology", get(get_system_topology))
        .route("/fs", get(browse_directories))
        .route("/user/quota", get(get_own_quota))
        .route("/user/2fa/setup", post(setup_2fa))
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
                .patch(proxy_plugin_root_handler)
                .delete(proxy_plugin_root_handler),
        )
        .route(
            "/plugins/:id/proxy/*rest",
            get(proxy_plugin_wildcard_handler)
                .post(proxy_plugin_wildcard_handler)
                .put(proxy_plugin_wildcard_handler)
                .patch(proxy_plugin_wildcard_handler)
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
        .route("/apps/launch", post(crate::app_launch::issue))
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
        .route("/cluster/commands", get(list_worker_commands))
        .route("/cluster/nodes/:id", delete(remove_worker))
        .route("/cluster/nodes/:id/metrics", get(get_worker_metrics))
        .route("/cluster/nodes/:id/commands", post(dispatch_worker_command))
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
        .route("/logs", get(crate::service_logs::get_admin_logs))
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
            post(crate::streaming_portability::preview_handler).layer(
                axum::extract::DefaultBodyLimit::max(
                    crate::streaming_portability::MAX_REQUEST_BODY_BYTES,
                ),
            ),
        )
        .route(
            crate::streaming_portability::RESTORE_ROUTE,
            post(crate::streaming_portability::restore_handler).layer(
                axum::extract::DefaultBodyLimit::max(
                    crate::streaming_portability::MAX_REQUEST_BODY_BYTES,
                ),
            ),
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Health, Metrics & OpenAPI Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn health_check() -> Json<serde_json::Value> {
    let check_res = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(af_db::db_health_check),
    )
    .await;
    let (status, db_status, latency_ms) = match check_res {
        Ok(Ok(Ok(val))) => (
            "ok",
            "ok",
            val.get("latency_ms").and_then(|v| v.as_i64()).unwrap_or(0),
        ),
        _ => ("degraded", "unreachable", 0),
    };
    Json(serde_json::json!({
        "status": status,
        "uptime": format!("{:.1}s", START_TIME.elapsed().as_secs_f64()),
        "version": af_runner::af_release::runtime::runtime_identity().version,
        "database": db_status,
        "db_latency_ms": latency_ms,
    }))
}

async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

async fn health_ready() -> Response {
    let healthy = database_is_ready().await;
    let (code, db_state, ready_state) = if healthy {
        (StatusCode::OK, "ok", "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unreachable", "not_ready")
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

pub(crate) async fn database_is_ready() -> bool {
    let ready = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(|| af_db::db_readiness_check().map(|_| ())),
    )
    .await;
    matches!(ready, Ok(Ok(Ok(()))))
}

async fn authenticated_ready() -> Response {
    let healthy = database_is_ready().await;
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

fn parse_forwarded_ip_token(raw: &str) -> Option<std::net::IpAddr> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(sock) = trimmed.parse::<std::net::SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    let clean = trimmed
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(h, _)| h))
        .unwrap_or(trimmed);
    clean
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

fn forwarded_headers_exclusively_loopback(headers: &axum::http::HeaderMap) -> bool {
    let mut saw_any_client_ip = false;

    for val in headers.get_all("x-forwarded-for") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        for hop in raw.split(',') {
            let Some(ip) = parse_forwarded_ip_token(hop) else {
                return false;
            };
            if !ip.is_loopback() {
                return false;
            }
            saw_any_client_ip = true;
        }
    }

    for val in headers.get_all("x-real-ip") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        let Some(ip) = parse_forwarded_ip_token(raw) else {
            return false;
        };
        if !ip.is_loopback() {
            return false;
        }
        saw_any_client_ip = true;
    }

    for val in headers.get_all("forwarded") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        let mut saw_for_in_header = false;
        for element in raw.split(',') {
            for pair in element.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    if k.trim().eq_ignore_ascii_case("for") {
                        let Some(ip) = parse_forwarded_ip_token(v) else {
                            return false;
                        };
                        if !ip.is_loopback() {
                            return false;
                        }
                        saw_for_in_header = true;
                        saw_any_client_ip = true;
                    }
                }
            }
        }
        if !saw_for_in_header {
            return false;
        }
    }

    saw_any_client_ip
}

async fn is_metrics_request_authorized(req: Request) -> bool {
    let (parts, _body) = req.into_parts();
    drop(_body);

    if env::var("METRICS_PUBLIC")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false)
    {
        return true;
    }

    let peer_ip = parts
        .extensions
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::connect_info::ConnectInfo(addr)| addr.ip().to_canonical());
    let had_proxy_headers = parts
        .extensions
        .get::<crate::ws::InboundProxyForwarded>()
        .map(|f| f.0)
        .unwrap_or_else(|| {
            parts.headers.contains_key("x-forwarded-for")
                || parts.headers.contains_key("x-real-ip")
                || parts.headers.contains_key("forwarded")
        });

    if peer_ip.is_none_or(|ip| ip.is_loopback())
        && (!had_proxy_headers || forwarded_headers_exclusively_loopback(&parts.headers))
    {
        return true;
    }

    let bearer = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(presented) = bearer {
        if let Ok(expected) = env::var("METRICS_BEARER_TOKEN") {
            let expected = expected.trim();
            if !expected.is_empty()
                && af_models::constant_time_eq(presented.as_bytes(), expected.as_bytes())
            {
                return true;
            }
        }
    }

    let Some(raw_token) = crate::auth::resolve_raw_token(&parts.headers) else {
        return false;
    };
    let Ok(claims) = crate::auth::decode_session_claims(&raw_token, false) else {
        return false;
    };
    if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
        return false;
    }
    let ua = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let client_ip = extract_client_ip_for_peer(&parts.headers, peer_ip);
    let hdr_ip = extract_client_ip(&parts.headers);
    if !crate::auth::matches_client_fingerprint(&claims.cfp, &client_ip, &ua)
        && !crate::auth::matches_client_fingerprint(&claims.cfp, &hdr_ip, &ua)
    {
        return false;
    }
    crate::auth::blocking_auth_work(move || {
        if crate::auth::is_session_token_revoked_beyond_grace(&claims.jti, claims.user_id) {
            return false;
        }
        let Ok(conn) = af_db::get_read_conn() else {
            return false;
        };
        let Ok(subj) = crate::auth::load_active_human_subject(&conn, claims.user_id) else {
            return false;
        };
        if !subj.role.eq_ignore_ascii_case("admin") {
            return false;
        }
        if claims.ver < subj.sessions_revoked_after {
            return false;
        }
        if crate::auth::table_exists(&conn, "active_sessions").unwrap_or(false) {
            let resolved_jti = crate::auth::resolve_current_session_jti(&claims.jti);
            let session_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3))",
                    params![claims.user_id, claims.jti, resolved_jti],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if !session_exists {
                return false;
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

async fn prometheus_metrics(req: Request) -> Response {
    if !is_metrics_request_authorized(req).await {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    }

    let Ok(m) = tokio::task::spawn_blocking(af_hardware::get_system_metrics_core).await else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to collect system metrics",
        );
    };
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

    let version = af_runner::af_release::runtime::runtime_identity()
        .version
        .clone();
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
         aetherflow_build_info{{runtime=\"rust\",version=\"{}\",os=\"{}\",arch=\"{}\"}} 1\n",
        START_TIME.elapsed().as_secs_f64(),
        m.cpu_usage,
        mem_total_gb * 1073741824.0,
        mem_used_gb * 1073741824.0,
        mem_pct,
        disk_pct,
        version,
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
// Hardware, Metrics, Services & Marketplace
// ─────────────────────────────────────────────────────────────────────────────

async fn get_system_metrics() -> Json<af_models::SystemMetrics> {
    Json(af_hardware::get_system_metrics_core())
}

async fn get_hardware_info() -> Json<af_models::HardwareReport> {
    Json(af_hardware::get_detailed_hardware())
}

async fn get_services(Extension(auth_user): Extension<AuthUser>) -> Response {
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

// ─────────────────────────────────────────────────────────────────────────────
// Settings, Profile & Users
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

fn is_masked_secret(raw: &str) -> bool {
    let value = raw.trim();
    value.starts_with("****") || value == af_db::SECRET_MASK
}

fn mask_secret(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let dec = match af_db::decrypt_key(raw) {
        Ok(value) if !value.starts_with("enc:v1:") => value,
        _ => return "****".to_string(),
    };
    if dec.chars().count() > 4 {
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
        "****".to_string()
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

async fn update_settings(
    Extension(user): Extension<AuthUser>,
    Json(mut req): Json<SettingsPayload>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
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
    fn endpoint_origin_tuple(raw: &str) -> Option<(String, String, u16)> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let parsed = url::Url::parse(trimmed).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let port = parsed.port_or_known_default()?;
        Some((parsed.scheme().to_ascii_lowercase(), host, port))
    }

    fn is_loopback_ai_endpoint_url(raw: &str) -> bool {
        let Ok(parsed) = url::Url::parse(raw.trim()) else {
            return false;
        };
        let Some(host) = parsed.host_str() else {
            return false;
        };
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
    }

    let prev_base_domain = af_db::get_base_domain();

    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let (prev_anth_endpoint, prev_anth_key): (String, String) = conn
        .query_row(
            "SELECT COALESCE(anthropic_endpoint, ''), COALESCE(anthropic_api_key, '') FROM settings WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or_default();
    let effective_prev_anth = if prev_anth_endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        prev_anth_endpoint.trim()
    };
    let effective_next_anth = if req.anthropic_endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        req.anthropic_endpoint.trim()
    };
    let retaining_anth_key =
        is_masked_secret(&req.anthropic_api_key) && !prev_anth_key.trim().is_empty();
    let supplying_fresh_anth_key =
        !req.anthropic_api_key.trim().is_empty() && !is_masked_secret(&req.anthropic_api_key);
    let will_have_anth_key = supplying_fresh_anth_key || retaining_anth_key;

    if retaining_anth_key
        && endpoint_origin_tuple(effective_prev_anth) != endpoint_origin_tuple(effective_next_anth)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "ENDPOINT_KEY_REBIND_DENIED",
            "Changing anthropic_endpoint while an API key is stored requires supplying a fresh API key in the same request",
        );
    }
    if will_have_anth_key
        && !req.anthropic_endpoint.trim().is_empty()
        && !req.anthropic_endpoint.trim().starts_with("https://")
        && !is_loopback_ai_endpoint_url(&req.anthropic_endpoint)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INSECURE_AI_ENDPOINT",
            "Non-loopback AI endpoints carrying an API key must use https://",
        );
    }

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
            if !is_masked_secret(value) {
                let encrypted = if value.is_empty() {
                    String::new()
                } else {
                    af_db::encrypt_key(value)?
                };
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
    af_db::get_base_domain();

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
                            external_access_enabled: false,
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
    PeerIp(peer_ip): PeerIp,
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
    let ip = extract_client_ip_for_peer(&headers, peer_ip);
    let ticket = issue_ws_ticket_for_session(auth_user.user_id, &auth_user.jti, &ip);
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
    let trimmed = req.email.trim().to_string();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid email address",
        );
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || trimmed
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid email address",
        );
    }

    let user_id = auth_user.user_id;
    crate::auth::blocking_response(move || {
        let Ok(mut conn) = af_db::get_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        };
        let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        };
        let conflict: i64 = match tx.query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1 COLLATE NOCASE AND id != ?2",
            params![trimmed, user_id],
            |r| r.get(0),
        ) {
            Ok(c) => c,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to update profile",
                );
            }
        };
        if conflict > 0 {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Email address is already in use",
            );
        }
        if tx
            .execute(
                "UPDATE users SET email = ?1 WHERE id = ?2",
                params![trimmed, user_id],
            )
            .is_err()
            || tx.commit().is_err()
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to update profile",
            );
        }
        Json(serde_json::json!({ "message": "Profile updated successfully" })).into_response()
    })
    .await
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
    if req.current_password.len() > 72 || req.new_password.len() > 72 {
        return crate::auth::password_too_long();
    }
    crate::auth::blocking_response(move || update_password_blocking(auth_user, headers, req)).await
}

fn update_password_blocking(
    auth_user: AuthUser,
    headers: HeaderMap,
    req: ChangePasswordReq,
) -> Response {
    if req.new_password.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "New password must be at least 8 characters",
        );
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let pre_revoked_after =
        if crate::auth::column_exists(&conn, "users", "sessions_revoked_after").unwrap_or(false) {
            conn.query_row(
                "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
                params![auth_user.user_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
        } else {
            0
        };
    let Ok(existing_hash) = conn.query_row(
        "SELECT COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
    };
    drop(conn);

    if !crate::auth::verify_password(&req.current_password, &existing_hash) {
        return api_error(
            StatusCode::FORBIDDEN,
            "INVALID_CURRENT_PASSWORD",
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
    let tx_outcome = (|| -> anyhow::Result<Option<(String, Vec<String>)>> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = if crate::auth::column_exists(&tx, "users", "sessions_revoked_after")
            .unwrap_or(false)
        {
            tx.execute(
                "UPDATE users SET password_hash = ?1 \
                 WHERE id = ?2 AND COALESCE(password_hash, '') = ?3 \
                   AND COALESCE(sessions_revoked_after, 0) <= ?4",
                params![
                    new_hash,
                    auth_user.user_id,
                    existing_hash,
                    pre_revoked_after
                ],
            )?
        } else {
            tx.execute(
                "UPDATE users SET password_hash = ?1 \
                 WHERE id = ?2 AND COALESCE(password_hash, '') = ?3",
                params![new_hash, auth_user.user_id, existing_hash],
            )?
        };
        if changed == 0 {
            return Ok(None);
        }
        let (new_ver, revoked_jtis) =
            crate::auth::revoke_all_user_credentials_in_tx(&tx, auth_user.user_id)?;
        let (new_token, _) = crate::auth::create_session_jwt_in_conn(
            &tx,
            auth_user.user_id,
            &headers,
            Utc::now().timestamp(),
            None,
            new_ver,
        )?;
        tx.commit()?;
        Ok(Some((new_token, revoked_jtis)))
    })();

    let (new_token, revoked_jtis) = match tx_outcome {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "SESSION_EXPIRED",
                "Credentials changed concurrently; please re-authenticate",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to update password",
            );
        }
    };
    crate::auth::finalize_user_credential_revocation(auth_user.user_id, &revoked_jtis);

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

    let mut resp = Json(serde_json::json!({
        "status": "success",
        "message": "Password updated successfully",
    }))
    .into_response();
    crate::auth::set_session_cookie(&mut resp, &new_token);
    resp
}

#[derive(Deserialize)]
struct AvatarReq {
    #[serde(default)]
    avatar: String,
    #[serde(default)]
    avatar_url: String,
}

fn validate_avatar_uri(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Avatar image or URL is required");
    }
    if trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("Avatar URI must not contain control characters");
    }
    if trimmed.starts_with('/') {
        if trimmed.starts_with("//") || trimmed.starts_with("/\\") || trimmed.contains("..") {
            return Err("Disallowed avatar URI path");
        }
        return Ok(trimmed.to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    const ALLOWED_RASTER_PREFIXES: &[&str] = &[
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/jpg;base64,",
        "data:image/webp;base64,",
        "data:image/gif;base64,",
    ];
    if let Some(prefix) = ALLOWED_RASTER_PREFIXES
        .iter()
        .find(|p| lower.starts_with(**p))
    {
        let b64_payload = &trimmed[prefix.len()..];
        if b64_payload.is_empty()
            || !b64_payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err("Invalid base64 raster avatar payload");
        }
        use base64::Engine as _;
        if base64::engine::general_purpose::STANDARD
            .decode(b64_payload)
            .is_err()
        {
            return Err("Malformed base64 raster avatar payload");
        }
        return Ok(trimmed.to_string());
    }
    if lower.starts_with("https://") {
        let Ok(parsed) = reqwest::Url::parse(trimmed) else {
            return Err("Invalid avatar HTTPS URL");
        };
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err("Invalid avatar HTTPS URL");
        }
        return Ok(trimmed.to_string());
    }
    Err("Disallowed avatar URI scheme; use https://, a root-relative path, or a base64 PNG/JPEG/WEBP/GIF data URI")
}

async fn update_avatar(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<AvatarReq>,
) -> Response {
    let val = if !req.avatar.trim().is_empty() {
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
    let validated = match validate_avatar_uri(&val) {
        Ok(uri) => uri,
        Err(msg) => {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", msg);
        }
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update avatar",
        );
    };
    if conn
        .execute(
            "UPDATE users SET avatar_url = ?1 WHERE id = ?2",
            params![validated, auth_user.user_id],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update avatar",
        );
    }
    Json(serde_json::json!({
        "status": "success",
        "message": "Avatar updated successfully",
        "avatar_url": validated,
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

async fn get_users(Extension(user): Extension<AuthUser>) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    let Ok(conn) = af_db::get_read_conn() else {
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
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
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
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
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
        for def in ["/mnt", "/media", "/srv", "/home"] {
            raw_roots.push(PathBuf::from(def));
        }
        raw_roots.push(env::temp_dir());

        if let Ok(cwd) = env::current_dir() {
            let cwd_canon = fs::canonicalize(&cwd).unwrap_or_else(|_| cwd.clone());
            let is_restricted_service_dir =
                ["/opt/AetherFlow", "/var/lib/aetherflow"]
                    .iter()
                    .any(|restricted| {
                        let r_path = std::path::Path::new(restricted);
                        let r_canon =
                            fs::canonicalize(r_path).unwrap_or_else(|_| r_path.to_path_buf());
                        cwd_canon == r_canon || cwd_canon.starts_with(&r_canon)
                    });
            if !is_restricted_service_dir {
                raw_roots.push(cwd);
            }
        }
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
        let Ok(connection) = af_db::get_read_conn() else {
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
    let user_id = auth_user.user_id;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);
    let (notifications, unread_count) = tokio::task::spawn_blocking(move || {
        let Ok(conn) = af_db::get_read_conn() else {
            return (Vec::new(), 0i64);
        };
        let unread: i64 =
            af_db::count_unread_notifications_for_user_with_conn(&conn, user_id).unwrap_or(0);
        let mut list = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT n.id, n.user_id, n.level, n.title, n.message, n.read, COALESCE(CAST(n.created_at AS TEXT), '') \
             FROM notifications n \
             LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.user_id = ?1 \
             WHERE (n.user_id = ?1 OR (n.user_id IS NULL AND nr.notification_id IS NULL)) \
             ORDER BY n.created_at DESC LIMIT ?2 OFFSET ?3",
        ) {
            if let Ok(rows) = stmt.query_map(params![user_id, limit, offset], |r| {
                Ok(af_services::Notification {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    level: r.get(2)?,
                    title: r.get(3)?,
                    message: r.get(4)?,
                    read: r.get(5)?,
                    created_at: r.get(6)?,
                })
            }) {
                for r in rows.flatten() {
                    list.push(r);
                }
            }
        }
        (list, unread)
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({
        "notifications": notifications,
        "unread_count": unread_count,
    }))
}

async fn mark_notification_read(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let user_id = auth_user.user_id;
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let conn = af_db::get_conn()?;
        af_db::mark_notification_read_for_user_with_conn(&conn, user_id, id)
    })
    .await;

    match res {
        Ok(Ok(true)) => {
            Json(serde_json::json!({ "message": "Notification marked as read" })).into_response()
        }
        Ok(Ok(false)) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Notification not found"),
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        ),
    }
}

async fn dismiss_all_notifications(Extension(auth_user): Extension<AuthUser>) -> Response {
    let user_id = auth_user.user_id;
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ?1 AND read = 0",
            params![user_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO notification_reads (notification_id, user_id) \
             SELECT id, ?1 FROM notifications WHERE user_id IS NULL",
            params![user_id],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await;

    match res {
        Ok(Ok(())) => {
            Json(serde_json::json!({ "message": "All notifications dismissed" })).into_response()
        }
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to dismiss notifications",
        ),
    }
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
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
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
        .unwrap_or(false);
    let tls_enabled = existing_ing
        .as_ref()
        .map(|c| c.tls_enabled)
        .unwrap_or(!public_domain.is_empty());

    let config_summary = match af_services::mutators::apply_blueprint_app_config_detailed(
        &app_name,
        u16::try_from(allocated_port).unwrap_or(0),
    )
    .await
    {
        Ok(summary) => summary,
        Err(error) => return blueprint_sync_failure_response(&anyhow::Error::msg(error)),
    };
    let mut unprivileged_skips = config_summary.unprivileged_skips;
    let mut warnings = config_summary.warnings;
    let config_applied = config_summary.config_applied;

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
        match af_services::mutators::sync_local_dns_domains(&dns_domains).await {
            Ok(()) => true,
            Err(error) if af_services::mutators::is_unprivileged_host_write_error(&error) => {
                if !unprivileged_skips.contains(&error) {
                    unprivileged_skips.push(error.clone());
                }
                warnings.push(format!(
                    "Local DNS hosts sync skipped in unprivileged API process: {}",
                    error
                ));
                false
            }
            Err(error) => return blueprint_sync_failure_response(&anyhow::Error::msg(error)),
        }
    };
    if let Err(error) = af_services::mutators::sync_network_dns_providers().await {
        return blueprint_sync_failure_response(&anyhow::Error::msg(error));
    }
    let network_dns_synced = true;

    if !unprivileged_skips.is_empty() && !ingress_synced && !config_applied {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "BLUEPRINT_HOST_WRITE_SKIPPED",
                "message": "Blueprint host configuration writes were skipped due to unprivileged filesystem restrictions and no database/ingress sync occurred",
                "unprivileged_skips": unprivileged_skips,
                "warnings": warnings,
            })),
        )
            .into_response();
    }

    let message = if unprivileged_skips.is_empty() && warnings.is_empty() {
        "Blueprint synchronized successfully"
    } else {
        "Blueprint synchronized with warnings (some host writes were skipped in unprivileged mode)"
    };

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
        mutated_files: config_summary.mutated_files,
        unprivileged_skips,
        warnings,
        ingress_synced,
        hosts_synced,
        network_dns_synced,
    };

    Json(serde_json::json!({
        "message": message,
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
    #[serde(default, alias = "api_key")]
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
    type StreamingServerSaveFn = fn(&str, &str, &str, bool) -> Result<String, Response>;
    let norm_provider = provider.trim().to_ascii_lowercase();
    let (provider_label, save): (&str, Option<StreamingServerSaveFn>) = match norm_provider.as_str()
    {
        "jellyfin" => ("Jellyfin", None),
        crate::streaming_emby::EMBY_PROVIDER_ID => (
            "Emby",
            Some(crate::streaming_ext::save_emby_server_configuration),
        ),
        "plex" => (
            "Plex",
            Some(crate::streaming_ext::save_plex_server_configuration),
        ),
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Supported streaming providers are Jellyfin, Emby, and Plex",
            )
        }
    };
    let clean_url = if let Some(save) = save {
        match save(&req.name, &req.url, &req.api_key, req.enabled) {
            Ok(url) => url,
            Err(response) => return response,
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
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
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

async fn get_ingress_configs(Extension(user): Extension<AuthUser>) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    crate::auth::blocking_response(|| {
        let configs = af_db::get_all_app_ingress_configs().unwrap_or_default();
        Json(serde_json::json!({ "configs": configs })).into_response()
    })
    .await
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
        .unwrap_or(false);

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

fn is_valid_ingress_app_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

async fn update_app_ingress_config(
    Path(app_name): Path<String>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<UpdateIngressReq>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    let clean_app = app_name.trim().to_lowercase();
    if clean_app.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "App name is required",
        );
    }
    if !is_valid_ingress_app_slug(&clean_app) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid application name; must be a DNS-safe lowercase slug",
        );
    }
    // Keep the app mutation guard until host synchronization or rollback finishes,
    // including when the HTTP client disconnects.
    let update = tokio::spawn(async move {
        let guarded_app = clean_app.clone();
        af_services::mutators::with_blueprint_mutation(&guarded_app, async move {
            upsert_app_ingress_config(clean_app, req).await
        })
        .await
    })
    .await;
    match update {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if af_runner::is_lifecycle_busy(&error) => {
            blueprint_sync_failure_response(&error)
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "Ingress update failed");
            api_error(
                StatusCode::BAD_GATEWAY,
                "INGRESS_SYNC_FAILED",
                "Ingress configuration could not be synchronized",
            )
        }
        Err(error) => {
            tracing::error!(%error, "Ingress update worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Ingress configuration could not be updated",
            )
        }
    }
}

async fn upsert_app_ingress_config(
    clean_app: String,
    req: UpdateIngressReq,
) -> anyhow::Result<Response> {
    let staged = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        af_db::invalidate_ingress_cache();
        let previous = af_db::get_app_ingress_config(&clean_app)?;
        let blueprint = af_services::get_blueprint(&clean_app);
        let runtime_port = af_services::mutators::get_app_runtime_meta(&clean_app).configured_port;
        let native_port = if runtime_port > 0 {
            runtime_port
        } else {
            blueprint
                .as_ref()
                .map_or(0, |blueprint| blueprint.default_port)
        };
        let cfg = match resolve_patched_ingress_config(
            &clean_app,
            &req,
            previous.as_ref(),
            native_port,
            Utc::now(),
        ) {
            Ok(cfg) => cfg,
            Err((status, code, message)) => return Ok(Err(api_error(status, code, message))),
        };
        let internal = blueprint
            .map(|blueprint| blueprint.internal_domain)
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| format!("{clean_app}.aether.local"));
        let port_changed = previous
            .as_ref()
            .is_some_and(|old| old.listen_port != cfg.listen_port);
        af_db::set_app_ingress_config(&cfg)?;
        Ok(Ok((cfg, previous, internal, port_changed)))
    })
    .await??;
    let (cfg, previous, internal, port_changed) = match staged {
        Ok(staged) => staged,
        Err(response) => return Ok(response),
    };

    let app = cfg.app_name.clone();
    let runtime = tokio::runtime::Handle::current();
    let sync_cfg = cfg.clone();
    let sync_internal = internal.clone();
    let sync = async {
        if port_changed {
            // The mutator handles its host port work in a blocking task and
            // reuses the app admission held by this update.
            af_services::mutators::apply_blueprint_app_config(&app, cfg.listen_port)
                .await
                .map_err(anyhow::Error::msg)?;
        }
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let apache_managed = apache_ingress_is_managed();
            let apache = sync_ingress_vhost(&sync_cfg, &sync_internal);
            match apache {
                Ok(true) => {}
                Ok(false) if !apache_managed => {}
                Err(error) if !apache_managed => {
                    tracing::warn!(%error, "Apache unavailable during unmanaged ingress update");
                }
                Ok(false) => anyhow::bail!("Managed Apache did not apply ingress configuration"),
                Err(error) => {
                    anyhow::bail!("Managed Apache failed to apply ingress configuration: {error}")
                }
            }
            let mut domains = vec![sync_internal];
            if !sync_cfg.public_domain.is_empty() && !domains.contains(&sync_cfg.public_domain) {
                domains.push(sync_cfg.public_domain);
            }
            if let Err(error) =
                runtime.block_on(af_services::mutators::sync_local_dns_domains(&domains))
            {
                tracing::warn!(%error, "Internal DNS synchronization failed during ingress update");
            }
            if let Err(error) =
                runtime.block_on(af_services::mutators::sync_network_dns_providers())
            {
                tracing::warn!(%error, "Network DNS synchronization failed during ingress update");
            }
            Ok(())
        })
        .await?
    }
    .await;

    if let Err(error) = sync {
        let rollback = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            restore_ingress_config(&app, previous.as_ref())?;
            if let Some(previous) = previous {
                if let Err(error) = sync_ingress_vhost(&previous, &internal) {
                    tracing::error!(app = %app, %error, "Could not reapply previous Apache vhost");
                }
            }
            Ok(())
        })
        .await;
        if !matches!(rollback, Ok(Ok(()))) {
            tracing::error!(?rollback, "Ingress database rollback failed");
            return Ok(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INGRESS_ROLLBACK_FAILED",
                "Ingress configuration could not be restored",
            ));
        }
        return Err(error);
    }
    if cfg.tls_enabled {
        af_services::mutators::trigger_apache_cert_sync().await;
    }
    Ok(Json(serde_json::json!({
        "message": "Ingress configuration updated successfully",
        "config": cfg,
    }))
    .into_response())
}

fn apache_ingress_is_managed() -> bool {
    env::var("PRIVILEGED_RUNNER_ENABLED").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    }) || af_services::mutators::resolve_config_path("/etc/apache2/sites-available").is_dir()
        || std::path::Path::new(&af_runner::runner_socket_path()).exists()
}

fn sync_ingress_vhost(cfg: &AppIngressConfig, internal: &str) -> Result<bool, String> {
    af_services::mutators::sync_apache_app_vhost(
        &cfg.app_name,
        cfg.listen_port,
        internal,
        &cfg.public_domain,
        cfg.external_access_enabled,
    )
}

fn restore_ingress_config(app: &str, previous: Option<&AppIngressConfig>) -> anyhow::Result<()> {
    if let Some(previous) = previous {
        af_db::get_conn()?
            .execute(
                "UPDATE app_ingress_configs SET public_domain = ?2, external_access_enabled = ?3,
             listen_port = ?4, tls_enabled = ?5, updated_at = ?6 WHERE app_name = ?1",
                params![
                    app,
                    previous.public_domain,
                    previous.external_access_enabled,
                    previous.listen_port,
                    previous.tls_enabled,
                    previous.updated_at.to_rfc3339()
                ],
            )
            .and_then(|changed| {
                if changed == 1 {
                    Ok(())
                } else {
                    Err(rusqlite::Error::QueryReturnedNoRows)
                }
            })?;
        af_db::invalidate_ingress_cache();
    } else {
        af_db::delete_app_ingress_config(app)?;
    }
    Ok(())
}

async fn get_notification_rules() -> Json<serde_json::Value> {
    let mut rules = Vec::new();
    if let Ok(conn) = af_db::get_read_conn() {
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
    if let Ok(conn) = af_db::get_read_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, type, COALESCE(config, '{}'), COALESCE(enabled, 1), COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_channels ORDER BY created_at DESC",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let channel_type: String = r.get(2)?;
                let raw_cfg: String = r.get(3)?;
                let cfg_val =
                    af_db::mask_notification_channel_config_str(&channel_type, &raw_cfg);
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "type": channel_type,
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
        "pending" | "approved" | "approved_history" | "rejected" | "executed" | "failed" | "all"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid status filter. Use: pending, approved, approved_history, rejected, executed, failed, all",
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

    let (actions, total) =
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

fn parse_action_gate_service_command(raw_action: &str) -> Result<(String, String, String), String> {
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

async fn approve_action(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    if let Some(message) = system_update_lifecycle_block().await {
        return message.into_response();
    }
    let existing = match af_db::get_pending_action_by_id(id) {
        Ok(Some(existing)) => {
            if existing.status != "pending" {
                return api_error(
                    StatusCode::CONFLICT,
                    "CONFLICT",
                    format!("Action already resolved: {}", existing.status),
                );
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

    let Ok(mut action) = af_db::resolve_action(id, "approved", &auth_user.username) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Action not found or already resolved",
        );
    };

    let manager = managed_by.trim();
    let deferred = svc_act == "restart"
        && matches!(
            target.trim_end_matches(".service"),
            "aetherflow-api" | "aetherflow-runner"
        );
    let exec_res = if deferred {
        af_runner::dispatch_core_restart(&target).await.map(|_| ())
    } else if manager.is_empty() {
        af_services::control_service(&target, &svc_act).await
    } else {
        af_services::control_service_with_manager(&target, &svc_act, manager).await
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

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
        let unauth_body = to_bytes(unauth_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
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
#[allow(clippy::await_holding_lock, clippy::field_reassign_with_default)]
mod tests;

#[cfg(test)]
mod hillclimb_tests;
