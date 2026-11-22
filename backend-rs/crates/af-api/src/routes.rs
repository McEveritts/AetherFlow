use crate::auth::{
    admin_only_middleware, auth_middleware, check_setup_needed, csrf_middleware, disable_2fa,
    get_session, issue_csrf_token, list_active_sessions, local_login, logout, mfa_login_verify,
    refresh_session_with_peer, revoke_session, setup_2fa, setup_admin, verify_2fa,
    verify_proxy_auth,
};
#[cfg(test)]
#[allow(unused_imports)]
use crate::auth::{api_error, AuthUser};
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
    control_streaming_session, get_streaming_artwork, sync_streaming_server_history,
    test_streaming_server,
};
use crate::ws::{
    handle_log_websocket, handle_websocket, normalize_request_forwarding_for_peer,
};
#[cfg(test)]
#[allow(unused_imports)]
use crate::ws::PeerIp;
#[cfg(test)]
#[allow(unused_imports)]
use af_models::{AppIngressConfig, MarketplaceApp, User};
use axum::extract::Request;
#[cfg(test)]
#[allow(unused_imports)]
use axum::extract::{Extension, Path, Query};
#[cfg(all(test, unix))]
#[allow(unused_imports)]
use std::os::unix::ffi::OsStrExt;
use axum::http::{header, HeaderValue, StatusCode};
#[cfg(test)]
#[allow(unused_imports)]
use axum::http::HeaderMap;
use axum::middleware::{self, Next};
use axum::response::Response;
#[cfg(test)]
#[allow(unused_imports)]
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post, put};
use axum::Router;
use chrono::Utc;
use once_cell::sync::Lazy;
#[cfg(test)]
#[allow(unused_imports)]
use rusqlite::params;
#[cfg(test)]
#[allow(unused_imports)]
use std::collections::HashMap;
#[cfg(test)]
#[allow(unused_imports)]
use std::env;
#[cfg(test)]
#[allow(unused_imports)]
use std::fs;
#[cfg(test)]
#[allow(unused_imports)]
use std::path::PathBuf;
use std::time::Instant;

mod account;
mod actions;
mod blueprints_ingress;
mod fs_browser;
mod health;
mod marketplace;
mod notifications;
mod services;
mod settings;
mod streaming;

use account::{
    delete_avatar, delete_user, get_users, issue_ws_ticket, update_avatar, update_password,
    update_profile, update_user_role,
};
#[cfg(test)]
#[allow(unused_imports)]
use account::{read_users, update_password_blocking, validate_avatar_uri, ChangePasswordReq};
use actions::{approve_action, list_pending_actions, reject_action};
use blueprints_ingress::{
    get_app_blueprint, get_blueprints, get_ingress_configs, sync_app_blueprint,
    update_app_ingress_config,
};
#[cfg(test)]
#[allow(unused_imports)]
use blueprints_ingress::{
    resolve_patched_ingress_config, sync_ingress_vhost, upsert_app_ingress_config,
    UpdateIngressReq,
};
use fs_browser::browse_directories;
pub(crate) use health::database_is_ready;
use health::{
    authenticated_ready, get_hardware_info, get_openapi_spec, get_system_metrics, health_check,
    health_live, health_ready, prometheus_metrics,
};
use notifications::{
    dismiss_all_notifications, get_audit_log, get_notification_channels, get_notification_rules,
    get_notifications, mark_notification_read,
};
#[cfg(test)]
#[allow(unused_imports)]
use notifications::PageQuery;
#[allow(unused_imports)]
pub(crate) use services::{
    is_valid_core_restart_job_unit, read_service_inventory, reconcile_pending_action,
    service_inventory_unavailable,
};
use services::{control_service_handler, get_core_restart_status, get_services};
#[cfg(test)]
#[allow(unused_imports)]
use services::{
    service_control_failure_response, validate_service_control_request, ServiceControlReq,
};
#[allow(unused_imports)]
pub(crate) use settings::is_generated_public_domain;
pub use settings::SettingsPayload;
use settings::{get_settings, update_settings};
#[cfg(test)]
#[allow(unused_imports)]
use settings::{
    get_settings_for_role, mask_secret, redact_settings_for_role,
    should_auto_update_active_domain, should_auto_update_retained_domain,
    BASE_DOMAIN_SYNC_STAGE_HOOK,
};
#[allow(unused_imports)]
pub(crate) use streaming::{update_streaming_server, UpdateStreamingServerReq};
use streaming::{get_streaming_dashboard, handle_streaming_demo};
#[cfg(test)]
#[allow(unused_imports)]
use streaming::DemoReq;

#[cfg(test)]
#[allow(unused_imports)]
use marketplace::{
    allocate_or_resolve_app_port, allocate_or_resolve_app_port_with,
    build_single_package_update_response, dispatch_package_lifecycle_with_target,
    emit_package_progress, finalize_post_script_lifecycle_with, finish_package_lifecycle,
    finish_package_lifecycle_with_recovery, get_marketplace_apps_blocking,
    get_marketplace_auth_info, is_lock_file_present, package_progress_payload,
    parse_uninstall_purge, pre_stop_units_for_package_update_with,
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with,
    resolve_package_lifecycle_port_with, restore_candidate_receipts,
    restore_pre_stopped_units_after_installer_failure_with,
    run_package_lifecycle_dispatch_gate_with, snapshot_candidate_receipts,
    system_update_lifecycle_block_with, verified_prior_state_recovery, UninstallQuery,
    CANDIDATE_QUIESCE_RECORDER,
};
// Keep the existing crate::routes paths for lifecycle callers.
#[allow(unused_imports)]
pub(crate) use marketplace::{
    append_package_job_output, reinstall_package, should_rollback_post_certification_failure,
    PackageActionQuery, PackageLifecycleFailure, ReceiptSnapshotEntry,
};
use marketplace::{
    check_package_updates, check_single_package_update, get_marketplace_apps, install_package,
    package_progress, uninstall_package, update_package,
};
#[cfg(test)]
#[allow(unused_imports)]
use marketplace::load_authoritative_app_ingress_config;
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

// ──────────────────────────────────────────────────────────────────────────────
// Regression & Unit Test Modules
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "http_lifecycle_regressions.rs"]
mod http_lifecycle_regressions;

#[cfg(all(test, unix))]
#[path = "services_readiness_regressions.rs"]
mod services_readiness_regressions;

#[cfg(all(test, unix))]
#[path = "approval_restart_regressions.rs"]
mod approval_restart_regressions;

#[cfg(all(test, unix))]
mod update_error_regressions;

#[cfg(test)]
#[allow(clippy::await_holding_lock, clippy::field_reassign_with_default)]
mod tests;

#[cfg(test)]
mod hillclimb_tests;
