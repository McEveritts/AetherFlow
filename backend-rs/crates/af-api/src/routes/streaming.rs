use crate::auth::{api_error, AuthUser};
use crate::streaming_ext::{
    clear_streaming_demo_data, get_streaming_dashboard_handler, seed_streaming_demo_data,
};
use crate::ws::extract_client_ip;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;
use serde::Deserialize;
use std::collections::HashMap;

pub(super) async fn get_streaming_dashboard(
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

pub(super) fn default_true() -> bool {
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
pub(super) struct DemoReq {
    #[serde(default)]
    pub(super) action: String,
}

pub(super) async fn handle_streaming_demo(
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
        if let Err(error) = clear_streaming_demo_data() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                error.to_string(),
            );
        }
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
