use super::config::{
    persist_verified_source_with_key, try_get_stored_emby_config_fail_closed,
    try_get_stored_jellyfin_config, try_get_stored_plex_config_fail_closed,
    try_get_stored_provider_config,
};
use super::dashboard::try_build_streaming_dashboard;
use super::emby::{fetch_emby_artwork_response, finalize_emby_server_test};
use super::jellyfin::{
    fetch_jellyfin_artwork_response, send_jellyfin_session_command, test_jellyfin_connection,
};
use super::models::{SessionCommandReq, TestStreamingServerReq};
use super::monitor::{
    parse_observed_session_key, sanitize_session_key_part, verify_monitor_source,
};
use super::plex::{
    fetch_plex_artwork_response, persist_plex_verified_identity, test_plex_connection,
};
use super::summary_sync::sync_jellyfin_watch_history;
use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_services::{StreamingDashboardResponse, StreamingServerStatus};
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

fn is_sqlite_storage_error(err: &anyhow::Error) -> bool {
    if err.chain().any(|cause| {
        cause
            .downcast_ref::<rusqlite::Error>()
            .is_some_and(|e| !matches!(e, rusqlite::Error::QueryReturnedNoRows))
    }) {
        return true;
    }
    let message = err.to_string();
    message.contains("Database pool not initialized")
        || message.contains("Failed to acquire SQLite connection")
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. GET /streaming/artwork/:itemId
// ──────────────────────────────────────────────────────────────────────────────

pub async fn get_streaming_artwork(
    Extension(user): Extension<AuthUser>,
    Path(item_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let trimmed = item_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "valid itemId is required",
        );
    }

    let has_explicit_provider = q.contains_key("provider");
    let provider = q
        .get("provider")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "jellyfin".into());
    if !matches!(provider.as_str(), "jellyfin" | "emby" | "plex") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let authorization = (|| -> anyhow::Result<bool> {
        let conn = af_db::get_conn()?;
        let Some(server_id): Option<String> = conn
            .query_row(
                "SELECT server_id FROM streaming_servers WHERE provider=?1 AND enabled=1 AND COALESCE(server_id,'')!=''",
                [&provider],
                |row| row.get(0),
            )
            .optional()?
        else {
            return Ok(false);
        };
        if q.get("serverId")
            .is_some_and(|requested| requested != &server_id)
        {
            return Ok(false);
        }
        if user.role == "admin" {
            return Ok(true);
        }
        if !has_explicit_provider {
            return Ok(false);
        }
        let included = crate::streaming_history::inclusion_predicate();
        Ok(conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM streaming_history h CROSS JOIN streaming_tracking_policies p WHERE p.id=1 AND h.provider=?1 AND h.server_id=?2 AND h.item_id=?3 AND ({included}) AND EXISTS(SELECT 1 FROM streaming_user_links identity WHERE identity.af_user_id=?4 AND identity.provider=h.provider AND identity.server_id=h.server_id AND identity.provider_user_id=h.user_id))"
            ),
            params![provider, server_id, trimmed, user.user_id],
            |row| row.get(0),
        )?)
    })();

    let authorized = match authorization {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::error!(%error, provider = %provider, "failed to verify streaming artwork authorization");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to verify artwork authorization",
            );
        }
    };
    if !authorized {
        return api_error(
            StatusCode::FORBIDDEN,
            "artwork_scope_denied",
            "Artwork is not available in your linked provider/server/item scope",
        );
    }

    let (_, selected_url, selected_key, selected_enabled) = match try_get_stored_provider_config(
        &provider,
    ) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::error!(%error, provider = %provider, "failed to load streaming provider config for artwork");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to load streaming provider configuration",
            );
        }
    };
    if let Err(error) = verify_monitor_source(&provider, &selected_url, &selected_key).await {
        if is_sqlite_storage_error(&error) {
            tracing::error!(%error, provider = %provider, "failed to verify streaming artwork provider identity");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to verify artwork provider identity",
            );
        }
        return api_error(
            StatusCode::CONFLICT,
            "streaming_identity_changed",
            "Artwork provider identity is unavailable or changed",
        );
    }

    match provider.as_str() {
        "plex" => {
            fetch_plex_artwork_response(&selected_url, &selected_key, selected_enabled, trimmed)
                .await
        }
        "emby" => {
            fetch_emby_artwork_response(&selected_url, &selected_key, selected_enabled, trimmed)
                .await
        }
        _ => {
            fetch_jellyfin_artwork_response(&selected_url, &selected_key, selected_enabled, trimmed)
                .await
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. POST /streaming/servers/test
// ──────────────────────────────────────────────────────────────────────────────

pub async fn test_streaming_server(Json(req): Json<TestStreamingServerReq>) -> Response {
    if req.provider.eq_ignore_ascii_case("emby") {
        let stored = match try_get_stored_emby_config_fail_closed() {
            Ok(cfg) => cfg,
            Err(error) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    format!("Failed to read stored Emby configuration: {error}"),
                );
            }
        };
        let target_url = if req.url.trim().is_empty() {
            stored.url.as_str()
        } else {
            req.url.trim()
        };
        let target_url = match crate::streaming_emby::validate_emby_server_url(target_url) {
            Ok(url) => url,
            Err(error) => {
                let (status, code) = error.http_status_and_code();
                return api_error(status, code, error.to_string());
            }
        };
        let same_server = target_url == stored.url.trim_end_matches('/');
        if req.api_key.trim().starts_with("****") && (!same_server || stored.api_key.is_empty()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "STREAMING_KEY_REQUIRED",
                "Provide a new API key when testing a different server URL; stored credentials cannot be transferred to another server",
            );
        }
        let target_key = if req.api_key.trim().is_empty() || req.api_key.trim().starts_with("****")
        {
            if same_server {
                stored.api_key.as_str()
            } else {
                ""
            }
        } else {
            req.api_key.trim()
        };
        return finalize_emby_server_test(&stored, &target_url, target_key, same_server).await;
    }

    if req.provider.eq_ignore_ascii_case("plex") {
        let stored = match try_get_stored_plex_config_fail_closed() {
            Ok(cfg) => cfg,
            Err(error) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    format!("Failed to read stored Plex configuration: {error}"),
                );
            }
        };
        let raw_target_url = if req.url.trim().is_empty() {
            stored.url.as_str()
        } else {
            req.url.trim()
        };
        let target_url = match af_services::validate_server_url(raw_target_url) {
            Ok(url) => url,
            Err(error) => {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string())
            }
        };
        let same_server = target_url.eq_ignore_ascii_case(stored.url.trim_end_matches('/'));
        if req.api_key.trim().starts_with("****") && (!same_server || stored.api_key.is_empty()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "STREAMING_KEY_REQUIRED",
                "Provide a new Plex token when testing a different server URL; stored credentials cannot be transferred to another server",
            );
        }
        let target_key = if req.api_key.trim().is_empty() || req.api_key.trim().starts_with("****")
        {
            if same_server {
                stored.api_key.as_str()
            } else {
                ""
            }
        } else {
            req.api_key.trim()
        };
        let expected_sid = if same_server && !stored.expected_server_id.is_empty() {
            Some(stored.expected_server_id.as_str())
        } else {
            None
        };
        return match test_plex_connection(&target_url, target_key, expected_sid).await {
            Ok(status) => {
                let ok = status.status == "connected";
                if ok && same_server && !target_key.is_empty() {
                    if let Err(error) =
                        persist_plex_verified_identity(&status, &target_url, target_key)
                    {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            format!("Failed to persist verified Plex server identity: {error}"),
                        );
                    }
                }
                let msg = if ok {
                    format!("Connected to {} ({})", status.name, status.version)
                } else if !status.error_message.is_empty() {
                    status.error_message.clone()
                } else {
                    "Plex server is unconfigured".to_string()
                };
                Json(serde_json::json!({
                    "ok": ok,
                    "message": msg,
                    "server": status,
                }))
                .into_response()
            }
            Err(err) => {
                if is_sqlite_storage_error(&err) {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        format!("Failed to verify Plex server identity in database: {err}"),
                    );
                }
                let fallback_status = StreamingServerStatus {
                    provider: "plex".to_string(),
                    name: "Plex Media Server".to_string(),
                    url: target_url,
                    configured: !target_key.is_empty(),
                    enabled: true,
                    status: if target_key.is_empty() {
                        "unconfigured".to_string()
                    } else {
                        "unreachable".to_string()
                    },
                    support_stage: "active".to_string(),
                    error_message: err.to_string(),
                    ..Default::default()
                };
                Json(serde_json::json!({
                    "ok": false,
                    "message": err.to_string(),
                    "server": fallback_status,
                }))
                .into_response()
            }
        };
    }

    if !req.provider.is_empty() && !req.provider.eq_ignore_ascii_case("jellyfin") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_streaming_provider",
            "Unsupported streaming provider",
        );
    }
    let (_, stored_url, stored_key, _) = match try_get_stored_jellyfin_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Failed to read stored Jellyfin configuration: {error}"),
            );
        }
    };
    let raw_target_url = if req.url.trim().is_empty() {
        stored_url.clone()
    } else {
        req.url.trim().to_string()
    };

    let clean_target_url = match af_services::validate_server_url(&raw_target_url) {
        Ok(u) => u,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };

    let raw_key = req.api_key.trim();
    let target_key = if raw_key.is_empty() || raw_key.starts_with("****") {
        if clean_target_url.eq_ignore_ascii_case(stored_url.trim().trim_end_matches('/')) {
            stored_key
        } else {
            String::new()
        }
    } else {
        raw_key.to_string()
    };

    match test_jellyfin_connection(&clean_target_url, &target_key).await {
        Ok(status) => {
            let ok = status.status == "connected";
            if ok && !target_key.is_empty() {
                let (_, current_url, current_key, enabled) = match try_get_stored_jellyfin_config()
                {
                    Ok(cfg) => cfg,
                    Err(error) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "INTERNAL_ERROR",
                            format!("Failed to reload Jellyfin configuration: {error}"),
                        );
                    }
                };
                if enabled
                    && current_url.trim_end_matches('/') == clean_target_url
                    && current_key == target_key
                {
                    let conn = match af_db::get_conn() {
                        Ok(conn) => conn,
                        Err(error) => {
                            return api_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                format!(
                                    "Failed to persist verified Jellyfin server identity: {error}"
                                ),
                            );
                        }
                    };
                    if let Err(error) = persist_verified_source_with_key(
                        &conn,
                        "jellyfin",
                        &clean_target_url,
                        &target_key,
                        &status.server_id,
                    ) {
                        if is_sqlite_storage_error(&error) {
                            return api_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "INTERNAL_ERROR",
                                format!(
                                    "Failed to persist verified Jellyfin server identity: {error}"
                                ),
                            );
                        }
                        return api_error(
                            StatusCode::CONFLICT,
                            "streaming_identity_changed",
                            error.to_string(),
                        );
                    }
                }
            }
            let msg = if ok {
                format!("Connected to {} (v{})", status.name, status.version)
            } else if !status.error_message.is_empty() {
                status.error_message.clone()
            } else {
                "Jellyfin server is unconfigured".to_string()
            };
            Json(serde_json::json!({
                "ok": ok,
                "message": msg,
                "server": status,
            }))
            .into_response()
        }
        Err(err) => {
            if is_sqlite_storage_error(&err) {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    format!("Failed to verify Jellyfin server identity in database: {err}"),
                );
            }
            let fallback_status = StreamingServerStatus {
                provider: "jellyfin".to_string(),
                name: "Jellyfin".to_string(),
                url: clean_target_url,
                configured: !target_key.is_empty(),
                enabled: true,
                status: if target_key.is_empty() {
                    "unconfigured".to_string()
                } else {
                    "unreachable".to_string()
                },
                support_stage: "active".to_string(),
                error_message: err.to_string(),
                ..Default::default()
            };
            Json(serde_json::json!({
                "ok": false,
                "message": err.to_string(),
                "server": fallback_status,
            }))
            .into_response()
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. POST /streaming/servers/:provider/sync
// ──────────────────────────────────────────────────────────────────────────────

pub async fn sync_streaming_server_history(
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let prov = provider.trim().to_lowercase();
    if prov == "emby" {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "emby_summary_sync_unsupported",
            "Emby item-summary synchronization is not supported yet; live telemetry is available and summaries are not playback events",
        );
    }
    if !prov.is_empty() && prov != "jellyfin" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Only Jellyfin watch history synchronization is supported",
        );
    }

    let outcome = match sync_jellyfin_watch_history().await {
        Ok(outcome) => outcome,
        Err(e) => {
            if is_sqlite_storage_error(&e) {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    format!("History sync failed: {}", e),
                );
            }
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("History sync failed: {}", e),
            );
        }
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        "streaming_history_sync",
        "streaming_server",
        "jellyfin",
        &outcome.imported.to_string(),
        &ip,
        ua,
    );

    let message = if outcome.has_more {
        "Jellyfin watch history batch synchronized (more items remain; run sync again to continue)"
    } else {
        "Jellyfin watch history synchronized"
    };

    Json(serde_json::json!({
        "message": message,
        "imported": outcome.imported,
        "complete": outcome.complete,
        "has_more": outcome.has_more,
        "remaining_sources": outcome.remaining_sources,
        "next_offset": outcome.next_offset,
    }))
    .into_response()
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. POST /streaming/sessions/:sessionId/command
// ──────────────────────────────────────────────────────────────────────────────

#[allow(clippy::result_large_err)]
fn resolve_target_session_provider(
    session_id: &str,
    explicit_provider: &str,
) -> Result<String, Response> {
    let norm_explicit = explicit_provider.trim().to_ascii_lowercase();
    if !norm_explicit.is_empty() {
        if norm_explicit == "jellyfin" || norm_explicit == crate::streaming_emby::EMBY_PROVIDER_ID {
            return Ok(norm_explicit);
        }
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_streaming_provider",
            "Unsupported streaming provider",
        ));
    }

    let norm_sess = sanitize_session_key_part(session_id, 96);
    let mut matched_jf = false;
    let mut matched_emby = false;
    let lookup_result = (|| -> anyhow::Result<()> {
        let conn = af_db::get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT session_key, provider FROM streaming_history \
             WHERE is_active = 1 AND provenance = 'observed_session' \
             ORDER BY id DESC LIMIT 64",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (key, prov) = row?;
            let is_match = parse_observed_session_key(&key)
                .map(|parsed| parsed.session_id == norm_sess)
                .unwrap_or(false);
            if is_match {
                if prov.trim().eq_ignore_ascii_case("jellyfin") {
                    matched_jf = true;
                } else if prov
                    .trim()
                    .eq_ignore_ascii_case(crate::streaming_emby::EMBY_PROVIDER_ID)
                {
                    matched_emby = true;
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = lookup_result {
        tracing::error!(%error, session_id = %session_id, "failed to resolve active session provider");
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to resolve active streaming session provider",
        ));
    }

    if matched_jf && matched_emby {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "AMBIGUOUS_SESSION_PROVIDER",
            "Multiple active streaming providers match sessionId; specify provider explicitly",
        ));
    }
    if matched_emby {
        return Ok(crate::streaming_emby::EMBY_PROVIDER_ID.to_string());
    }
    if matched_jf {
        return Ok("jellyfin".to_string());
    }

    let (_, _, jf_key, jf_enabled) = try_get_stored_jellyfin_config().map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to load Jellyfin configuration: {error}"),
        )
    })?;
    let emby_cfg = try_get_stored_emby_config_fail_closed().map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to load Emby configuration: {error}"),
        )
    })?;
    let jf_ready = jf_enabled && !jf_key.is_empty();
    let emby_ready = emby_cfg.enabled && !emby_cfg.api_key.is_empty();

    if emby_ready && !jf_ready {
        return Ok(crate::streaming_emby::EMBY_PROVIDER_ID.to_string());
    }
    if jf_ready && emby_ready && !session_id.trim().starts_with("demo-") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "AMBIGUOUS_SESSION_PROVIDER",
            "Both Jellyfin and Emby are enabled; specify provider explicitly for session control",
        ));
    }
    Ok("jellyfin".to_string())
}

pub async fn control_streaming_session(
    Extension(user): Extension<AuthUser>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SessionCommandReq>,
) -> Response {
    let clean_session_id = session_id.trim().to_string();
    if clean_session_id.is_empty()
        || clean_session_id.len() > 128
        || clean_session_id.contains('/')
        || clean_session_id.contains('\\')
        || clean_session_id.contains("..")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "valid sessionId is required",
        );
    }

    let cmd = req.command.trim().to_lowercase();
    if !matches!(cmd.as_str(), "pause" | "resume" | "stop" | "message") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "command must be one of: pause, resume, stop, message",
        );
    }

    let hdr = req.header.trim();
    let msg = req.message.trim();
    if hdr.len() > 120 || msg.len() > 1000 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "header (max 120 chars) or message (max 1000 chars) exceeds maximum length",
        );
    }
    if cmd == "message" && msg.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message text is required when command is message",
        );
    }

    let target_provider = match resolve_target_session_provider(&clean_session_id, &req.provider) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    if target_provider == crate::streaming_emby::EMBY_PROVIDER_ID {
        let emby_cfg = match try_get_stored_emby_config_fail_closed() {
            Ok(cfg) => cfg,
            Err(error) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    format!("Failed to load Emby configuration: {error}"),
                );
            }
        };
        if !emby_cfg.enabled || emby_cfg.api_key.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "emby_unconfigured",
                "Session control command failed: Emby server is not configured or enabled",
            );
        }
        let target = crate::streaming_emby::EmbyCommandTarget {
            provider: crate::streaming_emby::EMBY_PROVIDER_ID.to_string(),
            expected_server_id: emby_cfg.expected_server_id.clone(),
            session_id: clean_session_id.clone(),
            command: cmd.clone(),
            header: hdr.to_string(),
            message: msg.to_string(),
        };
        if let Err(err) = crate::streaming_emby::send_emby_session_command(
            &emby_cfg.url,
            &emby_cfg.api_key,
            &target,
        )
        .await
        {
            let (status, code) = err.http_status_and_code();
            return api_error(
                status,
                code,
                format!("Session control command failed: {}", err),
            );
        }

        let ip = extract_client_ip(&headers);
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        af_db::record_audit(
            user.user_id,
            &user.username,
            &format!("streaming_session_{}", cmd),
            "streaming_session",
            &clean_session_id,
            msg,
            &ip,
            ua,
        );

        return Json(serde_json::json!({
            "message": "Command sent to session",
            "provider": crate::streaming_emby::EMBY_PROVIDER_ID,
            "sessionId": clean_session_id,
            "command": cmd,
        }))
        .into_response();
    }

    if let Err(e) = send_jellyfin_session_command(&clean_session_id, &cmd, hdr, msg).await {
        if is_sqlite_storage_error(&e) {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Session control command failed: {e}"),
            );
        }
        let err_msg = e.to_string();
        let (status, code) = if err_msg.contains("not found") {
            (StatusCode::NOT_FOUND, "NOT_FOUND")
        } else if err_msg.contains("not configured")
            || err_msg.contains("does not support")
            || err_msg.contains("does not permit media control")
            || err_msg.contains("unsupported session command")
        {
            (StatusCode::BAD_REQUEST, "BAD_REQUEST")
        } else {
            (StatusCode::BAD_GATEWAY, "UPSTREAM_ERROR")
        };
        return api_error(
            status,
            code,
            format!("Session control command failed: {}", err_msg),
        );
    }

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        &format!("streaming_session_{}", cmd),
        "streaming_session",
        &clean_session_id,
        msg,
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "message": "Command sent to session",
        "sessionId": clean_session_id,
        "command": cmd,
    }))
    .into_response()
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. GET /streaming/dashboard
// ──────────────────────────────────────────────────────────────────────────────

pub async fn get_streaming_dashboard_handler(
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let window = q
        .get("window")
        .or_else(|| q.get("days"))
        .map(|s| s.as_str())
        .unwrap_or("30");
    let play_method = q.get("playMethod").map(|s| s.as_str()).unwrap_or("all");
    let media_type = q.get("mediaType").map(|s| s.as_str()).unwrap_or("all");
    let user = req.extensions().get::<AuthUser>().cloned();
    let Some(user) = user else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Authentication required"})),
        )
            .into_response();
    };
    if user.role != "admin" {
        return Json(StreamingDashboardResponse {
            updated_at: Utc::now().to_rfc3339(),
            ..Default::default()
        })
        .into_response();
    }
    match try_build_streaming_dashboard(window, play_method, media_type, true).await {
        Ok(payload) => Json(payload).into_response(),
        Err(error) => {
            tracing::error!(%error, "failed to load streaming dashboard analytics");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to load streaming dashboard analytics",
            )
        }
    }
}
