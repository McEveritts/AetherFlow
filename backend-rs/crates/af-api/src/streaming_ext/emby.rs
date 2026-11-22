use super::models::build_artwork_http_response;
use crate::auth::api_error;
use af_services::StreamingServerStatus;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use rusqlite::{params, OptionalExtension};

#[allow(clippy::result_large_err)]
pub fn save_emby_server_configuration(
    name_raw: &str,
    url_raw: &str,
    api_key_raw: &str,
    enabled: bool,
) -> Result<String, Response> {
    let clean_url = match crate::streaming_emby::validate_emby_server_url(url_raw) {
        Ok(u) => u,
        Err(e) => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                e.to_string(),
            ))
        }
    };

    let trimmed_key = api_key_raw.trim();
    let is_masked = trimmed_key.starts_with("****");
    let enc_key = if api_key_raw.is_empty() || is_masked {
        String::new()
    } else {
        let clean_token = crate::streaming_emby::sanitize_emby_token(api_key_raw);
        if clean_token.is_empty() {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Valid Emby API key is required",
            ));
        }
        match af_db::encrypt_key(&clean_token) {
            Ok(key) if !af_db::is_encryption_enabled() || key.starts_with("enc:v1:") => key,
            _ => {
                return Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "STREAMING_KEY_STORAGE_FAILED",
                    "Failed to encrypt provider credential; configuration was not changed",
                ));
            }
        }
    };

    let Ok(conn) = af_db::get_conn() else {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Emby server configuration",
        ));
    };

    if enc_key.is_empty() {
        let existing = conn
            .query_row(
                "SELECT url, api_key FROM streaming_servers WHERE provider = 'emby'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to read existing Emby server configuration",
                )
            })?;

        match existing {
            Some((previous_url, previous_key)) => {
                if previous_url.trim().trim_end_matches('/') != clean_url {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a new API key when changing the provider URL; stored credentials cannot be transferred to another server",
                    ));
                }
                if is_masked {
                    let valid_stored = !previous_key.trim().is_empty()
                        && if previous_key.starts_with("enc:v1:") {
                            af_db::decrypt_key(&previous_key)
                                .map(|d| !d.trim().is_empty() && !d.starts_with("enc:v1:"))
                                .unwrap_or(false)
                        } else {
                            true
                        };
                    if !valid_stored {
                        return Err(api_error(
                            StatusCode::BAD_REQUEST,
                            "STREAMING_KEY_REQUIRED",
                            "Stored Emby API key is missing or cannot be decrypted; provide a new API key",
                        ));
                    }
                }
            }
            None => {
                if is_masked
                    || clean_url
                        != crate::streaming_emby::resolve_default_emby_url().trim_end_matches('/')
                {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a new API key when configuring or changing the provider URL; stored credentials cannot be transferred to another server",
                    ));
                }
            }
        }
    }

    let name = if name_raw.trim().is_empty() {
        crate::streaming_emby::EMBY_DEFAULT_NAME.to_string()
    } else {
        name_raw.trim().to_string()
    };

    if conn
        .execute(
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
            params![
                crate::streaming_emby::EMBY_PROVIDER_ID,
                name,
                clean_url,
                enc_key,
                enabled
            ],
        )
        .is_err()
    {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Emby server configuration",
        ));
    }

    Ok(clean_url)
}

pub(super) fn persist_emby_verified_identity(
    status: &StreamingServerStatus,
    clean_url: &str,
    api_key: &str,
) -> anyhow::Result<()> {
    if status.status != "connected"
        || status.server_id.trim().is_empty()
        || api_key.trim().is_empty()
    {
        return Ok(());
    }
    let conn = af_db::get_conn()?;
    let norm_url = clean_url.trim().trim_end_matches('/');
    let Some(stored_key) = conn
        .query_row(
            "SELECT api_key FROM streaming_servers WHERE provider = 'emby' AND RTRIM(url, '/') = ?1",
            [norm_url],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(());
    };
    let plaintext = if stored_key.starts_with("enc:v1:") {
        match af_db::decrypt_key(&stored_key) {
            Ok(dec) if !dec.starts_with("enc:v1:") => dec,
            _ => String::new(),
        }
    } else {
        stored_key.clone()
    };
    if !plaintext.is_empty()
        && crate::streaming_emby::sanitize_emby_token(&plaintext)
            == crate::streaming_emby::sanitize_emby_token(api_key)
    {
        conn.execute(
            "UPDATE streaming_servers \
             SET server_id = ?1, server_version = ?2, last_connected_at = CURRENT_TIMESTAMP \
             WHERE provider = 'emby' AND RTRIM(url, '/') = ?3 AND api_key = ?4 \
               AND enabled=1 AND (COALESCE(server_id, '') = '' OR LOWER(server_id) = LOWER(?1))",
            params![
                status.server_id.trim(),
                status.version.trim(),
                norm_url,
                stored_key
            ],
        )?;
    }
    Ok(())
}

pub(super) async fn finalize_emby_server_test(
    stored: &crate::streaming_emby::EmbyServerConfig,
    target_url: &str,
    target_key: &str,
    same_server: bool,
) -> Response {
    let expected_sid = if same_server && !stored.expected_server_id.is_empty() {
        Some(stored.expected_server_id.as_str())
    } else {
        None
    };
    match crate::streaming_emby::test_emby_connection(target_url, target_key, expected_sid).await {
        Ok(mut server) => {
            server.enabled = if same_server { stored.enabled } else { false };
            server.support_stage = crate::streaming_emby::EMBY_SUPPORT_STAGE.to_string();
            if same_server && server.status == "connected" && !target_key.is_empty() {
                if let Err(error) = persist_emby_verified_identity(&server, target_url, target_key)
                {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        format!("Failed to persist verified Emby server identity: {error}"),
                    );
                }
            }
            Json(serde_json::json!({
                "ok": server.status == "connected",
                "message": "Emby adapter probe only; real-client acceptance is pending",
                "server": server,
            }))
            .into_response()
        }
        Err(error) => {
            let (status, code) = error.http_status_and_code();
            api_error(status, code, error.to_string())
        }
    }
}

pub(super) async fn fetch_emby_artwork_response(
    server_url: &str,
    api_key: &str,
    enabled: bool,
    item_id: &str,
) -> Response {
    if !enabled || api_key.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match crate::streaming_emby::fetch_emby_artwork(server_url, api_key, item_id).await {
        Ok(art) => build_artwork_http_response(art.bytes, art.content_type),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
