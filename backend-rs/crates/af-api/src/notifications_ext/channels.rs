use super::models::{CreateChannelReq, StoredChannel};
use super::webhook::{dispatch_to_channel, parse_webhook_url};
use crate::auth::api_error;
use axum::extract::Path;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};

pub(super) const WEBHOOK_HEADER_FIELDS: [&str; 2] = ["headers", "custom_headers"];

pub(super) fn parse_custom_webhook_header(
    name: &str,
    value: &serde_json::Value,
) -> Option<(HeaderName, HeaderValue)> {
    let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
    if matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-connection"
    ) {
        return None;
    }
    let value = HeaderValue::from_str(value.as_str()?.trim()).ok()?;
    Some((name, value))
}

pub(super) fn validate_notification_channel_config(
    channel_type: &str,
    cfg: &serde_json::Value,
) -> Result<(), String> {
    let Some(obj) = cfg.as_object() else {
        return Err("Channel config must be a JSON object".to_string());
    };
    for field in WEBHOOK_HEADER_FIELDS {
        if let Some(value) = obj.get(field) {
            let headers = value
                .as_object()
                .ok_or("Custom webhook headers must be an object")?;
            if headers
                .iter()
                .any(|(name, value)| parse_custom_webhook_header(name, value).is_none())
            {
                return Err("Custom webhook header is invalid or forbidden".into());
            }
        }
    }
    let url_str = obj
        .get("url")
        .or_else(|| obj.get("webhook_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    match channel_type {
        "telegram" => {
            let bot_token = obj
                .get("bot_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let chat_id = obj
                .get("chat_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if bot_token.is_empty() || chat_id.is_empty() {
                return Err("Telegram channel requires non-empty bot_token and chat_id".to_string());
            }
            if bot_token.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b'/' || b == b'?') {
                return Err("Invalid Telegram bot_token format".to_string());
            }
            Ok(())
        }
        "discord" | "slack" | "gotify" | "webhook" | "custom" | "email" => {
            if url_str.is_empty() {
                return Err(format!(
                    "{channel_type} channel requires a non-empty webhook url"
                ));
            }
            parse_webhook_url(url_str).map_err(|e| e.to_string())?;
            Ok(())
        }
        _ => Err(
            "Invalid channel type. Allowed: discord, slack, gotify, webhook, email, telegram, custom"
                .to_string(),
        ),
    }
}

pub async fn create_notification_channel(Json(req): Json<CreateChannelReq>) -> Response {
    if req.name.trim().is_empty() || req.channel_type.trim().is_empty() || req.config.is_null() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name, type, and config are required",
        );
    }

    let valid_types = [
        "discord", "slack", "gotify", "webhook", "email", "telegram", "custom",
    ];
    if !valid_types.contains(&req.channel_type.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid channel type. Allowed: discord, slack, gotify, webhook, email, telegram, custom",
        );
    }

    let parsed_cfg: serde_json::Value = match &req.config {
        serde_json::Value::String(s) => match serde_json::from_str(s) {
            Ok(v) => v,
            Err(_) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Channel config must be valid JSON",
                );
            }
        },
        other => other.clone(),
    };

    if let Err(msg) = validate_notification_channel_config(&req.channel_type, &parsed_cfg) {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", &msg);
    }

    let (encrypted_cfg, _) =
        match af_db::encrypt_notification_channel_config_value(&req.channel_type, &parsed_cfg) {
            Ok(res) => res,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CRYPTO_ERROR",
                    "Failed to encrypt notification channel credentials",
                );
            }
        };
    let config_str = serde_json::to_string(&encrypted_cfg).unwrap_or_else(|_| "{}".to_string());

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create channel",
        );
    };

    if conn
        .execute(
            "INSERT INTO notification_channels (name, type, config, enabled) VALUES (?1, ?2, ?3, ?4)",
            params![req.name.trim(), req.channel_type, config_str, req.enabled],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create channel",
        );
    }

    let id = conn.last_insert_rowid();
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Channel created",
            "id": id,
        })),
    )
        .into_response()
}

pub async fn test_notification_channel(Path(id): Path<i64>) -> Response {
    let conn = match af_db::get_read_conn() {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(channel_id = id, %error, "Database unavailable while loading notification channel");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to load notification channel",
            );
        }
    };

    let channel_opt = match conn
        .query_row(
            "SELECT id, name, type, config, enabled, COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_channels WHERE id = ?1",
            params![id],
            |r| {
                Ok(StoredChannel {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    channel_type: r.get(2)?,
                    config: r.get(3)?,
                    enabled: r.get(4)?,
                    created_at: r.get(5)?,
                })
            },
        )
        .optional()
    {
        Ok(channel) => channel,
        Err(error) => {
            tracing::warn!(channel_id = id, %error, "Failed to query notification channel");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to load notification channel",
            );
        }
    };
    drop(conn);

    let Some(channel) = channel_opt else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Channel not found");
    };

    let test_title = "AetherFlow Test Notification";
    let test_msg = format!(
        "This is a test notification from AetherFlow at {}",
        Utc::now().to_rfc3339()
    );

    match dispatch_to_channel(&channel, "info", test_title, &test_msg, None).await {
        Ok(()) => Json(serde_json::json!({
            "message": "Test notification sent"
        }))
        .into_response(),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Failed to send test notification: {}", err),
        ),
    }
}

pub async fn delete_notification_channel(Path(id): Path<i64>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete channel",
        );
    };

    if conn
        .execute(
            "DELETE FROM notification_channels WHERE id = ?1",
            params![id],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete channel",
        );
    }

    Json(serde_json::json!({ "message": "Channel deleted" })).into_response()
}
