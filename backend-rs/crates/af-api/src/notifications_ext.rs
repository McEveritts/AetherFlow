use crate::auth::{api_error, generate_recovery_codes, store_recovery_codes, AuthUser};
use crate::ws::{broadcast_ws_message, extract_client_ip};
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use futures::stream::{self, StreamExt};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Request & Response Payloads
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RegenerateRecoveryReq {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateRuleReq {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub condition_type: String,
    #[serde(default)]
    pub condition_value: String,
    #[serde(default = "default_rule_level")]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateRuleReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub condition_type: Option<String>,
    #[serde(default)]
    pub condition_value: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CreateChannelReq {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub channel_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChannel {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub config: String,
    pub enabled: bool,
    pub created_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. 2FA Recovery Code Regeneration (`POST /user/2fa/recovery/regenerate`)
// ─────────────────────────────────────────────────────────────────────────────

fn replace_recovery_hashes(
    conn: &rusqlite::Connection,
    user_id: i64,
    encrypted_secret: &str,
    password_hash: &str,
    code: &str,
    recovery: Option<crate::auth::RecoveryCodeMatch>,
    hashes: &[String],
) -> anyhow::Result<bool> {
    let secret = af_db::decrypt_key(encrypted_secret)?;
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let current: (String, bool, String) = transaction.query_row(
        "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![user_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !current.1 || current.0 != encrypted_secret || current.2 != password_hash {
        return Ok(false);
    }
    if !crate::auth::consume_totp_code(&transaction, user_id, &secret, code)
        && !crate::auth::consume_recovery_code(&transaction, user_id, recovery.as_ref())
    {
        return Ok(false);
    }
    store_recovery_codes(&transaction, user_id, hashes)?;
    transaction.commit()?;
    Ok(true)
}

#[cfg(test)]
fn replace_verified_recovery_codes(
    conn: &rusqlite::Connection,
    user_id: i64,
    encrypted_secret: &str,
    password_hash: &str,
    code: &str,
    password_ok: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    if !password_ok || code.trim().is_empty() {
        return Ok(None);
    }
    let recovery = crate::auth::match_recovery_in_connection(conn, user_id, code);
    let codes = generate_recovery_codes();
    let hashes = crate::auth::hash_recovery_codes(&codes)?;
    Ok(replace_recovery_hashes(
        conn,
        user_id,
        encrypted_secret,
        password_hash,
        code,
        recovery,
        &hashes,
    )?
    .then_some(codes))
}

pub async fn regenerate_2fa_recovery_codes(
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<RegenerateRecoveryReq>,
) -> Response {
    if req.code.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "A valid TOTP or recovery code is required",
        );
    }

    crate::auth::blocking_response(move || {
        let Ok(conn) = af_db::get_read_conn() else {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Database unavailable");
        };
        let row = conn.query_row(
            "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
            params![user.user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?, row.get::<_, String>(2)?)),
        );
        drop(conn);
        let Ok((encrypted_secret, totp_enabled, password_hash)) = row else {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to query user");
        };
        if !totp_enabled {
            return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Two-factor authentication is not enabled");
        }
        let password_ok = password_hash.is_empty()
            || (!req.password.is_empty()
                && crate::auth::verify_password(&req.password, &password_hash));
        let result = (|| -> anyhow::Result<Option<Vec<String>>> {
            if !password_ok {
                return Ok(None);
            }
            let recovery = crate::auth::validate_recovery_code(user.user_id, &req.code);
            if recovery.is_none()
                && !crate::auth::has_matching_totp_code(&af_db::decrypt_key(&encrypted_secret)?, &req.code)
            {
                return Ok(None);
            }
            let codes = generate_recovery_codes();
            let hashes = crate::auth::hash_recovery_codes(&codes)?;
            let conn = af_db::get_conn()?;
            Ok(replace_recovery_hashes(
                &conn, user.user_id, &encrypted_secret, &password_hash, &req.code, recovery, &hashes,
            )?.then_some(codes))
        })();
        let codes = match result {
            Ok(Some(codes)) => codes,
            Ok(None) => {
                let err_code = if !password_ok {
                    "INVALID_CURRENT_PASSWORD"
                } else {
                    "INVALID_2FA_CODE"
                };
                return api_error(StatusCode::FORBIDDEN, err_code, "Invalid verification code or password");
            }
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to regenerate recovery codes"),
        };
        let ip = extract_client_ip(&headers);
        let ua = headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).unwrap_or("");
        af_db::record_audit(user.user_id, &user.username, "2fa_recovery_regenerate", "user", "", "", &ip, ua);
        Json(serde_json::json!({
            "message": "Recovery codes regenerated",
            "recovery_codes": codes,
        })).into_response()
    }).await
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Action Approval Gate Lookup (`GET /actions/:id`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_pending_action(Path(id): Path<i64>) -> Response {
    match af_db::get_pending_action_by_id(id) {
        Ok(Some(action)) => {
            let reconciled = crate::routes::reconcile_pending_action(action).await;
            Json(reconciled).into_response()
        }
        Ok(None) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Action not found"),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_ERROR",
            "Could not load action",
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3–5. Notification Rules CRUD (`/notifications/rules`)
// ─────────────────────────────────────────────────────────────────────────────

fn default_rule_level() -> String {
    "warning".into()
}

fn normalize_rule_level(level: &str) -> Result<String, &'static str> {
    let level = level.trim().to_ascii_lowercase();
    match level.as_str() {
        "info" | "warning" | "critical" => Ok(level),
        _ => Err("Invalid level. Allowed levels are info, warning, and critical"),
    }
}

fn percentage_threshold(value: &str) -> Result<f64, &'static str> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|threshold| (0.0..=100.0).contains(threshold))
        .ok_or("condition_value must be a finite percentage between 0 and 100")
}

fn validate_rule_condition(condition_type: &str, value: &str) -> Result<(), &'static str> {
    match condition_type {
        "disk_usage" | "cpu_usage" | "memory_usage" => percentage_threshold(value).map(|_| ()),
        // This condition identifies a service by name.
        "service_down" if !value.is_empty() && value.len() <= 128 => Ok(()),
        "service_down" => Err("condition_value must identify a service"),
        _ => Err("Invalid condition_type. Allowed types are disk_usage, cpu_usage, memory_usage, and service_down"),
    }
}

fn rule_validation_error(message: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}

pub async fn create_notification_rule(Json(req): Json<CreateRuleReq>) -> Response {
    if req.name.trim().is_empty() || req.name.trim().len() > 128 {
        return rule_validation_error("Rule name must be between 1 and 128 characters");
    }
    let condition_type = req.condition_type.trim();
    let value = req.condition_value.trim();
    if let Err(message) = validate_rule_condition(condition_type, value) {
        return rule_validation_error(message);
    }
    let level = match normalize_rule_level(&req.level) {
        Ok(level) => level,
        Err(message) => return rule_validation_error(message),
    };

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create rule",
        );
    };

    if conn
        .execute(
            "INSERT INTO notification_rules (name, condition_type, condition_value, level) VALUES (?1, ?2, ?3, ?4)",
            params![req.name.trim(), condition_type, value, level],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create rule",
        );
    }

    let id = conn.last_insert_rowid();
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Rule created",
            "id": id,
        })),
    )
        .into_response()
}

pub async fn update_notification_rule(
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleReq>,
) -> Response {
    let mut set_clauses: Vec<String> = Vec::new();
    let mut bind_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref name) = req.name {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Rule name must be between 1 and 128 characters",
            );
        }
        bind_params.push(Box::new(trimmed.to_string()));
        set_clauses.push(format!("name = ?{}", bind_params.len()));
    }
    if let Some(ref condition_type) = req.condition_type {
        bind_params.push(Box::new(condition_type.trim().to_string()));
        set_clauses.push(format!("condition_type = ?{}", bind_params.len()));
    }
    if let Some(ref value) = req.condition_value {
        bind_params.push(Box::new(value.trim().to_string()));
        set_clauses.push(format!("condition_value = ?{}", bind_params.len()));
    }
    if let Some(ref level) = req.level {
        let level = match normalize_rule_level(level) {
            Ok(level) => level,
            Err(message) => return rule_validation_error(message),
        };
        bind_params.push(Box::new(level));
        set_clauses.push(format!("level = ?{}", bind_params.len()));
    }
    if let Some(enabled) = req.enabled {
        bind_params.push(Box::new(enabled));
        set_clauses.push(format!("enabled = ?{}", bind_params.len()));
    }

    if set_clauses.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "No fields to update",
        );
    }

    let Ok(mut conn) = af_db::get_conn() else {
        return rule_update_failed();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return rule_update_failed();
    };
    if req.condition_type.is_some() || req.condition_value.is_some() {
        let current = tx.query_row(
            "SELECT condition_type, condition_value FROM notification_rules WHERE id = ?1",
            [id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );
        let (current_type, current_value) = match current {
            Ok(condition) => condition,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found");
            }
            Err(_) => return rule_update_failed(),
        };
        let condition_type = req
            .condition_type
            .as_deref()
            .unwrap_or(&current_type)
            .trim();
        let value = req
            .condition_value
            .as_deref()
            .unwrap_or(&current_value)
            .trim();
        if let Err(message) = validate_rule_condition(condition_type, value) {
            return rule_validation_error(message);
        }
    }

    bind_params.push(Box::new(id));
    let query = format!(
        "UPDATE notification_rules SET {} WHERE id = ?{}",
        set_clauses.join(", "),
        bind_params.len()
    );

    let param_refs: Vec<&dyn rusqlite::ToSql> = bind_params.iter().map(|b| b.as_ref()).collect();
    match tx.execute(&query, param_refs.as_slice()) {
        Ok(0) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found"),
        Ok(_) if tx.commit().is_ok() => {
            Json(serde_json::json!({ "message": "Rule updated" })).into_response()
        }
        _ => rule_update_failed(),
    }
}

fn rule_update_failed() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Failed to update rule",
    )
}

pub async fn delete_notification_rule(Path(id): Path<i64>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        );
    };

    match conn.execute("DELETE FROM notification_rules WHERE id = ?1", params![id]) {
        Ok(0) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found"),
        Ok(_) => Json(serde_json::json!({ "message": "Rule deleted" })).into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6–8. Notification Channels CRUD & Test (`/notifications/channels`)
// ─────────────────────────────────────────────────────────────────────────────

const WEBHOOK_HEADER_FIELDS: [&str; 2] = ["headers", "custom_headers"];

fn parse_custom_webhook_header(
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

fn validate_notification_channel_config(
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
    let channel_opt = af_db::get_read_conn().ok().and_then(|conn| {
        conn.query_row(
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
        .ok()
        .flatten()
    });

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

// ─────────────────────────────────────────────────────────────────────────────
// 9. Background Notification Rule Engine & Durable Channel Dispatcher
// ─────────────────────────────────────────────────────────────────────────────

fn is_public_webhook_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let [first, second, third, fourth] = address.octets();
            !(first == 0
                || first == 10
                || first == 127
                || first >= 224
                || (first == 100 && (64..=127).contains(&second))
                || (first == 169 && second == 254)
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192
                    && (second == 168
                        || (second == 0 && (third == 0 || third == 2))
                        || (second == 88 && third == 99)))
                || (first == 198
                    && (second == 18 || second == 19 || (second == 51 && third == 100)))
                || (first == 203 && second == 0 && third == 113)
                || [first, second, third, fourth] == [168, 63, 129, 16])
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

fn allow_private_webhooks() -> bool {
    std::env::var("AETHERFLOW_ALLOW_PRIVATE_WEBHOOKS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn is_blocked_always_webhook_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => {
            let [first, second, third, fourth] = v4.octets();
            first == 0
                || first == 127
                || (first == 169 && second == 254)
                || [first, second, third, fourth] == [168, 63, 129, 16]
                || v4.is_multicast()
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_always_webhook_ip(std::net::IpAddr::V4(mapped));
            }
            let segments = v6.segments();
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || segments[0] == 0x2002
        }
    }
}

fn is_allowed_webhook_ip_with(address: std::net::IpAddr, allow_private: bool) -> bool {
    if is_public_webhook_ip(address) {
        return true;
    }
    if !allow_private || is_blocked_always_webhook_ip(address) {
        return false;
    }
    match address {
        std::net::IpAddr::V4(v4) => {
            let [first, second, _, _] = v4.octets();
            first == 10
                || (first == 100 && (64..=127).contains(&second))
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 168)
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_allowed_webhook_ip_with(std::net::IpAddr::V4(mapped), allow_private);
            }
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
fn is_allowed_webhook_ip(address: std::net::IpAddr) -> bool {
    is_allowed_webhook_ip_with(address, allow_private_webhooks())
}

fn parse_webhook_url_with(target: &str, allow_private: bool) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(target)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "Webhook must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Webhook credentials in URL are not allowed"
    );
    anyhow::ensure!(
        url.host().is_some() && url.port_or_known_default().is_some(),
        "Invalid webhook host or port"
    );
    match url.host() {
        Some(url::Host::Ipv4(address)) => anyhow::ensure!(
            is_allowed_webhook_ip_with(address.into(), allow_private),
            "Webhook target must be public"
        ),
        Some(url::Host::Ipv6(address)) => anyhow::ensure!(
            is_allowed_webhook_ip_with(address.into(), allow_private),
            "Webhook target must be public"
        ),
        _ => {}
    }
    Ok(url)
}

fn parse_webhook_url(target: &str) -> anyhow::Result<url::Url> {
    parse_webhook_url_with(target, allow_private_webhooks())
}

const RULE_COOLDOWN_SECS: i64 = 15 * 60;
const MAX_DELIVERY_ATTEMPTS: i32 = 3;
const DELIVERY_CLAIM_LEASE_SECS: i64 = 60;
const MAX_DELIVERIES_PER_TICK: usize = 16;
const MAX_CONCURRENT_DELIVERIES: usize = 4;
const MAX_DIAGNOSTIC_ERROR_LEN: usize = 256;

const AMBIGUOUS_RECLAIM_NOTE: &str = "Previous delivery claim expired before receipt committed; retrying (upstream may have accepted prior attempt)";
const AMBIGUOUS_DELIVERED_NOTE: &str =
    "Delivered after reclaiming expired claim; upstream may have received prior attempt";
const AMBIGUOUS_UNCERTAIN_NOTE: &str = "Delivery claim expired before receipt committed; upstream outcome uncertain (may have been delivered)";

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChannelDispatchError {
    Permanent {
        message: String,
        attempted_network: bool,
    },
    Transient {
        message: String,
        attempted_network: bool,
    },
}

impl ChannelDispatchError {
    fn permanent(message: impl Into<String>, attempted_network: bool) -> Self {
        Self::Permanent {
            message: sanitize_diagnostic_error(&message.into()),
            attempted_network,
        }
    }

    fn transient(message: impl Into<String>, attempted_network: bool) -> Self {
        Self::Transient {
            message: sanitize_diagnostic_error(&message.into()),
            attempted_network,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Permanent { message, .. } | Self::Transient { message, .. } => message,
        }
    }

    fn attempted_network(&self) -> bool {
        match self {
            Self::Permanent {
                attempted_network, ..
            }
            | Self::Transient {
                attempted_network, ..
            } => *attempted_network,
        }
    }

    fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}

fn sanitize_diagnostic_error(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len().min(MAX_DIAGNOSTIC_ERROR_LEN));
    let mut rest = raw;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        let next_http = lower.find("http://");
        let next_https = lower.find("https://");
        let next_url = match (next_http, next_https) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(pos) = next_url {
            cleaned.push_str(&rest[..pos]);
            cleaned.push_str("[redacted-url]");
            let after = &rest[pos..];
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '>'))
                .unwrap_or(after.len());
            rest = &after[end..];
        } else {
            cleaned.push_str(rest);
            break;
        }
    }
    let collapsed: String = cleaned
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = collapsed.trim();
    let mut out = String::new();
    for ch in trimmed.chars() {
        if out.len() + ch.len_utf8() > MAX_DIAGNOSTIC_ERROR_LEN {
            break;
        }
        out.push(ch);
    }
    out
}

fn classify_reqwest_error(err: &reqwest::Error) -> ChannelDispatchError {
    if err.is_redirect() {
        return ChannelDispatchError::permanent("webhook redirect rejected", true);
    }
    if err.is_builder() {
        return ChannelDispatchError::permanent("webhook request construction failed", false);
    }
    if err.is_timeout() {
        return ChannelDispatchError::transient("webhook request timed out", true);
    }
    if err.is_connect() {
        return ChannelDispatchError::transient("webhook connection failed", true);
    }
    if err.is_body() || err.is_decode() {
        return ChannelDispatchError::transient("webhook response error", true);
    }
    ChannelDispatchError::transient("webhook transport error", true)
}

fn delivery_retry_backoff_secs(completed_attempts: i32) -> i64 {
    match completed_attempts {
        ..=1 => 30,
        2 => 120,
        _ => 300,
    }
}

async fn webhook_client_classified(
    target: &str,
) -> Result<(reqwest::Client, url::Url), ChannelDispatchError> {
    let allow_private = allow_private_webhooks();
    let url = parse_webhook_url_with(target, allow_private).map_err(|_| {
        ChannelDispatchError::permanent("Webhook target rejected by URL policy", false)
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        ChannelDispatchError::permanent("Webhook target rejected by URL policy", false)
    })?;
    let (host, addresses) = match url.host().ok_or_else(|| {
        ChannelDispatchError::permanent("Webhook target rejected by URL policy", false)
    })? {
        url::Host::Domain(host) => {
            let lookup = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host, port)),
            )
            .await
            .map_err(|_| {
                ChannelDispatchError::transient("Webhook DNS resolution timed out", false)
            })?
            .map_err(|_| ChannelDispatchError::transient("Webhook DNS resolution failed", false))?;
            let addresses: Vec<std::net::SocketAddr> = lookup.collect();
            (host.to_owned(), addresses)
        }
        url::Host::Ipv4(address) => (
            address.to_string(),
            vec![std::net::SocketAddr::new(address.into(), port)],
        ),
        url::Host::Ipv6(address) => (
            address.to_string(),
            vec![std::net::SocketAddr::new(address.into(), port)],
        ),
    };
    if addresses.is_empty() {
        return Err(ChannelDispatchError::transient(
            "Webhook DNS resolution returned no addresses",
            false,
        ));
    }
    if !addresses
        .iter()
        .all(|address| is_allowed_webhook_ip_with(address.ip(), allow_private))
    {
        return Err(ChannelDispatchError::permanent(
            "Webhook target rejected by address policy",
            false,
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(&host, &addresses)
        .build()
        .map_err(|_| {
            ChannelDispatchError::permanent("Webhook client initialization failed", false)
        })?;
    Ok((client, url))
}

#[cfg(test)]
async fn webhook_client(target: &str) -> anyhow::Result<(reqwest::Client, url::Url)> {
    webhook_client_classified(target)
        .await
        .map_err(|err| anyhow::anyhow!(err.message().to_string()))
}

#[derive(Debug, Clone)]
struct PreparedChannelRequest {
    target_url: String,
    payload: serde_json::Value,
    headers: Vec<(HeaderName, HeaderValue)>,
}

fn prepare_channel_request(
    channel: &StoredChannel,
    level: &str,
    title: &str,
    message: &str,
) -> Result<PreparedChannelRequest, ChannelDispatchError> {
    let cfg: serde_json::Value =
        af_db::decrypt_notification_channel_config_str(&channel.channel_type, &channel.config)
            .map_err(|_| {
                ChannelDispatchError::permanent("invalid or undecryptable channel config", false)
            })?;

    let url_str = cfg
        .get("url")
        .or_else(|| cfg.get("webhook_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let color: u32 = match level {
        "critical" | "error" => 0xEF4444,
        "warning" => 0xF59E0B,
        "success" => 0x10B981,
        _ => 0x3B82F6,
    };

    let (target_url, payload) = match channel.channel_type.as_str() {
        "discord" => {
            if url_str.is_empty() {
                return Err(ChannelDispatchError::permanent(
                    "missing Discord webhook url",
                    false,
                ));
            }
            let body = serde_json::json!({
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color,
                    "timestamp": Utc::now().to_rfc3339(),
                    "footer": { "text": format!("AetherFlow • {}", level.to_uppercase()) }
                }]
            });
            (url_str, body)
        }
        "slack" => {
            if url_str.is_empty() {
                return Err(ChannelDispatchError::permanent(
                    "missing Slack webhook url",
                    false,
                ));
            }
            let body = serde_json::json!({
                "text": format!("*[{}]* *{}*\n{}", level.to_uppercase(), title, message)
            });
            (url_str, body)
        }
        "gotify" => {
            if url_str.is_empty() {
                return Err(ChannelDispatchError::permanent("missing Gotify url", false));
            }
            let token = cfg
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let full_url = if !token.is_empty() && !url_str.contains("token=") {
                format!("{}/message?token={}", url_str.trim_end_matches('/'), token)
            } else {
                url_str
            };
            let body = serde_json::json!({
                "title": title,
                "message": message,
                "priority": 5
            });
            (full_url, body)
        }
        "telegram" => {
            let bot_token = cfg
                .get("bot_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let chat_id = cfg
                .get("chat_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if bot_token.is_empty() || chat_id.is_empty() {
                return Err(ChannelDispatchError::permanent(
                    "missing Telegram bot_token or chat_id",
                    false,
                ));
            }
            if bot_token
                .bytes()
                .any(|b| b <= 0x20 || b >= 0x7f || b == b'/' || b == b'?')
            {
                return Err(ChannelDispatchError::permanent(
                    "invalid Telegram bot_token format",
                    false,
                ));
            }
            let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
            let body = serde_json::json!({
                "chat_id": chat_id,
                "text": format!("[{}] {}\n{}", level.to_uppercase(), title, message)
            });
            (tg_url, body)
        }
        "webhook" | "custom" => {
            if url_str.is_empty() {
                return Err(ChannelDispatchError::permanent(
                    "missing webhook url",
                    false,
                ));
            }
            let body = serde_json::json!({
                "level": level,
                "title": title,
                "message": message,
                "timestamp": Utc::now().to_rfc3339()
            });
            (url_str, body)
        }
        "email" => {
            if url_str.is_empty() {
                return Err(ChannelDispatchError::permanent(
                    "missing email webhook url",
                    false,
                ));
            }
            let body = serde_json::json!({
                "level": level,
                "title": title,
                "message": message,
                "timestamp": Utc::now().to_rfc3339()
            });
            (url_str, body)
        }
        other => {
            return Err(ChannelDispatchError::permanent(
                format!("unknown channel type: {}", other),
                false,
            ));
        }
    };

    let mut headers = Vec::new();
    for field in WEBHOOK_HEADER_FIELDS {
        if let Some(map) = cfg.get(field).and_then(|value| value.as_object()) {
            for (name, value) in map {
                if let Some((header_name, header_value)) = parse_custom_webhook_header(name, value)
                {
                    headers.push((header_name, header_value));
                }
            }
        }
    }

    Ok(PreparedChannelRequest {
        target_url,
        payload,
        headers,
    })
}

async fn send_prepared_channel_request(
    request: &PreparedChannelRequest,
) -> Result<(), ChannelDispatchError> {
    let (client, target) = webhook_client_classified(&request.target_url).await?;
    let mut post_req = client.post(target).json(&request.payload);
    for (name, value) in &request.headers {
        post_req = post_req.header(name, value);
    }
    match post_req.send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            let err_msg = format!("webhook returned HTTP {}", status.as_u16());
            if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() {
                Err(ChannelDispatchError::transient(err_msg, true))
            } else {
                Err(ChannelDispatchError::permanent(err_msg, true))
            }
        }
        Err(err) => Err(classify_reqwest_error(&err)),
    }
}

fn record_delivery_log(
    channel_id: i64,
    channel_type: &str,
    notification_id: Option<i64>,
    status: &str,
    attempts: i32,
    last_error: &str,
) {
    if let Ok(conn) = af_db::get_conn() {
        let now = Utc::now();
        let now_epoch = now.timestamp();
        let completed_at = if matches!(status, "delivered" | "failed" | "uncertain") {
            now.to_rfc3339()
        } else {
            String::new()
        };
        let sanitized = sanitize_diagnostic_error(last_error);
        let _ = conn.execute(
            "INSERT INTO notification_delivery_log (
                channel_id, channel_type, notification_id, status, attempts,
                last_error, completed_at, next_attempt_at, claim_token, lease_until, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, '', NULL, ?8)",
            params![
                channel_id,
                channel_type,
                notification_id,
                status,
                attempts,
                sanitized,
                completed_at,
                now_epoch
            ],
        );
    }
}

pub async fn dispatch_to_channel(
    channel: &StoredChannel,
    level: &str,
    title: &str,
    message: &str,
    notification_id: Option<i64>,
) -> anyhow::Result<()> {
    let prepared = match prepare_channel_request(channel, level, title, message) {
        Ok(req) => req,
        Err(err) => {
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                0,
                err.message(),
            );
            anyhow::bail!("{}", err.message());
        }
    };

    match send_prepared_channel_request(&prepared).await {
        Ok(()) => {
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "delivered",
                1,
                "",
            );
            Ok(())
        }
        Err(err) => {
            let attempts = if err.attempted_network() { 1 } else { 0 };
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                attempts,
                err.message(),
            );
            anyhow::bail!("{}", err.message())
        }
    }
}

pub(crate) fn channel_delivery_overview_in_conn(
    conn: &rusqlite::Connection,
    channel_id: i64,
) -> (i64, Option<serde_json::Value>) {
    let pending: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notification_delivery_log \
             WHERE channel_id = ?1 AND notification_id IS NOT NULL AND status IN ('pending', 'sending')",
            params![channel_id],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let last = conn
        .query_row(
            "SELECT id, notification_id, status, COALESCE(attempts, 0), \
                    COALESCE(last_error, ''), COALESCE(CAST(created_at AS TEXT), ''), \
                    COALESCE(CAST(completed_at AS TEXT), '') \
             FROM notification_delivery_log \
             WHERE channel_id = ?1 \
             ORDER BY id DESC LIMIT 1",
            params![channel_id],
            |r| {
                let last_error: String = r.get(4)?;
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "notification_id": r.get::<_, Option<i64>>(1)?,
                    "status": r.get::<_, String>(2)?,
                    "attempts": r.get::<_, i32>(3)?,
                    "last_error": sanitize_diagnostic_error(&last_error),
                    "created_at": r.get::<_, String>(5)?,
                    "completed_at": r.get::<_, String>(6)?,
                }))
            },
        )
        .optional()
        .ok()
        .flatten();

    (pending, last)
}

#[derive(Debug, Clone)]
struct RuleWithCooldown {
    rule: af_services::NotificationRule,
    last_triggered_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct CommittedRuleTrigger {
    notification: af_services::Notification,
    queued_deliveries: usize,
}

#[derive(Debug, Clone)]
struct ClaimedDelivery {
    id: i64,
    channel_id: i64,
    channel_type: String,
    notification_id: i64,
    attempts: i32,
    claim_token: String,
    reclaimed_expired_lease: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeliveryReceiptCommit {
    Committed(&'static str),
    StaleClaim,
}

fn is_rule_on_cooldown(last_triggered_at: Option<i64>, now_epoch: i64, cooldown_secs: i64) -> bool {
    last_triggered_at.is_some_and(|last| {
        last > now_epoch.saturating_sub(cooldown_secs)
            && last <= now_epoch.saturating_add(cooldown_secs)
    })
}

fn commit_rule_trigger_in_conn(
    conn: &rusqlite::Connection,
    rule: &af_services::NotificationRule,
    message: &str,
    now_epoch: i64,
    cooldown_secs: i64,
) -> anyhow::Result<Option<CommittedRuleTrigger>> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let min_eligible = now_epoch.saturating_sub(cooldown_secs);
    let max_clock_skew = now_epoch.saturating_add(cooldown_secs);
    let claimed_rule = tx.execute(
        "UPDATE notification_rules
         SET last_triggered_at = ?1
         WHERE id = ?2
           AND COALESCE(enabled, 1) != 0
           AND (
               last_triggered_at IS NULL
               OR last_triggered_at <= ?3
               OR last_triggered_at > ?4
           )",
        params![now_epoch, rule.id, min_eligible, max_clock_skew],
    )?;
    if claimed_rule == 0 {
        tx.commit()?;
        return Ok(None);
    }

    tx.execute(
        "INSERT INTO notifications (user_id, level, title, message) VALUES (NULL, ?1, ?2, ?3)",
        params![rule.level, rule.name, message],
    )?;
    let notif_id = tx.last_insert_rowid();
    anyhow::ensure!(notif_id > 0, "failed to allocate local notification id");
    let created_at: String = tx
        .query_row(
            "SELECT COALESCE(CAST(created_at AS TEXT), '') FROM notifications WHERE id = ?1",
            params![notif_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| Utc::now().to_rfc3339());

    let queued_deliveries = tx.execute(
        "INSERT INTO notification_delivery_log (
            channel_id,
            channel_type,
            notification_id,
            status,
            attempts,
            last_error,
            completed_at,
            next_attempt_at,
            claim_token,
            lease_until,
            updated_at
         )
         SELECT
            id,
            type,
            ?1,
            'pending',
            0,
            '',
            '',
            ?2,
            '',
            NULL,
            ?2
         FROM notification_channels
         WHERE COALESCE(enabled, 1) != 0
         ORDER BY id ASC",
        params![notif_id, now_epoch],
    )?;

    tx.commit()?;

    Ok(Some(CommittedRuleTrigger {
        notification: af_services::Notification {
            id: notif_id,
            user_id: None,
            level: rule.level.clone(),
            title: rule.name.clone(),
            message: message.to_string(),
            read: false,
            created_at,
        },
        queued_deliveries,
    }))
}

fn claim_due_deliveries_in_conn(
    conn: &rusqlite::Connection,
    now_epoch: i64,
    now_rfc3339: &str,
    max_batch: usize,
) -> anyhow::Result<Vec<ClaimedDelivery>> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;

    // Account for the ambiguous interval on the final attempt: if a worker crashed after
    // sending (and possibly after upstream accepted) before committing its receipt, never
    // retry past MAX_DELIVERY_ATTEMPTS; surface an operator-visible `uncertain` outcome.
    let finalized_uncertain = tx.execute(
        "UPDATE notification_delivery_log
         SET status = 'uncertain',
             claim_token = '',
             lease_until = NULL,
             completed_at = ?1,
             updated_at = ?2,
             last_error = ?3
         WHERE notification_id IS NOT NULL
           AND status = 'sending'
           AND lease_until IS NOT NULL
           AND lease_until <= ?2
           AND COALESCE(attempts, 0) >= ?4",
        params![
            now_rfc3339,
            now_epoch,
            AMBIGUOUS_UNCERTAIN_NOTE,
            MAX_DELIVERY_ATTEMPTS
        ],
    )?;
    if finalized_uncertain > 0 {
        tracing::warn!(
            count = finalized_uncertain,
            "Marked exhausted expired notification delivery claims as uncertain"
        );
    }

    let candidates: Vec<(i64, i64, String, i64, i32, String)> = {
        let mut stmt = tx.prepare(
            "SELECT id, channel_id, channel_type, notification_id, COALESCE(attempts, 0), status
             FROM notification_delivery_log
             WHERE notification_id IS NOT NULL
               AND COALESCE(attempts, 0) < ?1
               AND (
                   (status = 'pending' AND COALESCE(next_attempt_at, 0) <= ?2)
                   OR (status = 'sending' AND lease_until IS NOT NULL AND lease_until <= ?2)
               )
             ORDER BY id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![MAX_DELIVERY_ATTEMPTS, now_epoch, max_batch as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let lease_until = now_epoch.saturating_add(DELIVERY_CLAIM_LEASE_SECS);
    let mut claimed = Vec::with_capacity(candidates.len());
    for (id, channel_id, channel_type, notification_id, prev_attempts, prev_status) in candidates {
        let claim_token = uuid::Uuid::new_v4().to_string();
        let updated = tx.execute(
            "UPDATE notification_delivery_log
             SET status = 'sending',
                 attempts = COALESCE(attempts, 0) + 1,
                 claim_token = ?1,
                 lease_until = ?2,
                 updated_at = ?3,
                 last_error = CASE
                     WHEN status = 'sending' THEN ?4
                     ELSE COALESCE(last_error, '')
                 END
             WHERE id = ?5
               AND COALESCE(attempts, 0) < ?6
               AND (
                   (status = 'pending' AND COALESCE(next_attempt_at, 0) <= ?3)
                   OR (status = 'sending' AND lease_until IS NOT NULL AND lease_until <= ?3)
               )",
            params![
                claim_token,
                lease_until,
                now_epoch,
                AMBIGUOUS_RECLAIM_NOTE,
                id,
                MAX_DELIVERY_ATTEMPTS
            ],
        )?;
        if updated == 1 {
            claimed.push(ClaimedDelivery {
                id,
                channel_id,
                channel_type,
                notification_id,
                attempts: prev_attempts + 1,
                claim_token,
                reclaimed_expired_lease: prev_status == "sending",
            });
        }
    }

    tx.commit()?;
    Ok(claimed)
}

fn load_delivery_context_in_conn(
    conn: &rusqlite::Connection,
    claimed: &ClaimedDelivery,
) -> Result<(StoredChannel, PreparedChannelRequest), ChannelDispatchError> {
    let notif: Option<(String, String, String)> = conn
        .query_row(
            "SELECT n.level, n.title, n.message
             FROM notification_delivery_log d JOIN notifications n ON n.id = d.notification_id
             WHERE d.id = ?1 AND d.status = 'sending' AND d.claim_token = ?2",
            params![claimed.id, claimed.claim_token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| {
            ChannelDispatchError::transient("Failed to load notification record", false)
        })?;
    let Some((level, title, message)) = notif else {
        return Err(ChannelDispatchError::permanent(
            "Notification record missing or delivery claim superseded",
            false,
        ));
    };

    let channel_opt: Option<StoredChannel> = conn
        .query_row(
            "SELECT id, name, type, config, COALESCE(enabled, 1) != 0, COALESCE(CAST(created_at AS TEXT), '')
             FROM notification_channels WHERE id = ?1",
            params![claimed.channel_id],
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
        .map_err(|_| ChannelDispatchError::transient("Failed to load notification channel", false))?;
    let Some(channel) = channel_opt else {
        return Err(ChannelDispatchError::permanent(
            "Channel deleted before delivery",
            false,
        ));
    };
    if !channel.enabled {
        return Err(ChannelDispatchError::permanent(
            "Channel disabled before delivery",
            false,
        ));
    }

    let prepared = prepare_channel_request(&channel, &level, &title, &message)?;
    Ok((channel, prepared))
}

fn complete_claimed_delivery_in_conn(
    conn: &rusqlite::Connection,
    claimed: &ClaimedDelivery,
    outcome: &Result<(), ChannelDispatchError>,
    finish_epoch: i64,
    finish_rfc3339: &str,
) -> anyhow::Result<DeliveryReceiptCommit> {
    let (next_status, next_attempt_at, completed_at, last_error): (
        &'static str,
        i64,
        &str,
        String,
    ) = match outcome {
        Ok(()) => {
            let note = if claimed.reclaimed_expired_lease {
                AMBIGUOUS_DELIVERED_NOTE.to_string()
            } else {
                String::new()
            };
            ("delivered", 0, finish_rfc3339, note)
        }
        Err(err) if err.is_transient() && claimed.attempts < MAX_DELIVERY_ATTEMPTS => {
            let backoff = delivery_retry_backoff_secs(claimed.attempts);
            (
                "pending",
                finish_epoch.saturating_add(backoff),
                "",
                sanitize_diagnostic_error(err.message()),
            )
        }
        Err(err) => (
            "failed",
            0,
            finish_rfc3339,
            sanitize_diagnostic_error(err.message()),
        ),
    };

    let updated = conn.execute(
        "UPDATE notification_delivery_log
         SET status = ?1,
             claim_token = '',
             lease_until = NULL,
             next_attempt_at = ?2,
             completed_at = ?3,
             updated_at = ?4,
             last_error = ?5
         WHERE id = ?6
           AND status = 'sending'
           AND claim_token = ?7",
        params![
            next_status,
            next_attempt_at,
            completed_at,
            finish_epoch,
            last_error,
            claimed.id,
            claimed.claim_token
        ],
    )?;

    if updated == 0 {
        return Ok(DeliveryReceiptCommit::StaleClaim);
    }
    Ok(DeliveryReceiptCommit::Committed(next_status))
}

fn broadcast_triggered_notification(notification: &af_services::Notification) {
    let val = serde_json::to_value(notification).unwrap_or_default();
    let ws_msg = serde_json::json!({
        "type": "NOTIFICATION",
        "data": val,
    });
    broadcast_ws_message(&ws_msg);
}

async fn drain_due_deliveries_once() {
    let now = Utc::now();
    // All claims in the batch expire together. Reserve one second for the whole-second
    // SQLite lease so later tasks cannot send beyond their claim.
    let dispatch_deadline =
        tokio::time::Instant::now() + Duration::from_secs((DELIVERY_CLAIM_LEASE_SECS - 1) as u64);
    let now_epoch = now.timestamp();
    let now_rfc3339 = now.to_rfc3339();
    let claimed =
        match tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<ClaimedDelivery>> {
            let conn = af_db::get_conn()?;
            claim_due_deliveries_in_conn(&conn, now_epoch, &now_rfc3339, MAX_DELIVERIES_PER_TICK)
        })
        .await
        {
            Ok(Ok(items)) => items,
            Ok(Err(error)) => {
                tracing::warn!(%error, "Failed to claim due notification deliveries");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "Notification delivery claim task panicked");
                return;
            }
        };

    if claimed.is_empty() {
        return;
    }

    stream::iter(claimed)
        .for_each_concurrent(MAX_CONCURRENT_DELIVERIES, |item| async move {
            let item_for_load = item.clone();
            let context_res = tokio::task::spawn_blocking(move || {
                let conn = af_db::get_read_conn().map_err(|_| {
                    ChannelDispatchError::transient(
                        "Database unavailable for channel lookup",
                        false,
                    )
                })?;
                load_delivery_context_in_conn(&conn, &item_for_load)
            })
            .await
            .unwrap_or_else(|_| {
                Err(ChannelDispatchError::transient(
                    "Channel lookup task failed",
                    false,
                ))
            });

            if tokio::time::Instant::now() >= dispatch_deadline {
                return;
            }
            let send_outcome = match context_res {
                Ok((_channel, prepared)) => match tokio::time::timeout_at(
                    dispatch_deadline,
                    send_prepared_channel_request(&prepared),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        tracing::warn!(
                            delivery_id = item.id,
                            "Notification claim expired before a delivery receipt"
                        );
                        return;
                    }
                },
                Err(err) => Err(err),
            };

            let finish = Utc::now();
            let finish_epoch = finish.timestamp();
            let finish_rfc3339 = finish.to_rfc3339();
            let item_for_commit = item.clone();
            let outcome_for_commit = send_outcome.clone();
            let commit_res =
                tokio::task::spawn_blocking(move || -> anyhow::Result<DeliveryReceiptCommit> {
                    let conn = af_db::get_conn()?;
                    complete_claimed_delivery_in_conn(
                        &conn,
                        &item_for_commit,
                        &outcome_for_commit,
                        finish_epoch,
                        &finish_rfc3339,
                    )
                })
                .await;

            match commit_res {
                Ok(Ok(DeliveryReceiptCommit::Committed(status))) => {
                    if status != "delivered" {
                        tracing::warn!(
                            delivery_id = item.id,
                            channel_id = item.channel_id,
                            channel_type = %item.channel_type,
                            notification_id = item.notification_id,
                            attempts = item.attempts,
                            status,
                            "Notification channel delivery did not complete cleanly"
                        );
                    }
                }
                Ok(Ok(DeliveryReceiptCommit::StaleClaim)) => {
                    tracing::warn!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        "Skipped stale notification delivery receipt commit after claim lease loss"
                    );
                }
                Ok(Err(error)) => {
                    // Explicit ambiguous-interval handling: if upstream already accepted the
                    // send, do NOT revert the row to pending; leave the fenced `sending` lease
                    // to reconcile under the bounded attempt/uncertain policy.
                    tracing::error!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        upstream_accepted = send_outcome.is_ok(),
                        %error,
                        "Failed to persist notification delivery receipt"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        delivery_id = item.id,
                        channel_id = item.channel_id,
                        notification_id = item.notification_id,
                        attempts = item.attempts,
                        upstream_accepted = send_outcome.is_ok(),
                        %error,
                        "Notification delivery receipt task failed"
                    );
                }
            }
        })
        .await;
}

async fn evaluate_active_rules_once() {
    let now_epoch = Utc::now().timestamp();
    let rules = match tokio::task::spawn_blocking(move || -> Vec<RuleWithCooldown> {
        let Ok(conn) = af_db::get_read_conn() else {
            return Vec::new();
        };

        let mut rules_vec = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, condition_type, condition_value, COALESCE(level, 'warning'), \
                    COALESCE(enabled, 1) != 0, COALESCE(CAST(created_at AS TEXT), ''), last_triggered_at \
             FROM notification_rules WHERE COALESCE(enabled, 1) != 0",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(RuleWithCooldown {
                    rule: af_services::NotificationRule {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        condition_type: r.get(2)?,
                        condition_value: r.get(3)?,
                        level: r.get(4)?,
                        enabled: r.get(5)?,
                        created_at: r.get(6)?,
                    },
                    last_triggered_at: r.get(7)?,
                })
            }) {
                for rule in rows.flatten() {
                    if !is_rule_on_cooldown(rule.last_triggered_at, now_epoch, RULE_COOLDOWN_SECS) {
                        rules_vec.push(rule);
                    }
                }
            }
        }
        rules_vec
    })
    .await
    {
        Ok(rules) => rules,
        Err(_) => return,
    };

    if rules.is_empty() {
        return;
    }

    let metrics = af_hardware::get_system_metrics_core();
    let needs_services = rules
        .iter()
        .any(|entry| entry.rule.condition_type == "service_down");
    let active_services = if needs_services {
        tokio::task::spawn_blocking(af_services::get_active_services)
            .await
            .map_err(anyhow::Error::from)
            .and_then(|services| services)
            .inspect_err(|error| {
                tracing::warn!(%error, "Skipping service-down rules while service state is unknown");
            })
            .ok()
    } else {
        None
    };

    for entry in rules {
        let rule = entry.rule;
        let mut triggered = false;
        let mut message = String::new();

        match rule.condition_type.as_str() {
            "disk_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                for disk in &metrics.disks {
                    if disk.used_pct >= threshold {
                        triggered = true;
                        message = format!(
                            "Disk {} is at {:.1}% usage",
                            disk.mount_point, disk.used_pct
                        );
                        break;
                    }
                }
            }
            "cpu_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                if metrics.cpu_usage >= threshold {
                    triggered = true;
                    message = format!("CPU usage is at {:.1}%", metrics.cpu_usage);
                }
            }
            "memory_usage" => {
                let Ok(threshold) = percentage_threshold(&rule.condition_value) else {
                    continue;
                };
                if let Some(&total) = metrics.memory.get("total") {
                    if total > 0.0 {
                        let used = metrics.memory.get("used").copied().unwrap_or(0.0);
                        let pct = (used / total) * 100.0;
                        if pct >= threshold {
                            triggered = true;
                            message = format!("Memory usage is at {:.1}%", pct);
                        }
                    }
                }
            }
            "service_down" => {
                let target_svc = rule.condition_value.trim();
                if !target_svc.is_empty()
                    && service_down_confirmed(active_services.as_ref(), target_svc)
                {
                    triggered = true;
                    message = format!("Service {} is down", target_svc);
                }
            }
            _ => {}
        }

        if triggered {
            let trigger_epoch = Utc::now().timestamp();
            let rule_for_commit = rule.clone();
            let msg_for_commit = message.clone();
            let commit_res = tokio::task::spawn_blocking(move || {
                let conn = af_db::get_conn()?;
                commit_rule_trigger_in_conn(
                    &conn,
                    &rule_for_commit,
                    &msg_for_commit,
                    trigger_epoch,
                    RULE_COOLDOWN_SECS,
                )
            })
            .await;

            match commit_res {
                Ok(Ok(Some(committed))) => {
                    tracing::debug!(
                        rule_id = rule.id,
                        notification_id = committed.notification.id,
                        queued_deliveries = committed.queued_deliveries,
                        "Committed triggered notification rule and delivery intents"
                    );
                    broadcast_triggered_notification(&committed.notification);
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        rule_id = rule.id,
                        %error,
                        "Failed to admit triggered notification rule; rolled back without cooldown"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        rule_id = rule.id,
                        %error,
                        "Notification admission task failed"
                    );
                }
            }
        }
    }
}

pub fn start_notification_engine() {
    tokio::spawn(async move {
        // Resume committed unsent channel deliveries immediately on startup without
        // prematurely firing rules before system telemetry settles.
        drain_due_deliveries_once().await;

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip immediate tick 0 so rule evaluation waits for startup to settle.
        interval.tick().await;
        loop {
            interval.tick().await;
            evaluate_active_rules_once().await;
            drain_due_deliveries_once().await;
        }
    });
}

fn service_down_confirmed(
    services: Option<&std::collections::HashMap<String, af_services::ServiceStatusItem>>,
    target: &str,
) -> bool {
    services.is_some_and(|services| {
        !services.iter().any(|(label, item)| {
            (label.eq_ignore_ascii_case(target) || item.process.eq_ignore_ascii_case(target))
                && item.status == "running"
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notification_rule_create_and_partial_update_validate_the_resulting_rule() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();

        for value in ["85%", "> 90", "NaN", "inf", "-1", "101"] {
            let response = create_notification_rule(Json(CreateRuleReq {
                name: "Test".into(),
                condition_type: "disk_usage".into(),
                condition_value: value.into(),
                level: "warning".into(),
            }))
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value}");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert!(std::str::from_utf8(&body)
                .unwrap()
                .contains("VALIDATION_ERROR"));
        }
        let response = create_notification_rule(Json(CreateRuleReq {
            name: "Test".into(),
            condition_type: "service_down".into(),
            condition_value: "netdata".into(),
            level: " CrItIcAl ".into(),
        }))
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let conn = af_db::get_read_conn().unwrap();
        let (id, level): (i64, String) = conn
            .query_row(
                "SELECT id, level FROM notification_rules WHERE name = 'Test'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(level, "critical");
        drop(conn);

        let response = update_notification_rule(
            Path(id),
            Json(UpdateRuleReq {
                condition_type: Some("memory_usage".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = update_notification_rule(
            Path(id),
            Json(UpdateRuleReq {
                condition_type: Some("memory_usage".into()),
                condition_value: Some("100".into()),
                level: Some("INFO".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = update_notification_rule(
            Path(id),
            Json(UpdateRuleReq {
                level: Some("error".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn forbidden_webhook_headers_are_rejected_and_cannot_be_parsed_for_dispatch() {
        for name in [
            "Host",
            "Content-LENGTH",
            "Transfer-Encoding",
            "Connection",
            "Keep-Alive",
            "Upgrade",
            "TE",
            "Trailer",
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "Proxy-Connection",
        ] {
            let value = serde_json::json!("invalid override");
            assert!(
                parse_custom_webhook_header(name, &value).is_none(),
                "{name}"
            );
            for field in WEBHOOK_HEADER_FIELDS {
                let config = serde_json::json!({
                    "url": "https://example.test/hook",
                    (field): {(name): value},
                });
                assert!(
                    validate_notification_channel_config("webhook", &config).is_err(),
                    "{field}.{name}"
                );
            }
        }
        let config = serde_json::json!({
            "url": "https://example.test/hook",
            "headers": {"Authorization": "Bearer test", "X-Event": "alarm"}
        });
        assert!(validate_notification_channel_config("webhook", &config).is_ok());
        assert!(parse_custom_webhook_header("X-Event", &serde_json::json!("alert")).is_some());
    }

    #[test]
    fn service_down_rule_skips_unknown_then_resumes_on_known_state() {
        assert!(!service_down_confirmed(None, "Fixture"));
        let mut services = std::collections::HashMap::new();
        services.insert(
            "Fixture".to_string(),
            af_services::ServiceStatusItem {
                process: "fixture".into(),
                status: "running".into(),
                ..Default::default()
            },
        );
        assert!(!service_down_confirmed(Some(&services), "fixture"));
        services.get_mut("Fixture").unwrap().status = "stopped".into();
        assert!(service_down_confirmed(Some(&services), "fixture"));
        assert!(!service_down_confirmed(None, "fixture"));
        services.get_mut("Fixture").unwrap().status = "running".into();
        assert!(!service_down_confirmed(Some(&services), "FIXTURE"));
    }

    fn recovery_database() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY,totp_secret TEXT,totp_enabled INTEGER,password_hash TEXT,last_totp_step INTEGER DEFAULT -1);
            INSERT INTO users VALUES (1,'JBSWY3DPEHPK3PXP',1,'test-hash',-1);
            CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY,user_id INTEGER,code_hash TEXT,used INTEGER DEFAULT 0);
            INSERT INTO recovery_codes VALUES (1,1,'old-hash',0);").unwrap();
        conn
    }

    fn recovery_totp() -> String {
        let key = data_encoding::BASE32_NOPAD
            .decode(b"JBSWY3DPEHPK3PXP")
            .unwrap();
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &key, Utc::now().timestamp() as u64)
    }

    #[test]
    fn recovery_regeneration_consumes_totp_and_rejects_replay_or_changed_credentials() {
        let conn = recovery_database();
        let code = recovery_totp();
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "test-hash",
            "",
            true
        )
        .unwrap()
        .is_none());
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "test-hash",
            &code,
            true
        )
        .unwrap()
        .is_some());
        let hashes: Vec<String> = conn
            .prepare("SELECT code_hash FROM recovery_codes ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "test-hash",
            &code,
            true
        )
        .unwrap()
        .is_none());
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "stale-password-hash",
            &code,
            true
        )
        .unwrap()
        .is_none());
        let unchanged: Vec<String> = conn
            .prepare("SELECT code_hash FROM recovery_codes ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(hashes, unchanged);
    }

    #[test]
    fn recovery_storage_failure_rolls_back_totp_consumption_and_existing_codes() {
        let conn = recovery_database();
        let code = recovery_totp();
        conn.execute_batch("CREATE TRIGGER reject_recovery BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT,'simulated failure'); END;").unwrap();
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "test-hash",
            &code,
            true
        )
        .is_err());
        let old: String = conn
            .query_row("SELECT code_hash FROM recovery_codes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(old, "old-hash");
        let step: i64 = conn
            .query_row("SELECT last_totp_step FROM users WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(step, -1);
        conn.execute_batch("DROP TRIGGER reject_recovery;").unwrap();
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "test-hash",
            &code,
            true
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn webhook_rejects_nonpublic_and_embedded_addresses() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "168.63.129.16",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::7f00:1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!is_public_webhook_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_webhook_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[tokio::test]
    async fn webhook_dns_rejects_localhost_before_dispatch() {
        assert!(webhook_client("http://localhost/hook").await.is_err());
    }

    #[test]
    fn webhook_url_validation_blocks_alternate_literal_encodings() {
        for target in [
            "file:///etc/passwd",
            "ftp://example.com",
            "http://127.0.0.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "https://user:password@example.com/",
        ] {
            assert!(parse_webhook_url(target).is_err(), "{target}");
        }
        assert!(parse_webhook_url("https://example.com/hook").is_ok());
        assert!(parse_webhook_url("https://8.8.8.8/hook").is_ok());
    }

    #[test]
    fn channel_config_validation_blocks_ssrf_and_empty_email_relay() {
        assert!(validate_notification_channel_config(
            "discord",
            &serde_json::json!({"url": "http://169.254.169.254/latest/meta-data/"})
        )
        .is_err());
        assert!(validate_notification_channel_config("email", &serde_json::json!({})).is_err());
        assert!(validate_notification_channel_config(
            "discord",
            &serde_json::json!({"url": "https://8.8.8.8/webhook"})
        )
        .is_ok());
    }

    #[test]
    fn webhook_private_flag_allows_tailscale_cgnat_and_rfc1918_while_blocking_loopback_and_metadata(
    ) {
        for private_target in [
            "http://100.64.0.1:8080/hook",
            "https://100.100.100.100/hook",
            "http://192.168.1.50/hook",
            "http://10.1.2.3/hook",
            "http://172.16.5.5/hook",
            "http://[fd00::1]/hook",
        ] {
            assert!(
                parse_webhook_url_with(private_target, false).is_err(),
                "must reject {private_target} when private webhooks are disabled"
            );
            assert!(
                parse_webhook_url_with(private_target, true).is_ok(),
                "must allow {private_target} when private webhooks are enabled"
            );
        }

        for always_blocked in [
            "http://127.0.0.1/hook",
            "http://[::1]/hook",
            "http://0.0.0.0/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://168.63.129.16/machine",
            "http://[::ffff:127.0.0.1]/hook",
            "http://[::ffff:169.254.169.254]/hook",
        ] {
            assert!(
                parse_webhook_url_with(always_blocked, true).is_err(),
                "must ALWAYS block {always_blocked}"
            );
        }
        assert!(is_allowed_webhook_ip("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn regenerate_2fa_rejects_empty_password_on_password_backed_user() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        crate::plugins::tests::ensure_shared_test_db();
        let pw_hash = bcrypt::hash("correct-password", 4).unwrap();
        let enc_secret = af_db::encrypt_key("JBSWY3DPEHPK3PXP").unwrap();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute_batch(
                "DELETE FROM recovery_codes WHERE user_id IN (9101, 9102);
                 DELETE FROM users WHERE id IN (9101, 9102);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (id, username, role, password_hash, totp_secret, totp_enabled, last_totp_step)
                 VALUES (9101, 'totp-pw-user', 'user', ?1, ?2, 1, -1)",
                params![pw_hash, enc_secret],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (id, username, role, password_hash, totp_secret, totp_enabled, last_totp_step)
                 VALUES (9102, 'totp-oauth-user', 'user', '', ?1, 1, -1)",
                params![enc_secret],
            )
            .unwrap();
        }

        let pw_user = AuthUser {
            user_id: 9101,
            username: "totp-pw-user".into(),
            role: "user".into(),
            jti: "jti-9101".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let code = recovery_totp();

        // Empty password must fail with 403 INVALID_CURRENT_PASSWORD and NOT consume the TOTP code
        let empty_pw_resp = regenerate_2fa_recovery_codes(
            Extension(pw_user.clone()),
            HeaderMap::new(),
            Json(RegenerateRecoveryReq {
                code: code.clone(),
                password: String::new(),
            }),
        )
        .await;
        assert_eq!(empty_pw_resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(empty_pw_resp.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "INVALID_CURRENT_PASSWORD");

        // Valid password + same unconsumed TOTP code succeeds
        let ok_resp = regenerate_2fa_recovery_codes(
            Extension(pw_user),
            HeaderMap::new(),
            Json(RegenerateRecoveryReq {
                code: code.clone(),
                password: "correct-password".into(),
            }),
        )
        .await;
        assert_eq!(ok_resp.status(), StatusCode::OK);

        // OAuth-only user with empty password_hash can regenerate without a password
        let oauth_user = AuthUser {
            user_id: 9102,
            username: "totp-oauth-user".into(),
            role: "user".into(),
            jti: "jti-9102".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let oauth_resp = regenerate_2fa_recovery_codes(
            Extension(oauth_user),
            HeaderMap::new(),
            Json(RegenerateRecoveryReq {
                code,
                password: String::new(),
            }),
        )
        .await;
        assert_eq!(oauth_resp.status(), StatusCode::OK);
    }

    fn init_notification_test_schema(conn: &rusqlite::Connection) {
        conn.execute_batch(
            r#"CREATE TABLE notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                level TEXT NOT NULL DEFAULT 'info',
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                read BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE notification_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                condition_type TEXT NOT NULL,
                condition_value TEXT NOT NULL,
                level TEXT DEFAULT 'warning',
                enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE notification_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                config TEXT NOT NULL,
                enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE notification_delivery_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                channel_type TEXT NOT NULL,
                notification_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME
            );"#,
        )
        .unwrap();
        af_db::ensure_notification_schema_invariants(conn).unwrap();
    }

    fn durable_notification_test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_notification_test_schema(&conn);
        conn
    }

    fn drain_with_fake_sender<F>(
        conn: &rusqlite::Connection,
        now_epoch: i64,
        mut sender: F,
    ) -> Vec<(ClaimedDelivery, anyhow::Result<DeliveryReceiptCommit>)>
    where
        F: FnMut(&StoredChannel, &PreparedChannelRequest) -> Result<(), ChannelDispatchError>,
    {
        let now_rfc3339 = format!("2026-11-21T00:00:{}Z", now_epoch % 60);
        let claimed =
            claim_due_deliveries_in_conn(conn, now_epoch, &now_rfc3339, MAX_DELIVERIES_PER_TICK)
                .unwrap();
        let mut results = Vec::with_capacity(claimed.len());
        for item in claimed {
            let outcome = match load_delivery_context_in_conn(conn, &item) {
                Ok((channel, prepared)) => sender(&channel, &prepared),
                Err(err) => Err(err),
            };
            let commit =
                complete_claimed_delivery_in_conn(conn, &item, &outcome, now_epoch, &now_rfc3339);
            results.push((item, commit));
        }
        results
    }

    #[test]
    fn durable_rule_admission_failure_rolls_back_cooldown_notification_and_intents() {
        let conn = durable_notification_test_db();
        conn.execute(
            "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
             VALUES (1, 'High Disk', 'disk_usage', '90', 'critical', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notification_channels (id, name, type, config, enabled)
             VALUES (10, 'Ops Hook', 'webhook', '{\"url\":\"https://example.test/hook\",\"headers\":{\"Authorization\":\"Bearer top-secret-token\"}}', 1),
                    (11, 'Disabled Hook', 'webhook', '{\"url\":\"https://example.test/off\"}', 0)",
            [],
        )
        .unwrap();

        let rule = af_services::NotificationRule {
            id: 1,
            name: "High Disk".into(),
            condition_type: "disk_usage".into(),
            condition_value: "90".into(),
            level: "critical".into(),
            enabled: true,
            created_at: String::new(),
        };

        // Failure while inserting channel delivery intents must roll back cooldown and notification.
        conn.execute_batch(
            "CREATE TRIGGER fail_delivery_intent BEFORE INSERT ON notification_delivery_log
             BEGIN SELECT RAISE(ABORT, 'simulated delivery queue write failure'); END;",
        )
        .unwrap();
        assert!(commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "Disk / is at 95.0% usage",
            10_000,
            RULE_COOLDOWN_SECS
        )
        .is_err());
        let last_triggered: Option<i64> = conn
            .query_row(
                "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_triggered, None);
        let notif_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(notif_count, 0);
        let delivery_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notification_delivery_log", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(delivery_count, 0);

        conn.execute_batch("DROP TRIGGER fail_delivery_intent;")
            .unwrap();

        // Failure while inserting the local notification must also roll back cooldown.
        conn.execute_batch(
            "CREATE TRIGGER fail_local_notification BEFORE INSERT ON notifications
             BEGIN SELECT RAISE(ABORT, 'simulated notification write failure'); END;",
        )
        .unwrap();
        assert!(commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "Disk / is at 95.0% usage",
            10_000,
            RULE_COOLDOWN_SECS
        )
        .is_err());
        let last_triggered: Option<i64> = conn
            .query_row(
                "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_triggered, None);
        conn.execute_batch("DROP TRIGGER fail_local_notification;")
            .unwrap();

        // Once storage recovers, admission commits cooldown, broadcast notification, and enabled-only intents together.
        let committed = commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "Disk / is at 95.0% usage",
            10_000,
            RULE_COOLDOWN_SECS,
        )
        .unwrap()
        .expect("rule must commit after admission failure clears");
        assert_eq!(committed.notification.user_id, None);
        assert_eq!(committed.queued_deliveries, 1);

        let last_triggered: Option<i64> = conn
            .query_row(
                "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_triggered, Some(10_000));

        let queued_rows: Vec<(i64, String, i32, String)> = conn
            .prepare(
                "SELECT channel_id, status, attempts, COALESCE(last_error, '')
                 FROM notification_delivery_log",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            queued_rows,
            vec![(10, "pending".to_string(), 0, String::new())]
        );
    }

    #[test]
    fn restart_recovery_resumes_unsent_deliveries_enforces_durable_cooldown_and_sanitizes_diagnostics(
    ) {
        let conn = durable_notification_test_db();
        let (enc_hook, _) = af_db::encrypt_notification_channel_config_value(
            "webhook",
            &serde_json::json!({
                "url": "https://example.test/alerts?token=hook-secret-123",
                "headers": {
                    "Authorization": "Bearer super-secret-bearer",
                    "X-Event": "disk-alarm"
                }
            }),
        )
        .unwrap();
        let (enc_tg, _) = af_db::encrypt_notification_channel_config_value(
            "telegram",
            &serde_json::json!({
                "bot_token": "123456:TELEGRAM_SECRET_TOKEN",
                "chat_id": "998877"
            }),
        )
        .unwrap();

        conn.execute(
            "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
             VALUES (1, 'CPU High', 'cpu_usage', '90', 'warning', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notification_channels (id, name, type, config, enabled)
             VALUES (20, 'Primary Hook', 'webhook', ?1, 1),
                    (21, 'Ops Telegram', 'telegram', ?2, 1)",
            params![enc_hook.to_string(), enc_tg.to_string()],
        )
        .unwrap();

        let rule = af_services::NotificationRule {
            id: 1,
            name: "CPU High".into(),
            condition_type: "cpu_usage".into(),
            condition_value: "90".into(),
            level: "warning".into(),
            enabled: true,
            created_at: String::new(),
        };

        // First trigger commits cooldown + local alert + 2 pending delivery intents, then process "restarts" before sending.
        let committed = commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "CPU usage is at 94.0%",
            10_000,
            RULE_COOLDOWN_SECS,
        )
        .unwrap()
        .expect("initial trigger must commit");
        assert_eq!(committed.queued_deliveries, 2);

        // After restart, re-evaluating within cooldown (T+30s) must NOT repeat the alert.
        assert!(commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "CPU usage is at 95.0%",
            10_030,
            RULE_COOLDOWN_SECS,
        )
        .unwrap()
        .is_none());
        let notif_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(notif_count, 1);

        // Disable Telegram channel before restart drain completes to verify current channel policy is honored.
        conn.execute(
            "UPDATE notification_channels SET enabled = 0 WHERE id = 21",
            [],
        )
        .unwrap();

        // Startup drain at T+5: webhook gets transient 503 with credential-free diagnostic, disabled Telegram fails immediately without network call.
        let mut seen_channels = Vec::new();
        let first_pass = drain_with_fake_sender(&conn, 10_005, |ch, req| {
            seen_channels.push((ch.id, req.target_url.clone(), req.headers.clone()));
            Err(ChannelDispatchError::transient(
                "webhook returned HTTP 503 from https://example.test/alerts?token=hook-secret-123",
                true,
            ))
        });
        assert_eq!(first_pass.len(), 2);
        assert_eq!(seen_channels.len(), 1, "disabled channel must not be sent");
        assert_eq!(seen_channels[0].0, 20);
        assert_eq!(
            seen_channels[0].1,
            "https://example.test/alerts?token=hook-secret-123"
        );
        assert!(
            seen_channels[0].2.iter().any(|(k, v)| {
                k.as_str() == "authorization"
                    && v.to_str().ok() == Some("Bearer super-secret-bearer")
            }),
            "decrypted custom headers must be passed to sender"
        );
        assert!(
            seen_channels[0]
                .2
                .iter()
                .any(|(k, v)| { k.as_str() == "x-event" && v.to_str().ok() == Some("disk-alarm") }),
            "accepted webhook headers must be preserved"
        );

        // Verify diagnostics redact URLs/tokens and never leak credentials.
        let (pending_20, last_20) = channel_delivery_overview_in_conn(&conn, 20);
        assert_eq!(pending_20, 1);
        let last_20 = last_20.unwrap();
        assert_eq!(last_20["status"], "pending");
        assert_eq!(last_20["attempts"], 1);
        let err_20 = last_20["last_error"].as_str().unwrap();
        assert!(!err_20.contains("hook-secret-123"));
        assert!(!err_20.contains("super-secret-bearer"));
        assert!(err_20.contains("503"));

        let (pending_21, last_21) = channel_delivery_overview_in_conn(&conn, 21);
        assert_eq!(pending_21, 0);
        let last_21 = last_21.unwrap();
        assert_eq!(last_21["status"], "failed");
        assert!(last_21["last_error"].as_str().unwrap().contains("disabled"));

        // Before backoff elapses (T+34s, next_attempt_at is 10_035), nothing is claimed.
        let early_pass = drain_with_fake_sender(&conn, 10_034, |_ch, _req| Ok(()));
        assert!(early_pass.is_empty());

        // Once backoff elapses (T+35s), attempt 2 succeeds.
        let retry_pass = drain_with_fake_sender(&conn, 10_035, |ch, _req| {
            assert_eq!(ch.id, 20);
            Ok(())
        });
        assert_eq!(retry_pass.len(), 1);
        assert_eq!(
            retry_pass[0].1.as_ref().unwrap(),
            &DeliveryReceiptCommit::Committed("delivered")
        );

        let (pending_after, last_after) = channel_delivery_overview_in_conn(&conn, 20);
        assert_eq!(pending_after, 0);
        let last_after = last_after.unwrap();
        assert_eq!(last_after["status"], "delivered");
        assert_eq!(last_after["attempts"], 2);

        // Once the 15-minute cooldown expires (T + 900s), the rule can fire again.
        let second_trigger = commit_rule_trigger_in_conn(
            &conn,
            &rule,
            "CPU usage is at 96.0%",
            10_000 + RULE_COOLDOWN_SECS,
            RULE_COOLDOWN_SECS,
        )
        .unwrap();
        assert!(second_trigger.is_some());

        // Sanitizer explicitly strips Telegram/Gotify URLs containing secrets.
        let sanitized = sanitize_diagnostic_error(
            "error sending request for url (https://api.telegram.org/bot123456:TELEGRAM_SECRET_TOKEN/sendMessage): timed out",
        );
        assert!(!sanitized.contains("TELEGRAM_SECRET_TOKEN"));
        assert!(sanitized.contains("[redacted-url]"));
    }

    #[test]
    fn competing_claims_respect_lease_fencing_and_handle_ambiguous_interval() {
        let tmp_dir =
            std::env::temp_dir().join(format!("af-notif-competing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db_path = tmp_dir.join("notifications.sqlite");
        let conn_a = rusqlite::Connection::open(&db_path).unwrap();
        conn_a.busy_timeout(Duration::from_secs(5)).unwrap();
        conn_a.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        init_notification_test_schema(&conn_a);

        let conn_b = rusqlite::Connection::open(&db_path).unwrap();
        conn_b.busy_timeout(Duration::from_secs(5)).unwrap();

        conn_a
            .execute(
                "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
                 VALUES (1, 'Service Down', 'service_down', 'netdata', 'critical', 1)",
                [],
            )
            .unwrap();
        conn_a
            .execute(
                "INSERT INTO notification_channels (id, name, type, config, enabled)
                 VALUES (30, 'Alert Hook', 'webhook', '{\"url\":\"https://example.test/alert\"}', 1)",
                [],
            )
            .unwrap();

        let rule = af_services::NotificationRule {
            id: 1,
            name: "Service Down".into(),
            condition_type: "service_down".into(),
            condition_value: "netdata".into(),
            level: "critical".into(),
            enabled: true,
            created_at: String::new(),
        };

        // Competing evaluators on two separate SQLite connections: only one admits the trigger.
        let first = commit_rule_trigger_in_conn(
            &conn_a,
            &rule,
            "Service netdata is down",
            20_000,
            RULE_COOLDOWN_SECS,
        )
        .unwrap();
        let second = commit_rule_trigger_in_conn(
            &conn_b,
            &rule,
            "Service netdata is down",
            20_000,
            RULE_COOLDOWN_SECS,
        )
        .unwrap();
        assert!(first.is_some());
        assert!(second.is_none());

        // Worker A (conn_a) claims the pending delivery (attempt 1, active lease until 20_060).
        let worker_a_claims = claim_due_deliveries_in_conn(
            &conn_a,
            20_000,
            "2026-11-21T00:00:00Z",
            MAX_DELIVERIES_PER_TICK,
        )
        .unwrap();
        assert_eq!(worker_a_claims.len(), 1);
        let claim_a = worker_a_claims[0].clone();
        assert_eq!(claim_a.attempts, 1);
        assert!(!claim_a.reclaimed_expired_lease);

        // Competing Worker B (conn_b) running while lease is active must NOT claim the same delivery.
        let worker_b_early = claim_due_deliveries_in_conn(
            &conn_b,
            20_030,
            "2026-11-21T00:00:30Z",
            MAX_DELIVERIES_PER_TICK,
        )
        .unwrap();
        assert!(worker_b_early.is_empty());

        // Simulate ambiguous crash/stall past lease expiry (T = 20_061): Worker B reclaims attempt 2.
        let worker_b_claims = claim_due_deliveries_in_conn(
            &conn_b,
            20_061,
            "2026-11-21T00:01:01Z",
            MAX_DELIVERIES_PER_TICK,
        )
        .unwrap();
        assert_eq!(worker_b_claims.len(), 1);
        let claim_b = worker_b_claims[0].clone();
        assert_eq!(claim_b.id, claim_a.id);
        assert_eq!(claim_b.attempts, 2);
        assert!(claim_b.reclaimed_expired_lease);
        assert_ne!(claim_b.claim_token, claim_a.claim_token);
        assert!(load_delivery_context_in_conn(&conn_a, &claim_a).is_err());
        assert!(load_delivery_context_in_conn(&conn_b, &claim_b).is_ok());

        // Late Worker A tries to commit its stale receipt -> must be fenced out!
        let stale_res = complete_claimed_delivery_in_conn(
            &conn_a,
            &claim_a,
            &Ok(()),
            20_062,
            "2026-11-21T00:01:02Z",
        )
        .unwrap();
        assert_eq!(stale_res, DeliveryReceiptCommit::StaleClaim);

        // Worker B finishes and commits cleanly with an operator-visible note about the reclaimed claim.
        let fresh_res = complete_claimed_delivery_in_conn(
            &conn_b,
            &claim_b,
            &Ok(()),
            20_063,
            "2026-11-21T00:01:03Z",
        )
        .unwrap();
        assert_eq!(fresh_res, DeliveryReceiptCommit::Committed("delivered"));
        let (status, attempts, last_error): (String, i32, String) = conn_a
            .query_row(
                "SELECT status, attempts, COALESCE(last_error, '') FROM notification_delivery_log WHERE id = ?1",
                params![claim_b.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "delivered");
        assert_eq!(attempts, 2);
        assert!(last_error.contains("reclaiming expired claim"));

        // Now test ambiguous interval on the FINAL attempt (attempts == MAX_DELIVERY_ATTEMPTS):
        // when the final sending claim's lease expires without receipt, recovery must NOT resend
        // a 4th time and must transition the row to terminal `uncertain`.
        conn_a
            .execute(
                "INSERT INTO notification_delivery_log (
                    id, channel_id, channel_type, notification_id, status, attempts,
                    last_error, completed_at, next_attempt_at, claim_token, lease_until, updated_at
                 ) VALUES (999, 30, 'webhook', 1, 'sending', ?1, '', '', 0, 'lost-final-token', 20100, 20040)",
                params![MAX_DELIVERY_ATTEMPTS],
            )
            .unwrap();

        let reclaimed_after_final = claim_due_deliveries_in_conn(
            &conn_b,
            20_101,
            "2026-11-21T00:01:41Z",
            MAX_DELIVERIES_PER_TICK,
        )
        .unwrap();
        assert!(
            reclaimed_after_final.is_empty(),
            "expired final attempt must not be resent past MAX_DELIVERY_ATTEMPTS"
        );
        let (final_status, final_attempts, final_completed, final_err): (String, i32, String, String) =
            conn_a
                .query_row(
                    "SELECT status, attempts, COALESCE(CAST(completed_at AS TEXT), ''), COALESCE(last_error, '')
                     FROM notification_delivery_log WHERE id = 999",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
        assert_eq!(final_status, "uncertain");
        assert_eq!(final_attempts, MAX_DELIVERY_ATTEMPTS);
        assert!(!final_completed.is_empty());
        assert!(final_err.contains("uncertain"));

        // Also verify receipt-commit failure right after upstream accepts leaves row in `sending`
        // (does NOT revert to `pending`) so it stays bounded by lease & attempt cap.
        conn_a
            .execute(
                "INSERT INTO notification_delivery_log (
                    id, channel_id, channel_type, notification_id, status, attempts,
                    last_error, completed_at, next_attempt_at, claim_token, lease_until, updated_at
                 ) VALUES (1000, 30, 'webhook', 1, 'pending', 0, '', '', 20200, '', NULL, 20200)",
                [],
            )
            .unwrap();
        let claim_c = claim_due_deliveries_in_conn(
            &conn_a,
            20_200,
            "2026-11-21T00:03:20Z",
            MAX_DELIVERIES_PER_TICK,
        )
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(claim_c.id, 1000);
        conn_a
            .execute_batch(
                "CREATE TRIGGER fail_receipt_commit BEFORE UPDATE ON notification_delivery_log
                 BEGIN SELECT RAISE(ABORT, 'simulated db outage after upstream accept'); END;",
            )
            .unwrap();
        assert!(complete_claimed_delivery_in_conn(
            &conn_a,
            &claim_c,
            &Ok(()),
            20_201,
            "2026-11-21T00:03:21Z",
        )
        .is_err());
        conn_a
            .execute_batch("DROP TRIGGER fail_receipt_commit;")
            .unwrap();
        let (post_fail_status, post_fail_attempts): (String, i32) = conn_b
            .query_row(
                "SELECT status, attempts FROM notification_delivery_log WHERE id = 1000",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(post_fail_status, "sending");
        assert_eq!(post_fail_attempts, 1);

        drop(conn_b);
        drop(conn_a);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
