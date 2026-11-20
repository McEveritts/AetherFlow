use crate::auth::{api_error, generate_recovery_codes, store_recovery_codes, AuthUser};
use crate::ws::{broadcast_ws_message, extract_client_ip};
use af_db::PendingAction;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

fn query_pending_action_by_id(id: i64) -> Option<PendingAction> {
    let conn = af_db::get_conn().ok()?;
    conn.query_row(
        "SELECT id, classification, source, action, COALESCE(reason, ''), status, \
         COALESCE(CAST(created_at AS TEXT), ''), CAST(resolved_at AS TEXT), resolved_by, execution_log \
         FROM pending_actions WHERE id = ?1",
        params![id],
        |r| {
            Ok(PendingAction {
                id: r.get(0)?,
                classification: r.get(1)?,
                source: r.get(2)?,
                action: r.get(3)?,
                reason: r.get(4)?,
                status: r.get(5)?,
                created_at: r.get(6)?,
                resolved_at: r.get(7)?,
                resolved_by: r.get(8)?,
                execution_log: r.get(9)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

pub async fn get_pending_action(Path(id): Path<i64>) -> Response {
    match query_pending_action_by_id(id) {
        Some(action) => Json(action).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Action not found"),
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
// 9. Background Notification Rule Engine & Channel Dispatcher
// ─────────────────────────────────────────────────────────────────────────────

static RULE_COOLDOWNS: Lazy<Mutex<HashMap<i64, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

async fn webhook_client(target: &str) -> anyhow::Result<(reqwest::Client, url::Url)> {
    let allow_private = allow_private_webhooks();
    let url = parse_webhook_url_with(target, allow_private)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Invalid webhook port"))?;
    let (host, addresses) = match url
        .host()
        .ok_or_else(|| anyhow::anyhow!("Missing webhook host"))?
    {
        url::Host::Domain(host) => {
            let addresses: Vec<std::net::SocketAddr> = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host, port)),
            )
            .await??
            .collect();
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
    anyhow::ensure!(
        !addresses.is_empty()
            && addresses
                .iter()
                .all(|address| is_allowed_webhook_ip_with(address.ip(), allow_private)),
        "Webhook DNS must resolve only to allowed addresses"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(&host, &addresses)
        .build()?;
    Ok((client, url))
}

const RULE_COOLDOWN_DURATION: Duration = Duration::from_secs(15 * 60);

fn record_delivery_log(
    channel_id: i64,
    channel_type: &str,
    notification_id: Option<i64>,
    status: &str,
    attempts: i32,
    last_error: &str,
) {
    if let Ok(conn) = af_db::get_conn() {
        let completed_at = if status == "delivered" || status == "failed" {
            Utc::now().to_rfc3339()
        } else {
            String::new()
        };
        let _ = conn.execute(
            "INSERT INTO notification_delivery_log (channel_id, channel_type, notification_id, status, attempts, last_error, completed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                channel_id,
                channel_type,
                notification_id,
                status,
                attempts,
                last_error,
                completed_at
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
    let cfg: serde_json::Value =
        af_db::decrypt_notification_channel_config_str(&channel.channel_type, &channel.config)
            .map_err(|e| {
                let msg = format!("invalid channel config: {}", e);
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    &msg,
                );
                anyhow::anyhow!(msg)
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
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing webhook url",
                );
                anyhow::bail!("missing Discord webhook url");
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
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing webhook url",
                );
                anyhow::bail!("missing Slack webhook url");
            }
            let body = serde_json::json!({
                "text": format!("*[{}]* *{}*\n{}", level.to_uppercase(), title, message)
            });
            (url_str, body)
        }
        "gotify" => {
            if url_str.is_empty() {
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing gotify url",
                );
                anyhow::bail!("missing Gotify url");
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
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing bot_token or chat_id",
                );
                anyhow::bail!("missing Telegram bot_token or chat_id");
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
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing webhook url",
                );
                anyhow::bail!("missing webhook url");
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
                record_delivery_log(
                    channel.id,
                    &channel.channel_type,
                    notification_id,
                    "failed",
                    0,
                    "missing email webhook url",
                );
                anyhow::bail!("missing email webhook url");
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
            let err_msg = format!("unknown channel type: {}", other);
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                0,
                &err_msg,
            );
            anyhow::bail!(err_msg);
        }
    };

    let (client, target) = match webhook_client(&target_url).await {
        Ok(target) => target,
        Err(_) => {
            let message = "Webhook target rejected or DNS resolution failed";
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                0,
                message,
            );
            anyhow::bail!(message);
        }
    };
    let mut post_req = client.post(target).json(&payload);
    for field in WEBHOOK_HEADER_FIELDS {
        if let Some(headers) = cfg.get(field).and_then(|value| value.as_object()) {
            for (name, value) in headers {
                if let Some((name, value)) = parse_custom_webhook_header(name, value) {
                    post_req = post_req.header(name, value);
                }
            }
        }
    }
    match post_req.send().await {
        Ok(resp) if resp.status().is_success() => {
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
        Ok(resp) => {
            let err_msg = format!("webhook returned HTTP {}", resp.status());
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                1,
                &err_msg,
            );
            anyhow::bail!(err_msg)
        }
        Err(e) => {
            let err_msg = e.to_string();
            record_delivery_log(
                channel.id,
                &channel.channel_type,
                notification_id,
                "failed",
                1,
                &err_msg,
            );
            anyhow::bail!(err_msg)
        }
    }
}

fn broadcast_triggered_notification(notification: &af_services::Notification) {
    let val = serde_json::to_value(notification).unwrap_or_default();
    let ws_msg = serde_json::json!({
        "type": "NOTIFICATION",
        "data": val,
    });
    broadcast_ws_message(&ws_msg);
}

async fn evaluate_active_rules_once() {
    let (rules, channels) = {
        let Ok(conn) = af_db::get_read_conn() else {
            return;
        };

        let mut rules_vec = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, condition_type, condition_value, COALESCE(level, 'warning'), enabled, COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_rules WHERE enabled = 1",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(af_services::NotificationRule {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    condition_type: r.get(2)?,
                    condition_value: r.get(3)?,
                    level: r.get(4)?,
                    enabled: r.get(5)?,
                    created_at: r.get(6)?,
                })
            }) {
                for rule in rows.flatten() {
                    rules_vec.push(rule);
                }
            }
        }

        let mut channels_vec = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, name, type, config, enabled, COALESCE(CAST(created_at AS TEXT), '') \
             FROM notification_channels WHERE enabled = 1",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok(StoredChannel {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    channel_type: r.get(2)?,
                    config: r.get(3)?,
                    enabled: r.get(4)?,
                    created_at: r.get(5)?,
                })
            }) {
                for ch in rows.flatten() {
                    channels_vec.push(ch);
                }
            }
        }

        (rules_vec, channels_vec)
    };

    if rules.is_empty() {
        return;
    }

    let metrics = af_hardware::get_system_metrics_core();
    let active_services = tokio::task::spawn_blocking(af_services::get_active_services)
        .await
        .map_err(anyhow::Error::from)
        .and_then(|services| services)
        .inspect_err(|error| {
            tracing::warn!(%error, "Skipping service-down rules while service state is unknown");
        });

    for rule in rules {
        // Check 15-minute per-rule cooldown
        let on_cooldown = RULE_COOLDOWNS
            .lock()
            .ok()
            .and_then(|map| map.get(&rule.id).copied())
            .map(|last_fired| last_fired.elapsed() < RULE_COOLDOWN_DURATION)
            .unwrap_or(false);
        if on_cooldown {
            continue;
        }

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
                    && service_down_confirmed(active_services.as_ref().ok(), target_svc)
                {
                    triggered = true;
                    message = format!("Service {} is down", target_svc);
                }
            }
            _ => {}
        }

        if triggered {
            if let Ok(mut map) = RULE_COOLDOWNS.lock() {
                map.insert(rule.id, Instant::now());
            }

            let created_at = Utc::now().to_rfc3339();
            let mut notif_id = 0i64;
            if let Ok(conn) = af_db::get_conn() {
                if conn
                    .execute(
                        "INSERT INTO notifications (user_id, level, title, message) VALUES (NULL, ?1, ?2, ?3)",
                        params![rule.level, rule.name, message],
                    )
                    .is_ok()
                {
                    notif_id = conn.last_insert_rowid();
                }
            }

            let notif = af_services::Notification {
                id: notif_id,
                user_id: None,
                level: rule.level.clone(),
                title: rule.name.clone(),
                message: message.clone(),
                read: false,
                created_at,
            };

            broadcast_triggered_notification(&notif);

            for ch in &channels {
                let ch_clone = ch.clone();
                let lvl = rule.level.clone();
                let ttl = rule.name.clone();
                let msg = message.clone();
                let nid = if notif_id > 0 { Some(notif_id) } else { None };
                tokio::spawn(async move {
                    let _ = dispatch_to_channel(&ch_clone, &lvl, &ttl, &msg, nid).await;
                });
            }
        }
    }
}

pub fn start_notification_engine() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // Skip immediate tick 0 so startup settles first
        interval.tick().await;
        loop {
            interval.tick().await;
            evaluate_active_rules_once().await;
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
}
