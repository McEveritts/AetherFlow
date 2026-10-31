use crate::auth::{api_error, AuthUser};
use crate::ws::{broadcast_ws_message, extract_client_ip};
use af_db::PendingAction;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    #[serde(default)]
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

fn verify_totp_code_local(secret_b32: &str, code: &str) -> bool {
    let clean = secret_b32.trim().to_uppercase();
    let Ok(secret_bytes) = BASE32_NOPAD.decode(clean.as_bytes()) else {
        return false;
    };
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for offset in [0i64, -30i64, 30i64] {
        let ts = (now_secs as i64 + offset).max(0) as u64;
        let expected = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, ts);
        if expected == code.trim() {
            return true;
        }
    }
    false
}

fn generate_8_recovery_codes() -> Vec<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut codes = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let chars: Vec<char> = raw
            .iter()
            .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
            .collect();
        let code = format!(
            "{}-{}",
            chars[0..4].iter().collect::<String>(),
            chars[4..8].iter().collect::<String>()
        );
        codes.push(code);
    }
    codes
}

pub async fn regenerate_2fa_recovery_codes(
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<RegenerateRecoveryReq>,
) -> Response {
    if req.code.trim().is_empty() && req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "A valid TOTP code is required",
        );
    }

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query user",
        );
    };

    let row = conn.query_row(
        "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![user.user_id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, String>(2)?,
            ))
        },
    );

    let Ok((encrypted_secret, totp_enabled, password_hash)) = row else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query user",
        );
    };

    if !totp_enabled {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Two-factor authentication is not enabled",
        );
    }

    let mut verified = false;
    if !req.code.trim().is_empty() {
        let secret = af_db::decrypt_key(&encrypted_secret).unwrap_or(encrypted_secret);
        if verify_totp_code_local(&secret, &req.code) {
            verified = true;
        }
    }
    if !verified && !req.password.is_empty() && !password_hash.is_empty() {
        if bcrypt::verify(&req.password, &password_hash).unwrap_or(false) {
            verified = true;
        }
    }

    if !verified {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid verification code",
        );
    }

    let codes = generate_8_recovery_codes();

    // Persist in `recovery_codes` table (matching `backend/api/totp.go`)
    let _ = conn.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user.user_id],
    );
    for code in &codes {
        if let Ok(hash) = bcrypt::hash(code, bcrypt::DEFAULT_COST) {
            let _ = conn.execute(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                params![user.user_id, hash],
            );
        }
    }

    // Also store JSON array in `totp_recovery_codes` column on `users` (ensuring column exists)
    if let Ok(codes_json) = serde_json::to_string(&codes) {
        let _ = conn.execute_batch(
            "ALTER TABLE users ADD COLUMN totp_recovery_codes TEXT DEFAULT '[]';",
        );
        let _ = conn.execute(
            "UPDATE users SET totp_recovery_codes = ?1 WHERE id = ?2",
            params![codes_json, user.user_id],
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
        "2fa_recovery_regenerate",
        "user",
        "",
        "",
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "message": "Recovery codes regenerated",
        "recovery_codes": codes,
    }))
    .into_response()
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

pub async fn create_notification_rule(Json(req): Json<CreateRuleReq>) -> Response {
    if req.name.trim().is_empty()
        || req.condition_type.trim().is_empty()
        || req.condition_value.trim().is_empty()
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name, condition_type, and condition_value are required",
        );
    }

    let valid_types = ["disk_usage", "cpu_usage", "memory_usage", "service_down"];
    if !valid_types.contains(&req.condition_type.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid condition_type. Allowed: disk_usage, cpu_usage, memory_usage, service_down",
        );
    }

    let level = if req.level.trim().is_empty() {
        "warning".to_string()
    } else {
        req.level.trim().to_string()
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
            params![req.name.trim(), req.condition_type, req.condition_value.trim(), level],
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
        if !name.is_empty() {
            bind_params.push(Box::new(name.clone()));
            set_clauses.push(format!("name = ?{}", bind_params.len()));
        }
    }
    if let Some(ref ct) = req.condition_type {
        if !ct.is_empty() {
            bind_params.push(Box::new(ct.clone()));
            set_clauses.push(format!("condition_type = ?{}", bind_params.len()));
        }
    }
    if let Some(ref cv) = req.condition_value {
        if !cv.is_empty() {
            bind_params.push(Box::new(cv.clone()));
            set_clauses.push(format!("condition_value = ?{}", bind_params.len()));
        }
    }
    if let Some(ref lvl) = req.level {
        if !lvl.is_empty() {
            bind_params.push(Box::new(lvl.clone()));
            set_clauses.push(format!("level = ?{}", bind_params.len()));
        }
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

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update rule",
        );
    };

    bind_params.push(Box::new(id));
    let query = format!(
        "UPDATE notification_rules SET {} WHERE id = ?{}",
        set_clauses.join(", "),
        bind_params.len()
    );

    let param_refs: Vec<&dyn rusqlite::ToSql> = bind_params.iter().map(|b| b.as_ref()).collect();
    if conn.execute(&query, param_refs.as_slice()).is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update rule",
        );
    }

    Json(serde_json::json!({ "message": "Rule updated" })).into_response()
}

pub async fn delete_notification_rule(Path(id): Path<i64>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        );
    };

    if conn
        .execute("DELETE FROM notification_rules WHERE id = ?1", params![id])
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        );
    }

    Json(serde_json::json!({ "message": "Rule deleted" })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 6–8. Notification Channels CRUD & Test (`/notifications/channels`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn create_notification_channel(Json(req): Json<CreateChannelReq>) -> Response {
    if req.name.trim().is_empty() || req.channel_type.trim().is_empty() || req.config.is_null() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name, type, and config are required",
        );
    }

    let valid_types = [
        "discord",
        "slack",
        "gotify",
        "webhook",
        "email",
        "telegram",
        "custom",
    ];
    if !valid_types.contains(&req.channel_type.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid channel type. Allowed: discord, slack, gotify, webhook, email",
        );
    }

    let config_str = match &req.config {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    };

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
    let channel_opt = af_db::get_conn().ok().and_then(|conn| {
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

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

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
    let cfg: serde_json::Value = serde_json::from_str(&channel.config).map_err(|e| {
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
                    "delivered",
                    1,
                    "",
                );
                return Ok(());
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

    match HTTP_CLIENT.post(&target_url).json(&payload).send().await {
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
        let Ok(conn) = af_db::get_conn() else {
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
    let active_services = af_services::get_active_services();

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
                let threshold = rule.condition_value.trim().parse::<f64>().unwrap_or(0.0);
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
                let threshold = rule.condition_value.trim().parse::<f64>().unwrap_or(0.0);
                if metrics.cpu_usage >= threshold {
                    triggered = true;
                    message = format!("CPU usage is at {:.1}%", metrics.cpu_usage);
                }
            }
            "memory_usage" => {
                let threshold = rule.condition_value.trim().parse::<f64>().unwrap_or(0.0);
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
                if !target_svc.is_empty() {
                    let is_up = active_services.iter().any(|(label, item)| {
                        (label.eq_ignore_ascii_case(target_svc)
                            || item.process.eq_ignore_ascii_case(target_svc))
                            && item.status == "running"
                    });
                    if !is_up {
                        triggered = true;
                        message = format!("Service {} is down", target_svc);
                    }
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
