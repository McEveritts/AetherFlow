use crate::auth::{api_error, generate_recovery_codes, store_recovery_codes, AuthUser};
use crate::ws::{broadcast_ws_message, extract_client_ip};
use af_db::PendingAction;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, StatusCode};
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

fn replace_verified_recovery_codes(
    conn: &rusqlite::Connection,
    user_id: i64,
    encrypted_secret: &str,
    password_hash: &str,
    code: &str,
    password_verified: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    let transaction = conn.unchecked_transaction()?;
    let current: (String, bool, String) = transaction.query_row(
        "SELECT COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![user_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    )?;
    if !current.1 || current.0 != encrypted_secret || current.2 != password_hash {
        return Ok(None);
    }
    let secret = af_db::decrypt_key(&current.0).unwrap_or(current.0);
    if !password_verified && !crate::auth::consume_totp_code(&transaction, user_id, &secret, code) {
        return Ok(None);
    }
    let codes = generate_recovery_codes();
    store_recovery_codes(&transaction, user_id, &codes)?;
    transaction.commit()?;
    Ok(Some(codes))
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
        let password_verified = !req.password.is_empty() && !password_hash.is_empty()
            && crate::auth::verify_password(&req.password, &password_hash);
        let result = (|| -> anyhow::Result<_> {
            let conn = af_db::get_conn()?;
            replace_verified_recovery_codes(&conn, user.user_id, &encrypted_secret, &password_hash, &req.code, password_verified)
        })();
        let codes = match result {
            Ok(Some(codes)) => codes,
            Ok(None) => return api_error(StatusCode::FORBIDDEN,
                if req.code.trim().is_empty() { "INVALID_CURRENT_PASSWORD" } else { "INVALID_2FA_CODE" },
                "Invalid verification code or password"),
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

fn parse_webhook_url(target: &str) -> anyhow::Result<url::Url> {
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
            is_public_webhook_ip(address.into()),
            "Webhook target must be public"
        ),
        Some(url::Host::Ipv6(address)) => anyhow::ensure!(
            is_public_webhook_ip(address.into()),
            "Webhook target must be public"
        ),
        _ => {}
    }
    Ok(url)
}

async fn webhook_client(target: &str) -> anyhow::Result<(reqwest::Client, url::Url)> {
    let url = parse_webhook_url(target)?;
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
                .all(|address| is_public_webhook_ip(address.ip())),
        "Webhook DNS must resolve only to public addresses"
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
    match client.post(target).json(&payload).send().await {
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
            &code,
            false
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
            false
        )
        .unwrap()
        .is_none());
        assert!(replace_verified_recovery_codes(
            &conn,
            1,
            "JBSWY3DPEHPK3PXP",
            "stale-password-hash",
            "",
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
            false
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
            false
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
}
