use super::channels::{parse_custom_webhook_header, WEBHOOK_HEADER_FIELDS};
use super::models::StoredChannel;
use axum::http::{HeaderName, HeaderValue};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use std::time::Duration;

pub(super) fn is_public_webhook_ip(address: std::net::IpAddr) -> bool {
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

pub(super) fn is_allowed_webhook_ip_with(address: std::net::IpAddr, allow_private: bool) -> bool {
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
pub(super) fn is_allowed_webhook_ip(address: std::net::IpAddr) -> bool {
    is_allowed_webhook_ip_with(address, allow_private_webhooks())
}

pub(super) fn parse_webhook_url_with(
    target: &str,
    allow_private: bool,
) -> anyhow::Result<url::Url> {
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

pub(super) fn parse_webhook_url(target: &str) -> anyhow::Result<url::Url> {
    parse_webhook_url_with(target, allow_private_webhooks())
}

pub(super) const MAX_DIAGNOSTIC_ERROR_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ChannelDispatchError {
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
    pub(super) fn permanent(message: impl Into<String>, attempted_network: bool) -> Self {
        Self::Permanent {
            message: sanitize_diagnostic_error(&message.into()),
            attempted_network,
        }
    }

    pub(super) fn transient(message: impl Into<String>, attempted_network: bool) -> Self {
        Self::Transient {
            message: sanitize_diagnostic_error(&message.into()),
            attempted_network,
        }
    }

    pub(super) fn message(&self) -> &str {
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

    pub(super) fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}

pub(super) fn sanitize_diagnostic_error(raw: &str) -> String {
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

pub(super) fn delivery_retry_backoff_secs(completed_attempts: i32) -> i64 {
    match completed_attempts {
        ..=1 => 30,
        2 => 120,
        _ => 300,
    }
}

pub(super) async fn webhook_client_classified(
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
pub(super) async fn webhook_client(target: &str) -> anyhow::Result<(reqwest::Client, url::Url)> {
    webhook_client_classified(target)
        .await
        .map_err(|err| anyhow::anyhow!(err.message().to_string()))
}

#[derive(Debug, Clone)]
pub(super) struct PreparedChannelRequest {
    pub(super) target_url: String,
    pub(super) payload: serde_json::Value,
    pub(super) headers: Vec<(HeaderName, HeaderValue)>,
}

pub(super) fn prepare_channel_request(
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

pub(super) async fn send_prepared_channel_request(
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
    let pending: i64 = match conn.query_row(
        "SELECT COUNT(*) FROM notification_delivery_log \
         WHERE channel_id = ?1 AND notification_id IS NOT NULL AND status IN ('pending', 'sending')",
        params![channel_id],
        |r| r.get(0),
    ) {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(channel_id, %error, "Failed to count pending notification deliveries");
            0
        }
    };

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
        .unwrap_or_else(|error| {
            tracing::warn!(channel_id, %error, "Failed to query latest notification delivery");
            None
        });

    (pending, last)
}
