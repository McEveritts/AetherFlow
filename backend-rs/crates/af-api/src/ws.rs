use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
struct WsTicketEntry {
    user_id: i64,
    client_ip: String,
    expires_at: Instant,
}

static WS_TICKETS: Lazy<Mutex<HashMap<String, WsTicketEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static WS_BROADCAST_TX: Lazy<broadcast::Sender<String>> = Lazy::new(|| {
    let (tx, _) = broadcast::channel(256);
    tx
});

static CACHED_METRICS_JSON: Lazy<RwLock<Option<serde_json::Value>>> =
    Lazy::new(|| RwLock::new(None));
static CACHED_SERVICES_JSON: Lazy<RwLock<Option<serde_json::Value>>> =
    Lazy::new(|| RwLock::new(None));

pub fn broadcast_ws_message(payload: &serde_json::Value) {
    if let Ok(text) = serde_json::to_string(payload) {
        let _ = WS_BROADCAST_TX.send(text);
    }
}

pub fn start_metrics_broadcast_loop() {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut svc_counter = 0u32;
        loop {
            tick.tick().await;
            let metrics = af_hardware::get_system_metrics_core();
            let metrics_val = serde_json::to_value(&metrics).unwrap_or_default();
            if let Ok(mut guard) = CACHED_METRICS_JSON.write() {
                *guard = Some(metrics_val.clone());
            }

            let services_val = if svc_counter % 15 == 0 {
                let svcs = af_services::get_active_services();
                let val = serde_json::to_value(&svcs).unwrap_or_default();
                if let Ok(mut guard) = CACHED_SERVICES_JSON.write() {
                    *guard = Some(val.clone());
                }
                val
            } else {
                CACHED_SERVICES_JSON
                    .read()
                    .ok()
                    .and_then(|g| g.clone())
                    .unwrap_or_else(|| serde_json::json!({}))
            };
            svc_counter = svc_counter.wrapping_add(1);

            if WS_BROADCAST_TX.receiver_count() > 0 {
                let msg = serde_json::json!({
                    "type": "METRICS_UPDATE",
                    "data": {
                        "system": metrics_val,
                        "services": services_val,
                    }
                });
                broadcast_ws_message(&msg);
            }
        }
    });
}

pub fn issue_ws_ticket_for_user(user_id: i64, client_ip: &str) -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let ticket = hex::encode(b);

    if let Ok(mut map) = WS_TICKETS.lock() {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(
            ticket.clone(),
            WsTicketEntry {
                user_id,
                client_ip: client_ip.to_string(),
                expires_at: Instant::now() + Duration::from_secs(90),
            },
        );
    }
    ticket
}

fn is_loopback_ip(ip: &str) -> bool {
    matches!(ip, "127.0.0.1" | "::1" | "localhost" | "")
}

#[derive(Deserialize)]
pub struct WsTicketQuery {
    #[serde(default)]
    pub ticket: String,
}

pub async fn handle_websocket(
    Query(q): Query<WsTicketQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if q.ticket.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "WS_MISSING_TICKET",
                "message": "Missing ticket"
            })),
        )
            .into_response();
    }

    let entry_opt = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.remove(&q.ticket)
    });

    let Some(entry) = entry_opt else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "WS_INVALID_TICKET",
                "message": "Invalid or expired ticket"
            })),
        )
            .into_response();
    };

    let client_ip = extract_client_ip(&headers);
    if !entry.client_ip.is_empty()
        && !client_ip.is_empty()
        && entry.client_ip != client_ip
        && !(is_loopback_ip(&entry.client_ip) && is_loopback_ip(&client_ip))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "WS_IP_MISMATCH",
                "message": "Ticket IP mismatch"
            })),
        )
            .into_response();
    }

    let _ = entry.user_id;
    ws.on_upgrade(handle_ws_socket)
}

async fn handle_ws_socket(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = WS_BROADCAST_TX.subscribe();

    // Immediately push frame 0 METRICS_UPDATE snapshot so the client renders right away
    let initial_metrics = CACHED_METRICS_JSON
        .read()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| {
            serde_json::to_value(af_hardware::get_system_metrics_core()).unwrap_or_default()
        });
    let initial_services = CACHED_SERVICES_JSON
        .read()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| {
            serde_json::to_value(af_services::get_active_services()).unwrap_or_default()
        });

    let init_payload = serde_json::json!({
        "type": "METRICS_UPDATE",
        "data": {
            "system": initial_metrics,
            "services": initial_services,
        }
    });
    if let Ok(text) = serde_json::to_string(&init_payload) {
        let _ = sender.send(Message::Text(text.into())).await;
    }

    let mut write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
        loop {
            tokio::select! {
                Ok(msg) = rx.recv() => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                _ = ping_interval.tick() => {
                    if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    tokio::select! {
        _ = (&mut write_task) => read_task.abort(),
        _ = (&mut read_task) => write_task.abort(),
    }
}

pub async fn handle_log_websocket(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|mut socket| async move {
        let welcome = serde_json::json!({
            "type": "LOG_ENTRY",
            "data": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "source": "aetherflow-api",
                "unit": "aetherflow-api.service",
                "priority": "info",
                "message": "Connected to AetherFlow Rust log stream"
            }
        });
        if let Ok(txt) = serde_json::to_string(&welcome) {
            let _ = socket.send(Message::Text(txt.into())).await;
        }
        while let Some(Ok(msg)) = socket.recv().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    })
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "127.0.0.1".to_string()
}

pub fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    for val in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(raw) = val.to_str() {
            for part in raw.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn build_set_cookie(
    name: &str,
    value: &str,
    max_age: i64,
    same_site: &str,
    secure: bool,
    http_only: bool,
) -> String {
    let mut parts = vec![
        format!("{}={}", name, value),
        "Path=/".to_string(),
        format!("Max-Age={}", max_age),
        format!("SameSite={}", same_site),
    ];
    if secure {
        parts.push("Secure".to_string());
    }
    if http_only {
        parts.push("HttpOnly".to_string());
    }
    parts.join("; ")
}
