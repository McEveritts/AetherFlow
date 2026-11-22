use super::logs::websocket_origin_matches_host;
use super::proxy::extract_client_ip_for_peer;
use super::telemetry::{websocket_message_for_session, TELEMETRY};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;

#[derive(Clone, Copy, Debug, Default)]
pub struct PeerIp(pub Option<std::net::IpAddr>);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(addr)| addr.ip());
        Ok(Self(ip))
    }
}

#[derive(Clone, Debug)]
pub(super) struct WsTicketEntry {
    pub(super) user_id: i64,
    pub(super) session_jti: String,
    pub(super) session_ver: Option<i64>,
    pub(super) client_ip: String,
    pub(super) expires_at: Instant,
    pub(super) diagnostics_allowed: bool,
}

static WS_TICKETS: Lazy<Mutex<HashMap<String, WsTicketEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn issue_ws_ticket_for_session(user_id: i64, session_jti: &str, client_ip: &str) -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let ticket = hex::encode(b);

    let effective_jti = if session_jti.trim().is_empty() {
        let mut anon = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut anon);
        format!("ws-anon-{}", hex::encode(anon))
    } else {
        session_jti.trim().to_string()
    };

    let initial_ver = af_db::get_read_conn()
        .ok()
        .and_then(|c| crate::auth::load_active_human_subject(&c, user_id).ok())
        .map(|s| s.sessions_revoked_after);

    if let Ok(mut map) = WS_TICKETS.lock() {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(
            ticket.clone(),
            WsTicketEntry {
                user_id,
                session_jti: effective_jti,
                session_ver: initial_ver,
                client_ip: client_ip.to_string(),
                expires_at: Instant::now() + Duration::from_secs(30),
                diagnostics_allowed: false,
            },
        );
    }
    ticket
}

pub fn issue_ws_ticket_for_user(user_id: i64, client_ip: &str) -> String {
    issue_ws_ticket_for_session(user_id, "", client_ip)
}

fn is_loopback_ip(ip: &str) -> bool {
    let trimmed = ip.trim().trim_matches(['[', ']']);
    matches!(trimmed, "" | "localhost")
        || trimmed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.to_canonical().is_loopback())
}

#[derive(Deserialize)]
pub struct WsTicketQuery {
    #[serde(default)]
    pub ticket: String,
}

fn check_ws_jti_revocation(connection: &rusqlite::Connection, entry: &mut WsTicketEntry) -> bool {
    if entry.session_jti.is_empty() {
        return false;
    }
    if entry.session_jti.starts_with("ws-anon-")
        && !crate::auth::table_exists(connection, "revoked_tokens").unwrap_or(false)
    {
        return true;
    }
    !crate::auth::is_session_token_revoked_beyond_grace_with_conn(
        connection,
        &entry.session_jti,
        entry.user_id,
    )
}

pub(super) fn consume_live_ws_ticket(
    connection: &rusqlite::Connection,
    ticket: &str,
) -> Option<WsTicketEntry> {
    let mut entry = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, value| value.expires_at > Instant::now());
        map.remove(ticket)
    })?;
    if !check_ws_jti_revocation(connection, &mut entry) {
        return None;
    }
    let subj = crate::auth::load_active_human_subject(connection, entry.user_id).ok()?;
    if let Some(issued_ver) = entry.session_ver {
        if subj.sessions_revoked_after > issued_ver {
            return None;
        }
    } else {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }
    entry.diagnostics_allowed = subj.role == "admin";
    Some(entry)
}

pub async fn handle_websocket(
    Query(q): Query<WsTicketQuery>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !websocket_origin_matches_host(&headers, peer_ip, false) {
        return crate::auth::api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Cross-origin WebSocket upgrade rejected",
        );
    }
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

    let entry_opt = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_read_conn().ok()?;
        consume_live_ws_ticket(&connection, &q.ticket)
    })
    .await
    .ok()
    .flatten();

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

    let client_ip = extract_client_ip_for_peer(&headers, peer_ip);
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

    ws.max_message_size(64 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |socket| handle_ws_socket(socket, entry))
}

// A ticket authorizes the upgrade only. Existing sockets must not keep a stale
// administrative capability after the account is demoted, removed, or logged out.
pub(super) fn refresh_ws_authorization(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
) -> Option<bool> {
    if !check_ws_jti_revocation(connection, entry) {
        return None;
    }
    let subj = crate::auth::load_active_human_subject(connection, entry.user_id).ok()?;
    if let Some(issued_ver) = entry.session_ver {
        if subj.sessions_revoked_after > issued_ver {
            return None;
        }
    } else {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }
    entry.diagnostics_allowed &= subj.role == "admin";
    Some(entry.diagnostics_allowed)
}

pub(super) async fn current_ws_authorization(entry: &mut WsTicketEntry) -> Option<bool> {
    let mut checked = entry.clone();
    let (allowed, updated_jti, updated_ver) = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_read_conn().ok()?;
        let allowed = refresh_ws_authorization(&connection, &mut checked)?;
        Some((allowed, checked.session_jti, checked.session_ver))
    })
    .await
    .ok()??;
    entry.diagnostics_allowed = allowed;
    entry.session_jti = updated_jti;
    entry.session_ver = updated_ver;
    Some(allowed)
}

async fn handle_ws_socket(socket: WebSocket, mut entry: WsTicketEntry) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = TELEMETRY.broadcast.subscribe();
    TELEMETRY.service_refresh.notify_one();

    let init_payload = TELEMETRY.initial_snapshot().await;
    let Some(diagnostics_allowed) = current_ws_authorization(&mut entry).await else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    if let Some(text) = serde_json::to_string(&init_payload)
        .ok()
        .and_then(|text| websocket_message_for_session(text, diagnostics_allowed))
    {
        let _ = sender.send(Message::Text(text)).await;
    }

    let mut write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
        let mut auth_interval = tokio::time::interval(Duration::from_secs(5));
        auth_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        auth_interval.tick().await;
        loop {
            tokio::select! {
                Ok(msg) = rx.recv() => {
                    let Some(diagnostics_allowed) = current_ws_authorization(&mut entry).await else {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    };
                    if let Some(message) = websocket_message_for_session(msg, diagnostics_allowed) {
                        if sender.send(Message::Text(message)).await.is_err() {
                            break;
                        }
                    }
                }
                _ = auth_interval.tick() => {
                    if current_ws_authorization(&mut entry).await.is_none() {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    }
                }
                _ = ping_interval.tick() => {
                    if current_ws_authorization(&mut entry).await.is_none() {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    }
                    if sender.send(Message::Ping(Vec::new())).await.is_err() {
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
