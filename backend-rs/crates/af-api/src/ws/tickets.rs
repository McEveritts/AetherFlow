use super::logs::websocket_origin_matches_host;
use super::proxy::extract_client_ip_for_peer;
use super::telemetry::{
    websocket_message_for_peer_session, websocket_message_for_session, TELEMETRY,
};
use crate::auth::{AuthUser, PeerPrincipal};
use crate::peers::{
    is_live_link_state, PeerListenerRuntime, PeerRuntime, PeerWsPermit, RevocationEvent,
};
use af_db::peers::{self as db_peers, AccessMap};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WsPeerBinding {
    pub(super) link_id: String,
    pub(super) grant_id: String,
    pub(super) run_as_user_id: i64,
    pub(super) access: AccessMap,
}

#[derive(Clone)]
pub(super) struct WsTicketEntry {
    pub(super) user_id: i64,
    pub(super) session_jti: String,
    pub(super) session_ver: Option<i64>,
    pub(super) client_ip: String,
    pub(super) expires_at: Instant,
    pub(super) diagnostics_allowed: bool,
    pub(super) peer: Option<WsPeerBinding>,
    pub(super) peer_runtime: Option<Arc<PeerRuntime>>,
}

impl std::fmt::Debug for WsTicketEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsTicketEntry")
            .field("user_id", &self.user_id)
            .field("session_ver", &self.session_ver)
            .field("client_ip", &self.client_ip)
            .field("diagnostics_allowed", &self.diagnostics_allowed)
            .field("peer", &self.peer)
            .field("has_peer_runtime", &self.peer_runtime.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WsPeerScope {
    Telemetry,
    Logs,
}

#[derive(Clone, Debug)]
pub(super) struct WsAuthorizationSnapshot {
    pub(super) diagnostics_allowed: bool,
    pub(super) peer_access: Option<AccessMap>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RevocationWakeOutcome {
    CloseNow,
    Ignore,
    RecheckDb,
}

pub(super) fn classify_revocation_recv(
    recv: Result<RevocationEvent, broadcast::error::RecvError>,
    binding: &WsPeerBinding,
) -> RevocationWakeOutcome {
    match recv {
        Ok(RevocationEvent::LinkRevoked { link_id, .. }) => {
            if link_id == binding.link_id {
                RevocationWakeOutcome::CloseNow
            } else {
                RevocationWakeOutcome::Ignore
            }
        }
        Ok(RevocationEvent::GrantRevoked {
            link_id, grant_id, ..
        }) => {
            if grant_id == binding.grant_id {
                RevocationWakeOutcome::CloseNow
            } else if link_id == binding.link_id {
                RevocationWakeOutcome::RecheckDb
            } else {
                RevocationWakeOutcome::Ignore
            }
        }
        Err(broadcast::error::RecvError::Lagged(_)) | Err(broadcast::error::RecvError::Closed) => {
            RevocationWakeOutcome::RecheckDb
        }
    }
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
                peer: None,
                peer_runtime: None,
            },
        );
    }
    ticket
}

pub fn issue_ws_ticket_for_user(user_id: i64, client_ip: &str) -> String {
    issue_ws_ticket_for_session(user_id, "", client_ip)
}

async fn issue_ws_ticket_for_peer(
    principal: &PeerPrincipal,
    runtime: Arc<PeerRuntime>,
    client_ip: &str,
) -> Option<String> {
    if principal.run_as_user_id <= 0 || !principal.access.has_any_access() {
        return None;
    }

    let link_id = principal.link_id.clone();
    let grant_id = principal.grant_id.clone();
    let run_as_uid = principal.run_as_user_id;
    let verified = runtime
        .db
        .read("local", "issue_peer_ws_ticket", move |conn| {
            let Ok(subj) = crate::auth::load_active_peer_subject(conn, run_as_uid) else {
                return Ok(None);
            };
            if subj.role != "admin" {
                return Ok(None);
            }
            let Ok(Some(link)) = db_peers::get_peer_link(conn, &link_id) else {
                return Ok(None);
            };
            if !is_live_link_state(&link.state) {
                return Ok(None);
            }
            let Ok(Some(grant)) = db_peers::get_peer_grant(conn, &grant_id) else {
                return Ok(None);
            };
            if grant.link_id != link_id
                || grant.run_as_user_id != run_as_uid
                || grant.revoked_at.is_some()
                || grant.token_hash.is_none()
                || !grant.access.has_any_access()
            {
                return Ok(None);
            }
            Ok(Some((subj.sessions_revoked_after, grant.access)))
        })
        .await
        .ok()??;

    let (initial_ver, access) = verified;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let ticket = hex::encode(b);

    let diagnostics_allowed = access.services.allows_read() && access.marketplace.allows_read();
    let entry = WsTicketEntry {
        user_id: principal.run_as_user_id,
        session_jti: format!("peer-grant:{}", principal.grant_id),
        session_ver: Some(initial_ver),
        client_ip: client_ip.to_string(),
        expires_at: Instant::now() + Duration::from_secs(30),
        diagnostics_allowed,
        peer: Some(WsPeerBinding {
            link_id: principal.link_id.clone(),
            grant_id: principal.grant_id.clone(),
            run_as_user_id: principal.run_as_user_id,
            access,
        }),
        peer_runtime: Some(runtime),
    };

    if let Ok(mut map) = WS_TICKETS.lock() {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(ticket.clone(), entry);
    }
    Some(ticket)
}

/// Production handler for `GET /api/v1/auth/ws/ticket`.
///
/// Issues single-use 30-second WebSocket tickets for local human sessions and, when called through
/// the authenticated peer tunnel listener, issues peer-bound tickets tied to the verified
/// `(link_id, grant_id, run_as_user_id)` identity. Rejects plugin tokens unconditionally.
pub async fn handle_issue_ws_ticket(
    Extension(auth_user): Extension<AuthUser>,
    peer: Option<Extension<PeerPrincipal>>,
    peer_runtime: Option<Extension<PeerListenerRuntime>>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
) -> Response {
    if auth_user.plugin_id.is_some()
        || !auth_user.plugin_scopes.is_empty()
        || auth_user.role == "plugin"
    {
        return crate::auth::api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_WEBSOCKET_FORBIDDEN",
            "Scoped plugins cannot create operator WebSocket sessions; use scoped telemetry reads",
        );
    }

    let ip = extract_client_ip_for_peer(&headers, peer_ip);

    if let Some(Extension(principal)) = peer {
        if auth_user.user_id <= 0
            || auth_user.user_id != principal.run_as_user_id
            || auth_user.role != "admin"
            || !principal.access.has_any_access()
        {
            return crate::auth::api_error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Peer WebSocket ticket requires an active peer grant",
            );
        }
        let runtime = peer_runtime
            .map(|Extension(r)| r.0)
            .unwrap_or_else(PeerRuntime::global);
        let Some(ticket) = issue_ws_ticket_for_peer(&principal, runtime, &ip).await else {
            return crate::auth::api_error(
                StatusCode::FORBIDDEN,
                "PEER_SCOPE_DENIED",
                "Active peer grant is required to issue a WebSocket ticket",
            );
        };
        return Json(serde_json::json!({ "ticket": ticket })).into_response();
    }

    let ticket = issue_ws_ticket_for_session(auth_user.user_id, &auth_user.jti, &ip);
    Json(serde_json::json!({ "ticket": ticket })).into_response()
}

pub(super) fn is_loopback_ip(ip: &str) -> bool {
    let trimmed = ip.trim().trim_matches(['[', ']']);
    matches!(trimmed, "" | "localhost")
        || trimmed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.to_canonical().is_loopback())
}

pub(super) fn ticket_client_ip_matches(entry_ip: &str, client_ip: &str) -> bool {
    entry_ip.is_empty()
        || client_ip.is_empty()
        || entry_ip == client_ip
        || (is_loopback_ip(entry_ip) && is_loopback_ip(client_ip))
}

#[derive(Deserialize, Default)]
pub struct WsTicketQuery {
    #[serde(default)]
    pub ticket: String,
}

fn check_ws_jti_revocation(connection: &rusqlite::Connection, entry: &WsTicketEntry) -> bool {
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

fn verify_ws_session(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
) -> Option<crate::auth::ActiveSubject> {
    if entry.session_jti.trim().is_empty() {
        return None;
    }
    let check_ver = entry.session_ver.unwrap_or(0);
    let subj = crate::auth::verify_active_session_on_conn(
        connection,
        entry.user_id,
        &entry.session_jti,
        check_ver,
        chrono::Utc::now().timestamp(),
        crate::auth::RotationGrace::AllowAnyFingerprint,
    )
    .ok()?;
    if entry.session_ver.is_none() {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }
    Some(subj)
}

fn verify_peer_entry_with_conn(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
    scope: WsPeerScope,
) -> Option<WsAuthorizationSnapshot> {
    let binding = entry.peer.clone()?;
    if entry.user_id <= 0 || entry.user_id != binding.run_as_user_id {
        return None;
    }
    if !check_ws_jti_revocation(connection, entry) {
        return None;
    }
    let subj = crate::auth::load_active_peer_subject(connection, binding.run_as_user_id).ok()?;
    if subj.role != "admin" {
        return None;
    }
    if let Some(issued_ver) = entry.session_ver {
        if subj.sessions_revoked_after > issued_ver {
            return None;
        }
    } else {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }

    let link = db_peers::get_peer_link(connection, &binding.link_id)
        .ok()
        .flatten()?;
    if !is_live_link_state(&link.state) {
        return None;
    }

    let grant = db_peers::get_peer_grant(connection, &binding.grant_id)
        .ok()
        .flatten()?;
    if grant.link_id != binding.link_id
        || grant.run_as_user_id != binding.run_as_user_id
        || grant.revoked_at.is_some()
        || grant.token_hash.is_none()
    {
        return None;
    }

    let allowed_for_scope = match scope {
        WsPeerScope::Telemetry => grant.access.has_any_access(),
        WsPeerScope::Logs => grant.access.services.allows_read(),
    };
    if !allowed_for_scope {
        return None;
    }

    let diagnostics_allowed =
        grant.access.services.allows_read() && grant.access.marketplace.allows_read();
    entry.diagnostics_allowed = diagnostics_allowed;
    if let Some(ref mut b) = entry.peer {
        b.access = grant.access.clone();
    }
    Some(WsAuthorizationSnapshot {
        diagnostics_allowed,
        peer_access: Some(grant.access),
    })
}

#[cfg(test)]
pub(super) fn consume_live_ws_ticket(
    connection: &rusqlite::Connection,
    ticket: &str,
) -> Option<WsTicketEntry> {
    let mut entry = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, value| value.expires_at > Instant::now());
        if map.get(ticket).is_some_and(|v| v.peer.is_some()) {
            return None;
        }
        map.remove(ticket)
    })?;
    let subj = verify_ws_session(connection, &mut entry)?;
    entry.diagnostics_allowed = subj.role == "admin";
    Some(entry)
}

/// Consumes a live WebSocket ticket while strictly enforcing isolation between local human
/// sessions and peer-bound grants (`link_id`, `grant_id`, `run_as_user_id`).
pub(super) async fn consume_live_ws_ticket_for_context(
    ticket: &str,
    peer: Option<&PeerPrincipal>,
    peer_runtime: Option<Arc<PeerRuntime>>,
    expected_local_user_id: Option<i64>,
    scope: WsPeerScope,
) -> Option<WsTicketEntry> {
    let entry_opt = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, value| value.expires_at > Instant::now());
        let matches = map.get(ticket).is_some_and(|candidate| match peer {
            Some(principal) => candidate.peer.as_ref().is_some_and(|b| {
                b.link_id == principal.link_id
                    && b.grant_id == principal.grant_id
                    && b.run_as_user_id == principal.run_as_user_id
                    && candidate.user_id == principal.run_as_user_id
            }),
            None => {
                candidate.peer.is_none()
                    && expected_local_user_id.is_none_or(|uid| candidate.user_id == uid)
            }
        });
        if matches {
            map.remove(ticket)
        } else {
            None
        }
    });

    let mut entry = entry_opt?;
    if peer.is_some() {
        let runtime = peer_runtime
            .or_else(|| entry.peer_runtime.clone())
            .unwrap_or_else(PeerRuntime::global);
        entry.peer_runtime = Some(Arc::clone(&runtime));
        let mut checked = entry.clone();
        let verified = runtime
            .db
            .read("local", "consume_peer_ws_ticket", move |conn| {
                if verify_peer_entry_with_conn(conn, &mut checked, scope).is_some() {
                    Ok(Some(checked))
                } else {
                    Ok(None)
                }
            })
            .await
            .ok()??;
        Some(verified)
    } else {
        let mut checked = entry;
        tokio::task::spawn_blocking(move || {
            let connection = af_db::get_read_conn().ok()?;
            let subj = verify_ws_session(&connection, &mut checked)?;
            checked.diagnostics_allowed = subj.role == "admin";
            Some(checked)
        })
        .await
        .ok()
        .flatten()
    }
}

pub async fn handle_websocket(
    Query(q): Query<WsTicketQuery>,
    peer: Option<Extension<PeerPrincipal>>,
    peer_runtime: Option<Extension<PeerListenerRuntime>>,
    peer_ws_permit: Option<Extension<PeerWsPermit>>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let peer_principal = peer.map(|Extension(p)| p);
    if peer_principal.is_none() && !websocket_origin_matches_host(&headers, peer_ip, false) {
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

    let runtime_opt = peer_runtime.map(|Extension(r)| r.0);
    let Some(entry) = consume_live_ws_ticket_for_context(
        &q.ticket,
        peer_principal.as_ref(),
        runtime_opt,
        None,
        WsPeerScope::Telemetry,
    )
    .await
    else {
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
    if !ticket_client_ip_matches(&entry.client_ip, &client_ip) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "WS_IP_MISMATCH",
                "message": "Ticket IP mismatch"
            })),
        )
            .into_response();
    }

    // Subscribe to peer revocation broadcasts BEFORE entering `on_upgrade` so revocations that
    // occur between upgrade acceptance and socket task startup cannot be missed; the task also
    // immediately rechecks authoritative DB state upon entry.
    let revocation_rx = entry
        .peer_runtime
        .as_ref()
        .map(|rt| rt.subscribe_revocations());
    let held_ws_permit = peer_ws_permit.and_then(|Extension(p)| p.take());

    ws.max_message_size(64 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |socket| handle_ws_socket(socket, entry, revocation_rx, held_ws_permit))
}

// A ticket authorizes the upgrade only. Existing sockets must not keep a stale
// administrative capability after the account is demoted, removed, or logged out.
pub(super) fn refresh_ws_authorization(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
) -> Option<bool> {
    if entry.peer.is_some() {
        return verify_peer_entry_with_conn(connection, entry, WsPeerScope::Telemetry)
            .map(|snap| snap.diagnostics_allowed);
    }
    let subj = verify_ws_session(connection, entry)?;
    entry.diagnostics_allowed &= subj.role == "admin";
    Some(entry.diagnostics_allowed)
}

pub(super) async fn current_ws_authorization_ex(
    entry: &mut WsTicketEntry,
    scope: WsPeerScope,
) -> Option<WsAuthorizationSnapshot> {
    if entry.peer.is_some() {
        let runtime = entry
            .peer_runtime
            .clone()
            .unwrap_or_else(PeerRuntime::global);
        let mut checked = entry.clone();
        let (snap, updated) = runtime
            .db
            .read("local", "ws_auth_recheck", move |conn| {
                if let Some(snap) = verify_peer_entry_with_conn(conn, &mut checked, scope) {
                    Ok(Some((snap, checked)))
                } else {
                    Ok(None)
                }
            })
            .await
            .ok()??;
        entry.diagnostics_allowed = updated.diagnostics_allowed;
        entry.session_jti = updated.session_jti;
        entry.session_ver = updated.session_ver;
        entry.peer = updated.peer;
        return Some(snap);
    }

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
    Some(WsAuthorizationSnapshot {
        diagnostics_allowed: allowed,
        peer_access: None,
    })
}

pub(super) async fn current_ws_authorization(entry: &mut WsTicketEntry) -> Option<bool> {
    current_ws_authorization_ex(entry, WsPeerScope::Logs)
        .await
        .map(|snap| snap.diagnostics_allowed)
}

fn format_telemetry_message(message: String, auth: &WsAuthorizationSnapshot) -> Option<String> {
    if let Some(ref access) = auth.peer_access {
        websocket_message_for_peer_session(message, access)
    } else {
        websocket_message_for_session(message, auth.diagnostics_allowed)
    }
}

async fn handle_ws_socket(
    mut socket: WebSocket,
    mut entry: WsTicketEntry,
    mut revocation_rx: Option<broadcast::Receiver<RevocationEvent>>,
    _held_ws_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    let mut rx = TELEMETRY.broadcast.subscribe();
    TELEMETRY.service_refresh.notify_one();

    // Immediate authoritative DB recheck after subscription closes any registration race.
    let Some(initial_auth) = current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };

    let mut metrics_watch = TELEMETRY.subscribe_metrics();
    let mut sent_initial_snapshot = false;
    if let Some(init_payload) = TELEMETRY.cached_snapshot() {
        sent_initial_snapshot = true;
        if let Some(text) = serde_json::to_string(&init_payload)
            .ok()
            .and_then(|text| format_telemetry_message(text, &initial_auth))
        {
            if socket.send(Message::Text(text)).await.is_err() {
                return;
            }
        }
    }

    let is_peer = entry.peer.is_some();
    let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
    ping_interval.tick().await;
    let mut auth_interval = tokio::time::interval(if is_peer {
        Duration::from_millis(500)
    } else {
        Duration::from_secs(5)
    });
    auth_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    auth_interval.tick().await;

    loop {
        tokio::select! {
            recv = async {
                match revocation_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(ref binding) = entry.peer {
                    match classify_revocation_recv(recv, binding) {
                        RevocationWakeOutcome::CloseNow => {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        RevocationWakeOutcome::RecheckDb => {
                            if current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await.is_none() {
                                let _ = socket.send(Message::Close(None)).await;
                                break;
                            }
                        }
                        RevocationWakeOutcome::Ignore => {}
                    }
                }
            }
            changed = metrics_watch.changed(), if !sent_initial_snapshot => {
                if changed.is_ok() {
                    if let Some(init_payload) = TELEMETRY.cached_snapshot() {
                        sent_initial_snapshot = true;
                        let Some(auth) = current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await else {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        };
                        if let Some(text) = serde_json::to_string(&init_payload)
                            .ok()
                            .and_then(|text| format_telemetry_message(text, &auth))
                        {
                            if socket.send(Message::Text(text)).await.is_err() {
                                break;
                            }
                        }
                    }
                } else {
                    sent_initial_snapshot = true;
                }
            }
            msg_opt = socket.recv() => {
                match msg_opt {
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        break;
                    }
                    _ => {}
                }
            }
            broadcast_res = rx.recv() => {
                match broadcast_res {
                    Ok(msg) => {
                        let Some(auth) = current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await else {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        };
                        if let Some(message) = format_telemetry_message(msg, &auth) {
                            if socket.send(Message::Text(message)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await.is_none() {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = auth_interval.tick() => {
                if current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await.is_none() {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if current_ws_authorization_ex(&mut entry, WsPeerScope::Telemetry).await.is_none() {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
        }
    }
}
