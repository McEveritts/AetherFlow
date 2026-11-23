//! Admin link listing, endpoint editing, link revocation, and tunnel revoke-notice handling.

use super::errors::PeerError;
use super::health::evaluate_compatibility;
use super::listener::authenticate_active_link;
use super::pairing::{
    cleanup_pending_link_locked, derive_comparison_code, ensure_active_pending_link_row,
    has_active_pending_expiry, is_active_expiry, is_valid_credential_id, map_runner_error,
    pending_issuer_credential_id, remove_owned_wg_peer_locked, validate_endpoint_host,
};
use super::{
    capabilities, detect_local_endpoints, is_live_link_state, is_pending_link_state,
    is_revoked_or_revoking_state, is_revoked_state, is_revoking_state, public_link_state,
    PeerRuntime, RevocationEvent, PEER_PROTOCOL_VERSION,
};
use crate::auth::AuthUser;
use crate::ws::{extract_client_ip_for_peer, PeerIp};
use af_db::peers::{self as db_peers, AccessMap, PeerExport, PeerLink, PeerMount, TranscodeWorker};
use af_runner::{PeerCredentialSlot, PeerNetworkError, PeerNetworkRequest};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const REVOKE_NOTICE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Serialize)]
pub struct GrantSummaryView {
    pub id: String,
    pub run_as_user_id: i64,
    pub access: AccessMap,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct LinkGrantsView {
    pub inbound: Option<GrantSummaryView>,
    pub outbound: Option<GrantSummaryView>,
}

#[derive(Debug, Serialize)]
pub struct PeerLinkView {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub state: String,
    pub peer_version: Option<String>,
    pub peer_protocol: Option<i64>,
    pub capabilities: Vec<String>,
    pub compatibility: &'static str,
    pub missing_capabilities: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub high_latency: bool,
    pub last_ok_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i64,
    pub pending_attempt_id: Option<String>,
    pub pending_expires_at: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
    pub grants: LinkGrantsView,
    pub exports: Vec<PeerExport>,
    pub mounts: Vec<PeerMount>,
    pub transcode_worker: Option<TranscodeWorker>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpointReq {
    pub endpoint: String,
    #[serde(default)]
    pub wg_port: Option<u16>,
}

fn build_link_view(
    conn: &rusqlite::Connection,
    link: PeerLink,
    rtt_warn_ms: f64,
    now_ts: i64,
) -> PeerLinkView {
    let parsed_caps: Vec<String> = link
        .capabilities
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();
    let compat = evaluate_compatibility(link.peer_protocol, &parsed_caps);
    let grants = super::grants::load_link_grants_view(conn, &link.id).unwrap_or(LinkGrantsView {
        inbound: None,
        outbound: None,
    });
    let exports = db_peers::list_peer_exports_for_link(conn, &link.id).unwrap_or_default();
    let mounts = db_peers::list_peer_mounts_for_link(conn, &link.id).unwrap_or_default();
    let transcode_worker = db_peers::get_transcode_worker(conn, &link.id)
        .ok()
        .flatten();
    let high_latency = link.rtt_ms.is_some_and(|r| r > rtt_warn_ms);
    let state = public_link_state(&link.state).to_string();
    let pending_pairing = state == "pending"
        && link.pending_attempt_id.is_some()
        && has_active_pending_expiry(link.pending_expires_at, now_ts);

    PeerLinkView {
        id: link.id,
        name: link.name,
        wg_pubkey: link.wg_pubkey,
        tunnel_ip: link.tunnel_ip,
        endpoint: link.endpoint,
        wg_port: link.wg_port,
        state,
        peer_version: link.peer_version,
        peer_protocol: link.peer_protocol,
        capabilities: parsed_caps,
        compatibility: compat.status.as_str(),
        missing_capabilities: compat.missing_capabilities,
        rtt_ms: link.rtt_ms,
        high_latency,
        last_ok_at: link.last_ok_at,
        last_error: link.last_error,
        consecutive_failures: link.consecutive_failures,
        pending_attempt_id: link.pending_attempt_id.filter(|_| pending_pairing),
        pending_expires_at: link.pending_expires_at.filter(|_| pending_pairing),
        created_at: link.created_at,
        updated_at: link.updated_at,
        grants,
        exports,
        mounts,
        transcode_worker,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/peers
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_peers(State(runtime): State<Arc<PeerRuntime>>) -> Response {
    let server = runtime.local_server_name();
    let now_ts = runtime.now().timestamp();
    let rtt_warn_ms = runtime.rtt_warn_ms;
    let listen_port = runtime.listen_port;
    let detected_endpoints = detect_local_endpoints();

    let res = runtime
        .db
        .read(&server, "list_peers", move |conn| {
            let identity = db_peers::get_peer_identity(conn).map_err(|err| {
                PeerError::internal(
                    "local",
                    "list_peers",
                    format!("Failed loading peer identity: {err}"),
                )
            })?;
            let links = db_peers::list_peer_links(conn).map_err(|err| {
                PeerError::internal(
                    "local",
                    "list_peers",
                    format!("Failed listing peer links: {err}"),
                )
            })?;
            let peer_views: Vec<PeerLinkView> = links
                .into_iter()
                .map(|link| build_link_view(conn, link, rtt_warn_ms, now_ts))
                .collect();

            let open_windows: Vec<serde_json::Value> = db_peers::list_pairing_windows(conn)
                .unwrap_or_default()
                .into_iter()
                .filter(|w| w.consumed_at.is_none() && is_active_expiry(w.expires_at, now_ts))
                .map(|w| {
                    serde_json::json!({
                        "id": w.id,
                        "expires_at": w.expires_at,
                    })
                })
                .collect();

            let local_pubkey = identity.as_ref().map(|i| i.wg_pubkey.clone());
            let pending_attempts: Vec<serde_json::Value> = db_peers::list_pairing_attempts(conn)
                .unwrap_or_default()
                .into_iter()
                .filter(|a| {
                    matches!(a.status.as_str(), "pending" | "confirming")
                        && is_active_expiry(a.expires_at, now_ts)
                })
                .map(|a| {
                    let comparison_code =
                        match (a.remote_pubkey.as_deref(), local_pubkey.as_deref()) {
                            (Some(a_pk), Some(b_pk)) => Some(derive_comparison_code(a_pk, b_pk)),
                            _ => None,
                        };
                    serde_json::json!({
                        "id": a.id,
                        "window_id": a.window_id,
                        "remote_name": a.remote_name,
                        "remote_pubkey": a.remote_pubkey,
                        "remote_tunnel_ip": a.remote_tunnel_ip,
                        "remote_endpoint": a.remote_endpoint,
                        "source_ip": a.source_ip,
                        "status": a.status,
                        "comparison_code": comparison_code,
                        "expires_at": a.expires_at,
                        "created_at": a.created_at,
                    })
                })
                .collect();

            let identity_json = identity.map(|id| {
                serde_json::json!({
                    "wg_pubkey": id.wg_pubkey,
                    "tunnel_ip": id.tunnel_ip,
                    "wg_port": id.wg_port,
                    "listen_port": listen_port,
                    "created_at": id.created_at,
                })
            });

            Ok(serde_json::json!({
                "identity": identity_json,
                "peer_protocol": PEER_PROTOCOL_VERSION,
                "capabilities": capabilities(),
                "rtt_warn_ms": rtt_warn_ms,
                "peers": peer_views,
                "pairing_windows": open_windows,
                "pairing_attempts": pending_attempts,
                "detected_endpoints": detected_endpoints,
            }))
        })
        .await;

    match res {
        Ok(val) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/v1/admin/peers/:id/endpoint
// ─────────────────────────────────────────────────────────────────────────────

pub async fn update_peer_endpoint(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    Json(req): Json<UpdateEndpointReq>,
) -> Response {
    match update_peer_endpoint_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, req).await {
        Ok(val) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn update_peer_endpoint_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    req: UpdateEndpointReq,
) -> Result<serde_json::Value, PeerError> {
    let server = runtime.local_server_name();
    let step = "update_peer_endpoint";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let endpoint = validate_endpoint_host(&req.endpoint, &server, step)?;
    if req.wg_port == Some(0) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "WireGuard port must be between 1 and 65535",
            "Provide a valid UDP port",
        ));
    }

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c = link_id.to_string();
    let pre_now_ts = runtime.now().timestamp();
    let server_c = server.clone();
    let link = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&link.state) {
                return Err(PeerError::link_revoked(
                    &link.name,
                    step,
                    format!("Cannot update endpoint for revoked link '{}'", link.name),
                ));
            }
            if is_pending_link_state(&link.state) {
                ensure_active_pending_link_row(conn, &link, pre_now_ts, &link.name, step)?;
            } else if !is_live_link_state(&link.state) {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot update endpoint for link '{}' in state '{}'",
                        link.name, link.state
                    ),
                    "Refresh the Cluster page and inspect the link state",
                ));
            }
            Ok(link)
        })
        .await?;

    let port = req.wg_port.unwrap_or(link.wg_port);
    runtime
        .runner
        .dispatch(&PeerNetworkRequest::SetEndpoint {
            pubkey: link.wg_pubkey.clone(),
            endpoint: endpoint.clone(),
            port,
        })
        .await
        .and_then(|resp| resp.into_mutation())
        .map_err(|err| map_runner_error(err, &link.name, step))?;

    let link_id_s = link.id.clone();
    let wg_pubkey_s = link.wg_pubkey.clone();
    let tunnel_ip_s = link.tunnel_ip.clone();
    let endpoint_s = endpoint.clone();
    let clock = Arc::clone(&runtime.clock);
    let rtt_warn_ms = runtime.rtt_warn_ms;
    let server_c = server.clone();

    let (view, committed_name) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        "update_peer_endpoint",
                        format!("Failed starting endpoint update transaction: {err}"),
                    )
                },
            )?;
            let commit_now = clock();
            let commit_now_ts = commit_now.timestamp();
            let updated_at = commit_now.to_rfc3339();
            let changed = tx
                .execute(
                    "UPDATE peer_links \
                     SET endpoint = ?4, wg_port = ?5, updated_at = ?6 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND ( \
                           state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                           OR ( \
                               state IN ('pending', 'pending_owned') \
                               AND pending_expires_at IS NOT NULL \
                               AND pending_expires_at != 0 \
                               AND pending_expires_at > ?7 \
                               AND ( \
                                   pending_attempt_id IS NULL \
                                   OR NOT EXISTS ( \
                                       SELECT 1 FROM peer_pairing_attempts \
                                       WHERE id = peer_links.pending_attempt_id \
                                         AND ( \
                                             status NOT IN ('pending', 'confirming') \
                                             OR expires_at = 0 \
                                             OR expires_at <= ?7 \
                                         ) \
                                   ) \
                               ) \
                           ) \
                       )",
                    params![
                        link_id_s,
                        wg_pubkey_s,
                        tunnel_ip_s,
                        endpoint_s,
                        port,
                        updated_at,
                        commit_now_ts,
                    ],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        "update_peer_endpoint",
                        format!("Failed saving updated peer endpoint: {err}"),
                    )
                })?;

            if changed != 1 {
                let current = db_peers::get_peer_link(&tx, &link_id_s).map_err(|err| {
                    PeerError::internal(&server_c, "update_peer_endpoint", err.to_string())
                })?;
                return match current {
                    None => Err(PeerError::not_found(
                        &server_c,
                        "update_peer_endpoint",
                        "Peer link was removed before endpoint update completed",
                    )),
                    Some(cur) if is_revoked_or_revoking_state(&cur.state) => {
                        Err(PeerError::link_revoked(
                            &cur.name,
                            "update_peer_endpoint",
                            format!("Cannot update endpoint for revoked link '{}'", cur.name),
                        ))
                    }
                    Some(cur) if is_pending_link_state(&cur.state) => {
                        ensure_active_pending_link_row(
                            &tx,
                            &cur,
                            commit_now_ts,
                            &cur.name,
                            "update_peer_endpoint",
                        )?;
                        Err(PeerError::conflict(
                            &server_c,
                            "update_peer_endpoint",
                            "Peer link identity or state changed concurrently during endpoint update",
                            "Refresh the Cluster page and retry updating the endpoint",
                        ))
                    }
                    Some(_) => Err(PeerError::conflict(
                        &server_c,
                        "update_peer_endpoint",
                        "Peer link identity or state changed concurrently during endpoint update",
                        "Refresh the Cluster page and retry updating the endpoint",
                    )),
                };
            }

            let refreshed = db_peers::get_peer_link(&tx, &link_id_s)
                .map_err(|err| {
                    PeerError::internal(&server_c, "update_peer_endpoint", err.to_string())
                })?
                .ok_or_else(|| {
                    PeerError::not_found(&server_c, "update_peer_endpoint", "Peer link missing")
                })?;
            let committed_name = refreshed.name.clone();
            let view = build_link_view(&tx, refreshed, rtt_warn_ms, commit_now_ts);
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    "update_peer_endpoint",
                    format!("Failed committing endpoint update: {err}"),
                )
            })?;
            Ok((view, committed_name))
        })
        .await?;

    drop(_link_guard);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_endpoint_updated".to_string(),
            "peer_link".to_string(),
            link.id.clone(),
            format!(
                "Updated endpoint for '{}' to {endpoint}:{port}",
                committed_name
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(serde_json::json!({
        "peer": view,
        "updated": true,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified Revocation Invalidation & Retryable Resource Cleanup
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteRevocationTrigger {
    RevokeNotice,
    HealthCheck,
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteRevocationOutcome {
    pub(crate) notice_message: String,
}

/// Deletes held outbound link & grant credentials for `link_id`, verifying the typed runner
/// deletion acknowledgement and treating `NotFound` as already absent.
async fn delete_link_credentials_verified(
    runtime: &PeerRuntime,
    link_id: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    if !is_valid_credential_id(link_id) {
        return Ok(());
    }
    match runtime
        .runner
        .dispatch(&PeerNetworkRequest::DeleteLinkCredentials {
            link_id: link_id.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let ack = resp
                .into_link_credentials_deleted()
                .map_err(|err| map_runner_error(err, server, step))?;
            if ack.link_id != link_id {
                return Err(map_runner_error(
                    PeerNetworkError::Runtime(
                        "Runner did not confirm peer link credential deletion for the requested link"
                            .into(),
                    ),
                    server,
                    step,
                ));
            }
            Ok(())
        }
        Err(PeerNetworkError::NotFound(_)) => Ok(()),
        Err(err) => Err(map_runner_error(err, server, step)),
    }
}

/// Deletes the temporary `PendingIssuerToken` for `link_id`, verifying the typed runner deletion
/// acknowledgement and treating `NotFound` as already absent.
async fn delete_pending_issuer_credential_verified(
    runtime: &PeerRuntime,
    link_id: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    let cred_id = pending_issuer_credential_id(link_id);
    match runtime
        .runner
        .dispatch(&PeerNetworkRequest::DeleteCredential {
            slot: PeerCredentialSlot::PendingIssuerToken,
            id: cred_id.clone(),
        })
        .await
    {
        Ok(resp) => {
            let ack = resp
                .into_credential_deleted()
                .map_err(|err| map_runner_error(err, server, step))?;
            if ack.slot != PeerCredentialSlot::PendingIssuerToken || ack.id != cred_id {
                return Err(map_runner_error(
                    PeerNetworkError::Runtime(
                        "Runner did not confirm pending issuer credential deletion".into(),
                    ),
                    server,
                    step,
                ));
            }
            Ok(())
        }
        Err(PeerNetworkError::NotFound(_)) => Ok(()),
        Err(err) => Err(map_runner_error(err, server, step)),
    }
}

/// Removes owned WireGuard peer (strictly when durable affirmative ownership holds) and all
/// runner-managed credentials for a currently owned `revoked*` or `revoking*` link row.
/// Caller must hold `runtime.lock_link(link_id)`.
async fn cleanup_revoked_link_resources_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    expected_pubkey: &str,
    peer_name: &str,
    step: &str,
) -> Result<bool, PeerError> {
    let server = runtime.local_server_name();
    let link_id_c = link_id.to_string();
    let expected_pk_c = expected_pubkey.to_string();

    let revoked_link = runtime
        .db
        .read(&server, step, move |conn| {
            let current = db_peers::get_peer_link(conn, &link_id_c).map_err(|err| {
                PeerError::internal("local", "revocation_cleanup", err.to_string())
            })?;
            let Some(row) = current else {
                return Ok(None);
            };
            if row.wg_pubkey != expected_pk_c || !is_revoked_or_revoking_state(&row.state) {
                return Ok(None);
            }
            let other_owner_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM peer_links WHERE wg_pubkey = ?1 AND id != ?2",
                    params![expected_pk_c, link_id_c],
                    |r| r.get(0),
                )
                .map_err(|err| {
                    PeerError::internal("local", "revocation_cleanup", err.to_string())
                })?;
            if other_owner_count != 0 {
                return Ok(None);
            }
            Ok(Some(row))
        })
        .await?;

    let Some(link) = revoked_link else {
        return Ok(false);
    };

    super::grants::delete_revoked_link_staged_grant_credentials_locked(
        runtime, link_id, peer_name, step,
    )
    .await?;
    delete_link_credentials_verified(runtime, link_id, peer_name, step).await?;
    delete_pending_issuer_credential_verified(runtime, link_id, peer_name, step).await?;
    remove_owned_wg_peer_locked(runtime, &link, step).await?;
    Ok(true)
}

/// Unified remote revocation path shared by `POST /peer/v1/revoke-notice` and health
/// `LINK_REVOKED` detection.
///
/// Immediately disables incoming authorization in SQLite under identity/state guards, publishes
/// `RevocationEvent`, emits notification and audit entry strictly on committed transition, and
/// cleans up the owned WireGuard peer and credentials (persisting `pending_expires_at = 0` for
/// retry on transient runner failure).
pub(crate) async fn apply_remote_revocation(
    runtime: &PeerRuntime,
    link_id: &str,
    expected_pubkey: &str,
    expected_tunnel_ip: &str,
    source_ip_for_audit: Option<&str>,
    trigger: RemoteRevocationTrigger,
) -> Result<Option<RemoteRevocationOutcome>, PeerError> {
    let server = runtime.local_server_name();
    let step = match trigger {
        RemoteRevocationTrigger::RevokeNotice => "revoke_notice",
        RemoteRevocationTrigger::HealthCheck => "health_revoke",
    };

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let link_id_c = link_id.to_string();
    let pubkey_c = expected_pubkey.to_string();
    let tunnel_ip_c = expected_tunnel_ip.to_string();
    let increment_failures = matches!(trigger, RemoteRevocationTrigger::HealthCheck);
    let now_rfc = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let committed = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting revocation transaction: {err}"),
                    )
                },
            )?;

            let current_name: Option<String> = tx
                .query_row(
                    "SELECT name FROM peer_links \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned')",
                    params![link_id_c, pubkey_c, tunnel_ip_c],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed reading link for revocation: {err}"),
                    )
                })?;

            let Some(peer_name) = current_name else {
                return Ok(None);
            };
            let notice_message = format!("Link revoked by {peer_name}");

            let changed = tx
                .execute(
                    "UPDATE peer_links SET \
                        state = CASE state \
                            WHEN 'active' THEN 'revoked' \
                            WHEN 'down' THEN 'revoked' \
                            WHEN 'active_unowned' THEN 'revoked_unowned' \
                            WHEN 'down_unowned' THEN 'revoked_unowned' \
                        END, \
                        inbound_token_hash = NULL, \
                        pending_attempt_id = NULL, \
                        pending_expires_at = 0, \
                        last_error = ?4, \
                        consecutive_failures = CASE \
                            WHEN ?5 AND consecutive_failures < 9223372036854775807 THEN consecutive_failures + 1 \
                            ELSE consecutive_failures \
                        END, \
                        updated_at = ?6 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned')",
                    params![
                        link_id_c,
                        pubkey_c,
                        tunnel_ip_c,
                        notice_message,
                        increment_failures,
                        now_rfc,
                    ],
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed recording revocation: {err}"),
                    )
                })?;

            if changed != 1 {
                return Ok(None);
            }
            let grant_revocation = super::grants::revoke_all_grants_for_link_revocation_in_tx(
                &tx, &link_id_c, &now_rfc, &server_c, step,
            )?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing revocation: {err}"),
                )
            })?;
            Ok(Some((peer_name, notice_message, grant_revocation)))
        })
        .await?;

    let Some((peer_name, notice_message, grant_revocation)) = committed else {
        return Ok(None);
    };

    super::grants::finalize_grant_revocation_events(runtime, &grant_revocation);

    // Publish, notify, and audit immediately after authorization is durably disabled.
    runtime.publish_revocation(RevocationEvent::LinkRevoked {
        link_id: link_id.to_string(),
        peer_name: peer_name.clone(),
    });
    runtime
        .db
        .emit_notification(
            "warning",
            format!("Peer link revoked: {peer_name}"),
            notice_message.clone(),
        )
        .await;
    let audit_detail = match trigger {
        RemoteRevocationTrigger::RevokeNotice => notice_message.clone(),
        RemoteRevocationTrigger::HealthCheck => {
            format!("{notice_message} (detected via tunnel health check)")
        }
    };
    runtime
        .db
        .record_audit(
            0,
            format!("peer-{peer_name}"),
            "peer_link_revoked_by_remote".to_string(),
            "peer_link".to_string(),
            link_id.to_string(),
            audit_detail,
            source_ip_for_audit
                .unwrap_or(expected_tunnel_ip)
                .to_string(),
            String::new(),
        )
        .await;

    // Reliably remove only the owned WireGuard peer and credentials; keep `pending_expires_at = 0`
    // on transient error so periodic sweeps or re-pairing retry cleanup until complete.
    match cleanup_revoked_link_resources_locked(runtime, link_id, expected_pubkey, &peer_name, step)
        .await
    {
        Ok(true) => {
            let clear_id = link_id.to_string();
            let clear_pk = expected_pubkey.to_string();
            let clear_ts = runtime.now().to_rfc3339();
            let _ = runtime
                .db
                .write(&server, step, move |conn| {
                    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                        .map_err(|err| {
                            PeerError::internal("local", "revocation_cleanup", err.to_string())
                        })?;
                    let changed = tx
                        .execute(
                            "UPDATE peer_links SET pending_expires_at = NULL, updated_at = ?3 \
                             WHERE id = ?1 AND wg_pubkey = ?2 \
                               AND state IN ('revoked', 'revoked_unowned') AND pending_expires_at = 0",
                            params![clear_id, clear_pk, clear_ts],
                        )
                        .map_err(|err| {
                            PeerError::internal("local", "revocation_cleanup", err.to_string())
                        })?;
                    if changed == 1 {
                        let _ = db_peers::clear_peer_received_grant_cleanups_for_link(
                            &tx, &clear_id,
                        );
                    }
                    let _ = tx.commit();
                    Ok(())
                })
                .await;
        }
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(
                link_id = %link_id,
                %error,
                "Transient runner error during remote revocation cleanup; retained durable retry state"
            );
        }
    }

    Ok(Some(RemoteRevocationOutcome { notice_message }))
}

/// Retries incomplete revocation cleanup for a link in `revoking` state (admin delete) or
/// `revoked` state with `pending_expires_at IS NOT NULL` (remote/health revocation).
pub(crate) async fn retry_revocation_cleanup(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let step = "revocation_cleanup_retry";
    let _link_guard = runtime.lock_link(link_id, step).await?;

    let id_c = link_id.to_string();
    let current = runtime
        .db
        .read(&server, step, move |conn| {
            db_peers::get_peer_link(conn, &id_c).map_err(|err| {
                PeerError::internal("local", "revocation_cleanup_retry", err.to_string())
            })
        })
        .await?;

    let Some(link) = current else {
        return Ok(());
    };

    if is_revoking_state(&link.state) {
        if cleanup_revoked_link_resources_locked(
            runtime,
            &link.id,
            &link.wg_pubkey,
            &link.name,
            step,
        )
        .await?
        {
            let del_id = link.id.clone();
            let del_pk = link.wg_pubkey.clone();
            runtime
                .db
                .write(&server, step, move |conn| {
                    conn.execute(
                        "DELETE FROM peer_links \
                         WHERE id = ?1 AND state IN ('revoking', 'revoking_unowned') AND wg_pubkey = ?2",
                        params![del_id, del_pk],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            "local",
                            "revocation_cleanup_retry",
                            format!("Failed deleting finalized revoking peer link: {err}"),
                        )
                    })?;
                    Ok(())
                })
                .await?;
        }
        return Ok(());
    }

    if is_revoked_state(&link.state)
        && link.pending_expires_at.is_some()
        && cleanup_revoked_link_resources_locked(
            runtime,
            &link.id,
            &link.wg_pubkey,
            &link.name,
            step,
        )
        .await?
    {
        let upd_id = link.id.clone();
        let upd_pk = link.wg_pubkey.clone();
        let now_rfc = runtime.now().to_rfc3339();
        runtime
            .db
            .write(&server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                    |err| {
                        PeerError::internal(
                            "local",
                            "revocation_cleanup_retry",
                            format!("Failed starting revocation cleanup clear transaction: {err}"),
                        )
                    },
                )?;
                let changed = tx
                    .execute(
                        "UPDATE peer_links SET pending_expires_at = NULL, updated_at = ?3 \
                         WHERE id = ?1 AND state IN ('revoked', 'revoked_unowned') \
                           AND wg_pubkey = ?2 AND pending_expires_at IS NOT NULL",
                        params![upd_id, upd_pk, now_rfc],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            "local",
                            "revocation_cleanup_retry",
                            format!("Failed clearing revocation cleanup marker: {err}"),
                        )
                    })?;
                if changed == 1 {
                    db_peers::clear_peer_received_grant_cleanups_for_link(&tx, &upd_id).map_err(
                        |err| {
                            PeerError::internal(
                                "local",
                                "revocation_cleanup_retry",
                                format!("Failed clearing received grant cleanup entries: {err}"),
                            )
                        },
                    )?;
                }
                tx.commit().map_err(|err| {
                    PeerError::internal(
                        "local",
                        "revocation_cleanup_retry",
                        format!("Failed committing revocation cleanup clear: {err}"),
                    )
                })?;
                Ok(())
            })
            .await?;
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/admin/peers/:id (Revoke Link)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn delete_peer(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
) -> Response {
    match delete_peer_inner(&runtime, &auth_user, peer_ip, &headers, &link_id).await {
        Ok(val) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn delete_peer_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
) -> Result<serde_json::Value, PeerError> {
    let server = runtime.local_server_name();
    let step = "revoke_peer_link";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    // Handle pending links under canonical lock ordering (attempt_lock -> link_lock).
    loop {
        let id_c = link_id.to_string();
        let snapshot = runtime
            .db
            .read(&server, step, move |conn| {
                db_peers::get_peer_link(conn, &id_c).map_err(|err| {
                    PeerError::internal("local", "revoke_peer_link", err.to_string())
                })
            })
            .await?
            .ok_or_else(|| PeerError::not_found(&server, step, "Peer link was not found"))?;

        if !is_pending_link_state(&snapshot.state) {
            break;
        }

        let _attempt_guard = match snapshot.pending_attempt_id.as_deref() {
            Some(att_id) => Some(runtime.lock_attempt(att_id, step).await?),
            None => None,
        };
        let _link_guard = runtime.lock_link(link_id, step).await?;

        let id_c2 = link_id.to_string();
        let current = runtime
            .db
            .read(&server, step, move |conn| {
                db_peers::get_peer_link(conn, &id_c2).map_err(|err| {
                    PeerError::internal("local", "revoke_peer_link", err.to_string())
                })
            })
            .await?
            .ok_or_else(|| PeerError::not_found(&server, step, "Peer link was not found"))?;

        if !is_pending_link_state(&current.state) {
            break;
        }
        if current.pending_attempt_id != snapshot.pending_attempt_id {
            continue;
        }

        let cleaned = cleanup_pending_link_locked(
            runtime,
            &current.id,
            &current.wg_pubkey,
            current.pending_attempt_id.as_deref(),
            "cancelled",
            None,
        )
        .await?;

        drop(_link_guard);
        drop(_attempt_guard);

        if cleaned {
            runtime.publish_revocation(RevocationEvent::LinkRevoked {
                link_id: current.id.clone(),
                peer_name: current.name.clone(),
            });
            let client_ip = extract_client_ip_for_peer(headers, peer_ip);
            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_pairing_cancelled".to_string(),
                    "peer_link".to_string(),
                    current.id.clone(),
                    format!("Cancelled pending link with '{}'", current.name),
                    client_ip,
                    String::new(),
                )
                .await;
        }

        return Ok(serde_json::json!({
            "revoked": true,
            "link_id": current.id,
            "name": current.name,
            "notice_delivered": false,
        }));
    }

    // Phase A: Under link_lock, immediately disable incoming authorization and persist
    // durable `revoking` state before any network or runner call.
    let (link, prev_state, transitioned, grant_revocation) = {
        let _link_guard = runtime.lock_link(link_id, step).await?;
        let id_c = link_id.to_string();
        let now_rfc = runtime.now().to_rfc3339();
        let server_c = server.clone();

        runtime
            .db
            .write(&server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed starting link revocation transaction: {err}"),
                        )
                    },
                )?;
                let Some(link) = db_peers::get_peer_link(&tx, &id_c)
                    .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                else {
                    return Err(PeerError::not_found(
                        &server_c,
                        step,
                        "Peer link was not found",
                    ));
                };
                if is_pending_link_state(&link.state) {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Peer link state changed concurrently",
                        "Retry the delete request",
                    ));
                }
                let prev_state = link.state.clone();
                let changed = tx
                    .execute(
                        "UPDATE peer_links SET \
                            state = CASE state \
                                WHEN 'active' THEN 'revoking' \
                                WHEN 'down' THEN 'revoking' \
                                WHEN 'revoked' THEN 'revoking' \
                                WHEN 'revoking' THEN 'revoking' \
                                WHEN 'active_unowned' THEN 'revoking_unowned' \
                                WHEN 'down_unowned' THEN 'revoking_unowned' \
                                WHEN 'revoked_unowned' THEN 'revoking_unowned' \
                                WHEN 'revoking_unowned' THEN 'revoking_unowned' \
                            END, \
                            inbound_token_hash = NULL, \
                            pending_attempt_id = NULL, \
                            pending_expires_at = 0, \
                            updated_at = ?3 \
                         WHERE id = ?1 AND wg_pubkey = ?2 \
                           AND state IN (\
                               'active', 'down', 'revoked', 'revoking', \
                               'active_unowned', 'down_unowned', 'revoked_unowned', 'revoking_unowned'\
                           )",
                        params![link.id, link.wg_pubkey, now_rfc],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed disabling peer link authorization: {err}"),
                        )
                    })?;
                if changed != 1 {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Peer link changed concurrently during revocation",
                        "Refresh the Cluster page and retry",
                    ));
                }
                let grant_revocation = super::grants::revoke_all_grants_for_link_revocation_in_tx(
                    &tx, &link.id, &now_rfc, &server_c, step,
                )?;
                tx.commit().map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed committing revocation invalidation: {err}"),
                    )
                })?;
                let first_transition = !is_revoking_state(&prev_state);
                Ok((link, prev_state, first_transition, grant_revocation))
            })
            .await?
    };

    super::grants::finalize_grant_revocation_events(runtime, &grant_revocation);

    let was_live = is_live_link_state(&prev_state);
    let client_ip = extract_client_ip_for_peer(headers, peer_ip);

    // Publish and audit immediately on committed revocation/removal transition so downstream
    // consumers stop flows and audit trails are preserved even if Phase C runner cleanup fails
    // transiently and must be retried.
    if was_live {
        runtime.publish_revocation(RevocationEvent::LinkRevoked {
            link_id: link.id.clone(),
            peer_name: link.name.clone(),
        });
        runtime
            .db
            .record_audit(
                auth_user.user_id,
                auth_user.username.clone(),
                "peer_link_revoked".to_string(),
                "peer_link".to_string(),
                link.id.clone(),
                format!("Revoked peer link '{}'", link.name),
                client_ip,
                String::new(),
            )
            .await;
    } else if transitioned {
        runtime
            .db
            .record_audit(
                auth_user.user_id,
                auth_user.username.clone(),
                "peer_link_revoked".to_string(),
                "peer_link".to_string(),
                link.id.clone(),
                format!("Removed previously revoked peer link '{}'", link.name),
                client_ip,
                String::new(),
            )
            .await;
    }

    // Phase B: Best-effort authenticated revoke notice with NO shared lock held (prevents
    // mutual-revocation deadlock if both peers revoke each other simultaneously).
    let mut notice_delivered = false;
    if was_live {
        if let Ok(read_resp) = runtime
            .runner
            .dispatch(&PeerNetworkRequest::ReadCredential {
                slot: PeerCredentialSlot::LinkToken,
                id: link.id.clone(),
            })
            .await
            .and_then(|resp| resp.into_credential_read())
        {
            if let Some(held_token) = read_resp.into_secret() {
                let notice_body = serde_json::to_vec(&serde_json::json!({
                    "reason": "revoked_by_admin",
                    "server": server,
                }))
                .unwrap_or_default();
                if let Ok((status, _, _)) = runtime
                    .send_tunnel_request(
                        Method::POST,
                        &link.tunnel_ip,
                        "/peer/v1/revoke-notice",
                        Some(&held_token),
                        Some(notice_body),
                        REVOKE_NOTICE_TIMEOUT,
                    )
                    .await
                {
                    notice_delivered = status.is_success();
                }
            }
        }
    }

    // Phase C: Re-acquire link_lock and reliably clean up owned WireGuard peer and credentials.
    // On transient runner error, propagate failure while retaining durable `revoking` ownership
    // in SQLite so retries or the health sweep complete cleanup.
    {
        let _link_guard = runtime.lock_link(&link.id, step).await?;
        let cleaned = cleanup_revoked_link_resources_locked(
            runtime,
            &link.id,
            &link.wg_pubkey,
            &link.name,
            step,
        )
        .await?;

        if cleaned {
            let del_id = link.id.clone();
            let del_pk = link.wg_pubkey.clone();
            runtime
                .db
                .write(&server, step, move |conn| {
                    conn.execute(
                        "DELETE FROM peer_links \
                         WHERE id = ?1 AND state IN ('revoking', 'revoking_unowned') AND wg_pubkey = ?2",
                        params![del_id, del_pk],
                    )
                    .map_err(|err| {
                        PeerError::internal(
                            "local",
                            "revoke_peer_link",
                            format!("Failed deleting peer link: {err}"),
                        )
                    })?;
                    Ok(())
                })
                .await?;
        }
    }

    Ok(serde_json::json!({
        "revoked": true,
        "link_id": link.id,
        "name": link.name,
        "notice_delivered": notice_delivered,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunnel Listener Link Routes: GET /peer/v1/link & POST /peer/v1/revoke-notice
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn handle_tunnel_link_view(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let (auth, _permit) =
        match authenticate_active_link(&runtime, connect_info, &headers, "GET /peer/v1/link").await
        {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "link_id": auth.link.id,
            "name": auth.link.name,
            "state": public_link_state(&auth.link.state),
            "version": runtime.local_version(),
            "peer_protocol": PEER_PROTOCOL_VERSION,
            "capabilities": capabilities(),
        })),
    )
        .into_response()
}

pub(crate) async fn handle_tunnel_revoke_notice(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let (auth, _permit) = match authenticate_active_link(
        &runtime,
        connect_info,
        &headers,
        "POST /peer/v1/revoke-notice",
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    let source_ip_str = auth.source_ip.to_string();
    match apply_remote_revocation(
        &runtime,
        &auth.link.id,
        &auth.link.wg_pubkey,
        &auth.link.tunnel_ip,
        Some(&source_ip_str),
        RemoteRevocationTrigger::RevokeNotice,
    )
    .await
    {
        Ok(Some(outcome)) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "acknowledged": true,
                "state": "revoked",
                "message": outcome.notice_message,
            })),
        )
            .into_response(),
        Ok(None) => PeerError::link_revoked(
            runtime.local_server_name(),
            "revoke_notice",
            format!("Link with '{}' has already been revoked", auth.link.name),
        )
        .into_response(),
        Err(err) => err.into_response(),
    }
}
