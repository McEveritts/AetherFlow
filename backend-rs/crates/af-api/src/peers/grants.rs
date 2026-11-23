//! Scoped peer grant lifecycle (admin CRUD + reciprocal grant offers + tunnel token/revoke/offer handlers).
//!
//! Security & Concurrency Invariants:
//! - Independent 256-bit grant tokens: issuer stores ONLY the SHA-256 digest in `peer_grants.token_hash`;
//!   receiver stores the raw secret in runner-managed `PeerCredentialSlot::GrantToken` (mode `0640`).
//! - Canonical lock ordering: receiver grant writes, revokes, and credential cleanup retries reuse
//!   `link_locks` (`runtime.lock_link`) so revalidated live link ownership surrounds all runner
//!   credential I/O and cleanup can never leave a recreated token after link revocation.
//! - Never hold `link_locks` across outbound tunnel HTTP calls (`/peer/v1/grant-token`,
//!   `/peer/v1/grant-revoke`, `/peer/v1/grant-offer`) to prevent mutual deadlock when both peers
//!   concurrently configure or revoke grants.
//! - Monotonic generation fencing (`peer_grant_epochs` on issuer + `peer_received_grants.generation`
//!   on receiver) and copy-on-write staged runner slots (`peer_received_grants.credential_id` +
//!   `peer_received_grant_cleanups`) guarantee that:
//!   1. Failed/timed-out/malformed grant delivery fails closed without activating local access,
//!      and rotations NEVER overwrite the committed `GrantToken` before SQLite commits the new
//!      pointer; crashes or failures between staging and commit leave the prior committed token
//!      untouched and clean up the orphaned staged slot on retry/restart.
//!   2. Concurrent `PUT /grant` vs `PUT /grant` or `PUT /grant` vs `DELETE /grant` cannot resurrect
//!      stale or revoked grants on either server.
//!   3. `DELETE /grant` atomically disables the inbound grant, suspends the dedicated `peer-<name>`
//!      run-as user, revokes its credentials, and preserves the underlying link token, health check,
//!      and opposite-direction (`outbound`) grant.
//!   4. `/peer/v1/grant-revoke` queues durable slot cleanup in `peer_received_grant_cleanups`
//!      atomically with revocation, verifies typed runner deletion acknowledgements, and retries
//!      safely across restarts/sweeps without allowing stale retries to delete committed slots.
//!   5. `POST /grant-offer` is purely informational and never alters grant state on either server.

use super::errors::{redact_sensitive_text, PeerError};
use super::links::{GrantSummaryView, LinkGrantsView};
use super::listener::authenticate_active_link;
use super::pairing::{
    is_valid_credential_id, map_runner_error, mint_secret_token, sha256_prefixed,
};
use super::{
    is_live_link_state, is_pending_link_state, is_revoked_or_revoking_state, is_revoked_state,
    is_revoking_state, PeerRuntime, RevocationEvent, TunnelHttpError,
};
use crate::auth::AuthUser;
use crate::ws::{extract_client_ip_for_peer, PeerIp};
use af_db::peers::{self as db_peers, AccessMap, PeerGrant, PeerReceivedGrant};
use af_runner::{PeerCredentialSecret, PeerCredentialSlot, PeerNetworkError, PeerNetworkRequest};
use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const ADMIN_GRANT_BODY_LIMIT_BYTES: usize = 8192;
const GRANT_REVOKE_NOTICE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutGrantReq {
    access: AccessMap,
}

#[derive(Serialize, Deserialize)]
struct GrantTokenDeliveryPayload {
    grant_id: String,
    run_as_user_id: i64,
    access: AccessMap,
    created_by: String,
    created_at: String,
    generation: i64,
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GrantTokenDeliveryAck {
    accepted: bool,
    grant_id: String,
    generation: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct GrantRevokePayload {
    generation: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct GrantOfferPayload {
    #[serde(default)]
    from_server: Option<String>,
    #[serde(default)]
    requested_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct GrantOfferAck {
    received: bool,
}

/// Summary of grant & run-as user revocations committed inside an IMMEDIATE SQLite transaction.
#[derive(Debug, Default)]
pub(crate) struct CommittedGrantRevocation {
    pub(crate) generation: i64,
    pub(crate) revoked_grants: Vec<PeerGrant>,
    pub(crate) revoked_user_jtis: Vec<(i64, Vec<String>)>,
}

fn zeroize_string(secret: &mut String) {
    // SAFETY: Replacing every byte with `0` keeps UTF-8 valid (`\0` is valid UTF-8).
    let bytes = unsafe { secret.as_bytes_mut() };
    for b in bytes.iter_mut() {
        // SAFETY: volatile write prevents dead-store elimination.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    secret.clear();
}

fn zeroize_vec(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        // SAFETY: volatile write prevents dead-store elimination.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    buf.clear();
}

fn format_access_summary(access: &AccessMap) -> String {
    format!(
        "services={},marketplace={},settings={},files={},users={},network={},updates={},transcoding={}",
        access.services.as_str(),
        access.marketplace.as_str(),
        access.settings.as_str(),
        access.files.as_str(),
        access.users.as_str(),
        access.network.as_str(),
        access.updates.as_str(),
        access.transcoding.as_str(),
    )
}

fn sanitize_label(raw: &str, max_len: usize) -> String {
    let redacted = redact_sensitive_text(raw.trim());
    redacted
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Loads both directional grant summaries (`inbound` from `peer_grants`, `outbound` from
/// `peer_received_grants`) for a link. Never includes tokens or digests.
pub(crate) fn load_link_grants_view(
    conn: &rusqlite::Connection,
    link_id: &str,
) -> anyhow::Result<LinkGrantsView> {
    let inbound =
        db_peers::get_active_peer_grant_for_link(conn, link_id)?.map(|g| GrantSummaryView {
            id: g.id,
            run_as_user_id: g.run_as_user_id,
            access: g.access,
            created_by: g.created_by,
            created_at: g.created_at,
        });
    let outbound = db_peers::get_active_peer_received_grant_for_link(conn, link_id)?.map(|g| {
        GrantSummaryView {
            id: g.grant_id,
            run_as_user_id: g.run_as_user_id,
            access: g.access,
            created_by: g.created_by,
            created_at: g.created_at,
        }
    });
    Ok(LinkGrantsView { inbound, outbound })
}

fn upsert_peer_user_quota_status(
    conn: &rusqlite::Connection,
    user_id: i64,
    username: &str,
    status: &str,
) -> rusqlite::Result<()> {
    if !crate::auth::table_exists(conn, "user_quotas")? {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status, source, updated_at) \
         VALUES (?1, ?2, 0, 0, ?3, 'manual', CURRENT_TIMESTAMP) \
         ON CONFLICT(user_id) DO UPDATE SET \
             username = excluded.username, \
             status = excluded.status, \
             updated_at = CURRENT_TIMESTAMP",
        params![user_id, username, status],
    )?;
    Ok(())
}

/// Provisions or reuses a dedicated `account_type = 'peer'` run-as admin account for `link_id`.
/// Newly created accounts start in `suspended` status in `user_quotas` so a failed token delivery
/// can never leave an active peer account behind.
fn ensure_peer_run_as_user_in_tx(
    tx: &rusqlite::Connection,
    link_id: &str,
    peer_name: &str,
    server: &str,
    step: &str,
) -> Result<(i64, String), PeerError> {
    // 1. Reuse an existing `account_type = 'peer'` run-as account already bound to this link's
    //    grant history (never reusing human accounts or another link's account).
    let prior_uid: Option<i64> = tx
        .query_row(
            "SELECT run_as_user_id FROM peer_grants WHERE link_id = ?1 \
             ORDER BY created_at DESC, id DESC LIMIT 1",
            params![link_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|err| {
            PeerError::internal(
                server,
                step,
                format!("Failed looking up peer run-as user: {err}"),
            )
        })?;

    if let Some(uid) = prior_uid {
        let existing: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT id, username, COALESCE(account_type, 'human') FROM users WHERE id = ?1",
                params![uid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|err| {
                PeerError::internal(
                    server,
                    step,
                    format!("Failed loading peer run-as user: {err}"),
                )
            })?;
        if let Some((id, username, account_type)) = existing {
            if account_type.eq_ignore_ascii_case("peer") {
                return Ok((id, username));
            }
        }
    }

    // 2. Choose `peer-<name>` if unused; otherwise disambiguate with link ID suffix so we never
    //    collide with an existing human user or another link's peer account.
    let base_username = format!("peer-{peer_name}");
    let short_id: String = link_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let fallback_username = format!("peer-{peer_name}-{short_id}");

    let mut chosen = None;
    for candidate in [
        base_username,
        fallback_username,
        format!(
            "peer-{peer_name}-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        ),
    ] {
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
                params![candidate],
                |r| r.get(0),
            )
            .map_err(|err| {
                PeerError::internal(
                    server,
                    step,
                    format!("Failed checking peer run-as username availability: {err}"),
                )
            })?;
        if !exists {
            chosen = Some(candidate);
            break;
        }
    }
    let username = chosen.ok_or_else(|| {
        PeerError::internal(
            server,
            step,
            "Failed allocating unique peer run-as username",
        )
    })?;

    tx.execute(
        "INSERT INTO users (username, password_hash, email, avatar_url, role, account_type) \
         VALUES (?1, '', '', '', 'admin', 'peer')",
        params![username],
    )
    .map_err(|err| {
        PeerError::internal(
            server,
            step,
            format!("Failed creating peer run-as account: {err}"),
        )
    })?;
    let user_id = tx.last_insert_rowid();
    upsert_peer_user_quota_status(tx, user_id, &username, "suspended").map_err(|err| {
        PeerError::internal(
            server,
            step,
            format!("Failed initializing peer run-as account status: {err}"),
        )
    })?;

    Ok((user_id, username))
}

/// Atomically revokes all active inbound grants for `link_id`, bumps the issuer epoch to fence
/// concurrent `PUT /grant` operations, suspends the dedicated `peer` run-as user(s), and revokes
/// any credentials associated with those run-as accounts. Does NOT modify link tokens or received
/// outbound grants.
pub(crate) fn revoke_link_inbound_grants_in_tx(
    tx: &rusqlite::Connection,
    link_id: &str,
    now_rfc: &str,
    server: &str,
    step: &str,
) -> Result<CommittedGrantRevocation, PeerError> {
    let generation =
        db_peers::bump_peer_grant_epoch_for_revoke(tx, link_id, now_rfc).map_err(|err| {
            PeerError::internal(server, step, format!("Failed advancing grant epoch: {err}"))
        })?;
    let revoked_grants = db_peers::revoke_active_peer_grants_for_link(tx, link_id, now_rfc)
        .map_err(|err| {
            PeerError::internal(
                server,
                step,
                format!("Failed revoking active peer grants: {err}"),
            )
        })?;

    // Collect every distinct `account_type = 'peer'` run-as user linked to this peer's grants so
    // idempotent revokes always guarantee the run-as user is suspended and credentials invalidated.
    let mut peer_user_ids: HashSet<i64> = revoked_grants.iter().map(|g| g.run_as_user_id).collect();
    if let Ok(mut stmt) =
        tx.prepare("SELECT DISTINCT run_as_user_id FROM peer_grants WHERE link_id = ?1")
    {
        if let Ok(rows) = stmt.query_map(params![link_id], |r| r.get::<_, i64>(0)) {
            for uid in rows.flatten() {
                peer_user_ids.insert(uid);
            }
        }
    }

    let mut revoked_user_jtis = Vec::new();
    for uid in peer_user_ids {
        let row: Option<(String, String)> = tx
            .query_row(
                "SELECT username, COALESCE(account_type, 'human') FROM users WHERE id = ?1",
                params![uid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|err| {
                PeerError::internal(
                    server,
                    step,
                    format!("Failed checking peer run-as user: {err}"),
                )
            })?;
        if let Some((username, account_type)) = row {
            if account_type.eq_ignore_ascii_case("peer") {
                upsert_peer_user_quota_status(tx, uid, &username, "suspended").map_err(|err| {
                    PeerError::internal(
                        server,
                        step,
                        format!("Failed suspending peer run-as account: {err}"),
                    )
                })?;
                let (_, jtis) =
                    crate::auth::revoke_all_user_credentials_in_tx(tx, uid).map_err(|err| {
                        PeerError::internal(
                            server,
                            step,
                            format!("Failed revoking peer run-as credentials: {err}"),
                        )
                    })?;
                if !jtis.is_empty() {
                    revoked_user_jtis.push((uid, jtis));
                }
            }
        }
    }

    Ok(CommittedGrantRevocation {
        generation,
        revoked_grants,
        revoked_user_jtis,
    })
}

/// Revokes both inbound grants (with epoch fence and run-as suspension) AND marks any received
/// outbound grant revoked with a durable credential cleanup marker inside a link-revocation
/// IMMEDIATE transaction.
pub(crate) fn revoke_all_grants_for_link_revocation_in_tx(
    tx: &rusqlite::Connection,
    link_id: &str,
    now_rfc: &str,
    server: &str,
    step: &str,
) -> Result<CommittedGrantRevocation, PeerError> {
    let outcome = revoke_link_inbound_grants_in_tx(tx, link_id, now_rfc, server, step)?;
    if let Some(received) = db_peers::get_peer_received_grant(tx, link_id).map_err(|err| {
        PeerError::internal(
            server,
            step,
            format!("Failed reading received grant during link revocation: {err}"),
        )
    })? {
        let next_gen = received.generation.saturating_add(1).max(1);
        db_peers::mark_peer_received_grant_revoked(tx, link_id, next_gen, now_rfc).map_err(
            |err| {
                PeerError::internal(
                    server,
                    step,
                    format!("Failed marking received grant revoked during link revocation: {err}"),
                )
            },
        )?;
    }
    Ok(outcome)
}

/// Publishes post-commit credential revocation cache invalidations and `RevocationEvent::GrantRevoked`.
pub(crate) fn finalize_grant_revocation_events(
    runtime: &PeerRuntime,
    committed: &CommittedGrantRevocation,
) {
    for (uid, jtis) in &committed.revoked_user_jtis {
        crate::auth::finalize_user_credential_revocation(*uid, jtis);
    }
    for grant in &committed.revoked_grants {
        runtime.publish_revocation(RevocationEvent::GrantRevoked {
            link_id: grant.link_id.clone(),
            grant_id: grant.id.clone(),
            run_as_user_id: grant.run_as_user_id,
        });
    }
}

fn map_remote_grant_error(
    status: StatusCode,
    body: &[u8],
    peer_name: &str,
    step: &str,
) -> PeerError {
    let parsed = PeerError::from_remote_http(status, body, peer_name, step);
    match parsed {
        PeerError::PeerRouteUnclassified(_) => PeerError::version_incompatible(
            peer_name,
            step,
            format!(
                "'{peer_name}' does not support scoped grants yet (missing 'grants' capability)"
            ),
        ),
        other => other,
    }
}

fn map_tunnel_http_error(err: TunnelHttpError, peer_name: &str, step: &str) -> PeerError {
    match err {
        TunnelHttpError::Timeout(msg) => PeerError::handshake_timeout(peer_name, step, msg),
        TunnelHttpError::Unreachable(msg) => PeerError::link_down(peer_name, step, msg),
        TunnelHttpError::InvalidTarget(msg) => PeerError::invalid_request(
            peer_name,
            step,
            msg,
            "Verify the peer link tunnel IP and WireGuard state before retrying",
        ),
    }
}

async fn read_held_link_token(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_name: &str,
    step: &str,
) -> Result<PeerCredentialSecret, PeerError> {
    let read_resp = runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: link_id.to_string(),
        })
        .await
        .and_then(|resp| resp.into_credential_read())
        .map_err(|err| map_runner_error(err, peer_name, step))?;
    read_resp.into_secret().ok_or_else(|| {
        PeerError::unauthorized(
            peer_name,
            step,
            format!("Held link credential for '{peer_name}' is missing; re-pair the link"),
        )
    })
}

async fn clear_aborted_grant_op(
    runtime: &PeerRuntime,
    link_id: &str,
    generation: i64,
    op_id: &str,
) {
    let server = runtime.local_server_name();
    let link_id_s = link_id.to_string();
    let op_id_s = op_id.to_string();
    let now_rfc = runtime.now().to_rfc3339();
    let _ = runtime
        .db
        .write(&server, "abort_grant_op", move |conn| {
            let _ = db_peers::clear_peer_grant_op_if_matches(
                conn, &link_id_s, generation, &op_id_s, &now_rfc,
            );
            Ok(())
        })
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/peers/:id/grant
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_peer_grant(
    State(runtime): State<Arc<PeerRuntime>>,
    Path(link_id): Path<String>,
) -> Response {
    match get_peer_grant_inner(&runtime, &link_id).await {
        Ok(view) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(view),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn get_peer_grant_inner(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<LinkGrantsView, PeerError> {
    let server = runtime.local_server_name();
    let step = "get_peer_grant";
    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let id_c = link_id.to_string();
    let server_c = server.clone();
    runtime
        .db
        .read(&server, step, move |conn| {
            let _link = db_peers::get_peer_link(conn, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            load_link_grants_view(conn, &id_c).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed loading grant state: {err}"),
                )
            })
        })
        .await
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/v1/admin/peers/:id/grant
// ─────────────────────────────────────────────────────────────────────────────

pub async fn put_peer_grant(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match put_peer_grant_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(view) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(view),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn put_peer_grant_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<LinkGrantsView, PeerError> {
    let server = runtime.local_server_name();
    let step = "put_peer_grant";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }
    if raw_body.len() > ADMIN_GRANT_BODY_LIMIT_BYTES {
        return Err(PeerError::payload_too_large(
            &server,
            step,
            "Grant request body exceeds the 8 KiB limit",
            "Send only the access map payload",
        ));
    }
    let req: PutGrantReq = serde_json::from_slice(raw_body).map_err(|err| {
        PeerError::invalid_request(
            &server,
            step,
            format!("Invalid grant access payload: {err}"),
            "Send JSON {\"access\":{\"services\":\"none|read|write\",...}}",
        )
    })?;

    if !req.access.has_any_access() {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Select read or write access for at least one grant area",
            "Use DELETE /grant to revoke the existing grant",
        ));
    }

    // Phase 1 (IMMEDIATE tx, NO network, NO link_lock held across HTTP):
    // Verify live link, ensure dedicated peer run-as account, allocate grant_id + op_id + generation.
    let grant_id = Uuid::new_v4().to_string();
    let op_id = Uuid::new_v4().to_string();
    let created_at = runtime.now().to_rfc3339();
    let created_by = auth_user.username.clone();

    let id_c = link_id.to_string();
    let op_id_c = op_id.clone();
    let created_at_c = created_at.clone();
    let server_c = server.clone();

    let (link, run_as_user_id, generation) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting grant prepare transaction: {err}"),
                    )
                },
            )?;
            let link = db_peers::get_peer_link(&tx, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&link.state) {
                return Err(PeerError::link_revoked(
                    &link.name,
                    step,
                    format!("Cannot configure grant for revoked link '{}'", link.name),
                ));
            }
            if is_pending_link_state(&link.state) {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot configure grant for pending link '{}'; complete pairing first",
                        link.name
                    ),
                    "Confirm pairing before granting management access",
                ));
            }
            if !is_live_link_state(&link.state) {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot configure grant for link '{}' in state '{}'",
                        link.name, link.state
                    ),
                    "Refresh the Cluster page and check link status",
                ));
            }
            let (run_as_user_id, _run_as_username) =
                ensure_peer_run_as_user_in_tx(&tx, &link.id, &link.name, &server_c, step)?;
            let generation = db_peers::begin_peer_grant_op(&tx, &link.id, &op_id_c, &created_at_c)
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed recording grant generation fence: {err}"),
                    )
                })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing grant prepare transaction: {err}"),
                )
            })?;
            Ok((link, run_as_user_id, generation))
        })
        .await?;

    // Phase 2 (NO lock held — prevents mutual deadlock when both peers save grants simultaneously):
    // Mint fresh independent 256-bit grant token, deliver to remote over authenticated tunnel,
    // require strict confirmation {accepted: true, grant_id, generation}.
    let raw_grant_token = mint_secret_token();
    let token_hash = sha256_prefixed(raw_grant_token.expose_secret());

    let held_link_token = match read_held_link_token(runtime, &link.id, &link.name, step).await {
        Ok(tok) => tok,
        Err(err) => {
            drop(raw_grant_token);
            clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
            return Err(err);
        }
    };

    let mut delivery_payload = GrantTokenDeliveryPayload {
        grant_id: grant_id.clone(),
        run_as_user_id,
        access: req.access.clone(),
        created_by: created_by.clone(),
        created_at: created_at.clone(),
        generation,
        token: raw_grant_token.expose_secret().to_string(),
    };
    drop(raw_grant_token);

    let serialize_res = serde_json::to_vec(&delivery_payload);
    zeroize_string(&mut delivery_payload.token);
    drop(delivery_payload);

    let mut payload_bytes = match serialize_res {
        Ok(b) => b,
        Err(err) => {
            clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
            return Err(PeerError::internal(
                &server,
                step,
                format!("Failed serializing grant delivery payload: {err}"),
            ));
        }
    };

    let send_res = runtime
        .send_tunnel_request(
            Method::POST,
            &link.tunnel_ip,
            "/peer/v1/grant-token",
            Some(&held_link_token),
            Some(payload_bytes.clone()),
            runtime.tunnel_request_timeout,
        )
        .await;
    zeroize_vec(&mut payload_bytes);
    drop(held_link_token);

    let (status, resp_body, _rtt) = match send_res {
        Ok(ok) => ok,
        Err(err) => {
            clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
            return Err(map_tunnel_http_error(err, &link.name, "deliver_grant"));
        }
    };

    if !status.is_success() {
        clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
        return Err(map_remote_grant_error(
            status,
            &resp_body,
            &link.name,
            "deliver_grant",
        ));
    }

    let ack: GrantTokenDeliveryAck = match serde_json::from_slice(&resp_body) {
        Ok(parsed) => parsed,
        Err(_) => {
            clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
            return Err(PeerError::link_down(
                &link.name,
                "deliver_grant",
                format!(
                    "'{}' returned a malformed acknowledgement for grant delivery; grant was not activated",
                    link.name
                ),
            ));
        }
    };

    if !ack.accepted || ack.grant_id != grant_id || ack.generation != generation {
        clear_aborted_grant_op(runtime, &link.id, generation, &op_id).await;
        return Err(PeerError::link_down(
            &link.name,
            "deliver_grant",
            format!(
                "'{}' did not confirm grant delivery (accepted={}, id/generation match required); grant was not activated",
                link.name, ack.accepted
            ),
        ));
    }

    // Phase 3 (IMMEDIATE tx): verify link identity & epoch fence still match, activate new grant,
    // Revoke prior grants and sessions, then enable the dedicated run-as account.
    let id_c = link.id.clone();
    let expected_pk = link.wg_pubkey.clone();
    let expected_ip = link.tunnel_ip.clone();
    let op_id_c = op_id.clone();
    let grant_id_c = grant_id.clone();
    let created_by_c = created_by.clone();
    let created_at_c = created_at.clone();
    let access_c = req.access.clone();
    let commit_at = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let (view, superseded_grants, revoked_jtis) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting grant activation transaction: {err}"),
                    )
                },
            )?;
            let current_link = db_peers::get_peer_link(&tx, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::not_found(
                        &server_c,
                        step,
                        "Peer link was removed before grant activation completed",
                    )
                })?;
            if is_revoked_or_revoking_state(&current_link.state) {
                return Err(PeerError::link_revoked(
                    &current_link.name,
                    step,
                    format!(
                        "Link '{}' was revoked while grant delivery was in progress",
                        current_link.name
                    ),
                ));
            }
            if !is_live_link_state(&current_link.state)
                || current_link.wg_pubkey != expected_pk
                || current_link.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &current_link.name,
                    step,
                    "Peer link identity or state changed while grant delivery was in progress",
                    "Refresh the Cluster page and retry saving the grant",
                ));
            }

            let fence_ok = db_peers::clear_peer_grant_op_if_matches(
                &tx,
                &id_c,
                generation,
                &op_id_c,
                &commit_at,
            )
            .map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed checking grant epoch fence: {err}"),
                )
            })?;
            if !fence_ok {
                return Err(PeerError::conflict(
                    &current_link.name,
                    step,
                    "Grant was modified or revoked concurrently; stale update was discarded",
                    "Refresh the Cluster page to review the current grant state and retry if needed",
                ));
            }

            let run_as_username: String = tx
                .query_row(
                    "SELECT username FROM users WHERE id = ?1 AND COALESCE(account_type, 'human') = 'peer'",
                    params![run_as_user_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|err| {
                    PeerError::internal(&server_c, step, format!("Failed loading run-as user: {err}"))
                })?
                .ok_or_else(|| {
                    PeerError::internal(&server_c, step, "Peer run-as account disappeared during grant activation")
                })?;

            let superseded =
                db_peers::revoke_active_peer_grants_for_link(&tx, &id_c, &commit_at).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed revoking superseded peer grant: {err}"),
                        )
                    },
                )?;

            let new_grant = PeerGrant {
                id: grant_id_c,
                link_id: id_c.clone(),
                run_as_user_id,
                access: access_c.clone(),
                token_hash: Some(token_hash),
                created_by: created_by_c,
                created_at: created_at_c,
                revoked_at: None,
            };
            db_peers::insert_peer_grant(&tx, &new_grant).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed saving new peer grant: {err}"),
                )
            })?;

            upsert_peer_user_quota_status(&tx, run_as_user_id, &run_as_username, "active")
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed updating peer run-as account status: {err}"),
                    )
                })?;

            let revoked_jtis = if !superseded.is_empty() {
                crate::auth::revoke_all_user_credentials_in_tx(&tx, run_as_user_id)
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed rotating peer run-as sessions: {err}"),
                        )
                    })?
                    .1
            } else {
                Vec::new()
            };

            let view = load_link_grants_view(&tx, &id_c).map_err(|err| {
                PeerError::internal(&server_c, step, format!("Failed loading saved grant: {err}"))
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing grant activation: {err}"),
                )
            })?;
            Ok((view, superseded, revoked_jtis))
        })
        .await?;

    if !revoked_jtis.is_empty() {
        crate::auth::finalize_user_credential_revocation(run_as_user_id, &revoked_jtis);
    }
    for old in superseded_grants {
        runtime.publish_revocation(RevocationEvent::GrantRevoked {
            link_id: old.link_id,
            grant_id: old.id,
            run_as_user_id: old.run_as_user_id,
        });
    }

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_grant_updated".to_string(),
            "peer_grant".to_string(),
            grant_id,
            format!(
                "Updated inbound grant for '{}' (gen={}, {})",
                link.name,
                generation,
                format_access_summary(&req.access)
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(view)
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/admin/peers/:id/grant
// ─────────────────────────────────────────────────────────────────────────────

pub async fn delete_peer_grant(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
) -> Response {
    match delete_peer_grant_inner(&runtime, &auth_user, peer_ip, &headers, &link_id).await {
        Ok(view) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(view),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn delete_peer_grant_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
) -> Result<LinkGrantsView, PeerError> {
    let server = runtime.local_server_name();
    let step = "delete_peer_grant";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let id_c = link_id.to_string();
    let now_rfc = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let (link, committed, view) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting grant revocation transaction: {err}"),
                    )
                },
            )?;
            let link = db_peers::get_peer_link(&tx, &id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;

            let committed =
                revoke_link_inbound_grants_in_tx(&tx, &link.id, &now_rfc, &server_c, step)?;
            let view = load_link_grants_view(&tx, &link.id).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed loading grant state: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing grant revocation: {err}"),
                )
            })?;
            Ok((link, committed, view))
        })
        .await?;

    finalize_grant_revocation_events(runtime, &committed);

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    let detail = if committed.revoked_grants.is_empty() {
        format!(
            "Revoked inbound grant for '{}' (gen={}, already absent)",
            link.name, committed.generation
        )
    } else {
        format!(
            "Revoked {} active inbound grant(s) for '{}' (gen={})",
            committed.revoked_grants.len(),
            link.name,
            committed.generation
        )
    };
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_grant_revoked".to_string(),
            "peer_link".to_string(),
            link.id.clone(),
            detail,
            client_ip,
            String::new(),
        )
        .await;

    // Phase 2: best-effort revoke notice over the tunnel with NO locks held so the remote server
    // clears its `outbound` summary and held `GrantToken`. Local revocation is already durable.
    if is_live_link_state(&link.state) {
        if let Ok(held_link_token) = read_held_link_token(runtime, &link.id, &link.name, step).await
        {
            if let Ok(body) = serde_json::to_vec(&GrantRevokePayload {
                generation: committed.generation,
            }) {
                let _ = runtime
                    .send_tunnel_request(
                        Method::POST,
                        &link.tunnel_ip,
                        "/peer/v1/grant-revoke",
                        Some(&held_link_token),
                        Some(body),
                        GRANT_REVOKE_NOTICE_TIMEOUT,
                    )
                    .await;
            }
        }
    }

    Ok(view)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/peers/:id/grant-offer
// ─────────────────────────────────────────────────────────────────────────────

pub async fn send_grant_offer(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    Path(link_id): Path<String>,
    body: Bytes,
) -> Response {
    match send_grant_offer_inner(&runtime, &auth_user, peer_ip, &headers, &link_id, &body).await {
        Ok(()) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "sent": true })),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn send_grant_offer_inner(
    runtime: &PeerRuntime,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    link_id: &str,
    raw_body: &[u8],
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let step = "send_grant_offer";

    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }
    if raw_body.len() > ADMIN_GRANT_BODY_LIMIT_BYTES {
        return Err(PeerError::payload_too_large(
            &server,
            step,
            "Grant offer body exceeds allowed size",
            "Send an empty body or {}",
        ));
    }
    // Accept empty body or `{}` (empty JSON object); reject unexpected payloads cleanly.
    let trimmed_body = std::str::from_utf8(raw_body)
        .map_err(|_| {
            PeerError::invalid_request(
                &server,
                step,
                "Grant offer body must be empty or {}",
                "Omit the request body or send {}",
            )
        })?
        .trim();
    if !trimmed_body.is_empty() {
        let parsed: serde_json::Value = serde_json::from_str(trimmed_body).map_err(|_| {
            PeerError::invalid_request(
                &server,
                step,
                "Grant offer body must be empty or {}",
                "Omit the request body or send {}",
            )
        })?;
        if !parsed.as_object().is_some_and(|obj| obj.is_empty()) {
            return Err(PeerError::invalid_request(
                &server,
                step,
                "Grant offer does not accept payload fields",
                "Omit the request body or send {}",
            ));
        }
    }

    let id_c = link_id.to_string();
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
                    format!("Cannot send grant offer for revoked link '{}'", link.name),
                ));
            }
            if !is_live_link_state(&link.state) {
                return Err(PeerError::conflict(
                    &link.name,
                    step,
                    format!(
                        "Cannot send grant offer for link '{}' in state '{}'",
                        link.name, link.state
                    ),
                    "Complete pairing before inviting the remote administrator to review access",
                ));
            }
            Ok(link)
        })
        .await?;

    let held_link_token = read_held_link_token(runtime, &link.id, &link.name, step).await?;
    let payload_bytes = serde_json::to_vec(&GrantOfferPayload {
        from_server: Some(server.clone()),
        requested_by: Some(auth_user.username.clone()),
    })
    .map_err(|err| {
        PeerError::internal(
            &server,
            step,
            format!("Failed serializing grant offer payload: {err}"),
        )
    })?;

    let (status, resp_body, _rtt) = runtime
        .send_tunnel_request(
            Method::POST,
            &link.tunnel_ip,
            "/peer/v1/grant-offer",
            Some(&held_link_token),
            Some(payload_bytes),
            runtime.tunnel_request_timeout,
        )
        .await
        .map_err(|err| map_tunnel_http_error(err, &link.name, step))?;

    if !status.is_success() {
        return Err(map_remote_grant_error(status, &resp_body, &link.name, step));
    }
    if !serde_json::from_slice::<GrantOfferAck>(&resp_body).is_ok_and(|ack| ack.received) {
        return Err(PeerError::link_down(
            &link.name,
            step,
            "The peer did not confirm receipt of the grant offer",
        ));
    }

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    runtime
        .db
        .record_audit(
            auth_user.user_id,
            auth_user.username.clone(),
            "peer_grant_offer_sent".to_string(),
            "peer_link".to_string(),
            link.id.clone(),
            format!(
                "Sent informational grant review offer to '{}' (no grant state changed)",
                link.name
            ),
            client_ip,
            String::new(),
        )
        .await;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunnel Receiver Routes: /peer/v1/grant-token, /grant-revoke, /grant-offer
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn handle_tunnel_grant_token(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (auth, _permit) = match authenticate_active_link(
        &runtime,
        connect_info,
        &headers,
        "POST /peer/v1/grant-token",
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    match handle_tunnel_grant_token_inner(&runtime, &auth, &body).await {
        Ok(ack) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(ack),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

/// Allocates a fresh runner-safe staged `GrantToken` credential ID (`grant-<32 hex>`, 38 chars <= 64)
/// guaranteed distinct from `link_id` and any currently committed credential slot.
fn allocate_staged_grant_credential_id(link_id: &str, prior_cred_id: Option<&str>) -> String {
    loop {
        let candidate = format!("grant-{}", Uuid::new_v4().simple());
        if candidate != link_id && prior_cred_id != Some(candidate.as_str()) {
            return candidate;
        }
    }
}

/// Resolves the committed runner `GrantToken` credential ID for a received grant, preserving
/// compatibility with legacy rows that store the token under the canonical `link_id`.
#[allow(dead_code)]
pub(crate) fn committed_received_grant_credential_id(grant: &PeerReceivedGrant) -> &str {
    grant.effective_credential_id()
}

/// Resolves and reads the authoritative committed outbound `GrantToken` secret for `link_id`
/// under canonical `link_lock`. Intended for P6 outbound remote-management callers and tests;
/// transparently supports both copy-on-write staged slots and legacy canonical `link_id` slots.
#[allow(dead_code)]
pub(crate) async fn read_committed_received_grant_token(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<Option<(PeerReceivedGrant, PeerCredentialSecret)>, PeerError> {
    let server = runtime.local_server_name();
    let step = "read_committed_grant_token";
    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let link_id_c = link_id.to_string();
    let server_c = server.clone();
    let active_grant = runtime
        .db
        .read(&server, step, move |conn| {
            db_peers::get_active_peer_received_grant_for_link(conn, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))
        })
        .await?;

    let Some(grant) = active_grant else {
        return Ok(None);
    };
    let cred_id = committed_received_grant_credential_id(&grant);
    let secret = read_grant_token_verified(runtime, cred_id)
        .await
        .map_err(|err| map_runner_error(err, &server, step))?;
    Ok(secret.map(|s| (grant, s)))
}

fn is_definite_non_mutating_runner_error(err: &PeerNetworkError) -> bool {
    matches!(
        err,
        PeerNetworkError::Busy(_)
            | PeerNetworkError::InvalidInput(_)
            | PeerNetworkError::NotFound(_)
            | PeerNetworkError::PeerNotFound(_)
            | PeerNetworkError::PeerAlreadyExists(_)
            | PeerNetworkError::TunnelIpConflict(_)
            | PeerNetworkError::Conflict(_)
    )
}

async fn read_grant_token_verified(
    runtime: &PeerRuntime,
    credential_id: &str,
) -> Result<Option<PeerCredentialSecret>, PeerNetworkError> {
    let response = runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::GrantToken,
            id: credential_id.to_string(),
        })
        .await?;
    let read = response.into_credential_read()?;
    if read.slot != PeerCredentialSlot::GrantToken || read.id != credential_id {
        return Err(PeerNetworkError::Runtime(
            "Runner returned a mismatched peer grant credential read acknowledgement".into(),
        ));
    }
    if read.present {
        let secret = read.into_secret().ok_or_else(|| {
            PeerNetworkError::Runtime(
                "Runner reported a present peer grant credential without a secret value".into(),
            )
        })?;
        Ok(Some(secret))
    } else if read.value.is_some() {
        Err(PeerNetworkError::Runtime(
            "Runner reported an absent peer grant credential with a secret value".into(),
        ))
    } else {
        Ok(None)
    }
}

async fn write_grant_token_verified(
    runtime: &PeerRuntime,
    credential_id: &str,
    secret: &PeerCredentialSecret,
) -> Result<(), PeerNetworkError> {
    let mut write_req = PeerNetworkRequest::WriteCredential {
        slot: PeerCredentialSlot::GrantToken,
        id: credential_id.to_string(),
        value: secret.expose_secret().to_string(),
    };
    let write_res = runtime
        .runner
        .dispatch(&write_req)
        .await
        .and_then(|response| {
            let written = response.into_credential_written()?;
            if written.slot != PeerCredentialSlot::GrantToken
                || written.id != credential_id
                || !written.written
            {
                return Err(PeerNetworkError::Runtime(
                    "Runner did not confirm the peer grant credential write".into(),
                ));
            }
            Ok(())
        });
    if let PeerNetworkRequest::WriteCredential { ref mut value, .. } = write_req {
        zeroize_string(value);
    }
    write_res
}

async fn delete_grant_token_idempotent(
    runtime: &PeerRuntime,
    credential_id: &str,
    server: &str,
    step: &str,
) -> Result<(), PeerError> {
    match runtime
        .runner
        .dispatch(&PeerNetworkRequest::DeleteCredential {
            slot: PeerCredentialSlot::GrantToken,
            id: credential_id.to_string(),
        })
        .await
    {
        Ok(response) => {
            let deleted = response
                .into_credential_deleted()
                .map_err(|err| map_runner_error(err, server, step))?;
            if deleted.slot != PeerCredentialSlot::GrantToken || deleted.id != credential_id {
                return Err(map_runner_error(
                    PeerNetworkError::Runtime(
                        "Runner did not confirm the peer grant credential deletion".into(),
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

async fn delete_cleanup_row_if_matches_guarded(
    runtime: &PeerRuntime,
    link_id: &str,
    credential_id: &str,
    generation: i64,
    server: &str,
    step: &str,
) -> Result<bool, PeerError> {
    let link_id_c = link_id.to_string();
    let cred_id_c = credential_id.to_string();
    let server_c = server.to_string();
    let step_c = step.to_string();
    runtime
        .db
        .write(server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        &step_c,
                        format!("Failed starting grant cleanup clear transaction: {err}"),
                    )
                },
            )?;
            let removed = db_peers::delete_peer_received_grant_cleanup_if_matches(
                &tx, &link_id_c, &cred_id_c, generation,
            )
            .map_err(|err| {
                PeerError::internal(
                    &server_c,
                    &step_c,
                    format!("Failed clearing grant credential cleanup entry: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    &step_c,
                    format!("Failed committing grant cleanup clear transaction: {err}"),
                )
            })?;
            Ok(removed)
        })
        .await
}

/// Deletes every staged/retired/committed non-canonical `GrantToken` slot tracked for a revoked
/// or revoking link. Caller MUST hold `runtime.lock_link(link_id)` and have verified revoked link
/// ownership. Canonical `link_id` credentials are deleted by `DeleteLinkCredentials`.
pub(crate) async fn delete_revoked_link_staged_grant_credentials_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_name: &str,
    step: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let link_id_c = link_id.to_string();
    let server_c = server.clone();
    let step_c = step.to_string();
    let targets = runtime
        .db
        .read(&server, step, move |conn| {
            let mut entries: Vec<(String, Option<i64>)> =
                db_peers::list_peer_received_grant_cleanups_for_link(conn, &link_id_c)
                    .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?
                    .into_iter()
                    .filter(|item| item.credential_id != link_id_c)
                    .map(|item| (item.credential_id, Some(item.generation)))
                    .collect();
            if let Some(received) = db_peers::get_peer_received_grant(conn, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?
            {
                if let Some(cid) = received.credential_id {
                    if !cid.is_empty()
                        && cid != link_id_c
                        && !entries.iter().any(|(existing_id, _)| existing_id == &cid)
                    {
                        entries.push((cid, None));
                    }
                }
            }
            Ok(entries)
        })
        .await?;

    for (cred_id, cleanup_gen) in targets {
        delete_grant_token_idempotent(runtime, &cred_id, peer_name, step).await?;
        if let Some(gen_val) = cleanup_gen {
            let _ = delete_cleanup_row_if_matches_guarded(
                runtime, link_id, &cred_id, gen_val, &server, step,
            )
            .await;
        }
    }
    Ok(())
}

enum CleanupSlotDecision {
    Skip,
    ClearStaleMarkerOnly { cleanup_gen: i64 },
    DeleteSlot { cleanup_gen: i64 },
}

/// Retries durable pending `GrantToken` deletion for a single `(link_id, credential_id)` cleanup
/// row under canonical `link_lock`, enforcing:
/// - Revalidated link & cleanup row existence under `link_lock`.
/// - Exact generation match when `expected_generation` is specified.
/// - Absolute committed-slot protection: NEVER deletes the currently active committed slot.
/// - Verified typed runner deletion acknowledgement before removing the durable cleanup row.
pub(crate) async fn retry_received_grant_cleanup_slot(
    runtime: &PeerRuntime,
    link_id: &str,
    credential_id: &str,
    expected_generation: Option<i64>,
) -> Result<bool, PeerError> {
    let server = runtime.local_server_name();
    let step = "grant_cleanup_retry";
    if !is_valid_credential_id(link_id) || !is_valid_credential_id(credential_id) {
        return Ok(false);
    }

    let _link_guard = runtime.lock_link(link_id, step).await?;

    let link_id_c = link_id.to_string();
    let cred_id_c = credential_id.to_string();
    let server_c = server.clone();
    let decision = runtime
        .db
        .read(&server, step, move |conn| {
            let Some(link) = db_peers::get_peer_link(conn, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
            else {
                return Ok(CleanupSlotDecision::Skip);
            };
            // Links awaiting full link revocation cleanup own credential teardown via
            // `links::retry_revocation_cleanup`; avoid duplicate cleanup dispatch here.
            if is_revoking_state(&link.state)
                || (is_revoked_state(&link.state) && link.pending_expires_at.is_some())
            {
                return Ok(CleanupSlotDecision::Skip);
            }
            let Some(cleanup_row) =
                db_peers::get_peer_received_grant_cleanup(conn, &link_id_c, &cred_id_c)
                    .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
            else {
                return Ok(CleanupSlotDecision::Skip);
            };
            if let Some(exp_gen) = expected_generation {
                if cleanup_row.generation != exp_gen {
                    return Ok(CleanupSlotDecision::Skip);
                }
            }
            if let Some(active) = db_peers::get_peer_received_grant(conn, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
            {
                if active.revoked_at.is_none()
                    && committed_received_grant_credential_id(&active) == cleanup_row.credential_id
                {
                    if cleanup_row.generation < active.generation {
                        return Ok(CleanupSlotDecision::ClearStaleMarkerOnly {
                            cleanup_gen: cleanup_row.generation,
                        });
                    }
                    return Ok(CleanupSlotDecision::Skip);
                }
            }
            Ok(CleanupSlotDecision::DeleteSlot {
                cleanup_gen: cleanup_row.generation,
            })
        })
        .await?;

    match decision {
        CleanupSlotDecision::Skip => Ok(false),
        CleanupSlotDecision::ClearStaleMarkerOnly { cleanup_gen } => {
            delete_cleanup_row_if_matches_guarded(
                runtime,
                link_id,
                credential_id,
                cleanup_gen,
                &server,
                step,
            )
            .await
        }
        CleanupSlotDecision::DeleteSlot { cleanup_gen } => {
            delete_grant_token_idempotent(runtime, credential_id, &server, step).await?;
            delete_cleanup_row_if_matches_guarded(
                runtime,
                link_id,
                credential_id,
                cleanup_gen,
                &server,
                step,
            )
            .await
        }
    }
}

/// Sweeps all durable staged/retired/revoked `GrantToken` cleanup rows across all links.
/// Completely dormant (zero locks, zero runner calls) when no cleanup rows exist.
/// Never deletes any committed active slot and never modifies link health, notifications, or
/// inbound grant state.
pub(crate) async fn cleanup_pending_received_grant_credentials(runtime: &PeerRuntime) {
    let server = runtime.local_server_name();
    let pending = match runtime
        .db
        .read(&server, "grant_cleanup_sweep", |conn| {
            Ok(db_peers::list_peer_received_grant_cleanups(conn).unwrap_or_default())
        })
        .await
    {
        Ok(rows) => rows,
        Err(_) => return,
    };

    for row in pending {
        if let Err(error) = retry_received_grant_cleanup_slot(
            runtime,
            &row.link_id,
            &row.credential_id,
            Some(row.generation),
        )
        .await
        {
            tracing::warn!(
                link_id = %row.link_id,
                credential_id = %row.credential_id,
                generation = row.generation,
                %error,
                "Pending grant credential cleanup retry failed; retained durable marker for next sweep"
            );
        }
    }
}

async fn handle_tunnel_grant_token_inner(
    runtime: &PeerRuntime,
    auth: &super::listener::AuthenticatedPeerLink,
    raw_body: &[u8],
) -> Result<GrantTokenDeliveryAck, PeerError> {
    let server = runtime.local_server_name();
    let step = "receive_grant_token";

    let mut payload: GrantTokenDeliveryPayload =
        serde_json::from_slice(raw_body).map_err(|_| {
            PeerError::invalid_request(
                &server,
                step,
                "Invalid grant delivery payload",
                "Retry saving the grant from the issuing server",
            )
        })?;
    let new_token = PeerCredentialSecret::new(std::mem::take(&mut payload.token));

    if !is_valid_credential_id(&payload.grant_id)
        || payload.run_as_user_id <= 0
        || payload.generation <= 0
        || !payload.access.has_any_access()
        || new_token.expose_secret().len() < 32
        || new_token.expose_secret().len() > 256
        || !new_token
            .expose_secret()
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b.is_ascii_whitespace())
    {
        drop(new_token);
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Grant delivery payload failed validation",
            "Retry saving the grant from the issuing server",
        ));
    }

    let created_by = sanitize_label(&payload.created_by, 128);
    let created_at = sanitize_label(&payload.created_at, 64);
    if created_by.is_empty() || created_at.is_empty() {
        drop(new_token);
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Grant delivery metadata is missing created_by or created_at",
            "Retry saving the grant from the issuing server",
        ));
    }

    // Synchronize directly on canonical `link_lock` so revalidated live link ownership surrounds
    // staging, atomic pointer swap, and cleanup, preventing races with link revocation/cleanup.
    let _link_guard = runtime.lock_link(&auth.link.id, step).await?;

    // Phase 1 (IMMEDIATE tx): Revalidate live link ownership & generation fence, allocate a fresh
    // runner-managed staged credential slot, and persist durable cleanup intent BEFORE staging so
    // a crash or failure at any subsequent step never loses the prior committed GrantToken.
    let link_id_c = auth.link.id.clone();
    let expected_pk = auth.link.wg_pubkey.clone();
    let expected_ip = auth.link.tunnel_ip.clone();
    let incoming_gen = payload.generation;
    let stage_ts = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let staged_cred_id = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting grant staging transaction: {err}"),
                    )
                },
            )?;
            let current_link = db_peers::get_peer_link(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&current_link.state) {
                return Err(PeerError::link_revoked(
                    &server_c,
                    step,
                    format!("Link '{}' has been revoked", current_link.name),
                ));
            }
            if !is_live_link_state(&current_link.state)
                || current_link.wg_pubkey != expected_pk
                || current_link.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &server_c,
                    step,
                    "Peer link state changed during grant receipt",
                    "Retry saving the grant",
                ));
            }
            let existing = db_peers::get_peer_received_grant(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
            if let Some(ref ex) = existing {
                if incoming_gen <= ex.generation {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Stale or out-of-order grant delivery was rejected",
                        "Retry saving the grant to issue a newer generation",
                    ));
                }
            }
            let prior_cred_id = existing.as_ref().map(|ex| ex.effective_credential_id());
            let staged_id = allocate_staged_grant_credential_id(&link_id_c, prior_cred_id);
            db_peers::upsert_peer_received_grant_cleanup(
                &tx,
                &link_id_c,
                &staged_id,
                incoming_gen,
                &stage_ts,
            )
            .map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed recording durable grant staging cleanup intent: {err}"),
                )
            })?;
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing grant staging cleanup intent: {err}"),
                )
            })?;
            Ok(staged_id)
        })
        .await?;

    // Phase 2: Write the raw grant secret into the fresh staged runner slot. The previously
    // committed GrantToken file is NEVER overwritten or deleted before Phase 3 commits.
    let write_res = write_grant_token_verified(runtime, &staged_cred_id, &new_token).await;
    drop(new_token);
    if let Err(write_err) = write_res {
        if is_definite_non_mutating_runner_error(&write_err) {
            let _ = delete_cleanup_row_if_matches_guarded(
                runtime,
                &auth.link.id,
                &staged_cred_id,
                incoming_gen,
                &server,
                step,
            )
            .await;
        } else {
            // Ambiguous write failure or unconfirmed ack: remove staged slot if possible, or leave
            // its durable cleanup intent intact for restart/sweep recovery.
            match delete_grant_token_idempotent(runtime, &staged_cred_id, &server, step).await {
                Ok(()) => {
                    let _ = delete_cleanup_row_if_matches_guarded(
                        runtime,
                        &auth.link.id,
                        &staged_cred_id,
                        incoming_gen,
                        &server,
                        step,
                    )
                    .await;
                }
                Err(del_err) => {
                    tracing::warn!(
                        link_id = %auth.link.id,
                        credential_id = %staged_cred_id,
                        generation = incoming_gen,
                        error = %del_err,
                        "Retained durable cleanup intent for ambiguously staged GrantToken"
                    );
                }
            }
        }
        return Err(map_runner_error(write_err, &server, step));
    }

    // Phase 3 (IMMEDIATE tx): Atomically swap `peer_received_grants` pointer to `staged_cred_id`,
    // promote `staged_cred_id` out of `peer_received_grant_cleanups`, and durably queue any
    // retired prior committed slot for post-commit cleanup.
    let link_id_c = auth.link.id.clone();
    let expected_pk = auth.link.wg_pubkey.clone();
    let expected_ip = auth.link.tunnel_ip.clone();
    let grant_id_c = payload.grant_id.clone();
    let staged_cred_c = staged_cred_id.clone();
    let run_as_user_id = payload.run_as_user_id;
    let access_c = payload.access.clone();
    let updated_at = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let commit_res: Result<Option<(String, i64)>, PeerError> = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting received grant commit transaction: {err}"),
                    )
                },
            )?;
            let current_link = db_peers::get_peer_link(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&current_link.state) {
                return Err(PeerError::link_revoked(
                    &server_c,
                    step,
                    format!("Link '{}' has been revoked", current_link.name),
                ));
            }
            if !is_live_link_state(&current_link.state)
                || current_link.wg_pubkey != expected_pk
                || current_link.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &server_c,
                    step,
                    "Peer link state changed during grant receipt",
                    "Retry saving the grant",
                ));
            }
            let existing = db_peers::get_peer_received_grant(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
            if let Some(ref ex) = existing {
                if incoming_gen <= ex.generation {
                    return Err(PeerError::conflict(
                        &server_c,
                        step,
                        "Stale or out-of-order grant delivery was rejected",
                        "Retry saving the grant to issue a newer generation",
                    ));
                }
            }

            let retired_slot = existing.as_ref().and_then(|ex| {
                if ex.revoked_at.is_none() {
                    let old_id = ex.effective_credential_id().to_string();
                    (old_id != staged_cred_c).then_some((old_id, ex.generation))
                } else {
                    None
                }
            });

            let record = PeerReceivedGrant {
                link_id: link_id_c.clone(),
                grant_id: grant_id_c,
                run_as_user_id,
                access: access_c,
                created_by,
                created_at,
                generation: incoming_gen,
                revoked_at: None,
                credential_id: Some(staged_cred_c.clone()),
                updated_at: updated_at.clone(),
            };
            db_peers::upsert_peer_received_grant(&tx, &record).map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed saving received grant metadata: {err}"),
                )
            })?;
            db_peers::delete_peer_received_grant_cleanup_slot(&tx, &link_id_c, &staged_cred_c)
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed promoting staged grant slot out of cleanup queue: {err}"),
                    )
                })?;
            if let Some((ref old_id, old_gen)) = retired_slot {
                db_peers::upsert_peer_received_grant_cleanup(
                    &tx,
                    &link_id_c,
                    old_id,
                    old_gen,
                    &updated_at,
                )
                .map_err(|err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed queuing retired grant slot for cleanup: {err}"),
                    )
                })?;
            }
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing received grant metadata: {err}"),
                )
            })?;
            Ok(retired_slot)
        })
        .await;

    let retired_slot = match commit_res {
        Ok(retired) => retired,
        Err(commit_err) => {
            // Re-read authoritative SQLite state before deleting `staged_cred_id` so an ambiguous
            // commit that actually succeeded is never deleted, and never touch the prior slot.
            let check_link_id = auth.link.id.clone();
            let check_server = server.clone();
            let authoritative = runtime
                .db
                .read(&server, step, move |conn| {
                    db_peers::get_peer_received_grant(conn, &check_link_id)
                        .map_err(|err| PeerError::internal(&check_server, step, err.to_string()))
                })
                .await;

            match authoritative {
                Err(_) => {
                    tracing::warn!(
                        link_id = %auth.link.id,
                        credential_id = %staged_cred_id,
                        generation = incoming_gen,
                        "Ambiguous grant commit failure: unable to re-read SQLite; deferring staged slot reconciliation to sweep"
                    );
                }
                Ok(Some(ref cur))
                    if cur.revoked_at.is_none()
                        && committed_received_grant_credential_id(cur) == staged_cred_id =>
                {
                    tracing::warn!(
                        link_id = %auth.link.id,
                        credential_id = %staged_cred_id,
                        generation = incoming_gen,
                        "Ambiguous grant commit appears persisted in SQLite; preserving committed slot"
                    );
                }
                Ok(_) => {
                    match delete_grant_token_idempotent(runtime, &staged_cred_id, &server, step)
                        .await
                    {
                        Ok(()) => {
                            let _ = delete_cleanup_row_if_matches_guarded(
                                runtime,
                                &auth.link.id,
                                &staged_cred_id,
                                incoming_gen,
                                &server,
                                step,
                            )
                            .await;
                        }
                        Err(del_err) => {
                            tracing::warn!(
                                link_id = %auth.link.id,
                                credential_id = %staged_cred_id,
                                generation = incoming_gen,
                                error = %del_err,
                                "Transient runner error cleaning uncommitted staged GrantToken; durable cleanup intent retained while prior committed slot remains intact"
                            );
                        }
                    }
                }
            }
            return Err(commit_err);
        }
    };

    // Phase 4: Best-effort immediate removal of the retired prior slot after commit succeeds; on
    // transient runner failure, its durable cleanup row guarantees restart/sweep completion.
    if let Some((old_id, old_gen)) = retired_slot {
        match delete_grant_token_idempotent(runtime, &old_id, &server, step).await {
            Ok(()) => {
                if let Err(clear_err) = delete_cleanup_row_if_matches_guarded(
                    runtime,
                    &auth.link.id,
                    &old_id,
                    old_gen,
                    &server,
                    step,
                )
                .await
                {
                    tracing::warn!(
                        link_id = %auth.link.id,
                        credential_id = %old_id,
                        generation = old_gen,
                        error = %clear_err,
                        "Retired GrantToken deleted, but clearing durable cleanup row failed; sweep will reconcile idempotently"
                    );
                }
            }
            Err(del_err) => {
                tracing::warn!(
                    link_id = %auth.link.id,
                    credential_id = %old_id,
                    generation = old_gen,
                    error = %del_err,
                    "Transient runner error deleting retired GrantToken after promotion; durable cleanup row retained for sweep/restart"
                );
            }
        }
    }

    drop(_link_guard);

    runtime
        .db
        .record_audit(
            0,
            format!("peer-{}", auth.link.name),
            "peer_grant_received".to_string(),
            "peer_link".to_string(),
            auth.link.id.clone(),
            format!(
                "Received outbound management grant '{}' from '{}' (gen={}, {})",
                payload.grant_id,
                auth.link.name,
                payload.generation,
                format_access_summary(&payload.access)
            ),
            auth.source_ip.to_string(),
            String::new(),
        )
        .await;

    Ok(GrantTokenDeliveryAck {
        accepted: true,
        grant_id: payload.grant_id,
        generation: payload.generation,
    })
}

pub(crate) async fn handle_tunnel_grant_revoke(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (auth, _permit) = match authenticate_active_link(
        &runtime,
        connect_info,
        &headers,
        "POST /peer/v1/grant-revoke",
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    match handle_tunnel_grant_revoke_inner(&runtime, &auth, &body).await {
        Ok((revoked, generation)) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "revoked": revoked,
                "generation": generation,
            })),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn handle_tunnel_grant_revoke_inner(
    runtime: &PeerRuntime,
    auth: &super::listener::AuthenticatedPeerLink,
    raw_body: &[u8],
) -> Result<(bool, i64), PeerError> {
    let server = runtime.local_server_name();
    let step = "receive_grant_revoke";

    let payload: GrantRevokePayload = serde_json::from_slice(raw_body).map_err(|_| {
        PeerError::invalid_request(
            &server,
            step,
            "Invalid grant revocation payload",
            "Retry revoking the grant from the issuing server",
        )
    })?;
    if payload.generation <= 0 {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Grant revocation generation must be positive",
            "Retry revoking the grant",
        ));
    }

    // Synchronize directly on canonical `link_lock` so grant revocation and credential deletion
    // are serialized with grant staging/promotion, link revocation, and sweep cleanups.
    let _link_guard = runtime.lock_link(&auth.link.id, step).await?;

    let link_id_c = auth.link.id.clone();
    let expected_pk = auth.link.wg_pubkey.clone();
    let expected_ip = auth.link.tunnel_ip.clone();
    let gen_val = payload.generation;
    let now_rfc = runtime.now().to_rfc3339();
    let server_c = server.clone();

    let (applied, previously_active, pending_cleanups) = runtime
        .db
        .write(&server, step, move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(
                |err| {
                    PeerError::internal(
                        &server_c,
                        step,
                        format!("Failed starting grant revoke transaction: {err}"),
                    )
                },
            )?;
            let current_link = db_peers::get_peer_link(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .ok_or_else(|| PeerError::not_found(&server_c, step, "Peer link was not found"))?;
            if is_revoked_or_revoking_state(&current_link.state) {
                return Err(PeerError::link_revoked(
                    &server_c,
                    step,
                    format!("Link '{}' has been revoked", current_link.name),
                ));
            }
            if !is_live_link_state(&current_link.state)
                || current_link.wg_pubkey != expected_pk
                || current_link.tunnel_ip != expected_ip
            {
                return Err(PeerError::conflict(
                    &server_c,
                    step,
                    "Peer link state changed during grant revocation",
                    "Retry revoking the grant",
                ));
            }
            let previously_active = db_peers::get_peer_received_grant(&tx, &link_id_c)
                .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?
                .is_some_and(|existing| existing.revoked_at.is_none());
            // Atomically persists `revoked_at` AND durable `peer_received_grant_cleanups` row(s)
            // before touching the runner so crashes or transient runner failures recover on retry.
            let applied =
                db_peers::mark_peer_received_grant_revoked(&tx, &link_id_c, gen_val, &now_rfc)
                    .map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed marking received grant revoked: {err}"),
                        )
                    })?;
            let cleanups = if applied {
                db_peers::list_peer_received_grant_cleanups_for_link(&tx, &link_id_c).map_err(
                    |err| {
                        PeerError::internal(
                            &server_c,
                            step,
                            format!("Failed listing pending grant cleanups: {err}"),
                        )
                    },
                )?
            } else {
                Vec::new()
            };
            tx.commit().map_err(|err| {
                PeerError::internal(
                    &server_c,
                    step,
                    format!("Failed committing received grant revocation: {err}"),
                )
            })?;
            Ok((applied, previously_active, cleanups))
        })
        .await?;

    if applied {
        let mut first_del_err: Option<PeerError> = None;
        for entry in pending_cleanups {
            match delete_grant_token_idempotent(runtime, &entry.credential_id, &server, step).await
            {
                Ok(()) => {
                    if let Err(clear_err) = delete_cleanup_row_if_matches_guarded(
                        runtime,
                        &auth.link.id,
                        &entry.credential_id,
                        entry.generation,
                        &server,
                        step,
                    )
                    .await
                    {
                        tracing::warn!(
                            link_id = %auth.link.id,
                            credential_id = %entry.credential_id,
                            generation = entry.generation,
                            error = %clear_err,
                            "GrantToken was deleted, but clearing durable cleanup row failed; next sweep will reconcile idempotently"
                        );
                    }
                }
                Err(del_err) => {
                    tracing::warn!(
                        link_id = %auth.link.id,
                        credential_id = %entry.credential_id,
                        generation = entry.generation,
                        error = %del_err,
                        "Transient runner error deleting revoked GrantToken; retained durable cleanup row for retry"
                    );
                    if first_del_err.is_none() {
                        first_del_err = Some(del_err);
                    }
                }
            }
        }

        drop(_link_guard);

        if let Some(del_err) = first_del_err {
            if previously_active {
                runtime
                    .db
                    .record_audit(
                        0,
                        format!("peer-{}", auth.link.name),
                        "peer_grant_revoked_by_remote".to_string(),
                        "peer_link".to_string(),
                        auth.link.id.clone(),
                        format!(
                            "Revoked outbound management grant from '{}' (gen={}; credential cleanup queued for retry)",
                            auth.link.name, payload.generation
                        ),
                        auth.source_ip.to_string(),
                        String::new(),
                    )
                    .await;
            }
            return Err(del_err);
        }

        runtime
            .db
            .record_audit(
                0,
                format!("peer-{}", auth.link.name),
                "peer_grant_revoked_by_remote".to_string(),
                "peer_link".to_string(),
                auth.link.id.clone(),
                format!(
                    "Cleared outbound management grant revoked by '{}' (gen={})",
                    auth.link.name, payload.generation
                ),
                auth.source_ip.to_string(),
                String::new(),
            )
            .await;
    }

    Ok((applied, payload.generation))
}

pub(crate) async fn handle_tunnel_grant_offer(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (auth, _permit) = match authenticate_active_link(
        &runtime,
        connect_info,
        &headers,
        "POST /peer/v1/grant-offer",
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    let payload: GrantOfferPayload = if body.is_empty() {
        GrantOfferPayload::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(_) => {
                return PeerError::invalid_request(
                    runtime.local_server_name(),
                    "receive_grant_offer",
                    "Invalid grant offer payload",
                    "Send an empty body or JSON metadata",
                )
                .into_response();
            }
        }
    };

    let requester = payload
        .requested_by
        .as_deref()
        .map(|s| sanitize_label(s, 64))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "remote admin".to_string());

    // Purely informational: never creates, modifies, or revokes any grant.
    runtime
        .db
        .emit_notification(
            "info",
            format!("Access review requested by {}", auth.link.name),
            format!(
                "Administrator '{}' on '{}' invited you to review management access for '{}' on the Cluster page.",
                requester, auth.link.name, auth.link.name
            ),
        )
        .await;

    runtime
        .db
        .record_audit(
            0,
            format!("peer-{}", auth.link.name),
            "peer_grant_offer_received".to_string(),
            "peer_link".to_string(),
            auth.link.id.clone(),
            format!(
                "Received informational grant review offer from '{}' (requested_by={}; no grant state changed)",
                auth.link.name, requester
            ),
            auth.source_ip.to_string(),
            String::new(),
        )
        .await;

    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(GrantOfferAck { received: true }),
    )
        .into_response()
}
