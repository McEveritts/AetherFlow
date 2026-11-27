//! Periodic link health checks, WireGuard handshake liveness, compatibility evaluation,
//! state-change notifications, and expired pending attempt sweeps.

use super::errors::{PeerError, PeerErrorBody};
use super::links::{apply_remote_revocation, RemoteRevocationTrigger};
use super::{
    capabilities, is_active_link_state, is_down_link_state, is_live_link_state, pairing,
    PeerRuntime, MIN_PEER_PROTOCOL_VERSION, PEER_PROTOCOL_VERSION,
};
use af_db::peers::{self as db_peers, PeerLink};
use af_runner::{PeerCredentialSlot, PeerNetworkRequest, PeerStatusResponse};
use axum::http::{Method, StatusCode};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

pub const HEALTH_POLL_INTERVAL_SECS: u64 = 15;
pub const WG_HANDSHAKE_STALE_SECS: u64 = 180;
const TUNNEL_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompatibilityStatus {
    Compatible,
    Limited,
    Incompatible,
    Unknown,
}

impl CompatibilityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Limited => "limited",
            Self::Incompatible => "incompatible",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub status: CompatibilityStatus,
    pub missing_capabilities: Vec<String>,
}

/// Evaluates compatibility between this server's protocol & capabilities and a peer's advertised
/// protocol & capabilities.
pub fn evaluate_compatibility(
    remote_protocol: Option<i64>,
    remote_capabilities: &[String],
) -> CompatibilityReport {
    let Some(protocol) = remote_protocol else {
        return CompatibilityReport {
            status: CompatibilityStatus::Unknown,
            missing_capabilities: Vec::new(),
        };
    };
    if protocol < MIN_PEER_PROTOCOL_VERSION {
        return CompatibilityReport {
            status: CompatibilityStatus::Incompatible,
            missing_capabilities: capabilities().into_iter().map(str::to_string).collect(),
        };
    }

    let missing: Vec<String> = capabilities()
        .into_iter()
        .filter(|cap| !remote_capabilities.iter().any(|r| r == cap))
        .map(str::to_string)
        .collect();

    if protocol == PEER_PROTOCOL_VERSION && missing.is_empty() {
        CompatibilityReport {
            status: CompatibilityStatus::Compatible,
            missing_capabilities: Vec::new(),
        }
    } else if protocol >= MIN_PEER_PROTOCOL_VERSION {
        CompatibilityReport {
            status: CompatibilityStatus::Limited,
            missing_capabilities: missing,
        }
    } else {
        CompatibilityReport {
            status: CompatibilityStatus::Incompatible,
            missing_capabilities: missing,
        }
    }
}

fn deserialize_double_option_i64<'de, D>(deserializer: D) -> Result<Option<Option<i64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<i64>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
struct RemoteHealthPayload {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    peer_protocol: Option<i64>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    transcode: Option<af_transcode::TranscodeCapabilities>,
    #[serde(default)]
    load: Option<super::transcode::WorkerLoadSnapshot>,
    /// Distinguishes an absent key (`None`, older peers) from explicit `null` (`Some(None)`,
    /// remote has no active inbound grant) and an active generation (`Some(Some(g))`).
    #[serde(default, deserialize_with = "deserialize_double_option_i64")]
    inbound_grant_generation: Option<Option<i64>>,
}

/// Spawns the 15-second peer health and pending-expiry background loop.
pub(crate) fn spawn_health_loop(runtime: Arc<PeerRuntime>, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(HEALTH_POLL_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Avoid an immediate startup probe on boot before the API listener finishes binding.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    run_health_tick(&runtime).await;
                }
            }
        }
    });
}

/// Executes one health & pending-cleanup tick.
///
/// Completely dormant (performs zero runner calls or sockets) when no peer identity,
/// no peer links, and no pending pairing attempts exist.
pub(crate) async fn run_health_tick(runtime: &Arc<PeerRuntime>) {
    let server = runtime.local_server_name();
    let state_snapshot = runtime
        .db
        .read(&server, "health_tick", |conn| {
            let identity = db_peers::get_peer_identity(conn).ok().flatten();
            let links = db_peers::list_peer_links(conn).unwrap_or_default();
            let has_open_attempts = db_peers::list_pairing_attempts(conn)
                .unwrap_or_default()
                .iter()
                .any(|a| matches!(a.status.as_str(), "pending" | "confirming"));
            Ok((identity, links, has_open_attempts))
        })
        .await;

    let Ok((identity, links, has_open_attempts)) = state_snapshot else {
        return;
    };

    // Dormant standalone mode: do not call runner or bind sockets when unconfigured.
    if identity.is_none() && links.is_empty() && !has_open_attempts {
        return;
    }

    // Ensure listener is running and transcode dispatcher recovers from transient boot errors once
    // an identity exists.
    if identity.is_some() {
        if let Err(error) = runtime.ensure_listener_started().await {
            tracing::warn!(%error, "Peer tunnel listener is not yet bound");
        }
        super::transcode::reconcile_dispatcher_if_configured(runtime).await;
    }

    // Always clean up expired pending attempts/links and retry any durable revoked-grant
    // credential deletions.
    pairing::cleanup_expired_pending(runtime).await;
    super::grants::cleanup_pending_received_grant_credentials(runtime).await;

    // Reload links after pending/revocation cleanup and filter to checkable active/down links.
    let checkable_links: Vec<PeerLink> = runtime
        .db
        .read(&server, "health_tick", |conn| {
            Ok(db_peers::list_peer_links(conn)
                .unwrap_or_default()
                .into_iter()
                .filter(|l| is_live_link_state(&l.state) && l.inbound_token_hash.is_some())
                .collect())
        })
        .await
        .unwrap_or_default();

    if checkable_links.is_empty() {
        return;
    }

    // Warm local FFmpeg/GPU capability and load caches asynchronously whenever peers are active so
    // the first transcode dispatch never falls back locally solely due to a cold cache.
    let _ = super::transcode::cached_local_capabilities_nonblocking(runtime);
    let _ = super::transcode::cached_local_load_nonblocking(runtime);

    let wg_status = match runtime
        .runner
        .dispatch(&PeerNetworkRequest::Status)
        .await
        .and_then(|resp| resp.into_status())
    {
        Ok(status) => Some(status),
        Err(error) => {
            tracing::warn!(%error, "Failed querying afpeer0 status during peer health tick");
            None
        }
    };

    for link in checkable_links {
        check_single_link(runtime, link, wg_status.as_ref()).await;
    }
}

/// Checks one active or down link against WireGuard status (`present_live` + handshake age)
/// and link-authenticated tunnel `GET /health`.
///
/// Commits only health-owned columns under authoritative identity, state, and active-digest
/// guards so concurrent revocation or endpoint edits are never overwritten by a late probe.
pub(crate) async fn check_single_link(
    runtime: &PeerRuntime,
    link: PeerLink,
    wg_status: Option<&PeerStatusResponse>,
) {
    let now_rfc = runtime.now().to_rfc3339();

    if let Some(status) = wg_status {
        match status.peers.iter().find(|p| p.public_key == link.wg_pubkey) {
            None => {
                let reason = "WireGuard peer is missing from afpeer0";
                commit_link_down(runtime, &link, None, reason, &now_rfc).await;
                super::storage::gate_mounts_for_link_down_immediate(runtime, &link, reason).await;
                return;
            }
            Some(peer) if !peer.present_live => {
                let reason = "WireGuard peer was removed from live afpeer0 runtime";
                commit_link_down(runtime, &link, None, reason, &now_rfc).await;
                super::storage::gate_mounts_for_link_down_immediate(runtime, &link, reason).await;
                return;
            }
            Some(peer) => {
                // `present_live == true`: if a handshake has occurred and is older than 180s,
                // treat the tunnel as down. `handshake_age_secs == None` indicates a freshly
                // configured peer awaiting its first handshake, so proceed to tunnel `/health`.
                if let Some(age) = peer.handshake_age_secs {
                    if age > WG_HANDSHAKE_STALE_SECS {
                        let reason = format!(
                            "WireGuard handshake is stale ({age}s > {WG_HANDSHAKE_STALE_SECS}s)"
                        );
                        commit_link_down(runtime, &link, None, &reason, &now_rfc).await;
                        super::storage::gate_mounts_for_link_down_immediate(
                            runtime, &link, &reason,
                        )
                        .await;
                        return;
                    }
                }
            }
        }
    }

    let held_token = match runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: link.id.clone(),
        })
        .await
        .and_then(|resp| resp.into_credential_read())
    {
        Ok(read_resp) => match read_resp.into_secret() {
            Some(secret) => secret,
            None => {
                let reason = "Held outbound link credential is missing";
                commit_link_down(runtime, &link, None, reason, &now_rfc).await;
                super::storage::probe_mounts_while_link_degraded(runtime, &link, reason).await;
                return;
            }
        },
        Err(err) => {
            let reason = format!("Could not read outbound link credential: {err}");
            commit_link_down(runtime, &link, None, &reason, &now_rfc).await;
            super::storage::probe_mounts_while_link_degraded(runtime, &link, &reason).await;
            return;
        }
    };

    let health_res = runtime
        .send_tunnel_request(
            Method::GET,
            &link.tunnel_ip,
            "/health",
            Some(&held_token),
            None,
            TUNNEL_HEALTH_TIMEOUT,
        )
        .await;
    drop(held_token);

    let commit_now_rfc = runtime.now().to_rfc3339();
    match health_res {
        Ok((StatusCode::OK, body, rtt_ms)) => {
            let Ok(parsed) = serde_json::from_slice::<RemoteHealthPayload>(&body) else {
                let reason = "Peer tunnel /health returned unreadable JSON";
                commit_link_down(runtime, &link, None, reason, &commit_now_rfc).await;
                super::storage::probe_mounts_while_link_degraded(runtime, &link, reason).await;
                return;
            };
            let remote_transcode = parsed.transcode.clone();
            let remote_load = parsed.load.clone();
            let remote_inbound_grant_gen = parsed.inbound_grant_generation;
            let committed_healthy =
                commit_link_healthy(runtime, &link, parsed, rtt_ms, &commit_now_rfc).await;
            if committed_healthy {
                if let Some(load) = remote_load {
                    runtime.transcode_state.record_remote_load(&link.id, load);
                }
                if remote_inbound_grant_gen == Some(None) {
                    super::grants::reconcile_missing_remote_grant(runtime, &link).await;
                }
                if let Some(transcode_caps) = remote_transcode {
                    super::transcode::handle_remote_health_transcode_caps(
                        runtime,
                        &link,
                        transcode_caps,
                    )
                    .await;
                }
            }
            super::storage::reconcile_mounts_for_healthy_link(runtime, &link).await;
        }
        Ok((status, body, _rtt_ms)) => {
            if let Ok(err_body) = serde_json::from_slice::<PeerErrorBody>(&body) {
                if err_body.code == "LINK_REVOKED" {
                    let _ = apply_remote_revocation(
                        runtime,
                        &link.id,
                        &link.wg_pubkey,
                        &link.tunnel_ip,
                        Some(&link.tunnel_ip),
                        RemoteRevocationTrigger::HealthCheck,
                    )
                    .await;
                    return;
                }
            }
            let (protocol_override, reason) = if status == StatusCode::NOT_FOUND {
                (
                    Some(0),
                    "Peer returned HTTP 404 on tunnel /health (incompatible peer release)"
                        .to_string(),
                )
            } else {
                (
                    None,
                    format!("Peer tunnel /health returned HTTP {}", status.as_u16()),
                )
            };
            commit_link_down(runtime, &link, protocol_override, &reason, &commit_now_rfc).await;
            super::storage::probe_mounts_while_link_degraded(runtime, &link, &reason).await;
        }
        Err(err) => {
            let reason = format!("Peer tunnel /health failed: {}", err.message());
            commit_link_down(runtime, &link, None, &reason, &commit_now_rfc).await;
            super::storage::probe_mounts_while_link_degraded(runtime, &link, &reason).await;
        }
    }
}

async fn commit_link_healthy(
    runtime: &PeerRuntime,
    link: &PeerLink,
    parsed: RemoteHealthPayload,
    rtt_ms: f64,
    now_rfc: &str,
) -> bool {
    let server = runtime.local_server_name();
    let link_id = link.id.clone();
    let wg_pubkey = link.wg_pubkey.clone();
    let tunnel_ip = link.tunnel_ip.clone();
    let peer_version = parsed.version;
    let peer_protocol = parsed.peer_protocol;
    let capabilities_json = serde_json::to_string(&parsed.capabilities).ok();
    let rounded_rtt = (rtt_ms * 100.0).round() / 100.0;
    let now_s = now_rfc.to_string();

    let committed = runtime
        .db
        .write(&server, "health_tick", move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            let current: Option<(String, String)> = tx
                .query_row(
                    "SELECT state, name FROM peer_links \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                       AND inbound_token_hash IS NOT NULL",
                    params![link_id, wg_pubkey, tunnel_ip],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            let Some((prev_state, current_name)) = current else {
                return Ok(None);
            };

            let changed = tx
                .execute(
                    "UPDATE peer_links SET \
                        state = CASE state \
                            WHEN 'active' THEN 'active' \
                            WHEN 'down' THEN 'active' \
                            WHEN 'active_unowned' THEN 'active_unowned' \
                            WHEN 'down_unowned' THEN 'active_unowned' \
                        END, \
                        peer_version = COALESCE(?4, peer_version), \
                        peer_protocol = COALESCE(?5, peer_protocol), \
                        capabilities = COALESCE(?6, capabilities), \
                        rtt_ms = ?7, \
                        last_ok_at = ?8, \
                        last_error = NULL, \
                        consecutive_failures = 0, \
                        updated_at = ?8 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                       AND inbound_token_hash IS NOT NULL",
                    params![
                        link_id,
                        wg_pubkey,
                        tunnel_ip,
                        peer_version,
                        peer_protocol,
                        capabilities_json,
                        rounded_rtt,
                        now_s,
                    ],
                )
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            if changed != 1 {
                return Ok(None);
            }
            tx.commit()
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;
            Ok(Some((prev_state, current_name)))
        })
        .await;

    if let Ok(Some((prev_state, current_name))) = committed {
        if is_down_link_state(&prev_state) {
            runtime
                .db
                .emit_notification(
                    "info",
                    format!("Peer link recovered: {current_name}"),
                    format!(
                        "Link to {current_name} is healthy again (RTT {:.1} ms).",
                        rounded_rtt
                    ),
                )
                .await;
        }
        true
    } else {
        false
    }
}

async fn commit_link_down(
    runtime: &PeerRuntime,
    link: &PeerLink,
    peer_protocol_override: Option<i64>,
    reason: &str,
    now_rfc: &str,
) {
    let server = runtime.local_server_name();
    let link_id = link.id.clone();
    let wg_pubkey = link.wg_pubkey.clone();
    let tunnel_ip = link.tunnel_ip.clone();
    let reason_s = reason.to_string();
    let now_s = now_rfc.to_string();

    let committed = runtime
        .db
        .write(&server, "health_tick", move |conn| {
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            let current: Option<(String, String)> = tx
                .query_row(
                    "SELECT state, name FROM peer_links \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                       AND inbound_token_hash IS NOT NULL",
                    params![link_id, wg_pubkey, tunnel_ip],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            let Some((prev_state, current_name)) = current else {
                return Ok(None);
            };

            let changed = tx
                .execute(
                    "UPDATE peer_links SET \
                        state = CASE state \
                            WHEN 'active' THEN 'down' \
                            WHEN 'down' THEN 'down' \
                            WHEN 'active_unowned' THEN 'down_unowned' \
                            WHEN 'down_unowned' THEN 'down_unowned' \
                        END, \
                        peer_protocol = COALESCE(?4, peer_protocol), \
                        last_error = ?5, \
                        consecutive_failures = CASE \
                            WHEN consecutive_failures < 9223372036854775807 THEN consecutive_failures + 1 \
                            ELSE consecutive_failures \
                        END, \
                        updated_at = ?6 \
                     WHERE id = ?1 AND wg_pubkey = ?2 AND tunnel_ip = ?3 \
                       AND state IN ('active', 'down', 'active_unowned', 'down_unowned') \
                       AND inbound_token_hash IS NOT NULL",
                    params![
                        link_id,
                        wg_pubkey,
                        tunnel_ip,
                        peer_protocol_override,
                        reason_s,
                        now_s,
                    ],
                )
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;

            if changed != 1 {
                return Ok(None);
            }
            tx.commit()
                .map_err(|err| PeerError::internal("local", "health_tick", err.to_string()))?;
            Ok(Some((prev_state, current_name)))
        })
        .await;

    if let Ok(Some((prev_state, current_name))) = committed {
        if is_active_link_state(&prev_state) {
            runtime
                .db
                .emit_notification(
                    "warning",
                    format!("Peer link down: {current_name}"),
                    format!("Link to {current_name} is unreachable: {reason}"),
                )
                .await;
        }
    }
}
