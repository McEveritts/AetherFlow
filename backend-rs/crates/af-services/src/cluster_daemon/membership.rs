use super::auth::{
    constant_time_eq, ensure_cluster_schema, hash_psk_sha256, verify_cluster_psk,
    verify_enrolled_cluster_psk, verify_master_control_plane_psk, PeerTransportAuth,
};
use super::commands::{
    acknowledge_worker_command, cache_worker_metrics, get_cached_worker_metrics,
    lease_next_worker_command, remove_cached_worker_metrics, truncate_utf8,
    CLUSTER_COMMAND_LEASE_SECS,
};
use super::types::{
    RegisterWorkerRequest, RegisterWorkerResponse, WorkerHeartbeatRequest, WorkerHeartbeatResponse,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use rusqlite::params;

// ─────────────────────────────────────────────────────────────────────────────
// Master Node Registration, Heartbeat Processing & Health Sweep
// ─────────────────────────────────────────────────────────────────────────────

/// Sweeps `cluster_nodes` and marks any node whose `last_seen` (or `last_heartbeat`)
/// is older than 60 seconds as `status = 'offline'`. Returns the number of nodes marked offline.
pub fn sweep_stale_cluster_nodes() -> usize {
    ensure_cluster_schema();
    let Ok(conn) = af_db::get_conn() else {
        return 0;
    };

    let now = Utc::now();
    let mut stale_ids: Vec<(String, String)> = Vec::new();

    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, hostname, COALESCE(CAST(last_seen AS TEXT), ''), COALESCE(CAST(last_heartbeat AS TEXT), '') \
         FROM cluster_nodes WHERE status = 'online'",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        }) {
            for (id, hostname, last_seen, last_hb) in rows.flatten() {
                let ts_str = if !last_seen.trim().is_empty() {
                    last_seen.trim()
                } else {
                    last_hb.trim()
                };

                let is_stale = if ts_str.is_empty() {
                    true
                } else if let Ok(parsed) = DateTime::parse_from_rfc3339(ts_str) {
                    (now - parsed.with_timezone(&Utc)).num_seconds() > 60
                } else if let Ok(naive) =
                    chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
                {
                    let dt = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
                    (now - dt).num_seconds() > 60
                } else {
                    false
                };

                if is_stale {
                    stale_ids.push((id, hostname));
                }
            }
        }
    }

    let mut marked = 0usize;
    if !stale_ids.is_empty() {
        if let Ok(mut update_stmt) = conn.prepare(
            "UPDATE cluster_nodes SET status = 'offline' WHERE id = ?1 AND status != 'offline'",
        ) {
            for (id, hostname) in &stale_ids {
                if let Ok(n) = update_stmt.execute(params![id]) {
                    if n > 0 {
                        marked += n;
                        tracing::warn!(node_id = %id, hostname = %hostname, "cluster worker went offline (heartbeat timeout > 60s)");
                    }
                }
            }
        }
    }

    // Fallback SQLite native datetime sweep for any non-RFC3339 timestamps
    if let Ok(n) = conn.execute(
        "UPDATE cluster_nodes SET status = 'offline' \
         WHERE status = 'online' \
         AND datetime(COALESCE(NULLIF(CAST(last_seen AS TEXT), ''), CAST(last_heartbeat AS TEXT))) < datetime('now', '-60 seconds')",
        [],
    ) {
        marked += n;
    }

    marked
}

pub(super) fn is_enrolled_cluster_node(node_id: &str) -> bool {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(conn) = af_db::get_conn() else {
        return false;
    };
    conn.query_row(
        "SELECT COALESCE(psk_hash, '') FROM cluster_nodes WHERE id = ?1",
        params![trimmed],
        |r| r.get::<_, String>(0),
    )
    .map(|hash| !hash.trim().is_empty())
    .unwrap_or(false)
}

/// Validates and registers a worker node in `cluster_nodes` and initializes its in-memory state.
pub fn register_worker_node(req: &RegisterWorkerRequest) -> anyhow::Result<RegisterWorkerResponse> {
    register_worker_node_with_peer(req, &PeerTransportAuth::InternalCall)
}

/// Validates and registers a worker node with transport-layer peer certificate binding.
pub fn register_worker_node_with_peer(
    req: &RegisterWorkerRequest,
    peer_auth: &PeerTransportAuth,
) -> anyhow::Result<RegisterWorkerResponse> {
    let hostname = req.hostname.trim();
    let address = req.address.trim();
    let psk = req.psk.trim();

    if hostname.is_empty() || address.is_empty() || psk.is_empty() {
        return Ok(RegisterWorkerResponse {
            node_id: String::new(),
            accepted: false,
            message: "hostname, address, and psk are required".to_string(),
        });
    }

    if psk.len() < 32 {
        return Ok(RegisterWorkerResponse {
            node_id: String::new(),
            accepted: false,
            message: "psk must be at least 32 characters for adequate security".to_string(),
        });
    }

    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else {
        format!("node-{}", hostname)
    };

    ensure_cluster_schema();
    let incoming_cert_fp = peer_auth.mtls_cert_sha256();
    let mut conn = af_db::get_conn().context("cluster database unavailable")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .context("failed starting immediate cluster enrollment transaction")?;

    let existing_record: Option<(String, String)> = match tx.query_row(
        "SELECT COALESCE(psk_hash, ''), COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
        params![node_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        Ok(row) => Some(row),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e).context("failed querying existing cluster node state"),
    };

    if let Some((_, ref existing_cert)) = existing_record {
        let pinned_fp = existing_cert.trim();
        if !pinned_fp.is_empty() && !matches!(peer_auth, PeerTransportAuth::InternalCall) {
            let matches_pin = incoming_cert_fp
                .is_some_and(|fp| constant_time_eq(fp.as_bytes(), pinned_fp.as_bytes()));
            if !matches_pin {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: "peer certificate does not match enrolled worker certificate"
                        .to_string(),
                });
            }
        }
    }

    let is_master_psk = verify_master_control_plane_psk(psk);
    if !is_master_psk {
        let existing_psk_hash = existing_record
            .as_ref()
            .map(|(h, _)| h.trim())
            .unwrap_or("");
        if !existing_psk_hash.is_empty() {
            if let Err(err_msg) = verify_enrolled_cluster_psk(psk, existing_psk_hash) {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: err_msg.to_string(),
                });
            }
        } else {
            let token_hash = hash_psk_sha256(psk);
            let now_ts = Utc::now().timestamp();
            let consumed = tx
                .execute(
                    "UPDATE cluster_enrollment_tokens \
                     SET consumed_by = ?1 \
                     WHERE token_hash = ?2 AND consumed_by IS NULL AND expires_at >= ?3",
                    params![node_id, token_hash, now_ts],
                )
                .context("failed consuming cluster enrollment token")?;
            if consumed != 1 {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: "invalid or expired cluster enrollment token".to_string(),
                });
            }
        }
    }

    let psk_hash = hash_psk_sha256(psk);
    let cert_fp_to_store = incoming_cert_fp.unwrap_or("");
    let now_rfc3339 = Utc::now().to_rfc3339();

    tx.execute(
        "INSERT INTO cluster_nodes (id, hostname, address, psk_hash, peer_cert_sha256, role, status, last_heartbeat, last_seen, enrolled_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'worker', 'online', ?6, ?6, ?6) \
         ON CONFLICT(id) DO UPDATE SET \
             hostname = excluded.hostname, \
             address = excluded.address, \
             psk_hash = excluded.psk_hash, \
             peer_cert_sha256 = CASE WHEN excluded.peer_cert_sha256 != '' THEN excluded.peer_cert_sha256 ELSE COALESCE(cluster_nodes.peer_cert_sha256, '') END, \
             role = 'worker', \
             status = 'online', \
             last_heartbeat = excluded.last_heartbeat, \
             last_seen = excluded.last_seen",
        params![node_id, hostname, address, psk_hash, cert_fp_to_store, now_rfc3339],
    )
    .context("failed upserting enrolled cluster worker")?;
    tx.commit()
        .context("failed committing cluster worker enrollment")?;
    drop(conn);

    let version = if req.version.trim().is_empty() {
        "4.0.0"
    } else {
        req.version.trim()
    };

    let existing = get_cached_worker_metrics(&node_id);
    let initial_snapshot = serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "address": address,
        "version": version,
        "status": "online",
        "last_seen": now_rfc3339,
        "last_heartbeat": now_rfc3339,
        "cpu_usage": existing.as_ref().and_then(|v| v.get("cpu_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "ram_usage": existing.as_ref().and_then(|v| v.get("ram_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "disk_usage": existing.as_ref().and_then(|v| v.get("disk_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "metrics": existing.as_ref().and_then(|v| v.get("metrics")).cloned().unwrap_or(serde_json::Value::Null),
        "services": existing.as_ref().and_then(|v| v.get("services")).cloned().unwrap_or(serde_json::Value::Null),
        "services_status": if existing.as_ref().and_then(|v| v.get("services")).is_some_and(|value| value.is_array()) { "stale" } else { "unknown" },
        "services_observed_at": existing.as_ref().and_then(|v| v.get("services_observed_at")).cloned().unwrap_or(serde_json::Value::Null),
        "system_info": req.system_info,
    });
    cache_worker_metrics(&node_id, initial_snapshot);

    tracing::info!(
        node_id = %node_id,
        hostname = %hostname,
        address = %address,
        "cluster worker enrolled"
    );

    Ok(RegisterWorkerResponse {
        node_id,
        accepted: true,
        message: "welcome to the cluster".to_string(),
    })
}

/// Processes a worker metric heartbeat, updating `cluster_nodes` (`last_seen`, `last_heartbeat`,
/// `cpu_usage`, `ram_usage`, `disk_usage`, `status = 'online'`) and caching the full telemetry
/// snapshot in memory.
pub fn process_worker_heartbeat(
    req: &WorkerHeartbeatRequest,
) -> anyhow::Result<WorkerHeartbeatResponse> {
    process_worker_heartbeat_with_peer(req, &PeerTransportAuth::InternalCall)
}

/// Processes a worker metric heartbeat while enforcing per-node mTLS peer certificate pinning.
pub fn process_worker_heartbeat_with_peer(
    req: &WorkerHeartbeatRequest,
    peer_auth: &PeerTransportAuth,
) -> anyhow::Result<WorkerHeartbeatResponse> {
    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else if !req.hostname.trim().is_empty() {
        format!("node-{}", req.hostname.trim())
    } else {
        anyhow::bail!("node_id is required");
    };

    ensure_cluster_schema();
    let incoming_cert_fp = peer_auth.mtls_cert_sha256();

    if req.psk.trim().is_empty() {
        let Some(cert_fp) = incoming_cert_fp else {
            anyhow::bail!("psk is required");
        };
        let Ok(conn) = af_db::get_conn() else {
            anyhow::bail!("cluster database unavailable");
        };
        let Ok((stored_hash, stored_cert)) = conn.query_row(
            "SELECT COALESCE(psk_hash, ''), COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
            params![node_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ) else {
            anyhow::bail!("unauthenticated cluster worker: node is not enrolled");
        };
        if stored_hash.trim().is_empty() {
            anyhow::bail!("unauthenticated cluster worker: node is not enrolled");
        }
        if stored_cert.trim().is_empty()
            || !constant_time_eq(stored_cert.trim().as_bytes(), cert_fp.as_bytes())
        {
            anyhow::bail!("peer certificate does not match enrolled worker certificate");
        }
        let shared_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cluster_nodes WHERE peer_cert_sha256 = ?1",
                params![cert_fp],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if shared_count != 1 {
            anyhow::bail!(
                "shared worker client certificate requires x-cluster-psk header to disambiguate node identity"
            );
        }
    } else {
        if let Err(msg) = verify_cluster_psk(&node_id, &req.psk) {
            anyhow::bail!("{}", msg);
        }
        if !matches!(peer_auth, PeerTransportAuth::InternalCall) {
            let conn = af_db::get_conn().context("cluster database unavailable")?;
            let stored_cert: Option<String> = match conn.query_row(
                "SELECT COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
                params![node_id],
                |r| r.get::<_, String>(0),
            ) {
                Ok(val) => Some(val),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e).context("failed querying enrolled worker certificate pin"),
            };
            if let Some(stored) = stored_cert {
                let stored_trimmed = stored.trim();
                if !stored_trimmed.is_empty() {
                    let matches_pin = incoming_cert_fp.is_some_and(|fp| {
                        constant_time_eq(stored_trimmed.as_bytes(), fp.as_bytes())
                    });
                    if !matches_pin {
                        anyhow::bail!(
                            "peer certificate does not match enrolled worker certificate"
                        );
                    }
                }
            }
        }
    }

    let (cpu_usage, ram_usage, disk_usage) = extract_usage_Rollups(req);
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let ts = if req.timestamp > 0 {
        req.timestamp
    } else {
        now.timestamp()
    };

    let cert_fp_str = incoming_cert_fp.unwrap_or("");
    let updated = {
        let conn = af_db::get_conn().context("cluster database unavailable")?;
        conn.execute(
            "UPDATE cluster_nodes \
             SET status = 'online', \
                 last_heartbeat = ?1, \
                 last_seen = ?1, \
                 cpu_usage = ?2, \
                 ram_usage = ?3, \
                 disk_usage = ?4, \
                 peer_cert_sha256 = CASE WHEN COALESCE(peer_cert_sha256, '') = '' AND ?5 != '' THEN ?5 ELSE COALESCE(peer_cert_sha256, '') END \
             WHERE id = ?6",
            params![
                now_rfc3339,
                cpu_usage,
                ram_usage,
                disk_usage,
                cert_fp_str,
                node_id
            ],
        )
        .context("failed updating cluster worker heartbeat")?
    };

    if updated == 0 {
        remove_cached_worker_metrics(&node_id);
        anyhow::bail!(
            "cluster worker '{}' is not enrolled or has been deleted",
            node_id
        );
    }

    let previous = get_cached_worker_metrics(&node_id);
    let sys_info = req
        .system_info
        .as_ref()
        .and_then(|s| serde_json::to_value(s).ok())
        .or_else(|| {
            previous
                .as_ref()
                .and_then(|p| p.get("system_info"))
                .cloned()
        })
        .unwrap_or(serde_json::Value::Null);

    let metrics_val = if req.metrics.is_null() {
        serde_json::json!({
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "disk_usage": disk_usage,
        })
    } else {
        req.metrics.clone()
    };
    let (services, services_status, services_observed_at) =
        merge_worker_service_inventory(req, previous.as_ref(), ts);

    let version_val = previous
        .as_ref()
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("4.0.0");

    let sanitized_services_err = req
        .services_error
        .as_deref()
        .map(|s| truncate_utf8(s.trim(), 1024).to_string());

    let snapshot = serde_json::json!({
        "node_id": node_id,
        "hostname": if !req.hostname.is_empty() {
            serde_json::Value::String(req.hostname.clone())
        } else {
            previous.as_ref().and_then(|p| p.get("hostname")).cloned().unwrap_or(serde_json::Value::String(node_id.clone()))
        },
        "version": version_val,
        "status": "online",
        "timestamp": ts,
        "last_seen": now_rfc3339,
        "last_heartbeat": now_rfc3339,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage,
        "metrics": metrics_val,
        "services": services,
        "services_status": services_status,
        "services_observed_at": services_observed_at,
        "services_error": sanitized_services_err,
        "system_info": sys_info,
    });

    cache_worker_metrics(&node_id, snapshot);

    let mut confirmed_command_ids = Vec::new();
    for ack in &req.command_acks {
        match acknowledge_worker_command(&node_id, ack) {
            Ok(true) => confirmed_command_ids.push(ack.id.trim().to_string()),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(
                    node_id = %node_id,
                    command_id = %ack.id,
                    error = %err,
                    "failed persisting command ack during worker heartbeat"
                );
            }
        }
    }

    let command = lease_next_worker_command(&node_id, ts, CLUSTER_COMMAND_LEASE_SECS);
    Ok(WorkerHeartbeatResponse {
        timestamp: ts,
        acknowledged: true,
        command,
        confirmed_command_ids,
    })
}

fn merge_worker_service_inventory(
    request: &WorkerHeartbeatRequest,
    previous: Option<&serde_json::Value>,
    now: i64,
) -> (serde_json::Value, &'static str, Option<i64>) {
    let status = request.services_status.as_deref().unwrap_or("fresh");
    if status == "fresh" {
        if let Some(services) = &request.services {
            return (
                serde_json::json!(services),
                "fresh",
                Some(request.services_observed_at.unwrap_or(now)),
            );
        }
    }
    let previous_services = previous
        .and_then(|snapshot| snapshot.get("services"))
        .filter(|services| services.is_array())
        .cloned();
    if let Some(services) = previous_services {
        let observed_at = previous
            .and_then(|snapshot| snapshot.get("services_observed_at"))
            .and_then(|value| value.as_i64());
        return (services, "stale", observed_at);
    }
    if status == "stale" && request.services_observed_at.is_some() {
        if let Some(services) = &request.services {
            return (
                serde_json::json!(services),
                "stale",
                request.services_observed_at,
            );
        }
    }
    (serde_json::Value::Null, "unknown", None)
}

#[allow(non_snake_case)]
fn extract_usage_Rollups(req: &WorkerHeartbeatRequest) -> (f64, f64, f64) {
    let cpu = req
        .cpu_usage
        .or_else(|| req.metrics.get("cpu_usage").and_then(|v| v.as_f64()))
        .unwrap_or(0.0);

    let ram = req
        .ram_usage
        .or_else(|| req.metrics.get("ram_usage").and_then(|v| v.as_f64()))
        .or_else(|| {
            let used = req
                .metrics
                .get("memory")
                .and_then(|m| m.get("used"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("mem_used_gb").and_then(|v| v.as_f64()))?;
            let total = req
                .metrics
                .get("memory")
                .and_then(|m| m.get("total"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("mem_total_gb").and_then(|v| v.as_f64()))?;
            if total > 0.0 {
                Some(((used / total) * 1000.0).round() / 10.0)
            } else {
                Some(used)
            }
        })
        .unwrap_or(0.0);

    let disk = req
        .disk_usage
        .or_else(|| req.metrics.get("disk_usage").and_then(|v| v.as_f64()))
        .or_else(|| {
            let used = req
                .metrics
                .get("disk_space")
                .and_then(|d| d.get("used"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("disk_used_gb").and_then(|v| v.as_f64()))?;
            let total = req
                .metrics
                .get("disk_space")
                .and_then(|d| d.get("total"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("disk_total_gb").and_then(|v| v.as_f64()))?;
            if total > 0.0 {
                Some(((used / total) * 1000.0).round() / 10.0)
            } else {
                Some(used)
            }
        })
        .unwrap_or(0.0);

    (
        af_hardware::sanitize_f64(cpu),
        af_hardware::sanitize_f64(ram),
        af_hardware::sanitize_f64(disk),
    )
}
