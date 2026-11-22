//! Cluster Master/Worker Heartbeat & Registration Daemon.
//!
//! Provides:
//! - `start_cluster_runtime()`: Spawns the 30-second node health-sweep loop and, depending on
//!   `CLUSTER_MODE` (`"master"`, `"worker"`, or `"standalone"`), launches either the master
//!   TCP/HTTP JSON-RPC listener or the worker registration + 5-second telemetry heartbeat loop.
//! - `get_cached_worker_metrics(node_id)`: Returns the most recent rich telemetry snapshot
//!   pushed by a worker node if cached in memory.

mod auth;
mod commands;
mod grpc;
mod master;
mod membership;
mod receipts;
mod transport;
mod types;
mod worker;

#[cfg(test)]
mod tests;

use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

use commands::truncate_diagnostic_utf8;
#[cfg(test)]
use master::route_cluster_http_request;
use transport::MAX_CLUSTER_CONCURRENT_CONNS;
use worker::run_worker_registration_and_heartbeat_loop;

pub use auth::{
    constant_time_eq, ensure_cluster_schema, issue_cluster_enrollment_token, verify_cluster_psk,
    PeerTransportAuth,
};
pub use commands::{
    acknowledge_worker_command, cache_worker_metrics, enqueue_cluster_command,
    enqueue_cluster_command_with_action, get_cached_worker_metrics, is_allowed_worker_command_type,
    lease_next_worker_command, list_cluster_commands, normalize_cluster_command,
    pop_worker_command, queue_worker_command, queue_worker_command_checked,
    remove_cached_worker_metrics, truncate_utf8, ClusterCommandEnqueueError,
    NormalizedClusterCommand, WORKER_COMMAND_STATUS_EXECUTED, WORKER_COMMAND_STATUS_FAILED,
    WORKER_COMMAND_STATUS_UNKNOWN,
};
pub use master::serve_cluster_master_connection;
pub use membership::{
    process_worker_heartbeat, process_worker_heartbeat_with_peer, register_worker_node,
    register_worker_node_with_peer, sweep_stale_cluster_nodes,
};
pub use receipts::{
    enqueue_worker_ack_outbox_entry, evict_confirmed_acks_from_outbox,
    load_worker_ack_outbox_nofollow, load_worker_ack_outbox_strict,
    load_worker_command_receipts_strict, persist_worker_ack_outbox_atomic,
    persist_worker_command_receipts_atomic, resolve_worker_ack_outbox_path,
    resolve_worker_command_receipts_path, WorkerCommandReceipt, WorkerCommandReceiptPhase,
};
pub use transport::{
    build_master_mtls_acceptor, build_worker_mtls_connector, is_loopback_host,
    load_master_transport_security, resolve_master_bind_config, MasterBindConfig,
    MasterTransportSecurity,
};
pub use types::{
    ClusterCommandRecord, PendingWorkerCommand, RegisterWorkerRequest, RegisterWorkerResponse,
    WorkerCommandAck, WorkerCommandAckRequest, WorkerHeartbeatRequest, WorkerHeartbeatResponse,
    WorkerService, WorkerSystemInfo,
};
pub use worker::{
    load_worker_registration_state_nofollow, parse_worker_endpoint,
    persist_worker_registration_state_atomic, resolve_worker_registration_state_path,
    resolve_worker_transport, send_worker_json_post, PersistedWorkerRegistrationState,
    WorkerTargetEndpoint, WorkerTransportSecurity,
};

// ─────────────────────────────────────────────────────────────────────────────
// Public Entrypoint (`start_cluster_runtime`)
// ─────────────────────────────────────────────────────────────────────────────

/// Starts the Cluster Master/Worker runtime and background health-sweep daemon:
/// - Always spawns a 30-second health-sweep loop marking stale `cluster_nodes` (`last_seen` > 60s)
///   as `status = 'offline'`.
/// - If `CLUSTER_MODE=master`: enforces TLS 1.3 mutual TLS (`CLUSTER_CA_CERT`, `CLUSTER_SERVER_CERT`,
///   `CLUSTER_SERVER_KEY`) and binds `CLUSTER_GRPC_HOST:CLUSTER_GRPC_PORT` (default `127.0.0.1:50051`),
///   serving both legacy `cluster.ClusterService` HTTP/2 gRPC and `/cluster/v1/*` HTTP JSON.
/// - If `CLUSTER_MODE=worker`: enforces TLS 1.3 mutual TLS (`CLUSTER_CA_CERT`, `CLUSTER_CLIENT_CERT`,
///   `CLUSTER_CLIENT_KEY`), enrolls with `CLUSTER_MASTER_ADDR`, and runs a 5-second heartbeat loop.
pub fn start_cluster_runtime() {
    ensure_cluster_schema();

    // Mark all persisted nodes offline at boot until they send a fresh heartbeat, matching Go's `loadFromDB()`
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute("UPDATE cluster_nodes SET status = 'offline'", []);
    }

    // 1. Always spawn the 30-second master node health-sweep loop
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            sweep_stale_cluster_nodes();
        }
    });

    // 2. Evaluate `CLUSTER_MODE` ("master", "worker", or "standalone" default)
    let mode = env::var("CLUSTER_MODE")
        .unwrap_or_else(|_| "standalone".to_string())
        .trim()
        .to_lowercase();

    match mode.as_str() {
        "master" => {
            let bind_cfg = resolve_master_bind_config();
            let security = match load_master_transport_security(&bind_cfg.host) {
                Ok(sec) => sec,
                Err(e) => {
                    tracing::error!(
                        listen_addr = %bind_cfg.bind_addr,
                        error = %e,
                        "cluster master refused startup due to missing or invalid mTLS configuration"
                    );
                    return;
                }
            };

            let bind_addr = bind_cfg.bind_addr;
            tracing::info!(
                role = "master",
                listen_addr = %bind_addr,
                "cluster mode active (mTLS enforced)"
            );

            tokio::spawn(async move {
                match TcpListener::bind(&bind_addr).await {
                    Ok(listener) => {
                        tracing::info!(
                            addr = %bind_addr,
                            "cluster mTLS gRPC + HTTP listener bound"
                        );
                        let conn_semaphore =
                            Arc::new(tokio::sync::Semaphore::new(MAX_CLUSTER_CONCURRENT_CONNS));
                        loop {
                            match listener.accept().await {
                                Ok((stream, _peer)) => {
                                    let Ok(permit) = conn_semaphore.clone().try_acquire_owned()
                                    else {
                                        tracing::warn!("cluster listener at connection capacity; dropping socket");
                                        continue;
                                    };
                                    let sec = security.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(e) =
                                            serve_cluster_master_connection(stream, sec).await
                                        {
                                            tracing::debug!(
                                                error = %e,
                                                "cluster connection handler error"
                                            );
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "cluster listener accept error");
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            addr = %bind_addr,
                            error = %e,
                            "failed to bind cluster listener"
                        );
                    }
                }
            });
        }
        "worker" => {
            let master_addr = env::var("CLUSTER_MASTER_ADDR")
                .unwrap_or_default()
                .trim()
                .to_string();
            let psk = env::var("CLUSTER_PSK")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    env::var("CLUSTER_ENROLL_TOKEN")
                        .ok()
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                })
                .unwrap_or_default();

            if master_addr.is_empty() {
                tracing::error!(
                    "CLUSTER_MODE=worker requires CLUSTER_MASTER_ADDR to be set; skipping worker loop"
                );
                return;
            }
            if psk.is_empty() {
                tracing::error!(
                    "CLUSTER_MODE=worker requires CLUSTER_PSK or CLUSTER_ENROLL_TOKEN to be set; skipping worker loop"
                );
                return;
            }

            let (endpoint, security) = match resolve_worker_transport(&master_addr) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(
                        master_addr = %master_addr,
                        error = %e,
                        "cluster worker refused startup due to missing or invalid mTLS configuration"
                    );
                    return;
                }
            };

            tracing::info!(
                role = "worker",
                master_addr = %endpoint.authority,
                "cluster mode active"
            );

            tokio::spawn(async move {
                run_worker_registration_and_heartbeat_loop(endpoint, security, psk).await;
            });
        }
        _ => {
            tracing::info!(role = "standalone", "cluster mode active");
        }
    }
}
