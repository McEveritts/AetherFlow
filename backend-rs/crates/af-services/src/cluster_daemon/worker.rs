use super::master::read_bounded_http_body;
use super::receipts::{
    resolve_worker_ack_outbox_path, resolve_worker_command_receipts_path, InFlightCommandGuard,
    WorkerCommandCoordinator, WorkerCommandDispatchPlan,
};
use super::transport::{
    build_worker_mtls_connector, env_flag_true, is_loopback_host, non_empty_env,
    TLS_HANDSHAKE_TIMEOUT,
};
use super::types::{
    RegisterWorkerRequest, RegisterWorkerResponse, WorkerCommandAck, WorkerCommandAckRequest,
    WorkerHeartbeatRequest, WorkerHeartbeatResponse, WorkerService, WorkerSystemInfo,
};
use anyhow::Context;
use axum::body::Bytes;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::Full;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ─────────────────────────────────────────────────────────────────────────────
// Worker Registration & 5-Second Telemetry Heartbeat Loop (mTLS Enforced)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTargetEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
}

#[derive(Clone)]
pub enum WorkerTransportSecurity {
    Mtls(TlsConnector),
    InsecureLoopback,
}

pub fn parse_worker_endpoint(
    raw_addr: &str,
    default_https: bool,
) -> anyhow::Result<WorkerTargetEndpoint> {
    let trimmed = raw_addr.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("CLUSTER_MASTER_ADDR must not be empty");
    }
    let url_str = if trimmed.contains("://") {
        trimmed.to_string()
    } else if default_https {
        format!("https://{}", trimmed)
    } else {
        format!("http://{}", trimmed)
    };
    let parsed = url::Url::parse(&url_str)
        .with_context(|| format!("invalid CLUSTER_MASTER_ADDR '{}'", raw_addr))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!("unsupported scheme '{}' in CLUSTER_MASTER_ADDR", scheme);
    }
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host in CLUSTER_MASTER_ADDR '{}'", raw_addr))?;
    let host = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port().unwrap_or(50051);
    let authority = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    Ok(WorkerTargetEndpoint {
        scheme,
        host,
        port,
        authority,
    })
}

/// Evaluates `CLUSTER_CA_CERT`, `CLUSTER_CLIENT_CERT`, `CLUSTER_CLIENT_KEY`, and `CLUSTER_MASTER_ADDR`.
/// Fails closed on partial TLS configuration, plaintext `http://` when mTLS certs are present,
/// or remote/unopted-in plaintext worker transport.
pub fn resolve_worker_transport(
    raw_master_addr: &str,
) -> anyhow::Result<(WorkerTargetEndpoint, WorkerTransportSecurity)> {
    let ca = non_empty_env("CLUSTER_CA_CERT");
    let cert = non_empty_env("CLUSTER_CLIENT_CERT");
    let key = non_empty_env("CLUSTER_CLIENT_KEY");

    match (ca, cert, key) {
        (Some(ca_path), Some(cert_path), Some(key_path)) => {
            let endpoint = parse_worker_endpoint(raw_master_addr, true)?;
            if endpoint.scheme != "https" {
                anyhow::bail!(
                    "refusing plaintext {}:// CLUSTER_MASTER_ADDR when worker mTLS certificates are configured",
                    endpoint.scheme
                );
            }
            let connector = build_worker_mtls_connector(
                Path::new(&ca_path),
                Path::new(&cert_path),
                Path::new(&key_path),
            )?;
            Ok((endpoint, WorkerTransportSecurity::Mtls(connector)))
        }
        (None, None, None) => {
            let endpoint = parse_worker_endpoint(raw_master_addr, false)?;
            if endpoint.scheme == "https" {
                anyhow::bail!(
                    "https:// CLUSTER_MASTER_ADDR requires CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY"
                );
            }
            if env_flag_true("CLUSTER_ALLOW_INSECURE_LOOPBACK") && is_loopback_host(&endpoint.host) {
                tracing::warn!(
                    master = %endpoint.authority,
                    "CLUSTER_ALLOW_INSECURE_LOOPBACK=true enabled for loopback worker without mTLS"
                );
                Ok((endpoint, WorkerTransportSecurity::InsecureLoopback))
            } else {
                anyhow::bail!(
                    "CLUSTER_MODE=worker requires CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY (refusing unencrypted transport to '{}')",
                    raw_master_addr
                )
            }
        }
        _ => anyhow::bail!(
            "CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY must all be set together for worker mTLS"
        ),
    }
}

pub async fn send_worker_json_post(
    endpoint: &WorkerTargetEndpoint,
    security: &WorkerTransportSecurity,
    path: &str,
    psk: &str,
    body_bytes: Vec<u8>,
) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .context("worker TCP connect timed out")?
    .with_context(|| format!("worker failed connecting to {}", endpoint.authority))?;

    match security {
        WorkerTransportSecurity::Mtls(connector) => {
            let server_name = ServerName::try_from(endpoint.host.clone())
                .map_err(|_| anyhow::anyhow!("invalid TLS server name '{}'", endpoint.host))?;
            let tls_stream =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
                    .await
                    .context("worker mTLS handshake timed out")?
                    .context("worker mTLS handshake failed")?;

            let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            if negotiated_h2 {
                let (mut sender, conn) = hyper::client::conn::http2::handshake(
                    TokioExecutor::new(),
                    TokioIo::new(tls_stream),
                )
                .await
                .context("worker HTTP/2 handshake failed")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let uri = format!("https://{}{}", endpoint.authority, path);
                let req = Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("content-type", "application/json")
                    .header("x-cluster-psk", psk)
                    .body(Full::new(Bytes::from(body_bytes)))?;
                let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                    .await
                    .context("worker HTTP/2 request timed out")??;
                let status = resp.status();
                let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
                Ok((status, resp_bytes))
            } else {
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                        .await
                        .context("worker HTTP/1.1 handshake failed")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", &endpoint.authority)
                    .header("content-type", "application/json")
                    .header("x-cluster-psk", psk)
                    .body(Full::new(Bytes::from(body_bytes)))?;
                let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                    .await
                    .context("worker HTTP/1.1 request timed out")??;
                let status = resp.status();
                let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
                Ok((status, resp_bytes))
            }
        }
        WorkerTransportSecurity::InsecureLoopback => {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .context("worker loopback HTTP/1.1 handshake failed")?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", &endpoint.authority)
                .header("content-type", "application/json")
                .header("x-cluster-psk", psk)
                .body(Full::new(Bytes::from(body_bytes)))?;
            let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                .await
                .context("worker loopback HTTP/1.1 request timed out")??;
            let status = resp.status();
            let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
            Ok((status, resp_bytes))
        }
    }
}

fn resolve_local_hostname() -> String {
    if let Ok(h) = env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = env::var("COMPUTERNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    "aetherflow-worker".to_string()
}

pub(super) fn collect_worker_services() -> anyhow::Result<Vec<WorkerService>> {
    Ok(crate::get_active_services()?
        .into_iter()
        .map(|(name, svc)| WorkerService {
            name,
            status: svc.status,
            uptime: svc.uptime,
            managed_by: svc.managed_by,
        })
        .collect())
}

#[derive(Default)]
pub(super) struct WorkerServiceInventory {
    pub(super) services: Option<Vec<WorkerService>>,
    pub(super) observed_at: Option<i64>,
    pub(super) error: Option<String>,
    pub(super) fresh: bool,
}

impl WorkerServiceInventory {
    pub(super) fn observe(&mut self, result: anyhow::Result<Vec<WorkerService>>, now: i64) {
        match result {
            Ok(services) => {
                self.services = Some(services);
                self.observed_at = Some(now);
                self.error = None;
                self.fresh = true;
            }
            Err(error) => {
                self.error = Some(error.to_string());
                self.fresh = false;
            }
        }
    }

    pub(super) fn status(&self) -> &'static str {
        if self.fresh {
            "fresh"
        } else if self.services.is_some() {
            "stale"
        } else {
            "unknown"
        }
    }
}

type WorkerInventoryTask = tokio::task::JoinHandle<anyhow::Result<Vec<WorkerService>>>;

pub(super) async fn poll_worker_service_inventory(
    task: &mut Option<WorkerInventoryTask>,
    inventory: &mut WorkerServiceInventory,
    now: i64,
) {
    if task.as_ref().is_some_and(|task| task.is_finished()) {
        let result = task
            .take()
            .unwrap()
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("inventory worker failed: {error}")));
        if let Err(error) = &result {
            tracing::warn!(%error, "cluster inventory unknown; continuing liveness heartbeat");
        }
        inventory.observe(result, now);
    } else if task.is_none() {
        inventory.fresh = false;
        *task = Some(tokio::task::spawn_blocking(collect_worker_services));
    }
}

pub(super) fn build_worker_heartbeat_payload(
    node_id: &str,
    hostname: &str,
    address: &str,
    psk: &str,
    inventory: &WorkerServiceInventory,
) -> (WorkerHeartbeatRequest, WorkerSystemInfo) {
    let sys_metrics = af_hardware::get_system_metrics_core();
    let mem_used_gb = sys_metrics.memory.get("used").copied().unwrap_or(0.0);
    let mem_total_gb = sys_metrics.memory.get("total").copied().unwrap_or(0.0);
    let disk_used_gb = sys_metrics.disk_space.get("used").copied().unwrap_or(0.0);
    let disk_total_gb = sys_metrics.disk_space.get("total").copied().unwrap_or(0.0);

    let ram_pct = if mem_total_gb > 0.0 {
        af_hardware::sanitize_f64(((mem_used_gb / mem_total_gb) * 1000.0).round() / 10.0)
    } else {
        0.0
    };
    let disk_pct = if disk_total_gb > 0.0 {
        af_hardware::sanitize_f64(((disk_used_gb / disk_total_gb) * 1000.0).round() / 10.0)
    } else {
        0.0
    };

    let sys_info = WorkerSystemInfo {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        cpu_cores: sys_metrics.per_core_cpu.len().max(1) as i32,
        total_memory_bytes: (mem_total_gb * 1024.0 * 1024.0 * 1024.0) as i64,
        total_disk_bytes: (disk_total_gb * 1024.0 * 1024.0 * 1024.0) as i64,
    };

    let mut rich_metrics =
        serde_json::to_value(&sys_metrics).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = rich_metrics.as_object_mut() {
        obj.insert("mem_used_gb".to_string(), serde_json::json!(mem_used_gb));
        obj.insert("mem_total_gb".to_string(), serde_json::json!(mem_total_gb));
        obj.insert("disk_used_gb".to_string(), serde_json::json!(disk_used_gb));
        obj.insert(
            "disk_total_gb".to_string(),
            serde_json::json!(disk_total_gb),
        );
        obj.insert("ram_usage".to_string(), serde_json::json!(ram_pct));
        obj.insert("disk_usage".to_string(), serde_json::json!(disk_pct));
        obj.insert(
            "net_rx_speed".to_string(),
            sys_metrics
                .network
                .get("down")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("0 B/s")),
        );
        obj.insert(
            "net_tx_speed".to_string(),
            sys_metrics
                .network
                .get("up")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("0 B/s")),
        );
    }

    let hb = WorkerHeartbeatRequest {
        node_id: node_id.to_string(),
        hostname: hostname.to_string(),
        address: address.to_string(),
        psk: psk.to_string(),
        timestamp: Utc::now().timestamp(),
        cpu_usage: Some(sys_metrics.cpu_usage),
        ram_usage: Some(ram_pct),
        disk_usage: Some(disk_pct),
        metrics: rich_metrics,
        services: inventory.services.clone(),
        services_status: Some(inventory.status().to_string()),
        services_observed_at: inventory.observed_at,
        services_error: inventory.error.clone(),
        system_info: Some(sys_info.clone()),
        command_acks: Vec::new(),
    };

    (hb, sys_info)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedWorkerRegistrationState {
    pub node_id: String,
    pub master_authority: String,
    pub credential: String,
    pub registered_at: String,
}

pub fn resolve_worker_registration_state_path() -> std::path::PathBuf {
    if let Ok(explicit) = env::var("CLUSTER_WORKER_STATE_FILE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = root.trim();
        if !trimmed.is_empty() && trimmed != "/" {
            return Path::new(trimmed).join("var/lib/aetherflow/cluster_worker_state.json");
        }
    }
    if let Ok(data_dir) = env::var("DATA_DIR") {
        let trimmed = data_dir.trim();
        if !trimmed.is_empty() {
            return Path::new(trimmed).join("cluster_worker_state.json");
        }
    }
    std::path::PathBuf::from("/var/lib/aetherflow/cluster_worker_state.json")
}

/// Atomically persists worker registration state & credential with `0600` permissions and `O_NOFOLLOW`.
pub fn persist_worker_registration_state_atomic(
    path: &Path,
    state: &PersistedWorkerRegistrationState,
) -> anyhow::Result<()> {
    use std::io::Write;
    let Some(parent) = path.parent() else {
        anyhow::bail!("worker state path must have a parent directory");
    };
    if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
        if pmeta.file_type().is_symlink() {
            anyhow::bail!("refusing symlink parent directory for worker registration state");
        }
    } else {
        std::fs::create_dir_all(parent).context("creating worker state parent directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to overwrite symlink worker registration state file");
        }
    }

    let payload = serde_json::to_vec_pretty(state)?;
    let tmp_name = format!(
        ".cluster_worker_state.{}.tmp",
        uuid::Uuid::new_v4().simple()
    );
    let tmp_path = parent.join(tmp_name);

    #[cfg(unix)]
    let mut tmp_file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_tmp = CString::new(tmp_path.as_os_str().as_bytes())
            .context("worker state temp path contains interior NUL")?;
        let fd = unsafe {
            libc::open(
                c_tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("opening exclusive 0600 worker registration temp file");
        }
        unsafe {
            let _ = libc::fchmod(fd, 0o600);
            std::fs::File::from_raw_fd(fd)
        }
    };
    #[cfg(not(unix))]
    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;

    if let Err(err) = tmp_file
        .write_all(&payload)
        .and_then(|_| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).context("writing worker registration state temp file");
    }
    drop(tmp_file);

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(&tmp_path);
            anyhow::bail!("worker registration state target turned into a symlink");
        }
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).context("atomically activating worker registration state file");
    }
    if let Ok(dir_f) = std::fs::File::open(parent) {
        let _ = dir_f.sync_all();
    }
    Ok(())
}

/// Loads persisted worker registration state safely with `O_NOFOLLOW`.
pub fn load_worker_registration_state_nofollow(
    path: &Path,
) -> Option<PersistedWorkerRegistrationState> {
    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        f
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::open(path).ok()?;

    let mut raw = Vec::new();
    file.take(64 * 1024).read_to_end(&mut raw).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub(super) fn parse_confirmed_command_ids(resp_bytes: &[u8]) -> Vec<String> {
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(resp_bytes) else {
        return Vec::new();
    };
    if val.get("acknowledged").and_then(|v| v.as_bool()) != Some(true) {
        return Vec::new();
    }
    val.get("confirmed_command_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn send_worker_command_ack_and_confirm(
    endpoint: WorkerTargetEndpoint,
    security: WorkerTransportSecurity,
    cred: String,
    node_id: String,
    coordinator: Arc<WorkerCommandCoordinator>,
    ack: WorkerCommandAck,
) {
    let cmd_id = ack.id.clone();
    let ack_req = WorkerCommandAckRequest {
        node_id,
        psk: String::new(),
        acks: vec![ack],
    };
    let Ok(bytes) = serde_json::to_vec(&ack_req) else {
        return;
    };
    if let Ok((st, body)) = send_worker_json_post(
        &endpoint,
        &security,
        "/cluster/v1/commands/ack",
        &cred,
        bytes,
    )
    .await
    {
        if st.is_success() {
            let confirmed = parse_confirmed_command_ids(&body);
            if confirmed.iter().any(|c| c == &cmd_id) {
                coordinator.mark_confirmed(&confirmed);
            }
        }
    }
}

fn resolve_live_enrollment_credential(fallback: &str) -> String {
    env::var("CLUSTER_ENROLL_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            env::var("CLUSTER_PSK")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| fallback.trim().to_string())
}

pub(super) async fn register_worker_with_bounded_backoff(
    endpoint: &WorkerTargetEndpoint,
    security: &WorkerTransportSecurity,
    credential: &str,
    preferred_node_id: &str,
    hostname: &str,
    worker_address: &str,
    state_path: &Path,
) -> String {
    let initial_ms = env::var("CLUSTER_REGISTER_INITIAL_BACKOFF_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1000);
    let max_ms = env::var("CLUSTER_REGISTER_MAX_BACKOFF_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= initial_ms)
        .unwrap_or(30_000);

    let (_, sys_info) = build_worker_heartbeat_payload(
        preferred_node_id,
        hostname,
        worker_address,
        "",
        &WorkerServiceInventory::default(),
    );
    let reg_payload = RegisterWorkerRequest {
        node_id: preferred_node_id.to_string(),
        hostname: hostname.to_string(),
        address: worker_address.to_string(),
        psk: String::new(),
        version: "4.0.0".to_string(),
        system_info: Some(sys_info),
    };
    let reg_bytes = serde_json::to_vec(&reg_payload).unwrap_or_default();
    let register_paths = ["/cluster/v1/register", "/api/v1/admin/cluster/enroll"];

    let mut backoff_ms = initial_ms;
    loop {
        let live_cred = resolve_live_enrollment_credential(credential);
        for path in &register_paths {
            match send_worker_json_post(endpoint, security, path, &live_cred, reg_bytes.clone())
                .await
            {
                Ok((status, resp_bytes)) if status.is_success() => {
                    if let Ok(parsed) =
                        serde_json::from_slice::<RegisterWorkerResponse>(&resp_bytes)
                    {
                        if parsed.accepted {
                            let assigned = if parsed.node_id.trim().is_empty() {
                                preferred_node_id.to_string()
                            } else {
                                parsed.node_id.trim().to_string()
                            };
                            let persisted = PersistedWorkerRegistrationState {
                                node_id: assigned.clone(),
                                master_authority: endpoint.authority.clone(),
                                credential: live_cred,
                                registered_at: Utc::now().to_rfc3339(),
                            };
                            if let Err(err) =
                                persist_worker_registration_state_atomic(state_path, &persisted)
                            {
                                tracing::warn!(
                                    path = %state_path.display(),
                                    error = %err,
                                    "failed persisting worker registration state"
                                );
                            }
                            tracing::info!(
                                node_id = %assigned,
                                master = %endpoint.authority,
                                "cluster worker registered with master"
                            );
                            return assigned;
                        }
                    }
                }
                Ok((status, _)) => {
                    tracing::warn!(
                        endpoint = %path,
                        status = %status,
                        backoff_ms = backoff_ms,
                        "cluster registration endpoint returned non-success; backing off"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        endpoint = %path,
                        error = %e,
                        backoff_ms = backoff_ms,
                        "cluster worker registration attempt failed; backing off"
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = backoff_ms.saturating_mul(2).min(max_ms);
    }
}

pub(super) async fn run_worker_registration_and_heartbeat_loop(
    endpoint: WorkerTargetEndpoint,
    security: WorkerTransportSecurity,
    psk: String,
) {
    let hostname = resolve_local_hostname();
    let local_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let worker_address = format!("{}:{}", hostname, local_port);
    let state_path = resolve_worker_registration_state_path();
    let outbox_path = resolve_worker_ack_outbox_path(&state_path);
    let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

    let mut active_cred = resolve_live_enrollment_credential(&psk);
    let mut assigned_node_id = format!("node-{}", hostname);

    if let Some(saved) = load_worker_registration_state_nofollow(&state_path)
        .filter(|s| s.master_authority == endpoint.authority && !s.node_id.trim().is_empty())
    {
        assigned_node_id = saved.node_id;
        if active_cred.is_empty() && !saved.credential.trim().is_empty() {
            active_cred = saved.credential;
        }
    } else {
        assigned_node_id = register_worker_with_bounded_backoff(
            &endpoint,
            &security,
            &active_cred,
            &assigned_node_id,
            &hostname,
            &worker_address,
            &state_path,
        )
        .await;
        if let Some(saved) = load_worker_registration_state_nofollow(&state_path) {
            if !saved.credential.trim().is_empty() {
                active_cred = saved.credential;
            }
        }
    }

    let hb_interval_ms = env::var("CLUSTER_HEARTBEAT_INTERVAL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= 20)
        .unwrap_or(5000);
    let mut ticker = tokio::time::interval(Duration::from_millis(hb_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut inventory = WorkerServiceInventory::default();
    let mut inventory_task = None;

    let cmd_coordinator = Arc::new(WorkerCommandCoordinator::load_and_recover(
        &assigned_node_id,
        &outbox_path,
        &receipts_path,
    ));

    loop {
        ticker.tick().await;
        poll_worker_service_inventory(&mut inventory_task, &mut inventory, Utc::now().timestamp())
            .await;
        let (mut hb_payload, _) = build_worker_heartbeat_payload(
            &assigned_node_id,
            &hostname,
            &worker_address,
            "",
            &inventory,
        );
        hb_payload.psk.clear();
        hb_payload.command_acks = cmd_coordinator.pending_acks_snapshot();

        let Ok(hb_bytes) = serde_json::to_vec(&hb_payload) else {
            continue;
        };

        match send_worker_json_post(
            &endpoint,
            &security,
            "/cluster/v1/heartbeat",
            &active_cred,
            hb_bytes,
        )
        .await
        {
            Ok((status, resp_bytes)) if status.is_success() => {
                if let Ok(pong) = serde_json::from_slice::<WorkerHeartbeatResponse>(&resp_bytes) {
                    if !pong.confirmed_command_ids.is_empty() {
                        cmd_coordinator.mark_confirmed(&pong.confirmed_command_ids);
                    }
                    if let Some(cmd) = pong.command {
                        match cmd_coordinator.prepare_command_dispatch(cmd) {
                            WorkerCommandDispatchPlan::SendAckOnly(ack) => {
                                let ep_clone = endpoint.clone();
                                let sec_clone = security.clone();
                                let cred_clone = active_cred.clone();
                                let node_clone = assigned_node_id.clone();
                                let coord_clone = Arc::clone(&cmd_coordinator);
                                tokio::spawn(async move {
                                    send_worker_command_ack_and_confirm(
                                        ep_clone,
                                        sec_clone,
                                        cred_clone,
                                        node_clone,
                                        coord_clone,
                                        ack,
                                    )
                                    .await;
                                });
                            }
                            WorkerCommandDispatchPlan::Execute(mutation) => {
                                let ep_clone = endpoint.clone();
                                let sec_clone = security.clone();
                                let cred_clone = active_cred.clone();
                                let node_clone = assigned_node_id.clone();
                                let coord_clone = Arc::clone(&cmd_coordinator);
                                tokio::spawn(async move {
                                    let mut guard = InFlightCommandGuard::new(
                                        Arc::clone(&coord_clone),
                                        mutation.id.clone(),
                                    );
                                    let outcome =
                                        crate::control_service(&mutation.service, &mutation.action)
                                            .await
                                            .map_err(|err| err.to_string());
                                    match coord_clone.complete_admitted_mutation(&mutation, outcome)
                                    {
                                        Ok(ack) => {
                                            guard.disarm();
                                            send_worker_command_ack_and_confirm(
                                                ep_clone,
                                                sec_clone,
                                                cred_clone,
                                                node_clone,
                                                coord_clone,
                                                ack,
                                            )
                                            .await;
                                        }
                                        Err(err) => {
                                            tracing::error!(
                                                command_id = %mutation.id,
                                                error = %err,
                                                "failed persisting completed cluster command result before ACK"
                                            );
                                        }
                                    }
                                });
                            }
                            WorkerCommandDispatchPlan::AlreadyInFlight
                            | WorkerCommandDispatchPlan::RejectedStaleLease
                            | WorkerCommandDispatchPlan::RejectedConflictingIdentity
                            | WorkerCommandDispatchPlan::RejectedCapacitySaturated
                            | WorkerCommandDispatchPlan::RejectedStorageFailure => {}
                        }
                    }
                }
            }
            Ok((status, _)) => {
                tracing::warn!(
                    status = %status,
                    "cluster master rejected heartbeat"
                );
                if status == StatusCode::UNAUTHORIZED {
                    let fresh_cred = resolve_live_enrollment_credential(&active_cred);
                    if !fresh_cred.is_empty() {
                        tracing::info!(
                            node_id = %assigned_node_id,
                            "heartbeat received 401 with credential available; re-triggering worker registration"
                        );
                        active_cred = fresh_cred;
                        assigned_node_id = register_worker_with_bounded_backoff(
                            &endpoint,
                            &security,
                            &active_cred,
                            &assigned_node_id,
                            &hostname,
                            &worker_address,
                            &state_path,
                        )
                        .await;
                        cmd_coordinator.set_node_id(&assigned_node_id);
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    master = %endpoint.authority,
                    "cluster heartbeat send error"
                );
            }
        }
    }
}
