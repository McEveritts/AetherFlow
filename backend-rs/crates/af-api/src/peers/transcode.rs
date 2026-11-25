//! Distributed Jellyfin transcoding control plane, Unix-socket dispatcher, worker WebSocket
//! relay, settings/parity endpoints, version alignment, and job history (Phase P9, Design Entry 48).
//!
//! Security & Reliability Invariants:
//! - Completely dormant on standalone servers: zero runner calls, zero Unix socket binds, and zero
//!   ffmpeg subprocesses until explicitly enabled or peer clustering is active.
//! - Dispatcher Unix socket (`/run/aetherflow-transcode/transcode.sock`, mode `0660`, world bits
//!   forbidden) is bound inside a private `0700` staging directory under an exclusive parent
//!   directory `flock`, published via non-replacing `hard_link`, and unlinked on drop only if
//!   `(dev, ino)` still matches.
//! - Honors P8's no-duplicate-exec and 1,500 ms remote-start budget
//!   (`RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT`): `Frame::RunLocal` is emitted ONLY when no
//!   remote worker could have received a complete `Frame::Start`. Once a complete `Frame::Start`
//!   has been transmitted over WebSocket, any worker timeout/drop/error tears down the worker
//!   stream (forcing `killpg(SIGKILL)`), marks the worker unhealthy for 60 s, and fails the job
//!   without ever issuing `Frame::RunLocal`.
//! - Hard-kill & revocation cleanup: closing the shim Unix socket without `Frame::Exit` or
//!   receiving a matching `RevocationEvent::LinkRevoked` / `GrantRevoked` immediately sends
//!   high-priority `Frame::Signal(SignalKind::Kill)` to the worker and closes both connections.
//! - Worker endpoint `GET /peer/v1/transcode/jobs` on the isolated WireGuard tunnel listener
//!   enforces tunnel source IP + constant-time `X-AF-Link-Token` + constant-time
//!   `X-AF-Grant-Token` + `AccessLevel::Write` on `Area::Transcoding` + active `account_type='peer'`
//!   run-as user + per-link WebSocket concurrency permit, auditing every start, denial, and end.

use super::errors::{
    bytes_rejection_to_peer_error, parse_required_json_bytes, redact_sensitive_text, PeerError,
};
use super::grants::read_committed_received_grant_token;
use super::health::{evaluate_compatibility, CompatibilityStatus};
use super::listener::{
    audit_listener_denial, authenticate_active_link, authenticate_active_link_ws,
    extract_or_generate_request_id, AuthenticatedPeerLink,
};
use super::pairing::{is_valid_credential_id, sha256_prefixed};
use super::{
    is_active_link_state, is_revoked_or_revoking_state, public_link_state, PeerRuntime,
    RevocationEvent, TunnelClientBindingKey, TunnelHttpError, HEADER_GRANT_TOKEN,
    HEADER_LINK_TOKEN,
};
use crate::auth::AuthUser;
use crate::ws::{extract_client_ip_for_peer, PeerIp};
use af_db::peers::{self as db_peers, PeerLink, PeerMount, TranscodeJob, TranscodeWorker};
use af_models::constant_time_eq;
use af_runner::{
    systemd_escape_path, validate_peer_mount_segment, JellyfinTranscodePaths,
    ParityFileCleanupReport, PeerCredentialSecret, PeerCredentialSlot, PeerNetworkError,
    PeerNetworkRequest, PeerStorageRequest, PeerTranscodeError, PeerTranscodeRequest,
    PeerTranscodeResponse, DEFAULT_JELLYFIN_CACHE_DIR, DEFAULT_JELLYFIN_TMP_DIR,
    DEFAULT_JELLYFIN_TRANSCODE_DIR, DEFAULT_PEER_MOUNTS_ROOT, DEFAULT_TRANSCODE_SHIM_PATH,
};
use af_transcode::argv;
use af_transcode::capabilities::{
    probe_capabilities, select_render_node, CapabilitiesConfig, RenderNodeInfo,
    TranscodeCapabilities,
};
use af_transcode::config::{
    configured_dispatcher_socket_path, configured_worker_socket_path, validate_absolute_clean_path,
    validate_socket_mode, DEFAULT_FRAME_WRITE_TIMEOUT, DEFAULT_WORKER_SOCKET_MODE,
    MAX_UNIX_SOCKET_PATH_BYTES, RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT,
};
use af_transcode::protocol::{
    bounded_frame_channel, decode_frame_payload, encode_frame_payload, read_frame, write_frame,
    ErrorKind, Frame, SignalKind, StartRequest, FRAME_CHANNEL_CAPACITY, MAX_FRAME_BYTES,
};
use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::rejection::BytesRejection;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::BoxFuture;
use futures::{SinkExt as _, StreamExt as _};
use rand::Rng as _;
use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpSocket, TcpStream, UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch, Mutex as TokioMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use uuid::Uuid;

pub const WORKER_UNHEALTHY_COOLDOWN_SECS: i64 = 60;
pub const WORKER_WEIGHT_MIN: i64 = 1;
pub const WORKER_WEIGHT_MAX: i64 = 100;
pub const WORKER_MAX_JOBS_MIN: i64 = 1;
pub const WORKER_MAX_JOBS_MAX: i64 = 64;
pub const RECENT_JOBS_LIMIT: usize = 50;
pub const TRANSCODE_JOB_RETENTION_DAYS: i64 = 7;

const LOCAL_CAPS_CACHE_TTL: Duration = Duration::from_secs(60);
const ADMIN_TRANSCODE_BODY_LIMIT_BYTES: usize = 32 * 1024;
const WORKER_SOCKET_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_000);
const KILL_SIGNAL_WRITE_TIMEOUT: Duration = Duration::from_millis(250);
const JELLYFIN_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const JELLYFIN_PROBE_MAX_BODY_BYTES: usize = 256 * 1024;
const JELLYFIN_ENABLE_PROBE_RETRIES: usize = 5;
const JELLYFIN_ENABLE_PROBE_RETRY_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_PARITY_TEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Strictly exceeds `af_runner::peer_transcode::TRANSCODE_MOUNT_CLIENT_TIMEOUT` (150 s) so slow mount starts on
/// the worker do not get prematurely cancelled by the controller HTTP client.
pub(crate) const TRANSCODE_MOUNT_SYNC_TIMEOUT: Duration = Duration::from_secs(180);
const AUTO_RESYNC_MOUNT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PENDING_DISPATCHER_CONNS: usize = 128;
const MAX_TUNNEL_TRANSCODE_PATHS: usize = 32;
const MAX_TRANSCODE_PATH_BYTES: usize = 4096;
const MOUNT_PURPOSE_MEDIA: &str = "media";
const MOUNT_PURPOSE_TRANSCODE: &str = "transcode";
const MOUNT_PURPOSE_TRANSCODE_BIND: &str = "transcode_bind";
const WS_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const DEFAULT_BIND_MEDIA_ROOTS: &[&str] = &[
    "/mnt",
    "/media",
    "/srv",
    "/downloads",
    "/data",
    "/var/lib/jellyfin",
];

const FORBIDDEN_TRANSCODE_SYSTEM_PREFIXES: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/boot",
    "/root",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/usr",
    "/var/lib/aetherflow",
    "/var/run",
    "/var/spool",
    "/opt/AetherFlow",
];

const FORBIDDEN_TRANSCODE_EXACT_PATHS: &[&str] = &[
    "/",
    "/tmp",
    "/var/tmp",
    "/var",
    "/home",
    "/mnt",
    "/mnt/af-peers",
    "/var/lib",
    "/var/cache",
];

static TEMP_DISPATCHER_SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Transcode Runner & Jellyfin Probe Traits
// ─────────────────────────────────────────────────────────────────────────────

/// Privileged runner abstraction for `/v1/peer-transcode`.
pub(crate) trait PeerTranscodeRunner: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerTranscodeRequest,
    ) -> BoxFuture<'a, Result<PeerTranscodeResponse, PeerTranscodeError>>;
}

pub(crate) struct ProductionPeerTranscodeRunner;

impl PeerTranscodeRunner for ProductionPeerTranscodeRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerTranscodeRequest,
    ) -> BoxFuture<'a, Result<PeerTranscodeResponse, PeerTranscodeError>> {
        Box::pin(af_runner::dispatch_peer_transcode(req))
    }
}

/// Result of querying local Jellyfin API for its active reported `ffmpeg` binary path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JellyfinFfmpegProbeOutcome {
    /// Jellyfin is not configured in `streaming_servers` or could not be reached.
    NotConfiguredOrUnreachable,
    /// Jellyfin responded and reported this `ffmpeg` executable path.
    Reported(String),
    /// Jellyfin responded cleanly but did not expose a non-empty `ffmpeg` path.
    ReachableMissingPath,
}

/// Injectable local Jellyfin API probe for `GET`/`PUT /api/v1/admin/peers/transcode`.
pub(crate) trait JellyfinFfmpegProbe: Send + Sync {
    fn probe_reported_ffmpeg<'a>(
        &'a self,
        runtime: &'a PeerRuntime,
    ) -> BoxFuture<'a, JellyfinFfmpegProbeOutcome>;
}

struct ProductionJellyfinFfmpegProbe;

impl JellyfinFfmpegProbe for ProductionJellyfinFfmpegProbe {
    fn probe_reported_ffmpeg<'a>(
        &'a self,
        runtime: &'a PeerRuntime,
    ) -> BoxFuture<'a, JellyfinFfmpegProbeOutcome> {
        Box::pin(async move { probe_local_jellyfin_ffmpeg_path(runtime).await })
    }
}

struct JellyfinServerCredentials {
    url: String,
    api_key: String,
}

fn load_local_jellyfin_credentials(
    conn: &rusqlite::Connection,
) -> Option<JellyfinServerCredentials> {
    if !crate::auth::table_exists(conn, "streaming_servers").unwrap_or(false) {
        return None;
    }
    let (url, stored_key): (String, String) = conn
        .query_row(
            "SELECT COALESCE(url, ''), COALESCE(api_key, '') \
             FROM streaming_servers WHERE provider = 'jellyfin' AND enabled = 1 LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten()?;
    let url = url.trim().to_string();
    if url.is_empty() || stored_key.trim().is_empty() {
        return None;
    }
    let api_key = if stored_key.starts_with("enc:v1:") {
        af_db::decrypt_key(&stored_key).ok()?
    } else {
        stored_key
    };
    let api_key = api_key.trim().to_string();
    if api_key.is_empty() || api_key.starts_with("enc:v1:") {
        return None;
    }
    Some(JellyfinServerCredentials { url, api_key })
}

fn extract_ffmpeg_path_from_jellyfin_json(val: &serde_json::Value) -> Option<String> {
    for key in [
        "EncoderAppPathDisplay",
        "EncoderAppPath",
        "EncoderPath",
        "FfmpegPath",
        "encoderAppPathDisplay",
        "encoderAppPath",
    ] {
        if let Some(raw) = val.get(key).and_then(|v| v.as_str()) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

async fn probe_local_jellyfin_ffmpeg_path(runtime: &PeerRuntime) -> JellyfinFfmpegProbeOutcome {
    let creds = runtime
        .db
        .read(
            &runtime.local_server_name(),
            "jellyfin_ffmpeg_probe",
            |conn| Ok(load_local_jellyfin_credentials(conn)),
        )
        .await
        .ok()
        .flatten();
    let Some(creds) = creds else {
        return JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable;
    };
    let Ok(clean_url) = af_services::validate_server_url(&creds.url) else {
        return JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable;
    };
    let Ok(mut token_hv) = HeaderValue::from_str(&creds.api_key) else {
        return JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable;
    };
    token_hv.set_sensitive(true);

    let Ok(client) = af_services::streaming_http_client_builder()
        .connect_timeout(JELLYFIN_PROBE_TIMEOUT)
        .timeout(JELLYFIN_PROBE_TIMEOUT)
        .build()
    else {
        return JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable;
    };

    let mut reached_any = false;
    for endpoint in ["/System/Configuration/encoding", "/System/Info"] {
        let resp = match client
            .get(format!("{clean_url}{endpoint}"))
            .header(header::ACCEPT, "application/json")
            .header("X-Emby-Token", token_hv.clone())
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }
        reached_any = true;
        if let Ok(bytes) =
            super::read_bounded_reqwest_body(resp, JELLYFIN_PROBE_MAX_BODY_BYTES).await
        {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(path) = extract_ffmpeg_path_from_jellyfin_json(&val) {
                    return JellyfinFfmpegProbeOutcome::Reported(path);
                }
            }
        }
    }

    if reached_any {
        JellyfinFfmpegProbeOutcome::ReachableMissingPath
    } else {
        JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime State Container & Slot Guards
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) struct DispatcherHandle {
    pub(crate) socket_path: PathBuf,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

struct CachedLocalCaps {
    fetched_at: Instant,
    caps: Option<TranscodeCapabilities>,
}

/// Shared per-`PeerRuntime` transcoding state (dispatcher lifecycle, worker health cooldowns,
/// active-job concurrency counters, local/remote capability caches, and mismatch notifications).
pub(crate) struct TranscodeRuntimeState {
    dispatcher: TokioMutex<Option<DispatcherHandle>>,
    enabled_fallback: AtomicBool,
    active_jobs: StdMutex<HashMap<String, usize>>,
    unhealthy_until: StdMutex<HashMap<String, DateTime<Utc>>>,
    local_caps_cache: StdMutex<Option<CachedLocalCaps>>,
    local_caps_refreshing: AtomicBool,
    local_caps_override: StdMutex<Option<Option<TranscodeCapabilities>>>,
    remote_caps: StdMutex<HashMap<String, TranscodeCapabilities>>,
    last_notified_mismatch: StdMutex<HashMap<String, (String, String)>>,
    jellyfin_probe: StdMutex<Arc<dyn JellyfinFfmpegProbe>>,
    dispatcher_socket_override: StdMutex<Option<PathBuf>>,
    worker_socket_override: StdMutex<Option<PathBuf>>,
    remote_start_timeout: StdMutex<Duration>,
    parity_timeout: StdMutex<Duration>,
    parity_dir_override: StdMutex<Option<PathBuf>>,
}

impl TranscodeRuntimeState {
    pub(crate) fn new() -> Self {
        Self {
            dispatcher: TokioMutex::new(None),
            enabled_fallback: AtomicBool::new(false),
            active_jobs: StdMutex::new(HashMap::new()),
            unhealthy_until: StdMutex::new(HashMap::new()),
            local_caps_cache: StdMutex::new(None),
            local_caps_refreshing: AtomicBool::new(false),
            local_caps_override: StdMutex::new(None),
            remote_caps: StdMutex::new(HashMap::new()),
            last_notified_mismatch: StdMutex::new(HashMap::new()),
            jellyfin_probe: StdMutex::new(Arc::new(ProductionJellyfinFfmpegProbe)),
            dispatcher_socket_override: StdMutex::new(None),
            worker_socket_override: StdMutex::new(None),
            remote_start_timeout: StdMutex::new(RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT),
            parity_timeout: StdMutex::new(DEFAULT_PARITY_TEST_TIMEOUT),
            parity_dir_override: StdMutex::new(None),
        }
    }

    pub(crate) fn dispatcher_socket_path(&self) -> PathBuf {
        self.dispatcher_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(configured_dispatcher_socket_path)
    }

    pub(crate) fn worker_socket_path(&self) -> PathBuf {
        self.worker_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(configured_worker_socket_path)
    }

    pub(crate) fn remote_start_timeout(&self) -> Duration {
        *self
            .remote_start_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn parity_timeout(&self) -> Duration {
        *self
            .parity_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn active_jobs_for(&self, link_id: &str) -> usize {
        self.active_jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(link_id)
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn try_acquire_job_slot(
        self: &Arc<Self>,
        link_id: &str,
        max_jobs: usize,
    ) -> Option<ActiveJobGuard> {
        let mut cap = max_jobs.clamp(WORKER_MAX_JOBS_MIN as usize, WORKER_MAX_JOBS_MAX as usize);
        if let Some(worker_cap) = self
            .remote_capabilities_for(link_id)
            .and_then(|c| c.worker_max_jobs)
            .filter(|&n| n > 0)
        {
            let clamped_worker_cap =
                worker_cap.clamp(WORKER_MAX_JOBS_MIN as usize, WORKER_MAX_JOBS_MAX as usize);
            cap = cap.min(clamped_worker_cap);
        }
        let mut map = self.active_jobs.lock().unwrap_or_else(|e| e.into_inner());
        let current = map.get(link_id).copied().unwrap_or(0);
        if current >= cap {
            return None;
        }
        map.insert(link_id.to_string(), current + 1);
        Some(ActiveJobGuard {
            state: Arc::clone(self),
            link_id: link_id.to_string(),
        })
    }

    pub(crate) fn mark_worker_unhealthy(&self, link_id: &str, now: DateTime<Utc>) {
        let until = now + ChronoDuration::seconds(WORKER_UNHEALTHY_COOLDOWN_SECS);
        self.unhealthy_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(link_id.to_string(), until);
    }

    pub(crate) fn clear_worker_unhealthy(&self, link_id: &str) {
        self.unhealthy_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(link_id);
    }

    pub(crate) fn active_unhealthy_until(
        &self,
        link_id: &str,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let mut map = self
            .unhealthy_until
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match map.get(link_id).copied() {
            Some(until) if until > now => Some(until),
            Some(_) => {
                map.remove(link_id);
                None
            }
            None => None,
        }
    }

    pub(crate) fn record_remote_capabilities(&self, link_id: &str, caps: TranscodeCapabilities) {
        self.remote_caps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(link_id.to_string(), caps);
    }

    pub(crate) fn remote_capabilities_for(&self, link_id: &str) -> Option<TranscodeCapabilities> {
        self.remote_caps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(link_id)
            .cloned()
    }

    pub(crate) fn clear_link_state(&self, link_id: &str) {
        self.unhealthy_until
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(link_id);
        self.remote_caps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(link_id);
        self.last_notified_mismatch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(link_id);
    }

    pub(crate) async fn is_dispatcher_active(&self) -> bool {
        let guard = self.dispatcher.lock().await;
        guard.as_ref().is_some_and(|h| !h.task.is_finished())
    }

    /// Invalidates the 60-second local FFmpeg/GPU capability cache (called after local
    /// `jellyfin` or `jellyfin-ffmpeg` updates complete).
    pub(crate) fn invalidate_local_capabilities_cache(&self) {
        *self
            .local_caps_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub(crate) fn has_dispatcher_socket_override(&self) -> bool {
        self.dispatcher_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub(crate) fn has_worker_socket_override(&self) -> bool {
        self.worker_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_local_capabilities_override(&self, caps: Option<TranscodeCapabilities>) {
        *self
            .local_caps_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(caps);
    }

    #[cfg(test)]
    pub(crate) fn set_jellyfin_probe(&self, probe: Arc<dyn JellyfinFfmpegProbe>) {
        *self
            .jellyfin_probe
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = probe;
    }

    #[cfg(test)]
    pub(crate) fn set_dispatcher_socket_override(&self, path: PathBuf) {
        *self
            .dispatcher_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    #[cfg(test)]
    pub(crate) fn set_worker_socket_override(&self, path: PathBuf) {
        *self
            .worker_socket_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    #[cfg(test)]
    pub(crate) fn set_remote_start_timeout(&self, timeout: Duration) {
        *self
            .remote_start_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = timeout;
    }

    #[cfg(test)]
    pub(crate) fn set_parity_dir_override(&self, dir: PathBuf) {
        *self
            .parity_dir_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(dir);
    }
}

pub(crate) struct ActiveJobGuard {
    state: Arc<TranscodeRuntimeState>,
    link_id: String,
}

impl Drop for ActiveJobGuard {
    fn drop(&mut self) {
        let mut map = self
            .state
            .active_jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.link_id) {
            if *count <= 1 {
                map.remove(&self.link_id);
            } else {
                *count -= 1;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cached Non-Blocking Local Capabilities Probe
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the currently cached local `TranscodeCapabilities` without ever spawning a
/// subprocess probe. Used by public `GET /health` so unconfigured standalone instances remain
/// completely dormant and avoid disclosing local hardware/package details.
#[allow(dead_code)]
pub(crate) fn cached_local_capabilities_snapshot_only(
    runtime: &PeerRuntime,
) -> Option<TranscodeCapabilities> {
    let state = &runtime.transcode_state;
    if let Some(override_val) = state
        .local_caps_override
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return override_val;
    }
    state
        .local_caps_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|entry| entry.caps.clone())
}

/// Returns cached local `TranscodeCapabilities` immediately without ever blocking `/health`.
///
/// When the cache is cold or past its 60-second TTL, spawns at most one background refresh task
/// (if a Tokio runtime is active) and immediately returns the last known snapshot (or `None`).
pub(crate) fn cached_local_capabilities_nonblocking(
    runtime: &PeerRuntime,
) -> Option<TranscodeCapabilities> {
    let state = &runtime.transcode_state;
    if let Some(override_val) = state
        .local_caps_override
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return override_val;
    }

    let (snapshot, needs_refresh) = {
        let guard = state
            .local_caps_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(entry) if entry.fetched_at.elapsed() < LOCAL_CAPS_CACHE_TTL => {
                (entry.caps.clone(), false)
            }
            Some(entry) => (entry.caps.clone(), true),
            None => (None, true),
        }
    };

    if needs_refresh
        && state
            .local_caps_refreshing
            .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
            .is_ok()
    {
        let state_arc = Arc::clone(state);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let probed = probe_capabilities(&CapabilitiesConfig::from_env())
                    .await
                    .ok();
                {
                    let mut guard = state_arc
                        .local_caps_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    *guard = Some(CachedLocalCaps {
                        fetched_at: Instant::now(),
                        caps: probed,
                    });
                }
                state_arc
                    .local_caps_refreshing
                    .store(false, AtomicOrdering::Release);
            });
        } else {
            state
                .local_caps_refreshing
                .store(false, AtomicOrdering::Release);
        }
    }

    snapshot
}

/// Refreshes local `TranscodeCapabilities` asynchronously if the cache is cold or stale.
/// Used by `GET /api/v1/admin/peers/transcode` and the active peer health loop (never `/health`).
pub(crate) async fn refresh_local_capabilities_if_stale(
    runtime: &PeerRuntime,
) -> Option<TranscodeCapabilities> {
    let state = &runtime.transcode_state;
    if let Some(override_val) = state
        .local_caps_override
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return override_val;
    }

    {
        let guard = state
            .local_caps_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref() {
            if entry.fetched_at.elapsed() < LOCAL_CAPS_CACHE_TTL {
                return entry.caps.clone();
            }
        }
    }

    let probed = probe_capabilities(&CapabilitiesConfig::from_env())
        .await
        .ok();
    {
        let mut guard = state
            .local_caps_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedLocalCaps {
            fetched_at: Instant::now(),
            caps: probed.clone(),
        });
    }
    probed
}

// ─────────────────────────────────────────────────────────────────────────────
// Debian Version Comparison & Mismatch Evaluation
// ─────────────────────────────────────────────────────────────────────────────

fn split_debian_version(ver: &str) -> (u64, &str, &str) {
    let trimmed = ver.trim();
    let (epoch, rest) = match trimmed.split_once(':') {
        Some((ep, after)) => match ep.parse::<u64>() {
            Ok(num) => (num, after),
            Err(_) => (0, trimmed),
        },
        None => (0, trimmed),
    };
    match rest.rsplit_once('-') {
        Some((upstream, rev)) => (epoch, upstream, rev),
        None => (epoch, rest, ""),
    }
}

fn debian_char_order(ch: u8) -> i32 {
    if ch == b'~' {
        -1
    } else if ch.is_ascii_alphabetic() {
        ch as i32
    } else {
        (ch as i32) + 256
    }
}

fn compare_debian_part(a: &str, b: &str) -> Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;

    while i < ab.len() || j < bb.len() {
        // Non-digit lexical comparison (`~` < end-of-part < letters < other chars).
        while (i < ab.len() && !ab[i].is_ascii_digit()) || (j < bb.len() && !bb[j].is_ascii_digit())
        {
            let ca = if i < ab.len() && !ab[i].is_ascii_digit() {
                let v = debian_char_order(ab[i]);
                i += 1;
                v
            } else {
                0
            };
            let cb = if j < bb.len() && !bb[j].is_ascii_digit() {
                let v = debian_char_order(bb[j]);
                j += 1;
                v
            } else {
                0
            };
            match ca.cmp(&cb) {
                Ordering::Equal => {}
                other => return other,
            }
        }

        // Numeric run comparison ignoring leading zeros (handles arbitrarily long digits).
        let ia = i;
        while i < ab.len() && ab[i].is_ascii_digit() {
            i += 1;
        }
        let jb = j;
        while j < bb.len() && bb[j].is_ascii_digit() {
            j += 1;
        }
        let da = ab[ia..i]
            .iter()
            .position(|&c| c != b'0')
            .map_or(&b""[..], |pos| &ab[ia + pos..i]);
        let db = bb[jb..j]
            .iter()
            .position(|&c| c != b'0')
            .map_or(&b""[..], |pos| &bb[jb + pos..j]);
        match da.len().cmp(&db.len()).then_with(|| da.cmp(db)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Compares two Debian/FFmpeg version strings following Debian Policy §5.6.12.
pub(crate) fn compare_debian_versions(a: &str, b: &str) -> Ordering {
    let (e1, u1, r1) = split_debian_version(a);
    let (e2, u2, r2) = split_debian_version(b);
    e1.cmp(&e2)
        .then_with(|| compare_debian_part(u1, u2))
        .then_with(|| compare_debian_part(r1, r2))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionAlignmentReport {
    pub(crate) mismatch: bool,
    pub(crate) message: Option<String>,
    pub(crate) align_target: Option<&'static str>,
    pub(crate) local_display: Option<String>,
    pub(crate) peer_display: Option<String>,
    pub(crate) both_known: bool,
}

fn clean_opt_str(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|v| !v.is_empty())
}

/// Evaluates `jellyfin-ffmpeg` version alignment between the local server and a worker peer.
///
/// Prefers `package_version` when both sides report it (catching Debian revision updates like
/// `8.1.3-1-trixie` vs `8.1.3-2-trixie`), falling back to `ffmpeg_version` when package metadata
/// is absent. Also flags mismatches if `package_version` matches but `ffmpeg_version` differs.
pub(crate) fn evaluate_version_alignment(
    local_name: &str,
    local_pkg: Option<&str>,
    local_ff: Option<&str>,
    peer_name: &str,
    peer_pkg: Option<&str>,
    peer_ff: Option<&str>,
) -> VersionAlignmentReport {
    let l_pkg = clean_opt_str(local_pkg);
    let p_pkg = clean_opt_str(peer_pkg);
    let l_ff = clean_opt_str(local_ff);
    let p_ff = clean_opt_str(peer_ff);

    let (compared_local, compared_peer) = match (l_pkg, p_pkg) {
        (Some(lp), Some(pp)) => {
            if lp == pp {
                // If package versions match, double-check raw ffmpeg_version if both present.
                match (l_ff, p_ff) {
                    (Some(lf), Some(pf)) if lf != pf => (lf, pf),
                    _ => {
                        return VersionAlignmentReport {
                            mismatch: false,
                            message: None,
                            align_target: None,
                            local_display: Some(lp.to_string()),
                            peer_display: Some(pp.to_string()),
                            both_known: true,
                        };
                    }
                }
            } else {
                (lp, pp)
            }
        }
        _ => match (l_ff, p_ff) {
            (Some(lf), Some(pf)) => (lf, pf),
            _ => {
                return VersionAlignmentReport {
                    mismatch: false,
                    message: None,
                    align_target: None,
                    local_display: l_pkg.or(l_ff).map(str::to_string),
                    peer_display: p_pkg.or(p_ff).map(str::to_string),
                    both_known: false,
                };
            }
        },
    };

    if compared_local == compared_peer {
        return VersionAlignmentReport {
            mismatch: false,
            message: None,
            align_target: None,
            local_display: Some(compared_local.to_string()),
            peer_display: Some(compared_peer.to_string()),
            both_known: true,
        };
    }

    let align_target = match compare_debian_versions(compared_local, compared_peer) {
        Ordering::Less => Some("local"),
        Ordering::Greater => Some("peer"),
        Ordering::Equal => {
            // Different strings with equal Debian order (e.g. non-standard build tag); prefer updating peer.
            Some("peer")
        }
    };

    let message = format!(
        "jellyfin-ffmpeg differs: {local_name} {compared_local} vs {peer_name} {compared_peer}"
    );

    VersionAlignmentReport {
        mismatch: true,
        message: Some(message),
        align_target,
        local_display: Some(compared_local.to_string()),
        peer_display: Some(compared_peer.to_string()),
        both_known: true,
    }
}

/// Called from `peers::health` when a remote peer's tunnel `GET /health` includes `transcode`
/// capability metadata: caches full capabilities, persists DB metadata without altering worker
/// enable/weight/max_jobs/parity settings, and emits deduplicated notifications when an enabled
/// worker has a `jellyfin-ffmpeg` version mismatch.
pub(crate) async fn handle_remote_health_transcode_caps(
    runtime: &PeerRuntime,
    link: &PeerLink,
    remote_caps: TranscodeCapabilities,
) {
    let server = runtime.local_server_name();
    runtime
        .transcode_state
        .record_remote_capabilities(&link.id, remote_caps.clone());

    let db_ffmpeg_ver = remote_caps
        .ffmpeg_version
        .clone()
        .or_else(|| remote_caps.package_version.clone());
    let db_encoders_json = serde_json::to_string(&remote_caps.encoders).ok();
    let db_render_node = remote_caps.primary_render_node.clone();
    let link_id_read = link.id.clone();

    // Compare incoming metadata against the existing `transcode_workers` row first so steady-state
    // 15-second health ticks skip unconditional SQLite write transactions.
    let existing_worker = runtime
        .db
        .read(&server, "health_transcode_check", move |conn| {
            Ok(db_peers::get_transcode_worker(conn, &link_id_read)
                .ok()
                .flatten())
        })
        .await
        .ok()
        .flatten();

    let worker_enabled = match existing_worker {
        Some(existing)
            if existing.ffmpeg_version == db_ffmpeg_ver
                && existing.encoders == db_encoders_json
                && existing.render_node == db_render_node =>
        {
            existing.enabled
        }
        _ => {
            let link_id_c = link.id.clone();
            runtime
                .db
                .write(&server, "health_transcode_sync", move |conn| {
                    conn.execute(
                        "INSERT INTO transcode_workers (\
                            link_id, enabled, weight, max_jobs, ffmpeg_version, encoders, render_node, \
                            parity_ok, parity_error\
                         ) VALUES (?1, 0, 1, 2, ?2, ?3, ?4, 0, NULL) \
                         ON CONFLICT(link_id) DO UPDATE SET \
                            ffmpeg_version = excluded.ffmpeg_version, \
                            encoders = excluded.encoders, \
                            render_node = excluded.render_node \
                         WHERE transcode_workers.ffmpeg_version IS NOT excluded.ffmpeg_version \
                            OR transcode_workers.encoders IS NOT excluded.encoders \
                            OR transcode_workers.render_node IS NOT excluded.render_node",
                        rusqlite::params![link_id_c, db_ffmpeg_ver, db_encoders_json, db_render_node],
                    )
                    .map_err(|err| {
                        PeerError::internal("local", "health_transcode_sync", err.to_string())
                    })?;

                    let enabled = db_peers::get_transcode_worker(conn, &link_id_c)
                        .ok()
                        .flatten()
                        .is_some_and(|w| w.enabled);
                    Ok(enabled)
                })
                .await
                .unwrap_or(false)
        }
    };

    if !worker_enabled {
        return;
    }

    let local_caps = refresh_local_capabilities_if_stale(runtime).await;
    let alignment = evaluate_version_alignment(
        &server,
        local_caps
            .as_ref()
            .and_then(|c| c.package_version.as_deref()),
        local_caps
            .as_ref()
            .and_then(|c| c.ffmpeg_version.as_deref()),
        &link.name,
        remote_caps.package_version.as_deref(),
        remote_caps.ffmpeg_version.as_deref(),
    );

    if alignment.mismatch {
        if let (Some(l_ver), Some(p_ver), Some(msg)) = (
            alignment.local_display.clone(),
            alignment.peer_display.clone(),
            alignment.message.clone(),
        ) {
            let should_notify = {
                let mut map = runtime
                    .transcode_state
                    .last_notified_mismatch
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let pair = (l_ver, p_ver);
                if map.get(&link.id) == Some(&pair) {
                    false
                } else {
                    map.insert(link.id.clone(), pair);
                    true
                }
            };
            if should_notify {
                let target_hint = match alignment.align_target {
                    Some("local") => format!("Update {server} to match"),
                    Some("peer") => format!("Update {} to match", link.name),
                    _ => "Update the older server to match".to_string(),
                };
                runtime
                    .db
                    .emit_notification(
                        "warning",
                        format!("jellyfin-ffmpeg mismatch: {}", link.name),
                        format!(
                            "{msg}. {target_hint} so remote transcoding on {} can resume.",
                            link.name
                        ),
                    )
                    .await;
            }
        }
    } else if alignment.both_known {
        runtime
            .transcode_state
            .last_notified_mismatch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&link.id);
    }
}

/// Prunes `transcode_jobs` rows older than 7 days (`TRANSCODE_JOB_RETENTION_DAYS`).
pub(crate) async fn prune_old_transcode_jobs(runtime: &PeerRuntime) -> usize {
    let cutoff = (runtime.now() - ChronoDuration::days(TRANSCODE_JOB_RETENTION_DAYS)).to_rfc3339();
    runtime
        .db
        .write(
            &runtime.local_server_name(),
            "transcode_prune",
            move |conn| {
                let removed = db_peers::prune_transcode_jobs_before(conn, &cutoff).unwrap_or(0);
                Ok(removed)
            },
        )
        .await
        .unwrap_or(0)
}

/// Tears down local `transcode_bind` (first) and `transcode` (second) mounts for `link_id`
/// while the caller already holds `runtime.lock_link(link_id)`, removing cleaned `peer_mounts`
/// rows inside an IMMEDIATE SQLite transaction and propagating runner or DB errors so retries
/// never leave orphan mounts behind.
async fn cleanup_worker_transcode_mounts_for_link_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    step: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    let server_c = server.clone();
    let step_c = step.to_string();
    let (bind_mounts, transcode_mounts) = runtime
        .db
        .read(&server, step, move |conn| {
            let all_mounts = db_peers::list_peer_mounts_for_link(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            let bind_mounts: Vec<(String, String)> = all_mounts
                .iter()
                .filter(|m| m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND)
                .map(|m| (m.id.clone(), m.mount_path.clone()))
                .collect();
            let transcode_mounts: Vec<(String, String)> = all_mounts
                .iter()
                .filter(|m| m.purpose == MOUNT_PURPOSE_TRANSCODE)
                .map(|m| (m.id.clone(), m.mount_path.clone()))
                .collect();
            Ok((bind_mounts, transcode_mounts))
        })
        .await?;

    if bind_mounts.is_empty() && transcode_mounts.is_empty() {
        return Ok(());
    }

    let mut first_error: Option<PeerError> = None;
    let mut removed_mount_ids: Vec<String> = Vec::new();

    // Tear down `transcode_bind` mounts BEFORE `transcode` or media NFS mounts.
    for (mount_id, mount_path) in bind_mounts {
        match runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::RemoveBindMedia { to: mount_path })
            .await
        {
            Ok(_) => removed_mount_ids.push(mount_id),
            Err(err) if err.is_not_found() => removed_mount_ids.push(mount_id),
            Err(err) => {
                tracing::warn!(
                    link_id = %link_id,
                    step = %step,
                    %err,
                    "Transcode bind-mount removal failed during teardown"
                );
                if first_error.is_none() {
                    first_error = Some(map_transcode_runner_error(err, &server, step));
                }
            }
        }
    }

    if !transcode_mounts.is_empty() {
        let transcode_mount_paths: Vec<String> =
            transcode_mounts.iter().map(|(_, p)| p.clone()).collect();
        match runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::RemoveTranscodeMounts {
                link_id: link_id.to_string(),
                paths: transcode_mount_paths,
            })
            .await
        {
            Ok(_) => {
                removed_mount_ids.extend(transcode_mounts.into_iter().map(|(id, _)| id));
            }
            Err(err) if err.is_not_found() => {
                removed_mount_ids.extend(transcode_mounts.into_iter().map(|(id, _)| id));
            }
            Err(err) => {
                tracing::warn!(
                    link_id = %link_id,
                    step = %step,
                    %err,
                    "Transcode NFS mount removal failed during teardown"
                );
                if first_error.is_none() {
                    first_error = Some(map_transcode_runner_error(err, &server, step));
                }
            }
        }
    }

    if !removed_mount_ids.is_empty() {
        let lid_del = link_id.to_string();
        let server_c = server.clone();
        let step_c = step.to_string();
        if let Err(err) = runtime
            .db
            .write(&server, step, move |conn| {
                let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                    .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                for mid in removed_mount_ids {
                    tx.execute(
                        "DELETE FROM peer_mounts WHERE id = ?1 AND link_id = ?2 \
                         AND purpose IN (?3, ?4)",
                        rusqlite::params![
                            mid,
                            lid_del,
                            MOUNT_PURPOSE_TRANSCODE,
                            MOUNT_PURPOSE_TRANSCODE_BIND
                        ],
                    )
                    .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                }
                tx.commit()
                    .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                Ok(())
            })
            .await
        {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }
    Ok(())
}

/// Tears down all local `transcode_bind` (first) and `transcode` (second) mounts owned by
/// `link_id` when inbound `transcoding: write` is revoked or downgraded, or when disabling the
/// local worker service. Completely dormant (zero locks or runner calls) when `link_id` has no
/// worker transcode mounts.
pub(crate) async fn cleanup_worker_transcode_mounts_for_link(
    runtime: &PeerRuntime,
    link_id: &str,
    step: &str,
) -> Result<(), PeerError> {
    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    let server_c = server.clone();
    let step_c = step.to_string();
    let has_any = runtime
        .db
        .read(&server, step, move |conn| {
            let mounts = db_peers::list_peer_mounts_for_link(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            Ok(mounts.iter().any(|m| {
                m.purpose == MOUNT_PURPOSE_TRANSCODE || m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND
            }))
        })
        .await?;
    if !has_any {
        return Ok(());
    }

    let _link_guard = runtime.lock_link(link_id, step).await?;
    cleanup_worker_transcode_mounts_for_link_locked(runtime, link_id, step).await
}

/// Tears down all transcode bind mounts, transcode NFS mounts, transcode exports, and DB rows
/// (`peer_mounts` and `transcode_workers`) for `link_id` while the caller holds
/// `runtime.lock_link(link_id)`. Propagates runner/DB errors instead of swallowing them so link
/// revocation remains retryable until all transcode resources are cleanly removed.
///
/// Completely dormant (zero runner calls) when `link_id` has no `transcode_workers` row or
/// transcode/bind mounts.
pub(crate) async fn cleanup_revoked_link_transcode_locked(
    runtime: &PeerRuntime,
    link_id: &str,
    step: &str,
) -> Result<(), PeerError> {
    runtime.transcode_state.clear_link_state(link_id);

    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    let server_c = server.clone();
    let step_c = step.to_string();
    let (had_worker, has_mounts) = runtime
        .db
        .read(&server, step, move |conn| {
            let has_worker = db_peers::get_transcode_worker(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?
                .is_some();
            let all_mounts = db_peers::list_peer_mounts_for_link(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            let has_mounts = all_mounts.iter().any(|m| {
                m.purpose == MOUNT_PURPOSE_TRANSCODE || m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND
            });
            Ok((has_worker, has_mounts))
        })
        .await?;

    if !had_worker && !has_mounts {
        return Ok(());
    }

    let mut first_error: Option<PeerError> = None;

    // 1. Tear down `transcode_bind` first, then `transcode` mounts, deleting cleaned DB rows.
    if has_mounts {
        if let Err(err) =
            cleanup_worker_transcode_mounts_for_link_locked(runtime, link_id, step).await
        {
            first_error = Some(err);
        }
    }

    // 2. Disable and tear down controller transcode exports + `transcode_workers` row.
    if had_worker {
        let lid_upd = link_id.to_string();
        let server_c = server.clone();
        let step_c = step.to_string();
        if let Err(err) = runtime
            .db
            .write(&server, step, move |conn| {
                conn.execute(
                    "UPDATE transcode_workers SET enabled = 0, parity_ok = 0 WHERE link_id = ?1",
                    rusqlite::params![lid_upd],
                )
                .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                Ok(())
            })
            .await
        {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }

        match runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::RemoveTranscodeExports {
                link_id: link_id.to_string(),
            })
            .await
        {
            Ok(_) => {
                let lid_del = link_id.to_string();
                let server_c = server.clone();
                let step_c = step.to_string();
                if let Err(err) = runtime
                    .db
                    .write(&server, step, move |conn| {
                        conn.execute(
                            "DELETE FROM transcode_workers WHERE link_id = ?1",
                            rusqlite::params![lid_del],
                        )
                        .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                        Ok(())
                    })
                    .await
                {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
            Err(err) if err.is_not_found() => {
                let lid_del = link_id.to_string();
                let server_c = server.clone();
                let step_c = step.to_string();
                if let Err(db_err) = runtime
                    .db
                    .write(&server, step, move |conn| {
                        conn.execute(
                            "DELETE FROM transcode_workers WHERE link_id = ?1",
                            rusqlite::params![lid_del],
                        )
                        .map_err(|e| PeerError::internal(&server_c, &step_c, e.to_string()))?;
                        Ok(())
                    })
                    .await
                {
                    if first_error.is_none() {
                        first_error = Some(db_err);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    link_id = %link_id,
                    step = %step,
                    %err,
                    "Transcode export removal failed during link revocation"
                );
                if first_error.is_none() {
                    first_error = Some(map_transcode_runner_error(err, &server, step));
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }
    Ok(())
}

/// Thin logging wrapper around [`cleanup_revoked_link_transcode_locked`] retained for any internal
/// best-effort callers and tests.
#[allow(dead_code)]
pub(crate) async fn cleanup_revoked_link_transcode_best_effort(
    runtime: &PeerRuntime,
    link_id: &str,
) {
    if let Err(err) =
        cleanup_revoked_link_transcode_locked(runtime, link_id, "transcode_revoke_cleanup").await
    {
        tracing::warn!(
            link_id = %link_id,
            %err,
            "Best-effort transcode revocation cleanup encountered an error"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Safe Dispatcher Unix Socket Binding (P8 Hardening Parity)
// ─────────────────────────────────────────────────────────────────────────────

/// Owned listening Unix socket with inode-verified cleanup on drop.
pub(crate) struct BoundDispatcherSocket {
    listener: UnixListener,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl BoundDispatcherSocket {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl Drop for BoundDispatcherSocket {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_socket() && meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

struct SocketStagingDir(PathBuf);

impl Drop for SocketStagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("s"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn current_euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and always succeeds on Unix.
    unsafe { libc::geteuid() }
}

fn current_egid() -> u32 {
    // SAFETY: `getegid` has no preconditions and always succeeds on Unix.
    unsafe { libc::getegid() }
}

/// Returns `true` if `target_gid` matches the process effective GID or any live supplementary group.
fn process_has_gid(target_gid: u32) -> bool {
    if current_egid() == target_gid {
        return true;
    }
    // SAFETY: `getgroups(0, NULL)` queries the supplementary group count without writing memory.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: `groups` has capacity for `count` elements.
    let n = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if n <= 0 {
        return false;
    }
    groups[..n as usize].contains(&target_gid)
}

fn is_namespace_or_group_restart_io_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            err.raw_os_error(),
            Some(libc::EROFS | libc::EACCES | libc::EPERM)
        )
}

fn is_restart_required_bind_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(is_namespace_or_group_restart_io_error)
    })
}

fn is_stale_unix_socket(path: &Path) -> io::Result<bool> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let max_sun_path = addr.sun_path.len() - 1;
    if path_bytes.is_empty() || path_bytes.len() > max_sun_path || path_bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path length",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (idx, &byte) in path_bytes.iter().enumerate() {
        addr.sun_path[idx] = byte as libc::c_char;
    }

    // SAFETY: Creates a fresh non-blocking cloexec Unix stream socket fd.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` is newly created and owned exclusively here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let addr_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1)
        as libc::socklen_t;

    // SAFETY: `addr` is initialized with NUL-terminated path bytes within `sun_path`.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            addr_len,
        )
    };
    if rc == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::ConnectionRefused {
        Ok(true)
    } else if err.kind() == io::ErrorKind::WouldBlock
        || err.raw_os_error() == Some(libc::EINPROGRESS)
    {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Binds the dispatcher Unix socket inside a private `0700` staging directory under an exclusive
/// parent `flock`, sets restricted `0660` permissions before publication, and publishes via
/// non-replacing `hard_link`.
pub(crate) fn bind_dispatcher_socket(
    socket_path: &Path,
    socket_mode: u32,
) -> anyhow::Result<BoundDispatcherSocket> {
    validate_socket_mode(socket_mode)?;
    validate_absolute_clean_path(socket_path)?;

    let path_bytes = socket_path.as_os_str().as_encoded_bytes().len();
    if path_bytes > MAX_UNIX_SOCKET_PATH_BYTES {
        anyhow::bail!(
            "dispatcher socket path '{}' ({path_bytes} bytes) exceeds Linux sun_path limit ({MAX_UNIX_SOCKET_PATH_BYTES})",
            socket_path.display()
        );
    }

    let parent = socket_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("dispatcher socket has no parent directory"))?;
    let parent_dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|err| {
            anyhow::anyhow!(
                "failed opening dispatcher socket directory '{}': {err}",
                parent.display()
            )
        })?;
    let metadata = parent_dir.metadata()?;
    let euid = current_euid();

    anyhow::ensure!(
        (metadata.uid() == euid || metadata.uid() == 0) && metadata.mode() & 0o022 == 0,
        "dispatcher socket directory '{}' must belong to the service user or root and forbid group or world writes (mode {:04o})",
        parent.display(),
        metadata.mode() & 0o7777
    );

    // SAFETY: `parent_dir` is a valid open directory fd; released when `parent_dir` drops.
    if unsafe { libc::flock(parent_dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(anyhow::anyhow!(
            "failed locking dispatcher socket directory '{}': {}",
            parent.display(),
            io::Error::last_os_error()
        ));
    }

    match fs::symlink_metadata(socket_path) {
        Ok(existing) => {
            anyhow::ensure!(
                existing.file_type().is_socket() && (existing.uid() == euid || euid == 0),
                "refusing to replace unmanaged dispatcher socket path '{}'",
                socket_path.display()
            );
            anyhow::ensure!(
                is_stale_unix_socket(socket_path)?,
                "dispatcher socket '{}' is already served by a live process",
                socket_path.display()
            );
            fs::remove_file(socket_path)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let seq = TEMP_DISPATCHER_SOCKET_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let staging_path = parent.join(format!(".af-disp-{}-{seq}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&staging_path)?;
    let staging = SocketStagingDir(staging_path);
    let staged = staging.0.join("s");

    let stage_fd = fs::File::open(&staging.0)?;
    let bind_path = format!("/proc/self/fd/{}/s", stage_fd.as_raw_fd());
    let listener = UnixListener::bind(&bind_path)?;

    // Propagate parent directory group (e.g. `jellyfin` on `/run/aetherflow-transcode`) onto the
    // staged socket BEFORE chmod + hard_link publication so Jellyfin's shim never hits EACCES.
    // Unprivileged `fchownat(-1, target_gid)` succeeds whenever `aetherflow-api` holds
    // `SupplementaryGroups=jellyfin` and does not depend on setgid bits under `RestrictSUIDSGID=yes`.
    if metadata.gid() != current_egid() {
        let rc = unsafe {
            libc::fchownat(
                stage_fd.as_raw_fd(),
                c"s".as_ptr(),
                (!0u32) as libc::uid_t,
                metadata.gid() as libc::gid_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            let os_err = io::Error::last_os_error();
            return Err(anyhow::Error::new(os_err).context(format!(
                "failed setting group {} on dispatcher socket '{}' (restart aetherflow-api.service to apply SupplementaryGroups=jellyfin)",
                metadata.gid(),
                socket_path.display()
            )));
        }
    }

    fs::set_permissions(&staged, fs::Permissions::from_mode(socket_mode))?;
    let bound_meta = fs::symlink_metadata(&staged)?;
    anyhow::ensure!(
        bound_meta.gid() == metadata.gid(),
        "dispatcher socket '{}' group {} does not match parent directory group {}",
        socket_path.display(),
        bound_meta.gid(),
        metadata.gid()
    );

    fs::hard_link(&staged, socket_path)?;

    Ok(BoundDispatcherSocket {
        listener,
        path: socket_path.to_path_buf(),
        dev: bound_meta.dev(),
        ino: bound_meta.ino(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 6455 Client WebSocket over Pinned WireGuard Tunnel TCP
// ─────────────────────────────────────────────────────────────────────────────

enum TunnelWsConnectError {
    Timeout(String),
    Unreachable(String),
    Rejected(StatusCode, String),
}

impl TunnelWsConnectError {
    fn message(&self) -> String {
        match self {
            Self::Timeout(m) | Self::Unreachable(m) => m.clone(),
            Self::Rejected(st, m) => format!("HTTP {}: {m}", st.as_u16()),
        }
    }
}

enum WsWriteError {
    /// Failed before a single byte of the WebSocket frame was written to the underlying stream.
    BeforeAnyBytesSent(String),
    /// Failed or timed out after at least one byte was written (ambiguous delivery).
    AfterBytesWritten(String),
}

impl WsWriteError {
    fn message(&self) -> &str {
        match self {
            Self::BeforeAnyBytesSent(m) | Self::AfterBytesWritten(m) => m,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum WsClientMessage {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
}

type TunnelUpgradedIo = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;

pub(super) struct WsClientReader<R> {
    reader: R,
    fragmented: Option<Vec<u8>>,
}

impl<R> WsClientReader<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            fragmented: None,
        }
    }
}

struct WsClientWriter<W> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> WsClientWriter<W> {
    async fn write_masked_frame(
        &mut self,
        opcode: u8,
        payload: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<(), WsWriteError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(WsWriteError::BeforeAnyBytesSent(format!(
                "frame payload {} exceeds maximum {MAX_FRAME_BYTES}",
                payload.len()
            )));
        }

        let mask: [u8; 4] = rand::thread_rng().gen();
        let mut buf = Vec::with_capacity(payload.len() + 14);
        buf.push(0x80 | (opcode & 0x0f));
        if payload.len() < 126 {
            buf.push(0x80 | (payload.len() as u8));
        } else if payload.len() <= u16::MAX as usize {
            buf.push(0x80 | 126);
            buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            buf.push(0x80 | 127);
            buf.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        buf.extend_from_slice(&mask);
        let payload_offset = buf.len();
        buf.extend_from_slice(payload);
        for (idx, b) in buf[payload_offset..].iter_mut().enumerate() {
            *b ^= mask[idx & 3];
        }

        let mut written = 0usize;
        while written < buf.len() {
            let step = tokio::time::timeout_at(deadline, self.writer.write(&buf[written..])).await;
            match step {
                Ok(Ok(0)) => {
                    let msg = "WebSocket closed while writing frame".to_string();
                    return if written == 0 {
                        Err(WsWriteError::BeforeAnyBytesSent(msg))
                    } else {
                        Err(WsWriteError::AfterBytesWritten(msg))
                    };
                }
                Ok(Ok(n)) => {
                    written += n;
                }
                Ok(Err(err)) => {
                    let msg = format!("WebSocket write failed: {err}");
                    return if written == 0 {
                        Err(WsWriteError::BeforeAnyBytesSent(msg))
                    } else {
                        Err(WsWriteError::AfterBytesWritten(msg))
                    };
                }
                Err(_) => {
                    let msg = "WebSocket write timed out".to_string();
                    return if written == 0 {
                        Err(WsWriteError::BeforeAnyBytesSent(msg))
                    } else {
                        Err(WsWriteError::AfterBytesWritten(msg))
                    };
                }
            }
        }

        match tokio::time::timeout_at(deadline, self.writer.flush()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(WsWriteError::AfterBytesWritten(format!(
                "WebSocket flush failed: {err}"
            ))),
            Err(_) => Err(WsWriteError::AfterBytesWritten(
                "WebSocket flush timed out".to_string(),
            )),
        }
    }

    async fn write_binary(
        &mut self,
        payload: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<(), WsWriteError> {
        self.write_masked_frame(0x2, payload, deadline).await
    }

    async fn write_pong(&mut self, payload: &[u8], timeout: Duration) -> Result<(), WsWriteError> {
        let bounded = &payload[..payload.len().min(125)];
        self.write_masked_frame(0xA, bounded, tokio::time::Instant::now() + timeout)
            .await
    }

    async fn write_close(&mut self, code: u16, timeout: Duration) {
        let _ = self
            .write_masked_frame(
                0x8,
                &code.to_be_bytes(),
                tokio::time::Instant::now() + timeout,
            )
            .await;
        let _ = tokio::time::timeout(timeout, self.writer.shutdown()).await;
    }
}

impl<R: AsyncRead + Unpin> WsClientReader<R> {
    pub(super) async fn read_message(&mut self) -> Result<Option<WsClientMessage>, String> {
        loop {
            let mut hdr = [0u8; 2];
            match self.reader.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    return if self.fragmented.take().is_some() {
                        Err("WebSocket closed mid-fragmented binary message".to_string())
                    } else {
                        Ok(None)
                    };
                }
                Err(err) => return Err(format!("WebSocket read failed: {err}")),
            }

            let fin = (hdr[0] & 0x80) != 0;
            let rsv = hdr[0] & 0x70;
            if rsv != 0 {
                return Err("WebSocket server frame set non-zero RSV bits".to_string());
            }
            let opcode = hdr[0] & 0x0f;
            let masked = (hdr[1] & 0x80) != 0;
            if masked {
                return Err("WebSocket server frame was unexpectedly masked".to_string());
            }

            let len_code = hdr[1] & 0x7f;
            let payload_len: usize = match len_code {
                0..=125 => len_code as usize,
                126 => {
                    let mut ext = [0u8; 2];
                    self.reader
                        .read_exact(&mut ext)
                        .await
                        .map_err(|e| format!("WebSocket extended length read failed: {e}"))?;
                    u16::from_be_bytes(ext) as usize
                }
                127 => {
                    let mut ext = [0u8; 8];
                    self.reader
                        .read_exact(&mut ext)
                        .await
                        .map_err(|e| format!("WebSocket 64-bit length read failed: {e}"))?;
                    let raw = u64::from_be_bytes(ext);
                    if raw > MAX_FRAME_BYTES as u64 {
                        return Err(format!(
                            "WebSocket frame payload {raw} exceeds maximum {MAX_FRAME_BYTES}"
                        ));
                    }
                    raw as usize
                }
                _ => unreachable!(),
            };

            let is_control = (opcode & 0x08) != 0;
            if is_control {
                if !fin || payload_len > 125 {
                    return Err("Invalid WebSocket control frame".to_string());
                }
                let mut payload = vec![0u8; payload_len];
                if payload_len > 0 {
                    self.reader
                        .read_exact(&mut payload)
                        .await
                        .map_err(|e| format!("WebSocket control payload read failed: {e}"))?;
                }
                match opcode {
                    0x8 => {
                        self.fragmented = None;
                        return Ok(None); // Close
                    }
                    0x9 => return Ok(Some(WsClientMessage::Ping(payload))),
                    0xA => continue, // Pong
                    other => return Err(format!("Unknown WebSocket control opcode 0x{other:x}")),
                }
            }

            let existing_len = self.fragmented.as_ref().map_or(0, Vec::len);
            if payload_len > MAX_FRAME_BYTES
                || existing_len.saturating_add(payload_len) > MAX_FRAME_BYTES
            {
                return Err(format!(
                    "WebSocket message length exceeds maximum {MAX_FRAME_BYTES} bytes"
                ));
            }

            let mut chunk = vec![0u8; payload_len];
            if payload_len > 0 {
                self.reader
                    .read_exact(&mut chunk)
                    .await
                    .map_err(|e| format!("WebSocket payload read failed: {e}"))?;
            }

            match opcode {
                0x2 => {
                    if self.fragmented.is_some() {
                        return Err(
                            "Received new WebSocket binary frame before prior continuation completed"
                                .to_string(),
                        );
                    }
                    if fin {
                        return Ok(Some(WsClientMessage::Binary(chunk)));
                    }
                    self.fragmented = Some(chunk);
                }
                0x0 => {
                    let Some(mut acc) = self.fragmented.take() else {
                        return Err("Received unexpected WebSocket continuation frame".to_string());
                    };
                    acc.extend_from_slice(&chunk);
                    if fin {
                        return Ok(Some(WsClientMessage::Binary(acc)));
                    }
                    self.fragmented = Some(acc);
                }
                other => {
                    return Err(format!(
                        "Unsupported WebSocket data opcode 0x{other:x} (expected binary)"
                    ));
                }
            }
        }
    }
}

async fn connect_bound_tunnel_tcp(
    dest_ip: IpAddr,
    port: u16,
    binding: &TunnelClientBindingKey,
    timeout: Duration,
) -> Result<TcpStream, TunnelWsConnectError> {
    let dest_ip = dest_ip.to_canonical();
    let local_ip = binding.local_ip.to_canonical();
    if dest_ip.is_ipv4() != local_ip.is_ipv4() {
        return Err(TunnelWsConnectError::Unreachable(
            "Peer tunnel IP address family mismatch".to_string(),
        ));
    }

    let socket = match local_ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|err| {
        TunnelWsConnectError::Unreachable(format!("TCP socket creation failed: {err}"))
    })?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(ref iface) = binding.interface {
        socket.bind_device(Some(iface.as_bytes())).map_err(|err| {
            TunnelWsConnectError::Unreachable(format!(
                "Failed binding socket to tunnel interface '{iface}': {err}"
            ))
        })?;
    }
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if binding.interface.is_some() {
        return Err(TunnelWsConnectError::Unreachable(
            "Tunnel interface binding requires Linux SO_BINDTODEVICE".to_string(),
        ));
    }

    socket
        .bind(SocketAddr::new(local_ip, 0))
        .map_err(|err| TunnelWsConnectError::Unreachable(format!("Local IP bind failed: {err}")))?;

    let dest_addr = SocketAddr::new(dest_ip, port);
    match tokio::time::timeout(timeout, socket.connect(dest_addr)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(err)) => Err(TunnelWsConnectError::Unreachable(format!(
            "Failed connecting to worker tunnel listener: {err}"
        ))),
        Err(_) => Err(TunnelWsConnectError::Timeout(
            "Timed out connecting to worker tunnel listener".to_string(),
        )),
    }
}

fn compute_ws_accept_key(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(WS_ACCEPT_GUID.as_bytes());
    let digest = hasher.finalize();
    BASE64_STANDARD.encode(digest)
}

async fn connect_tunnel_transcode_ws(
    runtime: &PeerRuntime,
    peer_tunnel_ip: &str,
    link_token: &PeerCredentialSecret,
    grant_token: &PeerCredentialSecret,
    request_id: &str,
    deadline: tokio::time::Instant,
) -> Result<
    (
        WsClientReader<ReadHalf<TunnelUpgradedIo>>,
        WsClientWriter<WriteHalf<TunnelUpgradedIo>>,
    ),
    TunnelWsConnectError,
> {
    let target_url = runtime
        .build_tunnel_url(peer_tunnel_ip, "/peer/v1/transcode/jobs")
        .map_err(|err| TunnelWsConnectError::Unreachable(err.message().to_string()))?;
    let dest_ip: IpAddr = peer_tunnel_ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| TunnelWsConnectError::Unreachable("Invalid peer tunnel IP".to_string()))?
        .to_canonical();
    let port = target_url
        .port_or_known_default()
        .ok_or_else(|| TunnelWsConnectError::Unreachable("Missing tunnel port".to_string()))?;

    let binding = runtime
        .resolve_outbound_tunnel_binding(dest_ip)
        .await
        .map_err(|err| match err {
            TunnelHttpError::Timeout(m) => TunnelWsConnectError::Timeout(m),
            TunnelHttpError::Unreachable(m) | TunnelHttpError::InvalidTarget(m) => {
                TunnelWsConnectError::Unreachable(m)
            }
        })?;

    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
    let connect_budget = remaining();
    if connect_budget.is_zero() {
        return Err(TunnelWsConnectError::Timeout(
            "Remote-start budget exhausted before TCP connect".to_string(),
        ));
    }

    let tcp_stream = connect_bound_tunnel_tcp(dest_ip, port, &binding, connect_budget).await?;
    let io = hyper_util::rt::TokioIo::new(tcp_stream);

    let (mut sender, conn) =
        tokio::time::timeout(remaining(), hyper::client::conn::http1::handshake(io))
            .await
            .map_err(|_| TunnelWsConnectError::Timeout("HTTP/1 handshake timed out".to_string()))?
            .map_err(|err| {
                TunnelWsConnectError::Unreachable(format!("HTTP/1 handshake failed: {err}"))
            })?;

    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!(error = %err, "transcode client websocket connection ended");
        }
    });

    let ws_nonce: [u8; 16] = rand::thread_rng().gen();
    let ws_key = BASE64_STANDARD.encode(ws_nonce);
    let expected_accept = compute_ws_accept_key(&ws_key);

    let host_authority = match dest_ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };

    let mut link_hv = HeaderValue::from_str(link_token.expose_secret()).map_err(|_| {
        TunnelWsConnectError::Unreachable("Invalid held link token bytes".to_string())
    })?;
    link_hv.set_sensitive(true);
    let mut grant_hv = HeaderValue::from_str(grant_token.expose_secret()).map_err(|_| {
        TunnelWsConnectError::Unreachable("Invalid held grant token bytes".to_string())
    })?;
    grant_hv.set_sensitive(true);

    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri("/peer/v1/transcode/jobs")
        .header(header::HOST, host_authority)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", &ws_key)
        .header(HeaderName::from_static(HEADER_LINK_TOKEN), link_hv)
        .header(HeaderName::from_static(HEADER_GRANT_TOKEN), grant_hv)
        .header(HeaderName::from_static("x-request-id"), request_id)
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|err| {
            TunnelWsConnectError::Unreachable(format!("Failed building WS upgrade request: {err}"))
        })?;

    let resp = tokio::time::timeout(remaining(), sender.send_request(req))
        .await
        .map_err(|_| {
            TunnelWsConnectError::Timeout("WebSocket upgrade response timed out".to_string())
        })?
        .map_err(|err| {
            TunnelWsConnectError::Unreachable(format!("WebSocket upgrade send failed: {err}"))
        })?;

    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(TunnelWsConnectError::Rejected(
            resp.status(),
            "Worker rejected WebSocket upgrade".to_string(),
        ));
    }

    let upgrade_ok = resp
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"));
    let conn_ok = resp.headers().get_all(header::CONNECTION).iter().any(|v| {
        v.to_str().ok().is_some_and(|raw| {
            raw.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    let accept_ok = resp
        .headers()
        .get("sec-websocket-accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|actual| {
            constant_time_eq(actual.trim().as_bytes(), expected_accept.as_bytes())
        });

    if !upgrade_ok || !conn_ok || !accept_ok {
        return Err(TunnelWsConnectError::Unreachable(
            "Worker returned invalid WebSocket handshake headers".to_string(),
        ));
    }

    let upgraded = tokio::time::timeout(remaining(), hyper::upgrade::on(resp))
        .await
        .map_err(|_| {
            TunnelWsConnectError::Timeout("WebSocket upgrade completion timed out".to_string())
        })?
        .map_err(|err| {
            TunnelWsConnectError::Unreachable(format!("WebSocket upgrade failed: {err}"))
        })?;

    let (read_half, write_half) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
    Ok((
        WsClientReader::new(read_half),
        WsClientWriter { writer: write_half },
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker-Side Tunnel WebSocket Handler: GET /peer/v1/transcode/jobs
// ─────────────────────────────────────────────────────────────────────────────

struct VerifiedInboundTranscodeGrant {
    auth: AuthenticatedPeerLink,
    grant: af_db::peers::PeerGrant,
    run_as_user_id: i64,
    run_as_username: String,
    source_ip_str: String,
    request_id: String,
}

/// Shared fail-closed inbound grant & run-as verification for `/peer/v1/transcode/jobs`
/// and `/peer/v1/transcode/mounts` (after link authentication).
async fn verify_inbound_transcode_grant(
    runtime: &PeerRuntime,
    auth: AuthenticatedPeerLink,
    headers: &HeaderMap,
    route_label: &str,
    action_label: &str,
) -> Result<VerifiedInboundTranscodeGrant, Box<Response>> {
    let local_server = runtime.local_server_name();
    let source_ip_str = auth.source_ip.to_string();
    let request_id = extract_or_generate_request_id(headers);

    // 1. Verify active inbound grant for this link.
    let link_id_lookup = auth.link.id.clone();
    let local_server_c = local_server.clone();
    let active_grant = match runtime
        .db
        .read(&local_server, "tunnel_transcode_grant_auth", move |conn| {
            db_peers::get_active_peer_grant_for_link(conn, &link_id_lookup).map_err(|err| {
                PeerError::internal(
                    &local_server_c,
                    "tunnel_transcode_grant_auth",
                    err.to_string(),
                )
            })
        })
        .await
    {
        Ok(g) => g,
        Err(err) => return Err(Box::new(err.into_response())),
    };

    let Some(grant) = active_grant else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_transcode_grant_auth",
            format!(
                "No active management grant is configured for peer '{}'",
                auth.link.name
            ),
        );
        runtime
            .db
            .record_audit(
                0,
                format!("peer-{}", auth.link.name),
                "peer_transcode_denied".to_string(),
                "peer_link".to_string(),
                auth.link.id.clone(),
                format!(
                    "Denied {action_label} via {} (request_id={}, reason=no_active_grant)",
                    auth.link.name, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return Err(Box::new(err.into_response()));
    };

    // 2. Verify `X-AF-Grant-Token` in constant time.
    let Some(presented_grant_token) = headers
        .get(HEADER_GRANT_TOKEN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_transcode_grant_auth",
            "Missing X-AF-Grant-Token header for transcode request",
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_transcode_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied {action_label} via {} (request_id={}, reason=missing_grant_token)",
                    auth.link.name, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return Err(Box::new(err.into_response()));
    };

    let Some(expected_grant_hash) = grant.token_hash.as_deref() else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_transcode_grant_auth",
            "Active grant has no valid token digest",
        );
        audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
        return Err(Box::new(err.into_response()));
    };

    let presented_grant_hash = sha256_prefixed(presented_grant_token);
    if !constant_time_eq(
        presented_grant_hash.as_bytes(),
        expected_grant_hash.as_bytes(),
    ) {
        let err = PeerError::unauthorized(
            &local_server,
            "tunnel_transcode_grant_auth",
            "Invalid X-AF-Grant-Token credential",
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_transcode_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied {action_label} via {} (request_id={}, reason=invalid_grant_token)",
                    auth.link.name, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return Err(Box::new(err.into_response()));
    }

    // 3. Require `transcoding: write` access.
    if !grant.access.transcoding.allows_write() {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_transcode_scope",
            format!(
                "Peer '{}' grant does not permit transcoding:write (current={})",
                auth.link.name,
                grant.access.transcoding.as_str()
            ),
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_transcode_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied {action_label} via {} (request_id={}, required=transcoding:write, actual={})",
                    auth.link.name,
                    request_id,
                    grant.access.transcoding.as_str()
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return Err(Box::new(err.into_response()));
    }

    // 4. Verify dedicated `account_type = 'peer'` run-as admin subject is active.
    let run_as_uid = grant.run_as_user_id;
    let local_server_c = local_server.clone();
    let run_as_subject = match runtime
        .db
        .read(&local_server, "tunnel_transcode_subject", move |conn| {
            Ok(crate::auth::load_active_peer_subject(conn, run_as_uid))
        })
        .await
    {
        Ok(Ok(subj)) if subj.role == "admin" => subj,
        Ok(_) => {
            let err = PeerError::peer_scope_denied(
                &local_server_c,
                "tunnel_transcode_subject",
                "Peer run-as account is inactive or not authorized",
            );
            runtime
                .db
                .record_audit(
                    grant.run_as_user_id,
                    format!("peer-{}", auth.link.name),
                    "peer_transcode_denied".to_string(),
                    "peer_grant".to_string(),
                    grant.id.clone(),
                    format!(
                        "Denied {action_label} via {} (request_id={}, reason=run_as_inactive)",
                        auth.link.name, request_id
                    ),
                    source_ip_str,
                    String::new(),
                )
                .await;
            return Err(Box::new(err.into_response()));
        }
        Err(err) => return Err(Box::new(err.into_response())),
    };

    Ok(VerifiedInboundTranscodeGrant {
        auth,
        grant,
        run_as_user_id: run_as_subject.user_id,
        run_as_username: run_as_subject.username,
        source_ip_str,
        request_id,
    })
}

/// Authenticated worker-side WebSocket endpoint on the isolated WireGuard peer tunnel listener.
///
/// Enforces:
/// 1. Active link via tunnel `ConnectInfo` IP + constant-time `X-AF-Link-Token` + per-link WS permit
/// 2. Active inbound grant via constant-time `X-AF-Grant-Token`
/// 3. `AccessLevel::Write` on `Area::Transcoding`
/// 4. Active `account_type = 'peer'` run-as admin subject
/// 5. Live revocation subscription killing the worker child immediately on link/grant revoke
pub(crate) async fn handle_tunnel_transcode_jobs(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let route_label = "GET /peer/v1/transcode/jobs";
    let local_server = runtime.local_server_name();

    // 1. Authenticate link source IP + link token + acquire per-link WebSocket concurrency permit.
    let (auth, ws_permit) =
        match authenticate_active_link_ws(&runtime, connect_info, &headers, route_label).await {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    let verified = match verify_inbound_transcode_grant(
        &runtime,
        auth,
        &headers,
        route_label,
        "transcode job",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    // 6. Validate WebSocket upgrade headers only AFTER authorization succeeded.
    let ws = match ws {
        Ok(upgrade) => upgrade,
        Err(rejection) => {
            return PeerError::invalid_request(
                &local_server,
                "tunnel_transcode_ws",
                format!("Expected WebSocket upgrade for transcode job stream: {rejection}"),
                "Connect to /peer/v1/transcode/jobs with valid RFC 6455 WebSocket upgrade headers",
            )
            .into_response();
        }
    };

    // Subscribe to revocations BEFORE upgrading so no revocation between auth and upgrade is missed.
    let rev_rx = runtime.subscribe_revocations();

    runtime
        .db
        .record_audit(
            verified.run_as_user_id,
            verified.run_as_username.clone(),
            "peer_transcode_job_started".to_string(),
            "peer_grant".to_string(),
            verified.grant.id.clone(),
            format!(
                "Accepted transcode job stream from {} (request_id={})",
                verified.auth.link.name, verified.request_id
            ),
            verified.source_ip_str.clone(),
            String::new(),
        )
        .await;

    let runtime_c = Arc::clone(&runtime);
    ws.max_frame_size(MAX_FRAME_BYTES)
        .max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            relay_worker_ws_session(
                runtime_c,
                socket,
                ws_permit,
                verified.auth.link,
                verified.grant.id,
                verified.run_as_user_id,
                verified.run_as_username,
                verified.source_ip_str,
                verified.request_id,
                rev_rx,
            )
            .await;
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TranscodeMediaBindSpec {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default)]
    pub(crate) writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TunnelTranscodeMountRequest {
    Sync {
        transcode_paths: Vec<String>,
        #[serde(default)]
        media_binds: Vec<TranscodeMediaBindSpec>,
    },
    #[serde(alias = "remove")]
    Teardown,
}

fn derive_transcode_mount_unit_name(path: &str) -> String {
    systemd_escape_path(path)
        .map(|esc| format!("{esc}.mount"))
        .unwrap_or_else(|_| format!("{}.mount", path.trim_start_matches('/').replace('/', "-")))
}

fn dedup_preserve_order(paths: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(paths.len());
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let trimmed = p.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn is_under_peer_mounts_root(path: &str) -> bool {
    let root = DEFAULT_PEER_MOUNTS_ROOT.trim_end_matches('/');
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn is_strict_descendant_path(child: &str, ancestor: &str) -> bool {
    if child == ancestor {
        return false;
    }
    if ancestor == "/" {
        return child.starts_with('/');
    }
    child
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn has_sensitive_dot_segment(path: &str) -> bool {
    path.split('/').skip(1).any(|seg| seg == ".ssh")
}

fn validate_canonical_transcode_path_syntax(
    path: &str,
    allow_peer_mounts_subpath: bool,
) -> Result<String, String> {
    if path.is_empty() || path.len() > MAX_TRANSCODE_PATH_BYTES {
        return Err("Path must be a non-empty canonical absolute path".to_string());
    }
    if path.trim() != path {
        return Err("Path must not have leading or trailing whitespace".to_string());
    }
    if !path.starts_with('/') {
        return Err("Path must be an absolute path starting with '/'".to_string());
    }
    if path == "/" || path.ends_with('/') || path.contains("//") {
        return Err(
            "Path must be a canonical non-root path without duplicate or trailing slashes"
                .to_string(),
        );
    }
    if path.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '"' | '\'' | '\\' | '#' | ';' | ',' | ':' | '(' | ')' | '*' | '?' | '[' | ']'
            )
    }) {
        return Err("Path contains disallowed control or config-syntax characters".to_string());
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." || segment.len() > 255 {
            return Err(
                "Path must not contain empty, '.', '..', or oversized segments".to_string(),
            );
        }
    }
    if FORBIDDEN_TRANSCODE_EXACT_PATHS.contains(&path) {
        return Err(format!("Refusing sensitive top-level directory '{path}'"));
    }
    for prefix in FORBIDDEN_TRANSCODE_SYSTEM_PREFIXES {
        if path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(format!("Refusing restricted system path '{path}'"));
        }
    }
    if is_under_peer_mounts_root(path) {
        if !allow_peer_mounts_subpath {
            return Err(format!(
                "Refusing peer mount hierarchy path '{path}' for transcode directory"
            ));
        }
        let _ = extract_peer_mount_segments(path)?;
    }
    Ok(path.to_string())
}

fn extract_peer_mount_segments(path: &str) -> Result<(String, String), String> {
    let prefix = format!("{}/", DEFAULT_PEER_MOUNTS_ROOT.trim_end_matches('/'));
    let Some(rest) = path.strip_prefix(&prefix) else {
        return Err(format!(
            "Peer mount path '{path}' must lie under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
        ));
    };
    let mut parts = rest.split('/');
    let link_seg = parts.next().unwrap_or("");
    let export_seg = parts.next().unwrap_or("");
    if link_seg.is_empty() || export_seg.is_empty() {
        return Err(format!(
            "Peer mount path '{path}' must specify <link>/<export>"
        ));
    }
    validate_peer_mount_segment(link_seg).map_err(|err| err.to_string())?;
    validate_peer_mount_segment(export_seg).map_err(|err| err.to_string())?;
    Ok((link_seg.to_string(), export_seg.to_string()))
}

fn normalize_allowed_bind_root(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed.chars().any(char::is_control) {
        return None;
    }
    let normalized = if trimmed.len() > 1 {
        trimmed.trim_end_matches('/')
    } else {
        trimmed
    };
    if normalized == "/" || normalized.contains("//") {
        return None;
    }
    if normalized
        .split('/')
        .skip(1)
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return None;
    }
    Some(normalized.to_string())
}

fn resolve_worker_bind_media_allowed_roots(runtime: &PeerRuntime) -> Option<Vec<String>> {
    #[cfg(test)]
    if let Some(ref roots) = runtime.allowed_fs_roots_override {
        return Some(
            roots
                .iter()
                .filter_map(|p| normalize_allowed_bind_root(&p.to_string_lossy()))
                .collect(),
        );
    }
    let _ = runtime;
    let env_raw = std::env::var("AF_ALLOWED_FS_ROOTS").ok()?;
    let trimmed = env_raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .split(',')
            .filter_map(normalize_allowed_bind_root)
            .collect(),
    )
}

/// Enforces the worker-side explicit allowlist on `transcode_paths`: every path must be canonical
/// and match one of the worker's own inspected Jellyfin cache/transcode/tmp directories, default
/// `/var/cache/jellyfin*` directories, or a direct single-segment subdirectory under
/// `/var/cache/jellyfin/`.
fn validate_worker_transcode_path_allowed(
    raw_path: &str,
    worker_paths: &JellyfinTranscodePaths,
) -> Result<String, String> {
    let canonical = validate_canonical_transcode_path_syntax(raw_path, false)?;
    let inspected_temp = worker_paths
        .transcoding_temp_path
        .trim()
        .trim_end_matches('/');
    let inspected_tmp = worker_paths.tmp_dir.trim().trim_end_matches('/');
    let inspected_cache = worker_paths.cache_dir.trim().trim_end_matches('/');
    let exact_allowed = [
        inspected_temp,
        inspected_tmp,
        inspected_cache,
        DEFAULT_JELLYFIN_CACHE_DIR,
        DEFAULT_JELLYFIN_TRANSCODE_DIR,
        DEFAULT_JELLYFIN_TMP_DIR,
    ];
    if exact_allowed
        .iter()
        .any(|allowed| !allowed.is_empty() && canonical == *allowed)
    {
        return Ok(canonical);
    }
    if let Some(sub) = canonical.strip_prefix(&format!("{DEFAULT_JELLYFIN_CACHE_DIR}/")) {
        if !sub.is_empty() && !sub.contains('/') && sub != "." && sub != ".." {
            return Ok(canonical);
        }
    }
    Err(format!(
        "Transcode mount path '{canonical}' is outside the worker Jellyfin cache/transcode allowlist"
    ))
}

/// Enforces the worker-side allowlist on controller-holds-media `BindMedia` target paths (`to`
/// outside `/mnt/af-peers/`).
fn validate_bind_media_target_allowlist(
    canonical_to: &str,
    configured_roots: Option<&[String]>,
) -> Result<(), String> {
    if has_sensitive_dot_segment(canonical_to) {
        return Err(format!(
            "Refusing sensitive bind target path '{canonical_to}'"
        ));
    }
    if let Some(roots) = configured_roots {
        if roots
            .iter()
            .any(|root| canonical_to == root || is_strict_descendant_path(canonical_to, root))
        {
            return Ok(());
        }
        return Err(format!(
            "Bind target '{canonical_to}' is outside allowed AF_ALLOWED_FS_ROOTS media roots"
        ));
    }
    if DEFAULT_BIND_MEDIA_ROOTS
        .iter()
        .any(|root| is_strict_descendant_path(canonical_to, root))
    {
        return Ok(());
    }
    Err(format!(
        "Bind target '{canonical_to}' is outside allowed media roots"
    ))
}

#[derive(Debug, Clone)]
struct VerifiedBindEntry {
    spec: TranscodeMediaBindSpec,
    calling_link_segment: String,
}

/// Authenticated worker-side path-parity mount synchronization endpoint on the isolated WireGuard
/// peer tunnel listener (`POST /peer/v1/transcode/mounts`).
///
/// Enforces active link + constant-time `X-AF-Link-Token` + constant-time `X-AF-Grant-Token` +
/// `transcoding: write` + active `account_type = 'peer'` admin subject. Enforces explicit
/// worker-side allowlists on `transcode_paths` and `media_binds`, calling-link confinement under
/// `/mnt/af-peers/`, cross-checks every media bind against this worker's own `peer_exports` /
/// `peer_mounts` rows for the calling link, and rolls back atomically on partial mount or DB
/// failure.
pub(crate) async fn handle_tunnel_transcode_mounts(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let route_label = "POST /peer/v1/transcode/mounts";
    let local_server = runtime.local_server_name();

    let (auth, _permit) =
        match authenticate_active_link(&runtime, connect_info, &headers, route_label).await {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    let verified = match verify_inbound_transcode_grant(
        &runtime,
        auth,
        &headers,
        route_label,
        "transcode mount sync",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    let body = match body {
        Ok(bytes) => bytes,
        Err(err) => {
            return bytes_rejection_to_peer_error(err, &local_server, "tunnel_transcode_mounts")
                .into_response();
        }
    };
    if body.len() > ADMIN_TRANSCODE_BODY_LIMIT_BYTES {
        return PeerError::payload_too_large(
            &local_server,
            "tunnel_transcode_mounts",
            format!("Request body exceeds the {ADMIN_TRANSCODE_BODY_LIMIT_BYTES}-byte limit"),
            "Reduce the transcode mount sync payload size and retry",
        )
        .into_response();
    }

    let req: TunnelTranscodeMountRequest = match parse_required_json_bytes(
        &headers,
        &body,
        &local_server,
        "tunnel_transcode_mounts",
    ) {
        Ok(r) => r,
        Err(err) => return err.into_response(),
    };

    match handle_tunnel_transcode_mounts_inner(&runtime, &verified, req).await {
        Ok(val) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(val),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn rollback_newly_created_worker_mounts(
    runtime: &PeerRuntime,
    link_id: &str,
    newly_applied_binds: &[VerifiedBindEntry],
    newly_mounted_tc_paths: &[String],
) {
    for prev in newly_applied_binds.iter().rev() {
        if let Err(rb_err) = runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::RemoveBindMedia {
                to: prev.spec.to.clone(),
            })
            .await
        {
            if !rb_err.is_not_found() {
                tracing::error!(
                    link_id = %link_id,
                    to = %prev.spec.to,
                    %rb_err,
                    "Rollback RemoveBindMedia failed during transcode mount sync"
                );
            }
        }
    }
    if !newly_mounted_tc_paths.is_empty() {
        if let Err(rb_err) = runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::RemoveTranscodeMounts {
                link_id: link_id.to_string(),
                paths: newly_mounted_tc_paths.to_vec(),
            })
            .await
        {
            if !rb_err.is_not_found() {
                tracing::error!(
                    link_id = %link_id,
                    paths = ?newly_mounted_tc_paths,
                    %rb_err,
                    "Rollback RemoveTranscodeMounts failed during transcode mount sync"
                );
            }
        }
    }
}

async fn handle_tunnel_transcode_mounts_inner(
    runtime: &PeerRuntime,
    verified: &VerifiedInboundTranscodeGrant,
    req: TunnelTranscodeMountRequest,
) -> Result<serde_json::Value, PeerError> {
    let server = runtime.local_server_name();
    let step = "tunnel_transcode_mounts";
    let link = &verified.auth.link;
    let _link_guard = runtime.lock_link(&link.id, step).await?;

    match req {
        TunnelTranscodeMountRequest::Teardown => {
            let lid = link.id.clone();
            let server_c = server.clone();
            let (transcode_mounts, bind_mounts) = runtime
                .db
                .read(&server, step, move |conn| {
                    let all = db_peers::list_peer_mounts_for_link(conn, &lid)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let tc: Vec<(String, String)> = all
                        .iter()
                        .filter(|m| m.purpose == MOUNT_PURPOSE_TRANSCODE)
                        .map(|m| (m.id.clone(), m.mount_path.clone()))
                        .collect();
                    let binds: Vec<(String, String)> = all
                        .iter()
                        .filter(|m| m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND)
                        .map(|m| (m.id.clone(), m.mount_path.clone()))
                        .collect();
                    Ok((tc, binds))
                })
                .await?;

            let mut removed_ids = Vec::new();
            for (mid, path) in &bind_mounts {
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::RemoveBindMedia { to: path.clone() })
                    .await
                {
                    if !err.is_not_found() {
                        return Err(map_transcode_runner_error(err, &server, step));
                    }
                }
                removed_ids.push(mid.clone());
            }

            if !transcode_mounts.is_empty() {
                let paths: Vec<String> = transcode_mounts.iter().map(|(_, p)| p.clone()).collect();
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::RemoveTranscodeMounts {
                        link_id: link.id.clone(),
                        paths,
                    })
                    .await
                {
                    if !err.is_not_found() {
                        return Err(map_transcode_runner_error(err, &server, step));
                    }
                }
                removed_ids.extend(transcode_mounts.iter().map(|(id, _)| id.clone()));
            }

            if !removed_ids.is_empty() {
                let lid_del = link.id.clone();
                let server_c = server.clone();
                runtime
                    .db
                    .write(&server, step, move |conn| {
                        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                            .map_err(|err| {
                            PeerError::internal(&server_c, step, err.to_string())
                        })?;
                        for mid in removed_ids {
                            tx.execute(
                                "DELETE FROM peer_mounts WHERE id = ?1 AND link_id = ?2",
                                rusqlite::params![mid, lid_del],
                            )
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        }
                        tx.commit()
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                        Ok(())
                    })
                    .await?;
            }

            runtime
                .db
                .record_audit(
                    verified.run_as_user_id,
                    verified.run_as_username.clone(),
                    "peer_transcode_mounts_removed".to_string(),
                    "peer_grant".to_string(),
                    verified.grant.id.clone(),
                    format!(
                        "Removed transcode mounts for {} (request_id={}, nfs={}, binds={})",
                        link.name,
                        verified.request_id,
                        transcode_mounts.len(),
                        bind_mounts.len()
                    ),
                    verified.source_ip_str.clone(),
                    String::new(),
                )
                .await;

            Ok(serde_json::json!({
                "status": "removed",
                "removed_transcode_mounts": transcode_mounts.len(),
                "removed_media_binds": bind_mounts.len(),
            }))
        }
        TunnelTranscodeMountRequest::Sync {
            transcode_paths,
            media_binds,
        } => {
            let raw_paths = dedup_preserve_order(transcode_paths);
            if raw_paths.is_empty() || raw_paths.len() > MAX_TUNNEL_TRANSCODE_PATHS {
                return Err(PeerError::invalid_request(
                    &server,
                    step,
                    format!(
                        "transcode_paths must contain between 1 and {MAX_TUNNEL_TRANSCODE_PATHS} absolute paths"
                    ),
                    "Provide non-empty deduplicated transcode directory paths",
                ));
            }
            if media_binds.len() > MAX_TUNNEL_TRANSCODE_PATHS {
                return Err(PeerError::invalid_request(
                    &server,
                    step,
                    format!("media_binds exceeds maximum of {MAX_TUNNEL_TRANSCODE_PATHS} entries"),
                    "Reduce the number of media bind entries",
                ));
            }

            // Explicit allowlist on `transcode_paths`: validate every path against this worker's
            // inspected Jellyfin cache/transcode/tmp directories BEFORE invoking any mutating
            // runner action.
            let (worker_paths, _) = inspect_jellyfin_paths_best_effort(runtime).await;
            let mut clean_paths: Vec<String> = Vec::with_capacity(raw_paths.len());
            for path in &raw_paths {
                let allowed = validate_worker_transcode_path_allowed(path, &worker_paths).map_err(
                    |reason| {
                        PeerError::invalid_request(
                            &server,
                            step,
                            reason,
                            "Use only Jellyfin cache/transcode/tmp directories allowed on the worker",
                        )
                    },
                )?;
                clean_paths.push(allowed);
            }

            // Load existing mounts, peer links, and exports to verify ownership, prevent
            // cross-link mount collisions, and authorize every media_bind against this server's
            // own records.
            let lid = link.id.clone();
            let server_c = server.clone();
            let (all_mounts, all_links, link_exports, link_media_mounts) = runtime
                .db
                .read(&server, step, move |conn| {
                    let all_mounts = db_peers::list_peer_mounts(conn)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let all_links = db_peers::list_peer_links(conn)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let link_exports = db_peers::list_peer_exports_for_link(conn, &lid)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    let link_media_mounts: Vec<PeerMount> = all_mounts
                        .iter()
                        .filter(|m| m.link_id == lid && m.purpose == MOUNT_PURPOSE_MEDIA)
                        .cloned()
                        .collect();
                    Ok((all_mounts, all_links, link_exports, link_media_mounts))
                })
                .await?;

            for path in &clean_paths {
                if let Some(existing) = all_mounts.iter().find(|m| m.mount_path == *path) {
                    if existing.link_id != link.id || existing.purpose != MOUNT_PURPOSE_TRANSCODE {
                        return Err(PeerError::conflict(
                            &server,
                            step,
                            format!(
                                "Transcode mount path '{path}' is already owned by another link or mount purpose"
                            ),
                            "Remove the conflicting peer mount before enabling this worker",
                        ));
                    }
                }
            }

            let calling_link_segment = super::storage::derive_link_mount_segment(link);
            // When the worker holds media and exports it to the controller, the controller mounts
            // the worker's export under `/mnt/af-peers/<worker-server-name>/<export>`. Allow this
            // worker's own local server segment on `to` ONLY when it does not collide with another
            // peer link's mount segment, so cross-link shadowing of any other peer is impossible.
            let local_server_segment = validate_peer_mount_segment(&server)
                .ok()
                .map(str::to_string)
                .filter(|loc_seg| {
                    !all_links.iter().any(|other| {
                        other.id != link.id
                            && super::storage::derive_link_mount_segment(other) == *loc_seg
                    })
                });
            let bind_allowed_roots = resolve_worker_bind_media_allowed_roots(runtime);

            let mut verified_binds: Vec<VerifiedBindEntry> = Vec::new();
            let mut seen_bind_targets = HashSet::new();
            for bind in media_binds {
                let from = bind.from.trim().to_string();
                let to = bind.to.trim().to_string();
                if from.is_empty()
                    || to.is_empty()
                    || from == to
                    || !seen_bind_targets.insert(to.clone())
                {
                    return Err(PeerError::invalid_request(
                        &server,
                        step,
                        "Invalid or duplicate media bind specification",
                        "Provide distinct non-empty source and destination paths",
                    ));
                }
                if clean_paths.contains(&to) {
                    return Err(PeerError::conflict(
                        &server,
                        step,
                        format!("Media bind target '{to}' collides with a transcode mount path"),
                        "Ensure media bind paths do not overlap transcode directories",
                    ));
                }
                if let Some(existing) = all_mounts.iter().find(|m| m.mount_path == to) {
                    if existing.link_id != link.id
                        || existing.purpose != MOUNT_PURPOSE_TRANSCODE_BIND
                    {
                        return Err(PeerError::conflict(
                            &server,
                            step,
                            format!(
                                "Media bind target '{to}' is already owned by another link or mount purpose"
                            ),
                            "Remove the conflicting peer mount before enabling this worker",
                        ));
                    }
                }

                let from_is_peer = is_under_peer_mounts_root(&from);
                let to_is_peer = is_under_peer_mounts_root(&to);
                let confined_seg = match (from_is_peer, to_is_peer) {
                    // Worker-holds-media: local exported path -> `/mnt/af-peers/<seg>/<export>`
                    (false, true) => {
                        let (to_link_seg, _) =
                            extract_peer_mount_segments(&to).map_err(|reason| {
                                PeerError::invalid_request(
                                    &server,
                                    step,
                                    reason,
                                    "Provide a canonical target path under /mnt/af-peers/<link>/<export>",
                                )
                            })?;
                        let allowed_by_export = link_exports
                            .iter()
                            .any(|exp| exp.path == from && (!bind.writable || exp.writable));
                        if !allowed_by_export {
                            runtime
                                .db
                                .record_audit(
                                    verified.run_as_user_id,
                                    verified.run_as_username.clone(),
                                    "peer_transcode_denied".to_string(),
                                    "peer_grant".to_string(),
                                    verified.grant.id.clone(),
                                    format!(
                                        "Denied unauthorized media bind '{from}' -> '{to}' from {} (request_id={})",
                                        link.name, verified.request_id
                                    ),
                                    verified.source_ip_str.clone(),
                                    String::new(),
                                )
                                .await;
                            return Err(PeerError::peer_scope_denied(
                                &server,
                                step,
                                format!(
                                    "Media bind '{from}' -> '{to}' is not backed by an active peer export for '{}'",
                                    link.name
                                ),
                            ));
                        }
                        if validate_canonical_transcode_path_syntax(&from, false).is_err()
                            || validate_canonical_transcode_path_syntax(&to, true).is_err()
                            || has_sensitive_dot_segment(&from)
                        {
                            return Err(PeerError::invalid_request(
                                &server,
                                step,
                                format!("Media bind '{from}' -> '{to}' uses a disallowed or non-canonical path"),
                                "Use clean canonical media export and peer mount paths",
                            ));
                        }
                        let segment_allowed = to_link_seg == calling_link_segment
                            || local_server_segment.as_deref() == Some(to_link_seg.as_str());
                        if !segment_allowed {
                            runtime
                                .db
                                .record_audit(
                                    verified.run_as_user_id,
                                    verified.run_as_username.clone(),
                                    "peer_transcode_denied".to_string(),
                                    "peer_grant".to_string(),
                                    verified.grant.id.clone(),
                                    format!(
                                        "Denied cross-link media bind '{from}' -> '{to}' from {} (calling_seg={}, request_id={})",
                                        link.name, calling_link_segment, verified.request_id
                                    ),
                                    verified.source_ip_str.clone(),
                                    String::new(),
                                )
                                .await;
                            return Err(PeerError::invalid_request(
                                &server,
                                step,
                                format!(
                                    "Media bind destination '{to}' lies outside calling link segment '{calling_link_segment}'"
                                ),
                                "Bind worker exports strictly under the calling peer's own /mnt/af-peers/<segment>/ hierarchy",
                            ));
                        }
                        to_link_seg
                    }
                    // Controller-holds-media: `/mnt/af-peers/<calling_link>/<export>` -> allowed local media root
                    (true, false) => {
                        let (from_link_seg, _) =
                            extract_peer_mount_segments(&from).map_err(|reason| {
                                PeerError::invalid_request(
                                    &server,
                                    step,
                                    reason,
                                    "Provide a canonical source path under /mnt/af-peers/<link>/<export>",
                                )
                            })?;
                        if from_link_seg != calling_link_segment {
                            runtime
                                .db
                                .record_audit(
                                    verified.run_as_user_id,
                                    verified.run_as_username.clone(),
                                    "peer_transcode_denied".to_string(),
                                    "peer_grant".to_string(),
                                    verified.grant.id.clone(),
                                    format!(
                                        "Denied cross-link media bind source '{from}' -> '{to}' from {} (calling_seg={}, request_id={})",
                                        link.name, calling_link_segment, verified.request_id
                                    ),
                                    verified.source_ip_str.clone(),
                                    String::new(),
                                )
                                .await;
                            return Err(PeerError::invalid_request(
                                &server,
                                step,
                                format!(
                                    "Media bind source '{from}' lies outside calling link segment '{calling_link_segment}'"
                                ),
                                "Bind only peer mounts belonging to the calling link",
                            ));
                        }
                        let canonical_to = validate_canonical_transcode_path_syntax(&to, false)
                            .and_then(|canon| {
                                validate_bind_media_target_allowlist(
                                    &canon,
                                    bind_allowed_roots.as_deref(),
                                )?;
                                Ok(canon)
                            })
                            .map_err(|reason| {
                                PeerError::invalid_request(
                                    &server,
                                    step,
                                    reason,
                                    "Bind controller media only inside allowed media storage roots",
                                )
                            })?;
                        if validate_canonical_transcode_path_syntax(&from, true).is_err() {
                            return Err(PeerError::invalid_request(
                                &server,
                                step,
                                format!("Media bind source '{from}' is not a valid canonical peer mount path"),
                                "Provide a valid /mnt/af-peers/<link>/<export> source path",
                            ));
                        }
                        let allowed_by_media_mount = link_media_mounts.iter().any(|m| {
                            m.mount_path == from
                                && m.remote_path == canonical_to
                                && (!bind.writable || m.writable)
                        });
                        if !allowed_by_media_mount {
                            runtime
                                .db
                                .record_audit(
                                    verified.run_as_user_id,
                                    verified.run_as_username.clone(),
                                    "peer_transcode_denied".to_string(),
                                    "peer_grant".to_string(),
                                    verified.grant.id.clone(),
                                    format!(
                                        "Denied unauthorized media bind '{from}' -> '{to}' from {} (request_id={})",
                                        link.name, verified.request_id
                                    ),
                                    verified.source_ip_str.clone(),
                                    String::new(),
                                )
                                .await;
                            return Err(PeerError::peer_scope_denied(
                                &server,
                                step,
                                format!(
                                    "Media bind '{from}' -> '{to}' is not backed by an active peer mount for '{}'",
                                    link.name
                                ),
                            ));
                        }
                        calling_link_segment.clone()
                    }
                    (true, true) => {
                        return Err(PeerError::invalid_request(
                            &server,
                            step,
                            format!(
                                "Refusing media bind with both source and destination under {DEFAULT_PEER_MOUNTS_ROOT}"
                            ),
                            "Specify exactly one path under /mnt/af-peers/<link>/<export>",
                        ));
                    }
                    (false, false) => {
                        return Err(PeerError::invalid_request(
                            &server,
                            step,
                            format!(
                                "Media bind requires exactly one of 'from' or 'to' to lie under {DEFAULT_PEER_MOUNTS_ROOT}/<link>/<export>"
                            ),
                            "Bind between a local media folder and a peer mount path",
                        ));
                    }
                };

                verified_binds.push(VerifiedBindEntry {
                    spec: TranscodeMediaBindSpec {
                        from,
                        to,
                        writable: bind.writable,
                    },
                    calling_link_segment: confined_seg,
                });
            }

            // Also auto-add local A-holds-media bind aliases if B mounted A's media exports at
            // `/mnt/af-peers/<A>/<slug>` and `remote_path` passes the worker media-root allowlist
            // and does not collide with an existing mount.
            for m in &link_media_mounts {
                if !seen_bind_targets.contains(&m.remote_path)
                    && !clean_paths.contains(&m.remote_path)
                    && m.mount_path != m.remote_path
                    && !all_mounts.iter().any(|ex| {
                        ex.mount_path == m.remote_path
                            && (ex.link_id != link.id || ex.purpose != MOUNT_PURPOSE_TRANSCODE_BIND)
                    })
                {
                    let seg_ok = extract_peer_mount_segments(&m.mount_path)
                        .is_ok_and(|(seg, _)| seg == calling_link_segment);
                    let target_ok = validate_canonical_transcode_path_syntax(&m.remote_path, false)
                        .and_then(|canon| {
                            validate_bind_media_target_allowlist(
                                &canon,
                                bind_allowed_roots.as_deref(),
                            )
                        })
                        .is_ok();
                    if !seg_ok || !target_ok {
                        tracing::warn!(
                            link_id = %link.id,
                            from = %m.mount_path,
                            to = %m.remote_path,
                            "Skipping controller-holds-media auto-bind outside worker allowlist or calling link segment"
                        );
                        continue;
                    }
                    seen_bind_targets.insert(m.remote_path.clone());
                    verified_binds.push(VerifiedBindEntry {
                        spec: TranscodeMediaBindSpec {
                            from: m.mount_path.clone(),
                            to: m.remote_path.clone(),
                            writable: false,
                        },
                        calling_link_segment: calling_link_segment.clone(),
                    });
                }
            }

            // Ensure NFS client tools are installed before mounting controller transcode folders.
            runtime
                .storage_runner
                .dispatch(&PeerStorageRequest::EnsurePackages)
                .await
                .map_err(|err| PeerError::internal(&server, step, err.to_string()))?;

            // Snapshot prior transcode mounts/binds for this link so rollback only removes newly
            // added mounts and stale mounts are torn down only after the new state commits.
            let prev_tc_mounts: Vec<PeerMount> = all_mounts
                .iter()
                .filter(|m| m.link_id == link.id && m.purpose == MOUNT_PURPOSE_TRANSCODE)
                .cloned()
                .collect();
            let prev_binds: Vec<PeerMount> = all_mounts
                .iter()
                .filter(|m| m.link_id == link.id && m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND)
                .cloned()
                .collect();
            let prev_tc_set: HashSet<&str> = prev_tc_mounts
                .iter()
                .map(|m| m.mount_path.as_str())
                .collect();
            let prev_bind_map: HashMap<&str, (&str, bool)> = prev_binds
                .iter()
                .map(|m| (m.mount_path.as_str(), (m.remote_path.as_str(), m.writable)))
                .collect();
            let newly_mounted_tc_paths: Vec<String> = clean_paths
                .iter()
                .filter(|p| !prev_tc_set.contains(p.as_str()))
                .cloned()
                .collect();

            // Mount controller's transcode/tmp/cache directories at identical paths.
            runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::MountTranscodeDirs {
                    link_id: link.id.clone(),
                    tunnel_ip: link.tunnel_ip.clone(),
                    paths: clean_paths.clone(),
                })
                .await
                .and_then(|resp| resp.into_mutation())
                .map_err(|err| map_transcode_runner_error(err, &server, step))?;

            // Bind authorized media folders at identical paths. On any failure, roll back both
            // newly applied `BindMedia` mounts and newly mounted `MountTranscodeDirs` mounts.
            let mut applied_binds: Vec<TranscodeMediaBindSpec> = Vec::new();
            let mut newly_applied_binds: Vec<VerifiedBindEntry> = Vec::new();
            for entry in &verified_binds {
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::BindMedia {
                        from: entry.spec.from.clone(),
                        to: entry.spec.to.clone(),
                        writable: entry.spec.writable,
                        calling_link_segment: Some(entry.calling_link_segment.clone()),
                    })
                    .await
                    .and_then(|resp| resp.into_mutation())
                {
                    rollback_newly_created_worker_mounts(
                        runtime,
                        &link.id,
                        &newly_applied_binds,
                        &newly_mounted_tc_paths,
                    )
                    .await;
                    return Err(map_transcode_runner_error(err, &server, step));
                }
                let existed_identically = prev_bind_map.get(entry.spec.to.as_str()).is_some_and(
                    |&(prev_from, prev_writable)| {
                        prev_from == entry.spec.from && prev_writable == entry.spec.writable
                    },
                );
                if !existed_identically {
                    newly_applied_binds.push(entry.clone());
                }
                applied_binds.push(entry.spec.clone());
            }

            // Persist `peer_mounts` rows (`purpose = "transcode"` and `"transcode_bind"`) inside a
            // single IMMEDIATE SQLite transaction so DB and host mount state remain atomic.
            let lid_w = link.id.clone();
            let paths_w = clean_paths.clone();
            let binds_w = applied_binds.clone();
            let server_c = server.clone();
            let db_res = runtime
                .db
                .write(&server, step, move |conn| {
                    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    tx.execute(
                        "DELETE FROM peer_mounts WHERE link_id = ?1 AND purpose IN (?2, ?3)",
                        rusqlite::params![
                            lid_w,
                            MOUNT_PURPOSE_TRANSCODE,
                            MOUNT_PURPOSE_TRANSCODE_BIND
                        ],
                    )
                    .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;

                    for path in &paths_w {
                        let mount = PeerMount {
                            id: format!("tc-{}", Uuid::new_v4().simple()),
                            link_id: lid_w.clone(),
                            remote_path: path.clone(),
                            mount_path: path.clone(),
                            unit_name: derive_transcode_mount_unit_name(path),
                            writable: true,
                            purpose: MOUNT_PURPOSE_TRANSCODE.to_string(),
                            state: "mounted".to_string(),
                            last_error: None,
                        };
                        db_peers::insert_peer_mount(&tx, &mount)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    }

                    for bind in &binds_w {
                        let mount = PeerMount {
                            id: format!("tb-{}", Uuid::new_v4().simple()),
                            link_id: lid_w.clone(),
                            remote_path: bind.from.clone(),
                            mount_path: bind.to.clone(),
                            unit_name: derive_transcode_mount_unit_name(&bind.to),
                            writable: bind.writable,
                            purpose: MOUNT_PURPOSE_TRANSCODE_BIND.to_string(),
                            state: "mounted".to_string(),
                            last_error: None,
                        };
                        db_peers::insert_peer_mount(&tx, &mount)
                            .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    }
                    tx.commit()
                        .map_err(|err| PeerError::internal(&server_c, step, err.to_string()))?;
                    Ok(())
                })
                .await;

            if let Err(db_err) = db_res {
                rollback_newly_created_worker_mounts(
                    runtime,
                    &link.id,
                    &newly_applied_binds,
                    &newly_mounted_tc_paths,
                )
                .await;
                return Err(db_err);
            }

            // Now that the new mounts and DB state committed cleanly, tear down any stale mounts
            // from prior syncs (binds first, then transcode NFS mounts).
            for old_bind in prev_binds
                .iter()
                .filter(|m| !applied_binds.iter().any(|b| b.to == m.mount_path))
            {
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::RemoveBindMedia {
                        to: old_bind.mount_path.clone(),
                    })
                    .await
                {
                    if !err.is_not_found() {
                        tracing::warn!(
                            link_id = %link.id,
                            to = %old_bind.mount_path,
                            %err,
                            "Best-effort stale transcode bind removal failed after sync"
                        );
                    }
                }
            }
            let stale_tc: Vec<String> = prev_tc_mounts
                .iter()
                .filter(|m| !clean_paths.contains(&m.mount_path))
                .map(|m| m.mount_path.clone())
                .collect();
            if !stale_tc.is_empty() {
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::RemoveTranscodeMounts {
                        link_id: link.id.clone(),
                        paths: stale_tc.clone(),
                    })
                    .await
                {
                    if !err.is_not_found() {
                        tracing::warn!(
                            link_id = %link.id,
                            paths = ?stale_tc,
                            %err,
                            "Best-effort stale transcode mount removal failed after sync"
                        );
                    }
                }
            }

            runtime
                .db
                .record_audit(
                    verified.run_as_user_id,
                    verified.run_as_username.clone(),
                    "peer_transcode_mounts_synced".to_string(),
                    "peer_grant".to_string(),
                    verified.grant.id.clone(),
                    format!(
                        "Synced transcode mounts for {} (request_id={}, nfs={}, binds={})",
                        link.name,
                        verified.request_id,
                        clean_paths.len(),
                        applied_binds.len()
                    ),
                    verified.source_ip_str.clone(),
                    String::new(),
                )
                .await;

            Ok(serde_json::json!({
                "status": "synced",
                "transcode_paths": clean_paths,
                "media_binds": applied_binds,
            }))
        }
    }
}

async fn is_inbound_transcode_grant_still_active(
    runtime: &PeerRuntime,
    link_id: &str,
    grant_id: &str,
) -> bool {
    let lid = link_id.to_string();
    let gid = grant_id.to_string();
    runtime
        .db
        .read(
            &runtime.local_server_name(),
            "transcode_rev_recheck",
            move |conn| {
                let link_ok = db_peers::get_peer_link(conn, &lid)
                    .ok()
                    .flatten()
                    .is_some_and(|l| !is_revoked_or_revoking_state(&l.state));
                let grant_ok = db_peers::get_active_peer_grant_for_link(conn, &lid)
                    .ok()
                    .flatten()
                    .is_some_and(|g| g.id == gid && g.access.transcoding.allows_write());
                Ok(link_ok && grant_ok)
            },
        )
        .await
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
async fn relay_worker_ws_session(
    runtime: Arc<PeerRuntime>,
    socket: WebSocket,
    _ws_permit: OwnedSemaphorePermit,
    link: PeerLink,
    grant_id: String,
    run_as_user_id: i64,
    run_as_username: String,
    source_ip: String,
    request_id: String,
    mut rev_rx: broadcast::Receiver<RevocationEvent>,
) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Re-check immediately after upgrade in case revocation landed right before upgrade finished.
    if !is_inbound_transcode_grant_still_active(&runtime, &link.id, &grant_id).await {
        let _ = ws_sink.send(AxumWsMessage::Close(None)).await;
        return;
    }

    let worker_socket_path = runtime.transcode_state.worker_socket_path();
    let worker_stream = match tokio::time::timeout(
        WORKER_SOCKET_CONNECT_TIMEOUT,
        UnixStream::connect(&worker_socket_path),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let msg = format!(
                "local transcode worker socket unavailable ({}): {err}",
                worker_socket_path.display()
            );
            if let Ok(payload) = encode_frame_payload(&Frame::Error {
                kind: ErrorKind::WorkerFailed,
                message: msg.clone(),
            }) {
                let _ = ws_sink.send(AxumWsMessage::Binary(payload)).await;
            }
            let _ = ws_sink.send(AxumWsMessage::Close(None)).await;
            runtime
                .db
                .record_audit(
                    run_as_user_id,
                    run_as_username,
                    "peer_transcode_job_failed".to_string(),
                    "peer_grant".to_string(),
                    grant_id,
                    format!(
                        "Transcode job from {} failed before worker connect (request_id={request_id}, reason={msg})",
                        link.name
                    ),
                    source_ip,
                    String::new(),
                )
                .await;
            return;
        }
        Err(_) => {
            let msg = "timed out connecting to local transcode worker socket".to_string();
            if let Ok(payload) = encode_frame_payload(&Frame::Error {
                kind: ErrorKind::WorkerFailed,
                message: msg.clone(),
            }) {
                let _ = ws_sink.send(AxumWsMessage::Binary(payload)).await;
            }
            let _ = ws_sink.send(AxumWsMessage::Close(None)).await;
            runtime
                .db
                .record_audit(
                    run_as_user_id,
                    run_as_username,
                    "peer_transcode_job_failed".to_string(),
                    "peer_grant".to_string(),
                    grant_id,
                    format!(
                        "Transcode job from {} failed (request_id={request_id}, reason={msg})",
                        link.name
                    ),
                    source_ip,
                    String::new(),
                )
                .await;
            return;
        }
    };

    let (mut worker_reader, mut worker_writer) = worker_stream.into_split();

    // Bounded 64-frame channels for backpressured bidirectional relay, plus priority kill signal.
    // Dedicated `worker_read_task` keeps non-cancel-safe `read_frame` outside `tokio::select!`.
    let (to_worker_tx, mut to_worker_rx) = bounded_frame_channel();
    let (urgent_kill_tx, mut urgent_kill_rx) = mpsc::channel::<()>(2);
    let (to_ws_tx, mut to_ws_rx) = mpsc::channel::<AxumWsMessage>(FRAME_CHANNEL_CAPACITY);
    let (from_worker_tx, mut from_worker_rx) =
        mpsc::channel::<Result<Option<Frame>, String>>(FRAME_CHANNEL_CAPACITY);

    let mut worker_read_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut worker_reader).await {
                Ok(Some(frame)) => {
                    let is_exit = matches!(frame, Frame::Exit(_));
                    if from_worker_tx.send(Ok(Some(frame))).await.is_err() || is_exit {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = from_worker_tx.send(Ok(None)).await;
                    break;
                }
                Err(err) => {
                    let _ = from_worker_tx.send(Err(err.to_string())).await;
                    break;
                }
            }
        }
    });

    let mut worker_write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                Some(()) = urgent_kill_rx.recv() => {
                    let _ = tokio::time::timeout(
                        KILL_SIGNAL_WRITE_TIMEOUT,
                        write_frame(&mut worker_writer, &Frame::Signal(SignalKind::Kill)),
                    ).await;
                    let _ = worker_writer.shutdown().await;
                    break;
                }
                maybe_frame = to_worker_rx.recv() => {
                    let Some(frame) = maybe_frame else {
                        let _ = worker_writer.shutdown().await;
                        break;
                    };
                    if tokio::time::timeout(
                        DEFAULT_FRAME_WRITE_TIMEOUT,
                        write_frame(&mut worker_writer, &frame),
                    )
                    .await
                    .map_or(true, |res| res.is_err())
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut ws_write_task = tokio::spawn(async move {
        while let Some(msg) = to_ws_rx.recv().await {
            if tokio::time::timeout(DEFAULT_FRAME_WRITE_TIMEOUT, ws_sink.send(msg))
                .await
                .map_or(true, |res| res.is_err())
            {
                break;
            }
        }
        let _ = tokio::time::timeout(
            KILL_SIGNAL_WRITE_TIMEOUT,
            ws_sink.send(AxumWsMessage::Close(None)),
        )
        .await;
    });

    let mut exit_code: Option<i32> = None;
    let mut termination_reason = "completed".to_string();

    loop {
        tokio::select! {
            biased;
            rev_ev = rev_rx.recv() => {
                let revoked = match rev_ev {
                    Ok(RevocationEvent::LinkRevoked { link_id, .. }) => link_id == link.id,
                    Ok(RevocationEvent::GrantRevoked { link_id, grant_id: rev_gid, .. }) => {
                        link_id == link.id
                            && (rev_gid == grant_id
                                || !is_inbound_transcode_grant_still_active(&runtime, &link.id, &grant_id).await)
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        !is_inbound_transcode_grant_still_active(&runtime, &link.id, &grant_id).await
                    }
                    Err(broadcast::error::RecvError::Closed) => true,
                };
                if revoked {
                    termination_reason = "revoked".to_string();
                    let _ = urgent_kill_tx.try_send(());
                    break;
                }
            }
            worker_item = from_worker_rx.recv() => {
                match worker_item {
                    Some(Ok(Some(frame))) => {
                        let is_exit = match &frame {
                            Frame::Exit(code) => {
                                exit_code = Some(*code);
                                true
                            }
                            _ => false,
                        };
                        match encode_frame_payload(&frame) {
                            Ok(payload) => {
                                if to_ws_tx.send(AxumWsMessage::Binary(payload)).await.is_err() {
                                    if !is_exit {
                                        termination_reason = "ws_send_closed".to_string();
                                        let _ = urgent_kill_tx.try_send(());
                                    }
                                    break;
                                }
                            }
                            Err(err) => {
                                termination_reason = format!("worker_encode_error:{err}");
                                let _ = urgent_kill_tx.try_send(());
                                break;
                            }
                        }
                        if is_exit {
                            break;
                        }
                    }
                    Some(Ok(None)) | None => {
                        if exit_code.is_none() {
                            termination_reason = "worker_eof".to_string();
                        }
                        break;
                    }
                    Some(Err(err)) => {
                        termination_reason = format!("worker_read_error:{err}");
                        if let Ok(payload) = encode_frame_payload(&Frame::Error {
                            kind: ErrorKind::WorkerFailed,
                            message: format!("worker stream error: {err}"),
                        }) {
                            let _ = to_ws_tx.try_send(AxumWsMessage::Binary(payload));
                        }
                        let _ = urgent_kill_tx.try_send(());
                        break;
                    }
                }
            }
            ws_item = ws_stream.next() => {
                match ws_item {
                    Some(Ok(AxumWsMessage::Binary(bytes))) => {
                        if bytes.len() > MAX_FRAME_BYTES {
                            termination_reason = "oversized_ws_frame".to_string();
                            let _ = urgent_kill_tx.try_send(());
                            break;
                        }
                        match decode_frame_payload(&bytes) {
                            Ok(Frame::Signal(SignalKind::Kill)) => {
                                termination_reason = "remote_kill".to_string();
                                let _ = urgent_kill_tx.try_send(());
                                break;
                            }
                            Ok(frame) => {
                                if to_worker_tx.send(frame).await.is_err() {
                                    termination_reason = "worker_write_closed".to_string();
                                    break;
                                }
                            }
                            Err(err) => {
                                termination_reason = format!("protocol_error:{err}");
                                if let Ok(payload) = encode_frame_payload(&Frame::Error {
                                    kind: ErrorKind::ProtocolViolation,
                                    message: format!("invalid transcode frame: {err}"),
                                }) {
                                    let _ = to_ws_tx.try_send(AxumWsMessage::Binary(payload));
                                }
                                let _ = urgent_kill_tx.try_send(());
                                break;
                            }
                        }
                    }
                    Some(Ok(AxumWsMessage::Ping(data))) => {
                        let _ = to_ws_tx.try_send(AxumWsMessage::Pong(data));
                    }
                    Some(Ok(AxumWsMessage::Pong(_))) => {}
                    Some(Ok(AxumWsMessage::Close(_))) | None => {
                        if exit_code.is_none() {
                            termination_reason = "dispatcher_disconnected".to_string();
                            let _ = urgent_kill_tx.try_send(());
                        }
                        break;
                    }
                    Some(Ok(AxumWsMessage::Text(_))) => {
                        termination_reason = "unexpected_text_frame".to_string();
                        let _ = urgent_kill_tx.try_send(());
                        break;
                    }
                    Some(Err(err)) => {
                        termination_reason = format!("ws_read_error:{err}");
                        let _ = urgent_kill_tx.try_send(());
                        break;
                    }
                }
            }
        }
    }

    drop(from_worker_rx);
    drop(to_worker_tx);
    drop(to_ws_tx);
    if !worker_read_task.is_finished() {
        worker_read_task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut worker_read_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut worker_write_task).await;
    if !worker_write_task.is_finished() {
        worker_write_task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut ws_write_task).await;
    if !ws_write_task.is_finished() {
        ws_write_task.abort();
    }

    let action = if termination_reason == "revoked" {
        "peer_transcode_job_revoked"
    } else {
        "peer_transcode_job_finished"
    };
    runtime
        .db
        .record_audit(
            run_as_user_id,
            run_as_username,
            action.to_string(),
            "peer_grant".to_string(),
            grant_id,
            format!(
                "Transcode job from {} ended (request_id={request_id}, exit_code={:?}, reason={termination_reason})",
                link.name, exit_code
            ),
            source_ip,
            String::new(),
        )
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher Worker Selection & Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct EligibleWorkerCandidate {
    link: PeerLink,
    weight: u64,
    max_jobs: usize,
}

/// Pure deterministic weighted-index selection helper for both production dispatch and tests.
pub(crate) fn select_weighted_index(weights: &[u64], roll: u64) -> Option<usize> {
    if weights.is_empty() {
        return None;
    }
    let mut cursor = roll;
    for (idx, &w) in weights.iter().enumerate() {
        let eff = w.max(1);
        if cursor < eff {
            return Some(idx);
        }
        cursor -= eff;
    }
    Some(weights.len() - 1)
}

fn pick_weighted_candidate(
    candidates: &mut Vec<EligibleWorkerCandidate>,
) -> Option<EligibleWorkerCandidate> {
    if candidates.is_empty() {
        return None;
    }
    let weights: Vec<u64> = candidates.iter().map(|c| c.weight.max(1)).collect();
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return Some(candidates.swap_remove(0));
    }
    let roll = rand::thread_rng().gen_range(0..total);
    let idx = select_weighted_index(&weights, roll)?;
    Some(candidates.swap_remove(idx))
}

fn parse_encoders_json(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
}

fn worker_supports_required_capability(
    cap: &argv::Capability,
    encoders: &[String],
    render_nodes: &[af_hardware::RenderNode],
) -> bool {
    if let Some(req_enc) = cap.required_encoder() {
        if !encoders.iter().any(|enc| enc.eq_ignore_ascii_case(req_enc)) {
            return false;
        }
    }
    if cap.requires_hardware() && select_render_node(cap, render_nodes).is_none() {
        return false;
    }
    true
}

fn worker_render_nodes_for(
    remote_caps: Option<&TranscodeCapabilities>,
    db_render_node: Option<&str>,
) -> Vec<af_hardware::RenderNode> {
    if let Some(caps) = remote_caps {
        if !caps.render_nodes.is_empty() {
            return caps
                .render_nodes
                .iter()
                .map(|n| af_hardware::RenderNode {
                    path: PathBuf::from(&n.path),
                    vendor_id: n.vendor_id.clone(),
                })
                .collect();
        }
    }
    if let Some(path) = clean_opt_str(db_render_node) {
        return vec![af_hardware::RenderNode {
            path: PathBuf::from(path),
            vendor_id: None,
        }];
    }
    Vec::new()
}

/// Computes effective worker concurrency by clamping the controller-configured `max_jobs`
/// against the worker's advertised `AF_TRANSCODE_WORKER_MAX_JOBS` cap when present.
pub(crate) fn effective_worker_max_jobs(
    configured_max_jobs: i64,
    remote_caps: Option<&TranscodeCapabilities>,
) -> usize {
    let configured = configured_max_jobs.clamp(WORKER_MAX_JOBS_MIN, WORKER_MAX_JOBS_MAX) as usize;
    match remote_caps.and_then(|c| c.worker_max_jobs) {
        Some(cap_max) if cap_max > 0 => {
            let clamped = cap_max.clamp(WORKER_MAX_JOBS_MIN as usize, WORKER_MAX_JOBS_MAX as usize);
            configured.min(clamped)
        }
        _ => configured,
    }
}

async fn collect_eligible_workers(
    runtime: &PeerRuntime,
    required_cap: &argv::Capability,
) -> Vec<EligibleWorkerCandidate> {
    let local_caps = cached_local_capabilities_nonblocking(runtime);
    let local_name = runtime.local_server_name();
    let now = runtime.now();

    let snapshot = runtime
        .db
        .read(&local_name, "dispatcher_select", |conn| {
            let links = db_peers::list_peer_links(conn).unwrap_or_default();
            let workers = db_peers::list_transcode_workers(conn).unwrap_or_default();
            let mut grants_by_link = HashMap::new();
            for link in &links {
                if let Ok(Some(grant)) =
                    db_peers::get_active_peer_received_grant_for_link(conn, &link.id)
                {
                    grants_by_link.insert(link.id.clone(), grant);
                }
            }
            Ok((links, workers, grants_by_link))
        })
        .await;

    let Ok((links, workers, grants_by_link)) = snapshot else {
        return Vec::new();
    };

    let worker_map: HashMap<String, TranscodeWorker> = workers
        .into_iter()
        .map(|w| (w.link_id.clone(), w))
        .collect();

    let mut eligible = Vec::new();
    for link in links {
        if !is_active_link_state(&link.state) {
            continue;
        }
        let Some(worker) = worker_map.get(&link.id) else {
            continue;
        };
        if !worker.enabled || !worker.parity_ok {
            continue;
        }
        let link_caps: Vec<String> = link
            .capabilities
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        if !link_caps.iter().any(|c| c == "transcode") {
            continue;
        }
        let Some(received_grant) = grants_by_link.get(&link.id) else {
            continue;
        };
        if !received_grant.access.transcoding.allows_write() {
            continue;
        }
        if runtime
            .transcode_state
            .active_unhealthy_until(&link.id, now)
            .is_some()
        {
            continue;
        }

        let remote_caps = runtime.transcode_state.remote_capabilities_for(&link.id);
        let max_jobs = effective_worker_max_jobs(worker.max_jobs, remote_caps.as_ref());
        if runtime.transcode_state.active_jobs_for(&link.id) >= max_jobs {
            continue;
        }
        let worker_pkg_ver = remote_caps
            .as_ref()
            .and_then(|c| c.package_version.as_deref());
        let worker_ff_ver = remote_caps
            .as_ref()
            .and_then(|c| c.ffmpeg_version.as_deref())
            .or(worker.ffmpeg_version.as_deref());

        let alignment = evaluate_version_alignment(
            &local_name,
            local_caps
                .as_ref()
                .and_then(|c| c.package_version.as_deref()),
            local_caps
                .as_ref()
                .and_then(|c| c.ffmpeg_version.as_deref()),
            &link.name,
            worker_pkg_ver,
            worker_ff_ver,
        );
        if alignment.mismatch || !alignment.both_known {
            continue;
        }

        let worker_encoders = match remote_caps.as_ref() {
            Some(caps) if !caps.encoders.is_empty() => caps.encoders.clone(),
            _ => parse_encoders_json(worker.encoders.as_deref()),
        };
        let worker_nodes =
            worker_render_nodes_for(remote_caps.as_ref(), worker.render_node.as_deref());
        if !worker_supports_required_capability(required_cap, &worker_encoders, &worker_nodes) {
            continue;
        }

        eligible.push(EligibleWorkerCandidate {
            link,
            weight: worker.weight.clamp(WORKER_WEIGHT_MIN, WORKER_WEIGHT_MAX) as u64,
            max_jobs,
        });
    }

    eligible
}

enum DispatcherStartError {
    /// Binding failed due to `EROFS`/`EACCES`/`EPERM` (the running `aetherflow-api` process
    /// still holds the pre-drop-in `ProtectSystem=strict` mount namespace or lacks
    /// `SupplementaryGroups=jellyfin` until restarted).
    RestartRequired(String),
    Fatal(PeerError),
}

/// Starts the dispatcher Unix socket server if not already running on the configured socket path.
pub(crate) async fn ensure_dispatcher_started(
    runtime: &Arc<PeerRuntime>,
) -> Result<PathBuf, PeerError> {
    match ensure_dispatcher_started_checked(runtime).await {
        Ok(path) => Ok(path),
        Err(DispatcherStartError::RestartRequired(msg)) => Err(PeerError::internal(
            runtime.local_server_name(),
            "transcode_dispatcher_start",
            msg,
        )),
        Err(DispatcherStartError::Fatal(err)) => Err(err),
    }
}

async fn ensure_dispatcher_started_checked(
    runtime: &Arc<PeerRuntime>,
) -> Result<PathBuf, DispatcherStartError> {
    let server = runtime.local_server_name();
    let socket_path = runtime.transcode_state.dispatcher_socket_path();
    let mut guard = runtime.transcode_state.dispatcher.lock().await;
    if let Some(existing) = guard.as_ref() {
        if existing.socket_path == socket_path && !existing.task.is_finished() {
            return Ok(existing.socket_path.clone());
        }
    }
    if let Some(stale) = guard.take() {
        let _ = stale.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), stale.task).await;
    }

    let bound =
        bind_dispatcher_socket(&socket_path, DEFAULT_WORKER_SOCKET_MODE).map_err(|err| {
            let msg = format!(
                "Failed binding transcode dispatcher socket '{}': {err}",
                socket_path.display()
            );
            if is_restart_required_bind_error(&err) {
                DispatcherStartError::RestartRequired(msg)
            } else {
                DispatcherStartError::Fatal(PeerError::internal(
                    &server,
                    "transcode_dispatcher_start",
                    msg,
                ))
            }
        })?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let rt_c = Arc::clone(runtime);
    let bound_path = bound.path().to_path_buf();
    let task = tokio::spawn(async move {
        serve_dispatcher_listener(rt_c, bound, shutdown_rx).await;
    });

    runtime
        .transcode_state
        .enabled_fallback
        .store(true, AtomicOrdering::Release);
    *guard = Some(DispatcherHandle {
        socket_path: bound_path.clone(),
        shutdown_tx,
        task,
    });
    Ok(bound_path)
}

/// Stops the dispatcher Unix socket server if running and cleans up its bound socket.
pub(crate) async fn stop_dispatcher(runtime: &PeerRuntime) {
    runtime
        .transcode_state
        .enabled_fallback
        .store(false, AtomicOrdering::Release);
    if let Some(handle) = runtime.transcode_state.dispatcher.lock().await.take() {
        let _ = handle.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), handle.task).await;
    }
}

/// Dormant-safe startup hook called by `peers::start_with_runtime`: delegates to
/// [`reconcile_dispatcher_if_configured`] so standalone instances remain completely dormant.
pub(crate) async fn start_dispatcher_if_configured(runtime: &Arc<PeerRuntime>) {
    reconcile_dispatcher_if_configured(runtime).await;
}

/// Reconciles the local Jellyfin transcode dispatcher on boot and every 15-second peer health
/// tick: returns immediately when the dispatcher is already active or no peer identity exists,
/// logs a warning on transient `InspectJellyfinPaths` failures instead of failing silently, and
/// automatically starts the dispatcher once `dropin_enabled && shim_installed` succeeds.
pub(crate) async fn reconcile_dispatcher_if_configured(runtime: &Arc<PeerRuntime>) {
    if runtime.transcode_state.is_dispatcher_active().await {
        return;
    }

    let server = runtime.local_server_name();
    let has_identity = runtime
        .db
        .read(&server, "transcode_startup", |conn| {
            Ok(db_peers::get_peer_identity(conn).ok().flatten().is_some())
        })
        .await
        .unwrap_or(false);
    if !has_identity {
        return;
    }

    let paths = match runtime
        .transcode_runner
        .dispatch(&PeerTranscodeRequest::InspectJellyfinPaths)
        .await
        .and_then(|resp| resp.into_jellyfin_paths())
    {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                %err,
                "Failed inspecting Jellyfin transcode paths while reconciling dispatcher; will retry on next health tick"
            );
            return;
        }
    };

    if paths.dropin_enabled && paths.shim_installed {
        // Warm local capability cache so the very first transcode after boot is never forced
        // local due to a cold cache.
        let _ = refresh_local_capabilities_if_stale(runtime).await;
        if let Err(err) = ensure_dispatcher_started(runtime).await {
            tracing::warn!(%err, "Failed starting transcode dispatcher during reconciliation");
        }
    }
}

async fn serve_dispatcher_listener(
    runtime: Arc<PeerRuntime>,
    bound: BoundDispatcherSocket,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let pending_sem = Arc::new(Semaphore::new(MAX_PENDING_DISPATCHER_CONNS));
    let mut connections = JoinSet::new();

    tracing::info!(
        socket = %bound.path().display(),
        "Peer transcode dispatcher listening"
    );

    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    tracing::warn!(error = %err, "Transcode dispatcher task panicked");
                }
            }
            accept_res = bound.listener().accept() => {
                let (stream, _) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "Transcode dispatcher accept error");
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        continue;
                    }
                };

                let Ok(permit) = pending_sem.clone().try_acquire_owned() else {
                    let mut stream = stream;
                    let _ = tokio::time::timeout(
                        KILL_SIGNAL_WRITE_TIMEOUT,
                        write_frame(&mut stream, &Frame::RunLocal),
                    ).await;
                    continue;
                };

                let rt = Arc::clone(&runtime);
                let conn_shutdown = shutdown_rx.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    handle_dispatcher_connection(rt, stream, conn_shutdown).await;
                });
            }
        }
    }

    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !connections.is_empty() {
        match tokio::time::timeout_at(drain_deadline, connections.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                break;
            }
        }
    }
    drop(bound);
}

async fn read_held_link_token_for_transcode(
    runtime: &PeerRuntime,
    link_id: &str,
) -> Result<Option<PeerCredentialSecret>, PeerError> {
    let resp = runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: link_id.to_string(),
        })
        .await
        .map_err(|err| match err {
            PeerNetworkError::Busy(m) => PeerError::busy("local", "transcode_dispatch", m),
            other => PeerError::internal("local", "transcode_dispatch", other.to_string()),
        })?;
    let read = resp
        .into_credential_read()
        .map_err(|err| PeerError::internal("local", "transcode_dispatch", err.to_string()))?;
    if read.slot != PeerCredentialSlot::LinkToken || read.id != link_id || !read.present {
        return Ok(None);
    }
    Ok(read.into_secret())
}

async fn insert_transcode_job_row(runtime: &PeerRuntime, job: TranscodeJob) {
    let _ = runtime
        .db
        .write(
            &runtime.local_server_name(),
            "transcode_job_record",
            move |conn| {
                let _ = db_peers::insert_transcode_job(conn, &job);
                Ok(())
            },
        )
        .await;
}

async fn update_transcode_job_row(runtime: &PeerRuntime, job: TranscodeJob) {
    let _ = runtime
        .db
        .write(
            &runtime.local_server_name(),
            "transcode_job_record",
            move |conn| {
                let _ = db_peers::update_transcode_job(conn, &job);
                Ok(())
            },
        )
        .await;
}

async fn is_outbound_transcode_grant_still_active(runtime: &PeerRuntime, link_id: &str) -> bool {
    let lid = link_id.to_string();
    runtime
        .db
        .read(
            &runtime.local_server_name(),
            "dispatcher_rev_recheck",
            move |conn| {
                let link_ok = db_peers::get_peer_link(conn, &lid)
                    .ok()
                    .flatten()
                    .is_some_and(|l| is_active_link_state(&l.state));
                let grant_ok = db_peers::get_active_peer_received_grant_for_link(conn, &lid)
                    .ok()
                    .flatten()
                    .is_some_and(|g| g.access.transcoding.allows_write());
                Ok(link_ok && grant_ok)
            },
        )
        .await
        .unwrap_or(false)
}

async fn handle_dispatcher_connection(
    runtime: Arc<PeerRuntime>,
    stream: UnixStream,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let (mut shim_reader, mut shim_writer) = stream.into_split();
    let remote_start_budget = runtime.transcode_state.remote_start_timeout();
    let start_deadline = tokio::time::Instant::now() + remote_start_budget;

    // 1. Read initial Frame::Start from shim within the remote-start budget.
    let first_frame = tokio::select! {
        biased;
        _ = shutdown_rx.changed() => return,
        res = tokio::time::timeout_at(start_deadline, read_frame(&mut shim_reader)) => res,
    };

    let start_req = match first_frame {
        Ok(Ok(Some(Frame::Start(req)))) => req,
        Ok(Ok(Some(_))) | Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
            return;
        }
    };

    // Probes should never arrive here because the shim runs them locally, but fail safely to local.
    if argv::is_probe(&start_req.args) {
        let _ = tokio::time::timeout(
            KILL_SIGNAL_WRITE_TIMEOUT,
            write_frame(&mut shim_writer, &Frame::RunLocal),
        )
        .await;
        return;
    }

    // Isolated transcode workers run with `PrivateNetwork=yes` and a local-only protocol
    // whitelist, so network-protocol inputs or non-local `-protocol_whitelist` flags must run
    // locally on the controller without contacting any remote worker.
    if argv::has_network_input(&start_req.args)
        || argv::has_disallowed_protocol_whitelist(&start_req.args)
    {
        tracing::info!(
            reason = "network_input_local_only",
            "Transcode job uses a network input or non-local protocol whitelist; returning Frame::RunLocal"
        );
        let job_id = Uuid::new_v4().to_string();
        let request_id = format!("tc-{}", Uuid::new_v4().simple());
        let now_rfc = runtime.now().to_rfc3339();
        let _ = tokio::time::timeout(
            DEFAULT_FRAME_WRITE_TIMEOUT,
            write_frame(&mut shim_writer, &Frame::RunLocal),
        )
        .await;
        insert_transcode_job_row(
            &runtime,
            TranscodeJob {
                id: job_id,
                link_id: None,
                started_at: now_rfc.clone(),
                ended_at: Some(now_rfc),
                exit_code: None,
                request_id: Some(request_id),
                ran_locally: true,
            },
        )
        .await;
        return;
    }

    let required_cap = argv::required_capability(&start_req.args);
    let job_id = Uuid::new_v4().to_string();
    let request_id = format!("tc-{}", Uuid::new_v4().simple());
    let started_at = runtime.now().to_rfc3339();

    let start_payload = match encode_frame_payload(&Frame::Start(start_req)) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, "Failed encoding Start frame; falling back locally");
            let _ = tokio::time::timeout(
                KILL_SIGNAL_WRITE_TIMEOUT,
                write_frame(&mut shim_writer, &Frame::RunLocal),
            )
            .await;
            insert_transcode_job_row(
                &runtime,
                TranscodeJob {
                    id: job_id,
                    link_id: None,
                    started_at,
                    ended_at: Some(runtime.now().to_rfc3339()),
                    exit_code: None,
                    request_id: Some(request_id),
                    ran_locally: true,
                },
            )
            .await;
            return;
        }
    };

    // 2. Collect eligible workers and iterate in weighted-random order without replacement.
    let mut candidates = collect_eligible_workers(&runtime, &required_cap).await;

    while let Some(candidate) = pick_weighted_candidate(&mut candidates) {
        if *shutdown_rx.borrow() || tokio::time::Instant::now() >= start_deadline {
            break;
        }

        let Some(slot_guard) = runtime
            .transcode_state
            .try_acquire_job_slot(&candidate.link.id, candidate.max_jobs)
        else {
            continue;
        };

        // Resolve held link token & committed grant token within remaining budget.
        let creds_res = tokio::time::timeout_at(start_deadline, async {
            let link_tok = read_held_link_token_for_transcode(&runtime, &candidate.link.id)
                .await
                .ok()
                .flatten()?;
            let (grant, grant_tok) =
                read_committed_received_grant_token(&runtime, &candidate.link.id)
                    .await
                    .ok()
                    .flatten()?;
            if !grant.access.transcoding.allows_write() {
                return None;
            }
            Some((link_tok, grant_tok))
        })
        .await;

        let Some((link_token, grant_token)) = creds_res.ok().flatten() else {
            runtime
                .transcode_state
                .mark_worker_unhealthy(&candidate.link.id, runtime.now());
            drop(slot_guard);
            continue;
        };

        // Open WebSocket to remote worker tunnel listener within remaining budget.
        let ws_pair = connect_tunnel_transcode_ws(
            &runtime,
            &candidate.link.tunnel_ip,
            &link_token,
            &grant_token,
            &request_id,
            start_deadline,
        )
        .await;
        drop(link_token);
        drop(grant_token);

        let (mut ws_reader, mut ws_writer) = match ws_pair {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(
                    link_id = %candidate.link.id,
                    peer = %candidate.link.name,
                    error = %err.message(),
                    "Transcode worker unreachable before Start; marking unhealthy for 60s"
                );
                runtime
                    .transcode_state
                    .mark_worker_unhealthy(&candidate.link.id, runtime.now());
                drop(slot_guard);
                continue;
            }
        };

        // Subscribe to revocations BEFORE transmitting Frame::Start.
        let rev_rx = runtime.subscribe_revocations();

        // Transmit Frame::Start over WebSocket.
        match ws_writer.write_binary(&start_payload, start_deadline).await {
            Ok(()) => {
                // COMMITTED REMOTE START BOUNDARY: NEVER send Frame::RunLocal from this point on!
            }
            Err(WsWriteError::BeforeAnyBytesSent(msg)) => {
                tracing::warn!(
                    link_id = %candidate.link.id,
                    peer = %candidate.link.name,
                    error = %msg,
                    "Transcode worker write failed before any bytes sent; marking unhealthy for 60s"
                );
                runtime
                    .transcode_state
                    .mark_worker_unhealthy(&candidate.link.id, runtime.now());
                drop(ws_writer);
                drop(ws_reader);
                drop(slot_guard);
                continue;
            }
            Err(WsWriteError::AfterBytesWritten(msg)) => {
                // Ambiguous partial/post-send failure: NEVER send Frame::RunLocal!
                tracing::warn!(
                    link_id = %candidate.link.id,
                    peer = %candidate.link.name,
                    error = %msg,
                    "Ambiguous failure transmitting Start frame to worker; aborting without local fallback"
                );
                runtime
                    .transcode_state
                    .mark_worker_unhealthy(&candidate.link.id, runtime.now());
                ws_writer.write_close(1011, KILL_SIGNAL_WRITE_TIMEOUT).await;
                let _ = tokio::time::timeout(
                    KILL_SIGNAL_WRITE_TIMEOUT,
                    write_frame(
                        &mut shim_writer,
                        &Frame::Error {
                            kind: ErrorKind::WorkerFailed,
                            message: "ambiguous failure submitting job to remote worker"
                                .to_string(),
                        },
                    ),
                )
                .await;
                insert_transcode_job_row(
                    &runtime,
                    TranscodeJob {
                        id: job_id,
                        link_id: Some(candidate.link.id),
                        started_at,
                        ended_at: Some(runtime.now().to_rfc3339()),
                        exit_code: Some(1),
                        request_id: Some(request_id),
                        ran_locally: false,
                    },
                )
                .await;
                return;
            }
        }

        // Wait for initial Frame::Started (handling any WebSocket Pings) within `start_deadline`.
        let started_outcome =
            wait_for_worker_started(&mut ws_reader, &mut ws_writer, start_deadline).await;
        match started_outcome {
            Ok(()) => {
                // Worker confirmed process launch! Deliver Frame::Started to the shim FIRST so
                // SQLite write contention never eats into the shim's 2,000 ms handshake deadline.
                let mut job_row = TranscodeJob {
                    id: job_id,
                    link_id: Some(candidate.link.id.clone()),
                    started_at,
                    ended_at: None,
                    exit_code: None,
                    request_id: Some(request_id.clone()),
                    ran_locally: false,
                };

                if tokio::time::timeout(
                    DEFAULT_FRAME_WRITE_TIMEOUT,
                    write_frame(&mut shim_writer, &Frame::Started),
                )
                .await
                .map_or(true, |res| res.is_err())
                {
                    // Shim disconnected right before receiving Started -> kill remote worker job!
                    if let Ok(kill_bytes) = encode_frame_payload(&Frame::Signal(SignalKind::Kill)) {
                        let _ = ws_writer
                            .write_binary(
                                &kill_bytes,
                                tokio::time::Instant::now() + KILL_SIGNAL_WRITE_TIMEOUT,
                            )
                            .await;
                    }
                    ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                    job_row.ended_at = Some(runtime.now().to_rfc3339());
                    job_row.exit_code = Some(137);
                    insert_transcode_job_row(&runtime, job_row).await;
                    return;
                }

                insert_transcode_job_row(&runtime, job_row.clone()).await;

                let (final_exit, mark_unhealthy) = relay_active_dispatcher_job(
                    &runtime,
                    &candidate.link.id,
                    shim_reader,
                    shim_writer,
                    ws_reader,
                    ws_writer,
                    rev_rx,
                    shutdown_rx,
                )
                .await;

                if mark_unhealthy {
                    runtime
                        .transcode_state
                        .mark_worker_unhealthy(&candidate.link.id, runtime.now());
                }

                job_row.ended_at = Some(runtime.now().to_rfc3339());
                job_row.exit_code = Some(final_exit);
                update_transcode_job_row(&runtime, job_row).await;
                drop(slot_guard);
                return;
            }
            Err((err_kind, err_msg)) => {
                // POST-START FAILURE: NEVER send Frame::RunLocal!
                tracing::warn!(
                    link_id = %candidate.link.id,
                    peer = %candidate.link.name,
                    error = %err_msg,
                    "Worker failed or timed out after Start before Started; aborting without local fallback"
                );
                runtime
                    .transcode_state
                    .mark_worker_unhealthy(&candidate.link.id, runtime.now());
                if let Ok(kill_bytes) = encode_frame_payload(&Frame::Signal(SignalKind::Kill)) {
                    let _ = ws_writer
                        .write_binary(
                            &kill_bytes,
                            tokio::time::Instant::now() + KILL_SIGNAL_WRITE_TIMEOUT,
                        )
                        .await;
                }
                ws_writer.write_close(1011, KILL_SIGNAL_WRITE_TIMEOUT).await;
                let _ = tokio::time::timeout(
                    KILL_SIGNAL_WRITE_TIMEOUT,
                    write_frame(
                        &mut shim_writer,
                        &Frame::Error {
                            kind: err_kind,
                            message: err_msg,
                        },
                    ),
                )
                .await;
                insert_transcode_job_row(
                    &runtime,
                    TranscodeJob {
                        id: job_id,
                        link_id: Some(candidate.link.id),
                        started_at,
                        ended_at: Some(runtime.now().to_rfc3339()),
                        exit_code: Some(1),
                        request_id: Some(request_id),
                        ran_locally: false,
                    },
                )
                .await;
                drop(slot_guard);
                return;
            }
        }
    }

    // 3. Definite pre-start fallback: NO worker received a complete Frame::Start.
    let _ = tokio::time::timeout(
        DEFAULT_FRAME_WRITE_TIMEOUT,
        write_frame(&mut shim_writer, &Frame::RunLocal),
    )
    .await;
    insert_transcode_job_row(
        &runtime,
        TranscodeJob {
            id: job_id,
            link_id: None,
            started_at,
            ended_at: Some(runtime.now().to_rfc3339()),
            exit_code: None,
            request_id: Some(request_id),
            ran_locally: true,
        },
    )
    .await;
}

async fn wait_for_worker_started<R, W>(
    ws_reader: &mut WsClientReader<R>,
    ws_writer: &mut WsClientWriter<W>,
    deadline: tokio::time::Instant,
) -> Result<(), (ErrorKind, String)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let msg = tokio::time::timeout_at(deadline, ws_reader.read_message())
            .await
            .map_err(|_| {
                (
                    ErrorKind::WorkerFailed,
                    "timed out waiting for worker Started acknowledgment".to_string(),
                )
            })?
            .map_err(|err| (ErrorKind::WorkerFailed, err))?;

        match msg {
            Some(WsClientMessage::Ping(data)) => {
                let _ = ws_writer.write_pong(&data, KILL_SIGNAL_WRITE_TIMEOUT).await;
            }
            Some(WsClientMessage::Binary(bytes)) => {
                let frame = decode_frame_payload(&bytes).map_err(|err| {
                    (
                        ErrorKind::ProtocolViolation,
                        format!("invalid worker frame before Started: {err}"),
                    )
                })?;
                match frame {
                    Frame::Started => return Ok(()),
                    Frame::Error { kind, message } => return Err((kind, message)),
                    other => {
                        return Err((
                            ErrorKind::ProtocolViolation,
                            format!("unexpected frame before Started: {other:?}"),
                        ));
                    }
                }
            }
            None => {
                return Err((
                    ErrorKind::WorkerFailed,
                    "worker disconnected before sending Started".to_string(),
                ));
            }
        }
    }
}

enum OutboundWsCommand {
    Binary(Vec<u8>),
    Pong(Vec<u8>),
}

/// Active bidirectional relay between local shim Unix socket and remote worker WebSocket.
/// Returns `(exit_code, should_mark_worker_unhealthy)`.
#[allow(clippy::too_many_arguments)]
async fn relay_active_dispatcher_job(
    runtime: &PeerRuntime,
    link_id: &str,
    mut shim_reader: tokio::net::unix::OwnedReadHalf,
    mut shim_writer: tokio::net::unix::OwnedWriteHalf,
    mut ws_reader: WsClientReader<ReadHalf<TunnelUpgradedIo>>,
    mut ws_writer: WsClientWriter<WriteHalf<TunnelUpgradedIo>>,
    mut rev_rx: broadcast::Receiver<RevocationEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (i32, bool) {
    let (to_ws_tx, mut to_ws_rx) = mpsc::channel::<OutboundWsCommand>(FRAME_CHANNEL_CAPACITY);
    let (urgent_kill_tx, mut urgent_kill_rx) = mpsc::channel::<()>(2);
    let (to_shim_tx, mut to_shim_rx) = bounded_frame_channel();
    // Dedicated reader tasks keep non-cancel-safe `WsClientReader::read_message` and
    // `read_frame` outside `tokio::select!`, preventing frame corruption under concurrent traffic
    // or unrelated revocation broadcasts.
    let (from_ws_tx, mut from_ws_rx) =
        mpsc::channel::<Result<Option<WsClientMessage>, String>>(FRAME_CHANNEL_CAPACITY);
    let (from_shim_tx, mut from_shim_rx) =
        mpsc::channel::<Result<Option<Frame>, String>>(FRAME_CHANNEL_CAPACITY);

    let mut ws_read_task = tokio::spawn(async move {
        loop {
            match ws_reader.read_message().await {
                Ok(Some(msg)) => {
                    if from_ws_tx.send(Ok(Some(msg))).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = from_ws_tx.send(Ok(None)).await;
                    break;
                }
                Err(err) => {
                    let _ = from_ws_tx.send(Err(err)).await;
                    break;
                }
            }
        }
    });

    let mut shim_read_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut shim_reader).await {
                Ok(Some(frame)) => {
                    if from_shim_tx.send(Ok(Some(frame))).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = from_shim_tx.send(Ok(None)).await;
                    break;
                }
                Err(err) => {
                    let _ = from_shim_tx.send(Err(err.to_string())).await;
                    break;
                }
            }
        }
    });

    // Priority-aware WebSocket writer so Signal(Kill) bypasses any full stdin queue immediately.
    let mut ws_write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                Some(()) = urgent_kill_rx.recv() => {
                    if let Ok(bytes) = encode_frame_payload(&Frame::Signal(SignalKind::Kill)) {
                        let _ = ws_writer
                            .write_binary(
                                &bytes,
                                tokio::time::Instant::now() + KILL_SIGNAL_WRITE_TIMEOUT,
                            )
                            .await;
                    }
                    ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                    break;
                }
                maybe_cmd = to_ws_rx.recv() => {
                    let Some(cmd) = maybe_cmd else {
                        ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                        break;
                    };
                    let deadline = tokio::time::Instant::now() + DEFAULT_FRAME_WRITE_TIMEOUT;
                    let res = match cmd {
                        OutboundWsCommand::Binary(bytes) => ws_writer.write_binary(&bytes, deadline).await,
                        OutboundWsCommand::Pong(data) => ws_writer.write_pong(&data, KILL_SIGNAL_WRITE_TIMEOUT).await,
                    };
                    if res.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut shim_write_task = tokio::spawn(async move {
        while let Some(frame) = to_shim_rx.recv().await {
            if tokio::time::timeout(
                DEFAULT_FRAME_WRITE_TIMEOUT,
                write_frame(&mut shim_writer, &frame),
            )
            .await
            .map_or(true, |res| res.is_err())
            {
                break;
            }
        }
        let _ = shim_writer.shutdown().await;
    });

    let (final_exit, mark_unhealthy) = loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = urgent_kill_tx.try_send(());
                    break (137, false);
                }
            }
            rev_ev = rev_rx.recv() => {
                let revoked = match rev_ev {
                    Ok(RevocationEvent::LinkRevoked { link_id: rev_lid, .. }) => rev_lid == link_id,
                    Ok(RevocationEvent::GrantRevoked { link_id: rev_lid, .. }) => {
                        rev_lid == link_id
                            && !is_outbound_transcode_grant_still_active(runtime, link_id).await
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        !is_outbound_transcode_grant_still_active(runtime, link_id).await
                    }
                    Err(broadcast::error::RecvError::Closed) => true,
                };
                if revoked {
                    let _ = urgent_kill_tx.try_send(());
                    break (137, false);
                }
            }
            ws_item = from_ws_rx.recv() => {
                match ws_item {
                    Some(Ok(Some(WsClientMessage::Ping(data)))) => {
                        let _ = to_ws_tx.try_send(OutboundWsCommand::Pong(data));
                    }
                    Some(Ok(Some(WsClientMessage::Binary(bytes)))) => {
                        match decode_frame_payload(&bytes) {
                            Ok(Frame::Exit(code)) => {
                                let _ = to_shim_tx.send(Frame::Exit(code)).await;
                                break (code, false);
                            }
                            Ok(Frame::Error { kind, message }) => {
                                let _ = to_shim_tx.send(Frame::Error { kind, message }).await;
                                break (1, true);
                            }
                            Ok(frame) => {
                                if to_shim_tx.send(frame).await.is_err() {
                                    // Shim closed unexpectedly while receiving output -> kill worker!
                                    let _ = urgent_kill_tx.try_send(());
                                    break (137, false);
                                }
                            }
                            Err(_) => {
                                let _ = urgent_kill_tx.try_send(());
                                break (1, true);
                            }
                        }
                    }
                    Some(Ok(None)) | Some(Err(_)) | None => {
                        // Remote worker stream dropped mid-job without Exit!
                        break (1, true);
                    }
                }
            }
            shim_item = from_shim_rx.recv() => {
                match shim_item {
                    Some(Ok(Some(Frame::Signal(SignalKind::Kill)))) => {
                        let _ = urgent_kill_tx.try_send(());
                        break (137, false);
                    }
                    Some(Ok(Some(frame))) => {
                        if let Ok(bytes) = encode_frame_payload(&frame) {
                            if to_ws_tx.send(OutboundWsCommand::Binary(bytes)).await.is_err() {
                                break (1, true);
                            }
                        }
                    }
                    Some(Ok(None)) | Some(Err(_)) | None => {
                        // Shim Unix socket closed without a preceding Frame::Exit (e.g. Jellyfin SIGKILL)!
                        // Immediately send Signal(Kill) to remote worker so it kills ffmpeg process group.
                        let _ = urgent_kill_tx.try_send(());
                        break (137, false);
                    }
                }
            }
        }
    };

    drop(from_ws_rx);
    drop(from_shim_rx);
    drop(to_ws_tx);
    drop(to_shim_tx);
    if !ws_read_task.is_finished() {
        ws_read_task.abort();
    }
    if !shim_read_task.is_finished() {
        shim_read_task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut ws_read_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut shim_read_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut ws_write_task).await;
    if !ws_write_task.is_finished() {
        ws_write_task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), &mut shim_write_task).await;
    if !shim_write_task.is_finished() {
        shim_write_task.abort();
    }

    (final_exit, mark_unhealthy)
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker Path-Parity Test (1-second clip / 5-second timeout)
// ─────────────────────────────────────────────────────────────────────────────

async fn cleanup_parity_output(
    runtime: &PeerRuntime,
    dir: &str,
    output_path: &Path,
    file_name: &str,
    use_local_fs: bool,
) -> Result<Option<ParityFileCleanupReport>, String> {
    if use_local_fs {
        if let Err(err) = fs::remove_file(output_path) {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::debug!(path = %output_path.display(), %err, "Local parity temp file cleanup failed");
            }
        }
        return Ok(None);
    }

    match runtime
        .transcode_runner
        .dispatch(&PeerTranscodeRequest::CleanupParityFile {
            dir: dir.to_string(),
            file_name: file_name.to_string(),
        })
        .await
        .and_then(|resp| resp.into_parity_file_cleanup())
    {
        Ok(report) => Ok(Some(report)),
        Err(err) => {
            // Fall back to direct unlink if runner is unavailable in non-sandboxed environments.
            let _ = fs::remove_file(output_path);
            Err(err.to_string())
        }
    }
}

async fn persist_worker_parity_outcome(
    runtime: &PeerRuntime,
    link_id: &str,
    ok: bool,
    error: Option<&str>,
) {
    let link_id_c = link_id.to_string();
    let error_c = error.map(redact_sensitive_text);
    let _ = runtime
        .db
        .write(
            &runtime.local_server_name(),
            "transcode_parity_persist",
            move |conn| {
                conn.execute(
                    "INSERT INTO transcode_workers (\
                    link_id, enabled, weight, max_jobs, ffmpeg_version, encoders, render_node, \
                    parity_ok, parity_error\
                 ) VALUES (?1, 0, 1, 2, NULL, NULL, NULL, ?2, ?3) \
                 ON CONFLICT(link_id) DO UPDATE SET \
                    parity_ok = excluded.parity_ok, \
                    parity_error = excluded.parity_error",
                    rusqlite::params![link_id_c, ok, error_c],
                )
                .map_err(|err| {
                    PeerError::internal("local", "transcode_parity_persist", err.to_string())
                })?;
                Ok(())
            },
        )
        .await;
}

async fn run_worker_parity_test(
    runtime: &PeerRuntime,
    link: &PeerLink,
    transcode_temp_dir: &str,
    tmp_dir: &str,
) -> ParityTestResultView {
    let started = Instant::now();
    let timeout = runtime.transcode_state.parity_timeout();
    let deadline = tokio::time::Instant::now() + timeout;

    let parity_override = runtime
        .transcode_state
        .parity_dir_override
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let use_local_fs = parity_override.is_some();
    let effective_dir = parity_override.unwrap_or_else(|| PathBuf::from(transcode_temp_dir));

    let outcome = execute_parity_test_inner(
        runtime,
        link,
        &effective_dir,
        tmp_dir,
        use_local_fs,
        deadline,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let (ok, error) = match outcome {
        Ok(()) => (true, None),
        Err(msg) => (false, Some(redact_sensitive_text(&msg))),
    };

    persist_worker_parity_outcome(runtime, &link.id, ok, error.as_deref()).await;

    ParityTestResultView {
        link_id: link.id.clone(),
        ok,
        elapsed_ms,
        error,
    }
}

async fn execute_parity_test_inner(
    runtime: &PeerRuntime,
    link: &PeerLink,
    transcode_dir: &Path,
    tmp_dir: &str,
    use_local_fs: bool,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    match fs::metadata(transcode_dir) {
        Ok(dir_meta) => {
            if !dir_meta.is_dir() {
                return Err(format!(
                    "Local transcode path '{}' is not a directory",
                    transcode_dir.display()
                ));
            }
        }
        Err(err) if !use_local_fs && err.kind() == io::ErrorKind::PermissionDenied => {
            // Production `jellyfin:jellyfin` 0700 transcode folder will be verified via root
            // `af-runner` `CleanupParityFile` after the worker completes.
        }
        Err(err) => {
            return Err(format!(
                "Local transcode folder '{}' is not accessible: {err}",
                transcode_dir.display()
            ));
        }
    }

    let link_token = read_held_link_token_for_transcode(runtime, &link.id)
        .await
        .map_err(|e| e.detail().message.clone())?
        .ok_or_else(|| format!("Held link credential for '{}' is missing", link.name))?;

    let (grant, grant_token) = read_committed_received_grant_token(runtime, &link.id)
        .await
        .map_err(|e| e.detail().message.clone())?
        .ok_or_else(|| format!("No active grant held for '{}'", link.name))?;

    if !grant.access.transcoding.allows_write() {
        return Err(format!(
            "Grant for '{}' does not include transcoding: write",
            link.name
        ));
    }

    let request_id = format!("parity-{}", Uuid::new_v4().simple());
    let file_name = format!(".af-parity-{}.ts", Uuid::new_v4().simple());
    let output_path = transcode_dir.join(&file_name);
    let output_str = output_path
        .to_str()
        .ok_or_else(|| "Parity output path is not valid UTF-8".to_string())?
        .to_string();
    let cwd_str = transcode_dir
        .to_str()
        .ok_or_else(|| "Transcode folder path is not valid UTF-8".to_string())?
        .to_string();

    let (mut ws_reader, mut ws_writer) = connect_tunnel_transcode_ws(
        runtime,
        &link.tunnel_ip,
        &link_token,
        &grant_token,
        &request_id,
        deadline,
    )
    .await
    .map_err(|err| {
        format!(
            "Failed connecting to '{}' for parity test: {}",
            link.name,
            err.message()
        )
    })?;
    drop(link_token);
    drop(grant_token);

    let mut env_subset = Vec::new();
    if Path::new(tmp_dir).is_absolute() && !tmp_dir.contains("..") {
        env_subset.push(("TMPDIR".to_string(), tmp_dir.to_string()));
    }

    let start_frame = Frame::Start(StartRequest {
        args: vec![
            "-nostdin".to_string(),
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "error".to_string(),
            "-y".to_string(),
            "-f".to_string(),
            "lavfi".to_string(),
            "-i".to_string(),
            "testsrc=duration=1:size=160x120:rate=10".to_string(),
            "-frames:v".to_string(),
            "10".to_string(),
            "-c:v".to_string(),
            "libx264".to_string(),
            "-f".to_string(),
            "mpegts".to_string(),
            output_str,
        ],
        cwd: cwd_str.clone(),
        env_subset,
    });

    let start_bytes = encode_frame_payload(&start_frame)
        .map_err(|err| format!("Failed encoding parity Start frame: {err}"))?;
    ws_writer
        .write_binary(&start_bytes, deadline)
        .await
        .map_err(|err| format!("Failed sending parity Start frame: {}", err.message()))?;

    if let Err((_, msg)) = wait_for_worker_started(&mut ws_reader, &mut ws_writer, deadline).await {
        ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
        let _ =
            cleanup_parity_output(runtime, &cwd_str, &output_path, &file_name, use_local_fs).await;
        return Err(format!("Worker failed starting parity test: {msg}"));
    }

    if let Ok(eof_bytes) = encode_frame_payload(&Frame::StdinEof) {
        let _ = ws_writer.write_binary(&eof_bytes, deadline).await;
    }

    let mut stderr_tail = String::new();
    let exit_code = loop {
        let msg = match tokio::time::timeout_at(deadline, ws_reader.read_message()).await {
            Ok(Ok(m)) => m,
            Ok(Err(err)) => {
                if let Ok(kill_bytes) = encode_frame_payload(&Frame::Signal(SignalKind::Kill)) {
                    let _ = ws_writer
                        .write_binary(
                            &kill_bytes,
                            tokio::time::Instant::now() + KILL_SIGNAL_WRITE_TIMEOUT,
                        )
                        .await;
                }
                ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                let _ = cleanup_parity_output(
                    runtime,
                    &cwd_str,
                    &output_path,
                    &file_name,
                    use_local_fs,
                )
                .await;
                return Err(format!("Parity test stream error: {err}"));
            }
            Err(_) => {
                if let Ok(kill_bytes) = encode_frame_payload(&Frame::Signal(SignalKind::Kill)) {
                    let _ = ws_writer
                        .write_binary(
                            &kill_bytes,
                            tokio::time::Instant::now() + KILL_SIGNAL_WRITE_TIMEOUT,
                        )
                        .await;
                }
                ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                let _ = cleanup_parity_output(
                    runtime,
                    &cwd_str,
                    &output_path,
                    &file_name,
                    use_local_fs,
                )
                .await;
                return Err(
                    "Parity test timed out waiting for worker ffmpeg completion".to_string()
                );
            }
        };

        match msg {
            Some(WsClientMessage::Ping(data)) => {
                let _ = ws_writer.write_pong(&data, KILL_SIGNAL_WRITE_TIMEOUT).await;
            }
            Some(WsClientMessage::Binary(bytes)) => {
                let frame = match decode_frame_payload(&bytes) {
                    Ok(f) => f,
                    Err(err) => {
                        ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                        let _ = cleanup_parity_output(
                            runtime,
                            &cwd_str,
                            &output_path,
                            &file_name,
                            use_local_fs,
                        )
                        .await;
                        return Err(format!("Parity test received invalid frame: {err}"));
                    }
                };
                match frame {
                    Frame::Exit(code) => break code,
                    Frame::Error { message, .. } => {
                        ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;
                        let _ = cleanup_parity_output(
                            runtime,
                            &cwd_str,
                            &output_path,
                            &file_name,
                            use_local_fs,
                        )
                        .await;
                        return Err(format!("Worker parity test error: {message}"));
                    }
                    Frame::Stderr(chunk) if stderr_tail.len() < 512 => {
                        stderr_tail.push_str(&String::from_utf8_lossy(&chunk));
                    }
                    _ => {}
                }
            }
            None => {
                let _ = cleanup_parity_output(
                    runtime,
                    &cwd_str,
                    &output_path,
                    &file_name,
                    use_local_fs,
                )
                .await;
                return Err("Worker closed stream before parity test finished".to_string());
            }
        }
    };

    ws_writer.write_close(1000, KILL_SIGNAL_WRITE_TIMEOUT).await;

    if exit_code != 0 {
        let _ =
            cleanup_parity_output(runtime, &cwd_str, &output_path, &file_name, use_local_fs).await;
        let detail = stderr_tail.trim();
        return if detail.is_empty() {
            Err(format!(
                "Worker parity encode exited with status {exit_code}"
            ))
        } else {
            Err(format!(
                "Worker parity encode exited with status {exit_code}: {detail}"
            ))
        };
    }

    if use_local_fs {
        let verify_res = (|| {
            let out_meta = fs::symlink_metadata(&output_path).map_err(|err| {
                format!(
                    "Parity output file was not visible on local server at '{}' (shared NFS transcode path mismatch): {err}",
                    output_path.display()
                )
            })?;
            if out_meta.file_type().is_symlink() || !out_meta.is_file() {
                return Err("Parity output path is not a regular file".to_string());
            }
            if out_meta.len() == 0 {
                return Err("Parity output file on local server is empty (0 bytes)".to_string());
            }
            let read_bytes = fs::read(&output_path).map_err(|err| {
                format!("Failed reading parity output file back on local server: {err}")
            })?;
            if read_bytes.is_empty() {
                return Err("Parity output file read back empty".to_string());
            }
            Ok(())
        })();
        let _ = cleanup_parity_output(runtime, &cwd_str, &output_path, &file_name, true).await;
        return verify_res;
    }

    // Production path: verify readability and unlink via root `af-runner` `CleanupParityFile`
    // so `ProtectSystem=strict` read-only mounts never leak `.af-parity-*.ts` files.
    let report = cleanup_parity_output(runtime, &cwd_str, &output_path, &file_name, false)
        .await
        .map_err(|err| {
            format!(
                "Failed verifying and removing parity output '{}' via privileged runner: {err}",
                output_path.display()
            )
        })?
        .ok_or_else(|| "Privileged runner did not return a parity cleanup report".to_string())?;

    if !report.existed {
        return Err(format!(
            "Parity output file was not visible on local server at '{}' (shared NFS transcode path mismatch)",
            output_path.display()
        ));
    }
    if report.size_bytes == 0 {
        return Err("Parity output file on local server is empty (0 bytes)".to_string());
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin HTTP Wire Types: GET / PUT /api/v1/admin/peers/transcode
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTranscodeInfoView {
    pub server_name: String,
    pub ffmpeg_version: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub encoders: Vec<String>,
    pub render_nodes: Vec<RenderNodeInfo>,
    pub primary_render_node: Option<String>,
    pub transcoding_temp_path: String,
    pub tmp_dir: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscodeWorkerView {
    pub link_id: String,
    pub peer_name: String,
    pub link_state: String,
    pub compatibility: &'static str,
    pub supports_transcode: bool,
    pub has_transcode_write_grant: bool,
    pub has_updates_write_grant: bool,
    pub enabled: bool,
    pub eligible: bool,
    pub ineligible_reason: Option<String>,
    pub weight: i64,
    pub max_jobs: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_max_jobs: Option<usize>,
    pub effective_max_jobs: usize,
    pub active_jobs: usize,
    pub unhealthy_until: Option<String>,
    pub ffmpeg_version: Option<String>,
    pub package_version: Option<String>,
    pub ffmpeg_mismatch: bool,
    pub ffmpeg_mismatch_message: Option<String>,
    pub align_target: Option<&'static str>,
    pub encoders: Vec<String>,
    pub render_node: Option<String>,
    pub parity_ok: bool,
    pub parity_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscodeJobView {
    pub id: String,
    pub link_id: Option<String>,
    pub peer_name: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub request_id: Option<String>,
    pub ran_locally: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityTestResultView {
    pub link_id: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscodeConfigResponse {
    pub enabled: bool,
    pub worker_service_enabled: bool,
    pub worker_service_active: bool,
    pub dispatcher_active: bool,
    pub dispatcher_socket: String,
    pub shim_installed: bool,
    pub shim_path: String,
    pub jellyfin_dropin_enabled: bool,
    pub jellyfin_reported_ffmpeg: Option<String>,
    pub api_restart_scheduled: bool,
    pub local: LocalTranscodeInfoView,
    pub workers: Vec<TranscodeWorkerView>,
    pub recent_jobs: Vec<TranscodeJobView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parity_result: Option<ParityTestResultView>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateTranscodeWorkerReq {
    link_id: String,
    enabled: bool,
    weight: i64,
    max_jobs: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateTranscodeConfigReq {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    worker_service_enabled: Option<bool>,
    #[serde(default)]
    workers: Option<Vec<UpdateTranscodeWorkerReq>>,
    #[serde(default)]
    run_parity_test_link_id: Option<String>,
}

fn map_transcode_runner_error(err: PeerTranscodeError, server: &str, step: &str) -> PeerError {
    match err {
        PeerTranscodeError::InvalidInput(msg) => PeerError::invalid_request(
            server,
            step,
            msg,
            "Verify transcoding configuration and Jellyfin paths, then retry",
        ),
        PeerTranscodeError::Conflict(msg) | PeerTranscodeError::UnmanagedFile(msg) => {
            PeerError::conflict(
                server,
                step,
                msg,
                "Inspect existing Jellyfin or systemd transcode files before retrying",
            )
        }
        PeerTranscodeError::NotFound(msg) => PeerError::not_found(server, step, msg),
        PeerTranscodeError::Busy(msg) => PeerError::busy(server, step, msg),
        PeerTranscodeError::Runtime(msg) => PeerError::internal(server, step, msg),
    }
}

fn default_jellyfin_paths() -> JellyfinTranscodePaths {
    JellyfinTranscodePaths {
        transcoding_temp_path: DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string(),
        tmp_dir: DEFAULT_JELLYFIN_TMP_DIR.to_string(),
        cache_dir: af_runner::DEFAULT_JELLYFIN_CACHE_DIR.to_string(),
        shim_path: DEFAULT_TRANSCODE_SHIM_PATH.to_string(),
        shim_installed: false,
        dropin_enabled: false,
        worker_unit_installed: false,
        worker_unit_active: false,
        jellyfin_uid: None,
        jellyfin_gid: None,
    }
}

async fn inspect_jellyfin_paths_best_effort(
    runtime: &PeerRuntime,
) -> (JellyfinTranscodePaths, bool) {
    match runtime
        .transcode_runner
        .dispatch(&PeerTranscodeRequest::InspectJellyfinPaths)
        .await
        .and_then(|resp| resp.into_jellyfin_paths())
    {
        Ok(paths) => (paths, true),
        Err(err) => {
            tracing::debug!(%err, "InspectJellyfinPaths unavailable; falling back to defaults");
            (default_jellyfin_paths(), false)
        }
    }
}

async fn build_transcode_config_response(
    runtime: &PeerRuntime,
    parity_result: Option<ParityTestResultView>,
) -> Result<TranscodeConfigResponse, PeerError> {
    let server_name = runtime.local_server_name();
    let now = runtime.now();
    let local_caps = refresh_local_capabilities_if_stale(runtime).await;
    let (paths, inspected) = inspect_jellyfin_paths_best_effort(runtime).await;
    let dispatcher_active = runtime.transcode_state.is_dispatcher_active().await;
    let dispatcher_socket = runtime
        .transcode_state
        .dispatcher_socket_path()
        .to_string_lossy()
        .into_owned();

    let probe = runtime
        .transcode_state
        .jellyfin_probe
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let jellyfin_reported_ffmpeg = match probe.probe_reported_ffmpeg(runtime).await {
        JellyfinFfmpegProbeOutcome::Reported(path) => Some(path),
        _ => None,
    };

    let (links, db_workers, received_grants, recent_jobs_raw) = runtime
        .db
        .read(&server_name, "get_transcode_settings", |conn| {
            let links = db_peers::list_peer_links(conn).map_err(|err| {
                PeerError::internal("local", "get_transcode_settings", err.to_string())
            })?;
            let workers = db_peers::list_transcode_workers(conn).map_err(|err| {
                PeerError::internal("local", "get_transcode_settings", err.to_string())
            })?;
            let mut grants = HashMap::new();
            for link in &links {
                if let Ok(Some(g)) =
                    db_peers::get_active_peer_received_grant_for_link(conn, &link.id)
                {
                    grants.insert(link.id.clone(), g);
                }
            }
            let jobs = db_peers::list_transcode_jobs(conn, RECENT_JOBS_LIMIT).map_err(|err| {
                PeerError::internal("local", "get_transcode_settings", err.to_string())
            })?;
            Ok((links, workers, grants, jobs))
        })
        .await?;

    let worker_map: HashMap<String, TranscodeWorker> = db_workers
        .into_iter()
        .map(|w| (w.link_id.clone(), w))
        .collect();
    let link_name_map: HashMap<String, String> = links
        .iter()
        .map(|l| (l.id.clone(), l.name.clone()))
        .collect();

    let mut worker_views = Vec::new();
    for link in &links {
        let pub_state = public_link_state(&link.state);
        if pub_state == "pending" || pub_state == "revoked" {
            continue;
        }
        let parsed_caps: Vec<String> = link
            .capabilities
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        let compat = evaluate_compatibility(link.peer_protocol, &parsed_caps);
        let supports_transcode = parsed_caps.iter().any(|c| c == "transcode");
        let grant = received_grants.get(&link.id);
        let has_transcode_write_grant = grant.is_some_and(|g| g.access.transcoding.allows_write());
        let has_updates_write_grant = grant.is_some_and(|g| {
            g.access.updates.allows_write() || g.access.marketplace.allows_write()
        });

        let db_w = worker_map.get(&link.id);
        let enabled = db_w.is_some_and(|w| w.enabled);
        let weight = db_w
            .map(|w| w.weight.clamp(WORKER_WEIGHT_MIN, WORKER_WEIGHT_MAX))
            .unwrap_or(1);
        let max_jobs = db_w
            .map(|w| w.max_jobs.clamp(WORKER_MAX_JOBS_MIN, WORKER_MAX_JOBS_MAX))
            .unwrap_or(2);
        let parity_ok = db_w.is_some_and(|w| w.parity_ok);
        let parity_error = db_w.and_then(|w| w.parity_error.clone());

        let active_jobs = runtime.transcode_state.active_jobs_for(&link.id);
        let unhealthy_until_dt = runtime
            .transcode_state
            .active_unhealthy_until(&link.id, now);
        let unhealthy_until = unhealthy_until_dt.map(|dt| dt.to_rfc3339());

        let remote_caps = runtime.transcode_state.remote_capabilities_for(&link.id);
        let worker_max_jobs = remote_caps
            .as_ref()
            .and_then(|c| c.worker_max_jobs)
            .filter(|&n| n > 0);
        let effective_max_jobs = effective_worker_max_jobs(max_jobs, remote_caps.as_ref());
        let ffmpeg_version = remote_caps
            .as_ref()
            .and_then(|c| c.ffmpeg_version.clone())
            .or_else(|| db_w.and_then(|w| w.ffmpeg_version.clone()));
        let package_version = remote_caps.as_ref().and_then(|c| c.package_version.clone());
        let encoders = match remote_caps.as_ref() {
            Some(caps) if !caps.encoders.is_empty() => caps.encoders.clone(),
            _ => parse_encoders_json(db_w.and_then(|w| w.encoders.as_deref())),
        };
        let render_node = remote_caps
            .as_ref()
            .and_then(|c| c.primary_render_node.clone())
            .or_else(|| db_w.and_then(|w| w.render_node.clone()));

        let alignment = evaluate_version_alignment(
            &server_name,
            local_caps
                .as_ref()
                .and_then(|c| c.package_version.as_deref()),
            local_caps
                .as_ref()
                .and_then(|c| c.ffmpeg_version.as_deref()),
            &link.name,
            package_version.as_deref(),
            ffmpeg_version.as_deref(),
        );

        let (eligible, ineligible_reason) = if !enabled {
            (false, None)
        } else if !is_active_link_state(&link.state) {
            (false, Some("Peer link is not active".to_string()))
        } else if !supports_transcode {
            (
                false,
                Some("Peer does not advertise transcode capability".to_string()),
            )
        } else if !has_transcode_write_grant {
            (
                false,
                Some("Peer grant does not include transcoding: write".to_string()),
            )
        } else if !parity_ok {
            (
                false,
                Some(
                    parity_error
                        .clone()
                        .unwrap_or_else(|| "Path parity test has not passed".to_string()),
                ),
            )
        } else if unhealthy_until.is_some() {
            (
                false,
                Some("Worker is temporarily marked unhealthy (60s cooldown)".to_string()),
            )
        } else if alignment.mismatch {
            (false, alignment.message.clone())
        } else if !alignment.both_known {
            (
                false,
                Some("Waiting for FFmpeg version report from both servers".to_string()),
            )
        } else if active_jobs >= effective_max_jobs {
            (
                false,
                Some(format!(
                    "Worker is at maximum concurrent jobs ({active_jobs}/{effective_max_jobs})"
                )),
            )
        } else {
            (true, None)
        };

        worker_views.push(TranscodeWorkerView {
            link_id: link.id.clone(),
            peer_name: link.name.clone(),
            link_state: pub_state.to_string(),
            compatibility: compat.status.as_str(),
            supports_transcode,
            has_transcode_write_grant,
            has_updates_write_grant,
            enabled,
            eligible,
            ineligible_reason,
            weight,
            max_jobs,
            worker_max_jobs,
            effective_max_jobs,
            active_jobs,
            unhealthy_until,
            ffmpeg_version,
            package_version,
            ffmpeg_mismatch: alignment.mismatch,
            ffmpeg_mismatch_message: alignment.message,
            align_target: alignment.align_target,
            encoders,
            render_node,
            parity_ok,
            parity_error,
        });
    }
    worker_views.sort_by(|a, b| {
        a.peer_name
            .cmp(&b.peer_name)
            .then(a.link_id.cmp(&b.link_id))
    });

    let recent_jobs: Vec<TranscodeJobView> = recent_jobs_raw
        .into_iter()
        .map(|job| {
            let peer_name = job
                .link_id
                .as_ref()
                .and_then(|id| link_name_map.get(id).cloned());
            TranscodeJobView {
                id: job.id,
                link_id: job.link_id,
                peer_name,
                started_at: job.started_at,
                ended_at: job.ended_at,
                exit_code: job.exit_code,
                request_id: job.request_id,
                ran_locally: job.ran_locally,
            }
        })
        .collect();

    let enabled = if inspected {
        paths.dropin_enabled && dispatcher_active
    } else {
        dispatcher_active
            || runtime
                .transcode_state
                .enabled_fallback
                .load(AtomicOrdering::Acquire)
    };

    let local_info = LocalTranscodeInfoView {
        server_name,
        ffmpeg_version: local_caps.as_ref().and_then(|c| c.ffmpeg_version.clone()),
        package_name: local_caps.as_ref().and_then(|c| c.package_name.clone()),
        package_version: local_caps.as_ref().and_then(|c| c.package_version.clone()),
        encoders: local_caps
            .as_ref()
            .map(|c| c.encoders.clone())
            .unwrap_or_default(),
        render_nodes: local_caps
            .as_ref()
            .map(|c| c.render_nodes.clone())
            .unwrap_or_default(),
        primary_render_node: local_caps
            .as_ref()
            .and_then(|c| c.primary_render_node.clone()),
        transcoding_temp_path: paths.transcoding_temp_path,
        tmp_dir: paths.tmp_dir,
    };

    Ok(TranscodeConfigResponse {
        enabled,
        worker_service_enabled: paths.worker_unit_installed,
        worker_service_active: paths.worker_unit_active,
        dispatcher_active,
        dispatcher_socket,
        shim_installed: paths.shim_installed,
        shim_path: paths.shim_path,
        jellyfin_dropin_enabled: paths.dropin_enabled,
        jellyfin_reported_ffmpeg,
        api_restart_scheduled: false,
        local: local_info,
        workers: worker_views,
        recent_jobs,
        parity_result,
    })
}

/// `GET /api/v1/admin/peers/transcode`
pub async fn get_transcode_settings(State(runtime): State<Arc<PeerRuntime>>) -> Response {
    match build_transcode_config_response(&runtime, None).await {
        Ok(resp) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(resp),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

/// `PUT /api/v1/admin/peers/transcode`
pub async fn put_transcode_settings(
    State(runtime): State<Arc<PeerRuntime>>,
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(bytes) => bytes,
        Err(err) => {
            return bytes_rejection_to_peer_error(
                err,
                &runtime.local_server_name(),
                "put_transcode_settings",
            )
            .into_response();
        }
    };
    match put_transcode_settings_inner(&runtime, &auth_user, peer_ip, &headers, &body).await {
        Ok(resp) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(resp),
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

async fn validate_worker_target_link(
    runtime: &PeerRuntime,
    link_id: &str,
    require_active_and_grant: bool,
    step: &str,
) -> Result<PeerLink, PeerError> {
    let server = runtime.local_server_name();
    if !is_valid_credential_id(link_id) {
        return Err(PeerError::invalid_request(
            &server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        ));
    }

    let lid = link_id.to_string();
    let server_c = server.clone();
    let step_c = step.to_string();
    let (link, received_grant) = runtime
        .db
        .read(&server, step, move |conn| {
            let link = db_peers::get_peer_link(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?
                .ok_or_else(|| {
                    PeerError::not_found(&server_c, &step_c, "Peer link was not found")
                })?;
            let grant = db_peers::get_active_peer_received_grant_for_link(conn, &lid)
                .map_err(|err| PeerError::internal(&server_c, &step_c, err.to_string()))?;
            Ok((link, grant))
        })
        .await?;

    if is_revoked_or_revoking_state(&link.state) {
        return Err(PeerError::link_revoked(
            &link.name,
            step,
            format!("Peer link '{}' has been revoked", link.name),
        ));
    }

    if require_active_and_grant {
        if !is_active_link_state(&link.state) {
            return Err(PeerError::link_down(
                &link.name,
                step,
                format!(
                    "Peer link '{}' must be active to enable transcoding or run parity tests",
                    link.name
                ),
            ));
        }

        let remote_caps: Vec<String> = link
            .capabilities
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        let compat = evaluate_compatibility(link.peer_protocol, &remote_caps);
        if matches!(
            compat.status,
            CompatibilityStatus::Incompatible | CompatibilityStatus::Unknown
        ) || !remote_caps.iter().any(|c| c == "transcode")
        {
            return Err(PeerError::version_incompatible(
                &link.name,
                step,
                format!(
                    "'{}' does not advertise remote transcoding support; update '{}' to use it as a worker",
                    link.name, link.name
                ),
            ));
        }

        if !received_grant.is_some_and(|g| g.access.transcoding.allows_write()) {
            return Err(PeerError::peer_scope_denied(
                &link.name,
                step,
                format!(
                    "Peer '{}' has not granted transcoding: write access to this server",
                    link.name
                ),
            ));
        }
    }

    Ok(link)
}

async fn has_configured_local_jellyfin(runtime: &PeerRuntime) -> bool {
    runtime
        .db
        .read(
            &runtime.local_server_name(),
            "jellyfin_configured_check",
            |conn| Ok(load_local_jellyfin_credentials(conn).is_some()),
        )
        .await
        .unwrap_or(false)
}

async fn send_remote_transcode_mounts(
    runtime: &PeerRuntime,
    link: &PeerLink,
    payload: &TunnelTranscodeMountRequest,
) -> Result<(), String> {
    let link_token = read_held_link_token_for_transcode(runtime, &link.id)
        .await
        .map_err(|e| e.detail().message.clone())?
        .ok_or_else(|| format!("Held link credential for '{}' is missing", link.name))?;

    let (grant, grant_token) = read_committed_received_grant_token(runtime, &link.id)
        .await
        .map_err(|e| e.detail().message.clone())?
        .ok_or_else(|| format!("No active grant held for '{}'", link.name))?;

    if !grant.access.transcoding.allows_write() {
        return Err(format!(
            "Grant for '{}' does not include transcoding: write",
            link.name
        ));
    }

    let body = serde_json::to_vec(payload)
        .map_err(|err| format!("Failed serializing transcode mount request: {err}"))?;
    let extra_headers = vec![
        (
            HEADER_GRANT_TOKEN.to_string(),
            grant_token.expose_secret().to_string(),
        ),
        (
            "x-request-id".to_string(),
            format!("tcmount-{}", Uuid::new_v4().simple()),
        ),
    ];

    let res = runtime
        .send_tunnel_request_with_headers(
            Method::POST,
            &link.tunnel_ip,
            "/peer/v1/transcode/mounts",
            Some(&link_token),
            &extra_headers,
            Some(body),
            TRANSCODE_MOUNT_SYNC_TIMEOUT,
        )
        .await;
    drop(link_token);
    drop(grant_token);

    let (status, resp_body, _) = res.map_err(|err| match err {
        TunnelHttpError::Timeout(m)
        | TunnelHttpError::Unreachable(m)
        | TunnelHttpError::InvalidTarget(m) => {
            format!(
                "Failed contacting '{}' for transcode mount sync: {m}",
                link.name
            )
        }
    })?;

    if !status.is_success() {
        let parsed =
            PeerError::from_remote_http(status, &resp_body, &link.name, "transcode_mount_sync");
        return Err(format!(
            "Worker '{}' failed transcode mount setup: {}",
            link.name,
            parsed.detail().message
        ));
    }

    Ok(())
}

async fn setup_worker_path_parity_mounts(
    runtime: &PeerRuntime,
    link: &PeerLink,
    paths_snapshot: &JellyfinTranscodePaths,
) -> Result<(), String> {
    let (uid, gid) = match (paths_snapshot.jellyfin_uid, paths_snapshot.jellyfin_gid) {
        (Some(u), Some(g)) if u > 0 && g > 0 => (u, g),
        _ => {
            return Err(
                "Local Jellyfin UID/GID could not be resolved; verify Jellyfin is installed before enabling transcode workers"
                    .to_string(),
            );
        }
    };

    let export_paths = dedup_preserve_order(vec![
        paths_snapshot.transcoding_temp_path.clone(),
        paths_snapshot.tmp_dir.clone(),
        paths_snapshot.cache_dir.clone(),
    ]);
    if export_paths.is_empty() {
        return Err("No valid Jellyfin transcode paths found to export".to_string());
    }

    let server = runtime.local_server_name();
    let lid = link.id.clone();
    let (local_identity, media_binds) = runtime
        .db
        .read(&server, "transcode_parity_setup", move |conn| {
            let identity = db_peers::get_peer_identity(conn).ok().flatten();
            let binds: Vec<TranscodeMediaBindSpec> =
                db_peers::list_peer_mounts_for_link(conn, &lid)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|m| m.purpose == MOUNT_PURPOSE_MEDIA && m.remote_path != m.mount_path)
                    .map(|m| TranscodeMediaBindSpec {
                        from: m.remote_path,
                        to: m.mount_path,
                        writable: false,
                    })
                    .collect();
            Ok((identity, binds))
        })
        .await
        .map_err(|e| e.detail().message.clone())?;

    let Some(identity) = local_identity else {
        return Err("Local peer identity is not initialized".to_string());
    };

    // Ensure local NFS server packages and tunnel-IP binding before exporting transcode folders.
    runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::EnsurePackages)
        .await
        .map_err(|err| format!("Failed ensuring local NFS packages for transcode export: {err}"))?;
    runtime
        .storage_runner
        .dispatch(&PeerStorageRequest::ConfigureNfsd {
            tunnel_ip: identity.tunnel_ip,
        })
        .await
        .map_err(|err| format!("Failed configuring local nfsd on tunnel IP: {err}"))?;

    runtime
        .transcode_runner
        .dispatch(&PeerTranscodeRequest::ExportTranscodeDirs {
            link_id: link.id.clone(),
            tunnel_ip: link.tunnel_ip.clone(),
            uid,
            gid,
            paths: export_paths.clone(),
        })
        .await
        .and_then(|resp| resp.into_mutation())
        .map_err(|err| format!("Failed exporting local Jellyfin transcode directories: {err}"))?;

    // Instruct the worker over the authenticated tunnel to mount these exact transcode paths
    // and apply any authorized media bind-mounts.
    send_remote_transcode_mounts(
        runtime,
        link,
        &TunnelTranscodeMountRequest::Sync {
            transcode_paths: export_paths,
            media_binds,
        },
    )
    .await
}

/// Best-effort bounded resync of `/peer/v1/transcode/mounts` triggered after P7 peer storage
/// export/mount mutations when `link_id` is an enabled transcode worker and controller offloading
/// is active. Completely dormant (zero runner or HTTP calls) otherwise. Caller MUST NOT hold
/// `link_lock`.
pub(crate) async fn resync_worker_transcode_mounts_if_active_best_effort(
    runtime: &PeerRuntime,
    link_id: &str,
) {
    let server = runtime.local_server_name();
    let lid = link_id.to_string();
    let active_worker_link = runtime
        .db
        .read(&server, "transcode_storage_resync", move |conn| {
            let Some(worker) = db_peers::get_transcode_worker(conn, &lid).ok().flatten() else {
                return Ok(None);
            };
            if !worker.enabled {
                return Ok(None);
            }
            let link = db_peers::get_peer_link(conn, &lid)
                .ok()
                .flatten()
                .filter(|l| is_active_link_state(&l.state));
            Ok(link)
        })
        .await
        .ok()
        .flatten();

    let Some(link) = active_worker_link else {
        return;
    };

    let dispatcher_active = runtime.transcode_state.is_dispatcher_active().await;
    let (paths_snapshot, inspected) = inspect_jellyfin_paths_best_effort(runtime).await;
    let offloading_active = dispatcher_active
        || (inspected && paths_snapshot.dropin_enabled && paths_snapshot.shim_installed);
    if !offloading_active {
        return;
    }

    match tokio::time::timeout(
        AUTO_RESYNC_MOUNT_TIMEOUT,
        setup_worker_path_parity_mounts(runtime, &link, &paths_snapshot),
    )
    .await
    {
        Ok(Ok(())) => {
            tracing::info!(
                link_id = %link.id,
                peer = %link.name,
                "Auto-resynced transcode path-parity mounts after peer storage update"
            );
        }
        Ok(Err(err)) => {
            tracing::warn!(
                link_id = %link.id,
                peer = %link.name,
                error = %redact_sensitive_text(&err),
                "Best-effort transcode mount auto-resync failed after peer storage update"
            );
        }
        Err(_) => {
            tracing::warn!(
                link_id = %link.id,
                peer = %link.name,
                timeout_secs = AUTO_RESYNC_MOUNT_TIMEOUT.as_secs(),
                "Best-effort transcode mount auto-resync timed out after peer storage update"
            );
        }
    }
}

async fn put_transcode_settings_inner(
    runtime: &Arc<PeerRuntime>,
    auth_user: &AuthUser,
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    raw_body: &[u8],
) -> Result<TranscodeConfigResponse, PeerError> {
    let server = runtime.local_server_name();
    let step = "put_transcode_settings";

    if raw_body.len() > ADMIN_TRANSCODE_BODY_LIMIT_BYTES {
        return Err(PeerError::payload_too_large(
            &server,
            step,
            format!("Request body exceeds the {ADMIN_TRANSCODE_BODY_LIMIT_BYTES}-byte limit"),
            "Send a compact JSON payload for transcode settings",
        ));
    }

    let req: UpdateTranscodeConfigReq =
        parse_required_json_bytes(headers, raw_body, &server, step)?;

    // Pre-validate worker updates and parity link target before mutating anything.
    let mut validated_workers: Vec<(PeerLink, &UpdateTranscodeWorkerReq)> = Vec::new();
    if let Some(ref updates) = req.workers {
        let mut seen = HashSet::with_capacity(updates.len());
        for upd in updates {
            if !seen.insert(upd.link_id.as_str()) {
                return Err(PeerError::invalid_request(
                    &server,
                    step,
                    format!("Duplicate worker update for link '{}'", upd.link_id),
                    "Provide each link_id at most once per request",
                ));
            }
            if !(WORKER_WEIGHT_MIN..=WORKER_WEIGHT_MAX).contains(&upd.weight) {
                return Err(PeerError::invalid_request(
                    &server,
                    step,
                    format!(
                        "Worker weight {} must be between {WORKER_WEIGHT_MIN} and {WORKER_WEIGHT_MAX}",
                        upd.weight
                    ),
                    "Choose a weight between 1 and 100",
                ));
            }
            if !(WORKER_MAX_JOBS_MIN..=WORKER_MAX_JOBS_MAX).contains(&upd.max_jobs) {
                return Err(PeerError::invalid_request(
                    &server,
                    step,
                    format!(
                        "Worker max_jobs {} must be between {WORKER_MAX_JOBS_MIN} and {WORKER_MAX_JOBS_MAX}",
                        upd.max_jobs
                    ),
                    "Choose max_jobs between 1 and 64",
                ));
            }
            let link =
                validate_worker_target_link(runtime, &upd.link_id, upd.enabled, step).await?;
            validated_workers.push((link, upd));
        }
    }

    let explicit_parity_link = if let Some(ref link_id) = req.run_parity_test_link_id {
        Some(validate_worker_target_link(runtime, link_id, true, "transcode_parity_test").await?)
    } else {
        None
    };

    let client_ip = extract_client_ip_for_peer(headers, peer_ip);
    let mut need_api_restart = false;

    // 1. Toggle Jellyfin dispatcher enabled/disabled.
    if let Some(enable) = req.enabled {
        if enable {
            let ensure_report = runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::EnsureDispatcherDir)
                .await
                .and_then(|resp| resp.into_mutation())
                .map_err(|err| map_transcode_runner_error(err, &server, "ensure_dispatcher_dir"))?;

            runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::InstallShim)
                .await
                .and_then(|resp| resp.into_mutation())
                .map_err(|err| map_transcode_runner_error(err, &server, "install_shim"))?;

            runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::EnableJellyfin)
                .await
                .and_then(|resp| resp.into_mutation())
                .map_err(|err| map_transcode_runner_error(err, &server, "enable_jellyfin"))?;

            // Verify Jellyfin reported ffmpeg path (retrying briefly if Jellyfin is configured
            // and still booting after restart); if reachable and mismatched, roll back!
            let (paths_after, _) = inspect_jellyfin_paths_best_effort(runtime).await;
            let expected_shim = paths_after.shim_path.clone();
            let probe = runtime
                .transcode_state
                .jellyfin_probe
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();

            let mut probe_outcome = probe.probe_reported_ffmpeg(runtime).await;
            if matches!(
                probe_outcome,
                JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable
            ) && has_configured_local_jellyfin(runtime).await
            {
                for _ in 0..JELLYFIN_ENABLE_PROBE_RETRIES {
                    tokio::time::sleep(JELLYFIN_ENABLE_PROBE_RETRY_DELAY).await;
                    probe_outcome = probe.probe_reported_ffmpeg(runtime).await;
                    if !matches!(
                        probe_outcome,
                        JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable
                    ) {
                        break;
                    }
                }
            }

            match probe_outcome {
                JellyfinFfmpegProbeOutcome::Reported(reported)
                    if reported.trim() != expected_shim.trim() =>
                {
                    let _ = runtime
                        .transcode_runner
                        .dispatch(&PeerTranscodeRequest::DisableJellyfin)
                        .await;
                    return Err(PeerError::conflict(
                        &server,
                        "verify_jellyfin_ffmpeg",
                        format!(
                            "Jellyfin reported ffmpeg path '{}' instead of expected shim '{}'; rolled back Jellyfin transcode drop-in",
                            reported.trim(),
                            expected_shim.trim()
                        ),
                        "Verify Jellyfin's JELLYFIN_FFMPEG environment setting and systemd drop-in precedence, then retry",
                    ));
                }
                JellyfinFfmpegProbeOutcome::ReachableMissingPath => {
                    let _ = runtime
                        .transcode_runner
                        .dispatch(&PeerTranscodeRequest::DisableJellyfin)
                        .await;
                    return Err(PeerError::conflict(
                        &server,
                        "verify_jellyfin_ffmpeg",
                        "Jellyfin API responded without a reported ffmpeg path; rolled back Jellyfin transcode drop-in",
                        "Verify Jellyfin encoding configuration and retry enabling distributed transcoding",
                    ));
                }
                JellyfinFfmpegProbeOutcome::Reported(_)
                | JellyfinFfmpegProbeOutcome::NotConfiguredOrUnreachable => {}
            }

            match ensure_dispatcher_started_checked(runtime).await {
                Ok(_) => {
                    if ensure_report.api_restart_required
                        || (!runtime.transcode_state.has_dispatcher_socket_override()
                            && paths_after
                                .jellyfin_gid
                                .is_some_and(|gid| !process_has_gid(gid)))
                    {
                        need_api_restart = true;
                    }
                }
                Err(DispatcherStartError::RestartRequired(msg)) => {
                    // `aetherflow-api.service` is still running under the pre-drop-in
                    // `ProtectSystem=strict` mount namespace or without `SupplementaryGroups=jellyfin`.
                    // Keep the Jellyfin drop-in enabled and schedule a post-response API restart so
                    // `start_dispatcher_if_configured` binds the socket immediately on boot.
                    tracing::info!(
                        reason = %msg,
                        "Scheduling deferred aetherflow-api restart to activate 20-aetherflow-transcode.conf"
                    );
                    need_api_restart = true;
                }
                Err(DispatcherStartError::Fatal(err)) => {
                    let _ = runtime
                        .transcode_runner
                        .dispatch(&PeerTranscodeRequest::DisableJellyfin)
                        .await;
                    return Err(err);
                }
            }

            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_transcode_enabled".to_string(),
                    "peer_transcode".to_string(),
                    server.clone(),
                    if need_api_restart {
                        "Enabled distributed Jellyfin transcoding shim and scheduled API restart to activate dispatcher drop-in"
                            .to_string()
                    } else {
                        "Enabled distributed Jellyfin transcoding dispatcher and shim".to_string()
                    },
                    client_ip.clone(),
                    String::new(),
                )
                .await;
        } else {
            stop_dispatcher(runtime).await;
            runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::DisableJellyfin)
                .await
                .and_then(|resp| resp.into_mutation())
                .map_err(|err| map_transcode_runner_error(err, &server, "disable_jellyfin"))?;

            // Tear down controller transcode exports for all configured workers and send
            // best-effort remote mount teardown to enabled workers without failing local disable
            // if a remote worker is currently offline.
            let server_c = server.clone();
            let (all_workers, links_by_id) = runtime
                .db
                .read(&server, "disable_transcode_teardown", move |conn| {
                    let workers = db_peers::list_transcode_workers(conn).map_err(|err| {
                        PeerError::internal(
                            &server_c,
                            "disable_transcode_teardown",
                            err.to_string(),
                        )
                    })?;
                    let links: HashMap<String, PeerLink> = db_peers::list_peer_links(conn)
                        .map_err(|err| {
                            PeerError::internal(
                                &server_c,
                                "disable_transcode_teardown",
                                err.to_string(),
                            )
                        })?
                        .into_iter()
                        .map(|l| (l.id.clone(), l))
                        .collect();
                    Ok((workers, links))
                })
                .await?;

            for worker in all_workers {
                runtime
                    .transcode_state
                    .clear_worker_unhealthy(&worker.link_id);
                let mut teardown_note: Option<String> = None;
                if worker.enabled {
                    if let Some(link) = links_by_id.get(&worker.link_id) {
                        let remote_res = tokio::time::timeout(
                            AUTO_RESYNC_MOUNT_TIMEOUT,
                            send_remote_transcode_mounts(
                                runtime,
                                link,
                                &TunnelTranscodeMountRequest::Teardown,
                            ),
                        )
                        .await;
                        let err_opt = match remote_res {
                            Ok(Ok(())) => None,
                            Ok(Err(err)) => Some(err),
                            Err(_) => Some(format!(
                                "Timed out after {}s waiting for remote mount teardown",
                                AUTO_RESYNC_MOUNT_TIMEOUT.as_secs()
                            )),
                        };
                        if let Some(err) = err_opt {
                            let redacted = redact_sensitive_text(&err);
                            tracing::warn!(
                                link_id = %link.id,
                                peer = %link.name,
                                error = %redacted,
                                "Best-effort remote transcode mount teardown failed while disabling controller offloading"
                            );
                            teardown_note = Some(format!(
                                "Remote mount teardown skipped (worker unreachable during disable): {redacted}"
                            ));
                        }
                    }
                }
                if let Err(err) = runtime
                    .transcode_runner
                    .dispatch(&PeerTranscodeRequest::RemoveTranscodeExports {
                        link_id: worker.link_id.clone(),
                    })
                    .await
                {
                    if !err.is_not_found() {
                        tracing::warn!(
                            link_id = %worker.link_id,
                            %err,
                            "Best-effort transcode export removal failed while disabling controller offloading"
                        );
                    }
                }
                let lid_upd = worker.link_id.clone();
                let note_c = teardown_note;
                let _ = runtime
                    .db
                    .write(&server, "disable_transcode_teardown", move |conn| {
                        conn.execute(
                            "UPDATE transcode_workers SET enabled = 0, parity_ok = 0, parity_error = ?2 WHERE link_id = ?1",
                            rusqlite::params![lid_upd, note_c],
                        )
                        .map_err(|err| {
                            PeerError::internal("local", "disable_transcode_teardown", err.to_string())
                        })?;
                        Ok(())
                    })
                    .await;
            }

            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_transcode_disabled".to_string(),
                    "peer_transcode".to_string(),
                    server.clone(),
                    "Disabled distributed Jellyfin transcoding dispatcher, removed Jellyfin drop-in, and tore down worker transcode exports/mounts"
                        .to_string(),
                    client_ip.clone(),
                    String::new(),
                )
                .await;
        }
    }

    // 2. Toggle local transcode worker systemd service.
    if let Some(worker_enable) = req.worker_service_enabled {
        // When disabling the local worker service, tear down ALL local worker transcode/bind
        // mounts (binds first, then transcode NFS mounts, deleting `peer_mounts` rows) BEFORE
        // removing `af-transcode-worker.service`.
        if !worker_enable {
            let server_c = server.clone();
            let mount_link_ids: Vec<String> = runtime
                .db
                .read(&server, "remove_worker_unit", move |conn| {
                    let mut ids: Vec<String> = db_peers::list_peer_mounts(conn)
                        .map_err(|err| {
                            PeerError::internal(&server_c, "remove_worker_unit", err.to_string())
                        })?
                        .into_iter()
                        .filter(|m| {
                            m.purpose == MOUNT_PURPOSE_TRANSCODE
                                || m.purpose == MOUNT_PURPOSE_TRANSCODE_BIND
                        })
                        .map(|m| m.link_id)
                        .collect();
                    ids.sort();
                    ids.dedup();
                    Ok(ids)
                })
                .await?;

            for lid in mount_link_ids {
                cleanup_worker_transcode_mounts_for_link(runtime, &lid, "remove_worker_unit")
                    .await?;
            }
        }

        let runner_req = if worker_enable {
            PeerTranscodeRequest::InstallWorkerUnit
        } else {
            PeerTranscodeRequest::RemoveWorkerUnit
        };
        let action_step = if worker_enable {
            "install_worker_unit"
        } else {
            "remove_worker_unit"
        };
        let worker_report = runtime
            .transcode_runner
            .dispatch(&runner_req)
            .await
            .and_then(|resp| resp.into_mutation())
            .map_err(|err| map_transcode_runner_error(err, &server, action_step))?;

        if worker_enable {
            if worker_report.api_restart_required {
                need_api_restart = true;
            } else if !runtime.transcode_state.has_worker_socket_override()
                && !runtime.transcode_state.has_dispatcher_socket_override()
            {
                let (paths_w, inspected_w) = inspect_jellyfin_paths_best_effort(runtime).await;
                if inspected_w
                    && paths_w
                        .jellyfin_gid
                        .is_some_and(|gid| !process_has_gid(gid))
                {
                    need_api_restart = true;
                }
            }
        }

        runtime
            .db
            .record_audit(
                auth_user.user_id,
                auth_user.username.clone(),
                if worker_enable {
                    "peer_transcode_worker_service_enabled"
                } else {
                    "peer_transcode_worker_service_disabled"
                }
                .to_string(),
                "peer_transcode".to_string(),
                server.clone(),
                if worker_enable {
                    "Installed and started af-transcode-worker.service".to_string()
                } else {
                    "Stopped and removed af-transcode-worker.service".to_string()
                },
                client_ip.clone(),
                String::new(),
            )
            .await;
    }

    // 3. Apply per-worker updates (upsert weights/max_jobs/enabled, coordinate transcode exports
    //    and worker-side mounts/binds, and auto-run parity test on newly enabled workers).
    let (paths_snapshot, _) = inspect_jellyfin_paths_best_effort(runtime).await;
    let mut parity_result: Option<ParityTestResultView> = None;
    let mut setup_failed_links: HashSet<String> = HashSet::new();

    for (link, upd) in validated_workers {
        let lid = link.id.clone();
        let enabled = upd.enabled;
        let weight = upd.weight;
        let max_jobs = upd.max_jobs;
        let server_c = server.clone();

        let prev_parity_ok = runtime
            .db
            .write(&server, "update_transcode_worker", move |conn| {
                let existing = db_peers::get_transcode_worker(conn, &lid).map_err(|err| {
                    PeerError::internal(&server_c, "update_transcode_worker", err.to_string())
                })?;
                let worker = TranscodeWorker {
                    link_id: lid.clone(),
                    enabled,
                    weight,
                    max_jobs,
                    ffmpeg_version: existing.as_ref().and_then(|w| w.ffmpeg_version.clone()),
                    encoders: existing.as_ref().and_then(|w| w.encoders.clone()),
                    render_node: existing.as_ref().and_then(|w| w.render_node.clone()),
                    parity_ok: existing.as_ref().is_some_and(|w| w.parity_ok),
                    parity_error: existing.as_ref().and_then(|w| w.parity_error.clone()),
                };
                db_peers::upsert_transcode_worker(conn, &worker).map_err(|err| {
                    PeerError::internal(&server_c, "update_transcode_worker", err.to_string())
                })?;
                Ok(worker.parity_ok)
            })
            .await?;

        if enabled {
            let setup_started = Instant::now();
            if let Err(setup_err) =
                setup_worker_path_parity_mounts(runtime, &link, &paths_snapshot).await
            {
                let redacted = redact_sensitive_text(&setup_err);
                tracing::warn!(
                    link_id = %link.id,
                    error = %redacted,
                    "Transcode path-parity export/mount setup failed while enabling worker"
                );
                persist_worker_parity_outcome(runtime, &link.id, false, Some(&redacted)).await;
                setup_failed_links.insert(link.id.clone());
                parity_result = Some(ParityTestResultView {
                    link_id: link.id.clone(),
                    ok: false,
                    elapsed_ms: setup_started.elapsed().as_millis() as u64,
                    error: Some(redacted),
                });
            } else {
                let explicit_same_link = explicit_parity_link
                    .as_ref()
                    .is_some_and(|l| l.id == link.id);
                if !prev_parity_ok && !explicit_same_link {
                    let res = run_worker_parity_test(
                        runtime,
                        &link,
                        &paths_snapshot.transcoding_temp_path,
                        &paths_snapshot.tmp_dir,
                    )
                    .await;
                    parity_result = Some(res);
                }
            }
        } else {
            runtime.transcode_state.clear_worker_unhealthy(&link.id);
            if let Err(err) =
                send_remote_transcode_mounts(runtime, &link, &TunnelTranscodeMountRequest::Teardown)
                    .await
            {
                tracing::debug!(
                    link_id = %link.id,
                    error = %err,
                    "Best-effort remote transcode mount teardown failed while disabling worker"
                );
            }
            if let Err(err) = runtime
                .transcode_runner
                .dispatch(&PeerTranscodeRequest::RemoveTranscodeExports {
                    link_id: link.id.clone(),
                })
                .await
            {
                if !err.is_not_found() {
                    tracing::warn!(
                        link_id = %link.id,
                        %err,
                        "Best-effort transcode export removal failed while disabling worker"
                    );
                }
            }
        }

        runtime
            .db
            .record_audit(
                auth_user.user_id,
                auth_user.username.clone(),
                "peer_transcode_worker_updated".to_string(),
                "peer_link".to_string(),
                link.id.clone(),
                format!(
                    "Updated transcode worker '{}' (enabled={enabled}, weight={weight}, max_jobs={max_jobs})",
                    link.name
                ),
                client_ip.clone(),
                String::new(),
            )
            .await;
    }

    // 4. Execute explicit 1-second clip / 5-second timeout parity test if requested (unless
    //    path-parity mount setup already failed for that exact link in step 3 above).
    if let Some(link) = explicit_parity_link {
        if !setup_failed_links.contains(&link.id) {
            let res = run_worker_parity_test(
                runtime,
                &link,
                &paths_snapshot.transcoding_temp_path,
                &paths_snapshot.tmp_dir,
            )
            .await;
            runtime
                .db
                .record_audit(
                    auth_user.user_id,
                    auth_user.username.clone(),
                    "peer_transcode_parity_tested".to_string(),
                    "peer_link".to_string(),
                    link.id.clone(),
                    format!(
                        "Ran transcode parity test for '{}' (ok={}, elapsed_ms={})",
                        link.name, res.ok, res.elapsed_ms
                    ),
                    client_ip.clone(),
                    String::new(),
                )
                .await;
            parity_result = Some(res);
        }
    }

    let mut resp = build_transcode_config_response(runtime, parity_result).await?;

    if need_api_restart {
        runtime
            .transcode_runner
            .dispatch(&PeerTranscodeRequest::ScheduleApiRestart)
            .await
            .and_then(|r| r.into_mutation())
            .map_err(|err| map_transcode_runner_error(err, &server, "schedule_api_restart"))?;
        resp.api_restart_scheduled = true;
        if req.enabled == Some(true) && resp.jellyfin_dropin_enabled {
            resp.enabled = true;
        }
    }

    Ok(resp)
}
