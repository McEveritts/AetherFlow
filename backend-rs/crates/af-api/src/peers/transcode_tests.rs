use super::health::run_health_tick;
use super::listener::{build_listener_router, spawn_tunnel_listener};
use super::pairing::sha256_prefixed;
use super::storage::MountHealthTracker;
use super::storage_tests::FakePeerStorageRunner;
use super::tests::{
    call_admin, fixture_wg_pubkey, open_isolated_peer_db, pair_two_test_runtimes, FakePeerRunner,
    RouterPublicTransport, UnreachablePublicTransport,
};
use super::transcode::{
    balanced_local_baseline_weight, bind_dispatcher_socket,
    cleanup_revoked_link_transcode_best_effort, cleanup_revoked_link_transcode_locked,
    cleanup_worker_transcode_mounts_for_link, compare_debian_versions, effective_worker_max_jobs,
    ensure_dispatcher_started, evaluate_version_alignment, handle_remote_health_transcode_caps,
    parse_proc_stat_state_and_starttime, prune_old_transcode_jobs,
    reconcile_dispatcher_if_configured, score_worker_candidate, select_weighted_index,
    stop_dispatcher, JellyfinFfmpegProbe, JellyfinFfmpegProbeOutcome, PeerTranscodeRunner,
    TranscodeRuntimeState, WorkerLoadSnapshot, WsClientMessage, WsClientReader,
    TRANSCODE_MOUNT_SYNC_TIMEOUT,
};
use super::{
    start_with_runtime, KeyedAsyncLockPool, PeerDb, PeerRunner, PeerRuntime, RevocationEvent,
    TunnelTransportBinding, HEADER_GRANT_TOKEN, HEADER_LINK_TOKEN, PEER_LOCK_WAIT_TIMEOUT,
};
use af_db::peers::{
    self as db_peers, AccessMap, PeerExport, PeerGrant, PeerMount, PeerReceivedGrant, TranscodeJob,
};
use af_runner::{
    JellyfinTranscodePaths, ParityFileCleanupReport, PeerCredentialSlot, PeerTranscodeError,
    PeerTranscodeRequest, PeerTranscodeResponse, TranscodeMutationReport,
    DEFAULT_JELLYFIN_CACHE_DIR, DEFAULT_JELLYFIN_TMP_DIR, DEFAULT_JELLYFIN_TRANSCODE_DIR,
    DEFAULT_TRANSCODE_SHIM_PATH,
};
use af_transcode::capabilities::{RenderNodeInfo, TranscodeCapabilities};
use af_transcode::config::DEFAULT_WORKER_SOCKET_MODE;
use af_transcode::protocol::{decode_frame_payload, read_frame, write_frame, Frame, StartRequest};
use af_transcode::shim::{run_shim_protocol, LocalFallbackReason, ShimConfig, ShimDecision};
use af_transcode::worker::{bind_worker_socket, serve_worker_listener, WorkerConfig};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message as AxumWsMessage, WebSocketUpgrade};
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::BoxFuture;
use futures::StreamExt as _;
use rusqlite::Connection;
use serde_json::json;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::{broadcast, watch, Mutex as TokioMutex, Notify};
use tower::ServiceExt;
use uuid::Uuid;

static TRANSCODE_LOOPBACK_OCTET: AtomicU16 = AtomicU16::new(20);

fn next_transcode_loopback_ips(count: usize) -> Vec<IpAddr> {
    let base = TRANSCODE_LOOPBACK_OCTET.fetch_add(count as u16, AtomicOrdering::SeqCst);
    (0..count)
        .map(|offset| {
            let n = base + offset as u16;
            let hi = (n / 200) as u8;
            let lo = (n % 200) as u8 + 10;
            IpAddr::V4(Ipv4Addr::new(127, 3, hi, lo))
        })
        .collect()
}

/// Self-contained controllable test clock (independent of private methods on `tests::FakeClock`).
struct TestClock {
    epoch: AtomicI64,
    monotonic_secs: AtomicU64,
}

impl TestClock {
    fn new(start: i64) -> Arc<Self> {
        Arc::new(Self {
            epoch: AtomicI64::new(start),
            monotonic_secs: AtomicU64::new(100),
        })
    }

    fn advance(&self, secs: i64) {
        self.epoch.fetch_add(secs, AtomicOrdering::SeqCst);
        if secs > 0 {
            self.monotonic_secs
                .fetch_add(secs as u64, AtomicOrdering::SeqCst);
        }
    }

    fn now(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.epoch.load(AtomicOrdering::SeqCst), 0)
            .expect("valid test timestamp")
    }

    fn as_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> DateTime<Utc> + Send + Sync> {
        let clock = Arc::clone(self);
        Arc::new(move || clock.now())
    }

    fn as_monotonic_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> Duration + Send + Sync> {
        let clock = Arc::clone(self);
        Arc::new(move || Duration::from_secs(clock.monotonic_secs.load(AtomicOrdering::SeqCst)))
    }
}

/// Short temp directory with `0700` permissions (safe for Unix domain socket parent validation
/// and Linux's 107-byte `sun_path` limit).
struct ShortTempDir {
    path: PathBuf,
}

impl ShortTempDir {
    fn new(tag: &str) -> Self {
        let short = &Uuid::new_v4().simple().to_string()[..8];
        let path = PathBuf::from(format!("/tmp/af{tag}-{short}"));
        fs::create_dir_all(&path).expect("create short temp dir");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 short temp dir");
        Self { path }
    }
}

impl Drop for ShortTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Fake privileged transcode runner used across `af-api` peer tests (zero host I/O).
#[derive(Debug, Default)]
pub(super) struct FakeTranscodeRunnerState {
    pub(super) calls: Vec<PeerTranscodeRequest>,
    pub(super) transcoding_temp_path: String,
    pub(super) tmp_dir: String,
    pub(super) cache_dir: String,
    pub(super) shim_path: String,
    pub(super) shim_installed: bool,
    pub(super) dropin_enabled: bool,
    pub(super) worker_unit_installed: bool,
    pub(super) worker_unit_active: bool,
    pub(super) jellyfin_uid: Option<u32>,
    pub(super) jellyfin_gid: Option<u32>,
    pub(super) api_restart_required_on_ensure_dir: bool,
    pub(super) api_restart_required_on_install_worker: bool,
    pub(super) cleanup_parity_override: Option<ParityFileCleanupReport>,
    pub(super) fail_next: HashMap<&'static str, PeerTranscodeError>,
}

pub(super) struct FakePeerTranscodeRunner {
    pub(super) state: StdMutex<FakeTranscodeRunnerState>,
}

impl FakePeerTranscodeRunner {
    pub(super) fn new() -> Self {
        Self {
            state: StdMutex::new(FakeTranscodeRunnerState {
                calls: Vec::new(),
                transcoding_temp_path: DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string(),
                tmp_dir: DEFAULT_JELLYFIN_TMP_DIR.to_string(),
                cache_dir: DEFAULT_JELLYFIN_CACHE_DIR.to_string(),
                shim_path: DEFAULT_TRANSCODE_SHIM_PATH.to_string(),
                shim_installed: false,
                dropin_enabled: false,
                worker_unit_installed: false,
                worker_unit_active: false,
                jellyfin_uid: Some(110),
                jellyfin_gid: Some(115),
                api_restart_required_on_ensure_dir: false,
                api_restart_required_on_install_worker: false,
                cleanup_parity_override: None,
                fail_next: HashMap::new(),
            }),
        }
    }

    fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn action_name(req: &PeerTranscodeRequest) -> &'static str {
        match req {
            PeerTranscodeRequest::InspectJellyfinPaths => "inspect_jellyfin_paths",
            PeerTranscodeRequest::EnsureDispatcherDir => "ensure_dispatcher_dir",
            PeerTranscodeRequest::InstallShim => "install_shim",
            PeerTranscodeRequest::EnableJellyfin => "enable_jellyfin",
            PeerTranscodeRequest::DisableJellyfin => "disable_jellyfin",
            PeerTranscodeRequest::InstallWorkerUnit => "install_worker_unit",
            PeerTranscodeRequest::RemoveWorkerUnit => "remove_worker_unit",
            PeerTranscodeRequest::ExportTranscodeDirs { .. } => "export_transcode_dirs",
            PeerTranscodeRequest::RemoveTranscodeExports { .. } => "remove_transcode_exports",
            PeerTranscodeRequest::MountTranscodeDirs { .. } => "mount_transcode_dirs",
            PeerTranscodeRequest::RemoveTranscodeMounts { .. } => "remove_transcode_mounts",
            PeerTranscodeRequest::BindMedia { .. } => "bind_media",
            PeerTranscodeRequest::RemoveBindMedia { .. } => "remove_bind_media",
            PeerTranscodeRequest::ScheduleApiRestart => "schedule_api_restart",
            PeerTranscodeRequest::CleanupParityFile { .. } => "cleanup_parity_file",
        }
    }

    fn call_count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }

    fn count_action(&self, action: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|req| Self::action_name(req) == action)
            .count()
    }
}

impl PeerTranscodeRunner for FakePeerTranscodeRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerTranscodeRequest,
    ) -> BoxFuture<'a, Result<PeerTranscodeResponse, PeerTranscodeError>> {
        let action = Self::action_name(req);
        let res = (|| {
            let mut st = self.state.lock().unwrap();
            st.calls.push(req.clone());
            if let Some(err) = st.fail_next.remove(action) {
                return Err(err);
            }
            match req {
                PeerTranscodeRequest::InspectJellyfinPaths => Ok(
                    PeerTranscodeResponse::JellyfinPaths(JellyfinTranscodePaths {
                        transcoding_temp_path: st.transcoding_temp_path.clone(),
                        tmp_dir: st.tmp_dir.clone(),
                        cache_dir: st.cache_dir.clone(),
                        shim_path: st.shim_path.clone(),
                        shim_installed: st.shim_installed,
                        dropin_enabled: st.dropin_enabled,
                        worker_unit_installed: st.worker_unit_installed,
                        worker_unit_active: st.worker_unit_active,
                        jellyfin_uid: st.jellyfin_uid,
                        jellyfin_gid: st.jellyfin_gid,
                    }),
                ),
                PeerTranscodeRequest::EnsureDispatcherDir => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "dispatcher runtime dir ensured".to_string(),
                        units: Vec::new(),
                        paths: vec!["/run/aetherflow-transcode".to_string()],
                        api_restart_required: st.api_restart_required_on_ensure_dir,
                    }))
                }
                PeerTranscodeRequest::InstallShim => {
                    st.shim_installed = true;
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "shim installed".to_string(),
                        units: Vec::new(),
                        paths: vec![st.shim_path.clone()],
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::EnableJellyfin => {
                    st.dropin_enabled = true;
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "jellyfin drop-in enabled".to_string(),
                        units: vec!["jellyfin.service".to_string()],
                        paths: Vec::new(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::DisableJellyfin => {
                    st.dropin_enabled = false;
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "jellyfin drop-in disabled".to_string(),
                        units: vec!["jellyfin.service".to_string()],
                        paths: Vec::new(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::InstallWorkerUnit => {
                    st.worker_unit_installed = true;
                    st.worker_unit_active = true;
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "worker unit installed".to_string(),
                        units: vec!["af-transcode-worker.service".to_string()],
                        paths: Vec::new(),
                        api_restart_required: st.api_restart_required_on_install_worker,
                    }))
                }
                PeerTranscodeRequest::RemoveWorkerUnit => {
                    st.worker_unit_installed = false;
                    st.worker_unit_active = false;
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "worker unit removed".to_string(),
                        units: vec!["af-transcode-worker.service".to_string()],
                        paths: Vec::new(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::ExportTranscodeDirs { paths, .. } => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "transcode dirs exported".to_string(),
                        units: Vec::new(),
                        paths: paths.clone(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::RemoveTranscodeExports { .. } => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "transcode exports removed".to_string(),
                        units: Vec::new(),
                        paths: Vec::new(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::MountTranscodeDirs { paths, .. }
                | PeerTranscodeRequest::RemoveTranscodeMounts { paths, .. } => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "transcode mounts updated".to_string(),
                        units: Vec::new(),
                        paths: paths.clone(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::BindMedia { to, .. }
                | PeerTranscodeRequest::RemoveBindMedia { to } => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "bind media updated".to_string(),
                        units: Vec::new(),
                        paths: vec![to.clone()],
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::ScheduleApiRestart => {
                    Ok(PeerTranscodeResponse::Mutation(TranscodeMutationReport {
                        changed: true,
                        detail: "scheduled deferred API restart".to_string(),
                        units: vec!["aetherflow-api.service".to_string()],
                        paths: Vec::new(),
                        api_restart_required: false,
                    }))
                }
                PeerTranscodeRequest::CleanupParityFile { dir, file_name } => {
                    if let Some(ref ov) = st.cleanup_parity_override {
                        return Ok(PeerTranscodeResponse::ParityFileCleanup(ov.clone()));
                    }
                    let path = Path::new(dir).join(file_name);
                    match fs::symlink_metadata(&path) {
                        Ok(meta) => {
                            let size_bytes = meta.len();
                            let removed = fs::remove_file(&path).is_ok();
                            Ok(PeerTranscodeResponse::ParityFileCleanup(
                                ParityFileCleanupReport {
                                    existed: true,
                                    size_bytes,
                                    removed,
                                },
                            ))
                        }
                        Err(_) => Ok(PeerTranscodeResponse::ParityFileCleanup(
                            ParityFileCleanupReport {
                                existed: false,
                                size_bytes: 0,
                                removed: false,
                            },
                        )),
                    }
                }
            }
        })();
        Box::pin(async move { res })
    }
}

struct FakeJellyfinProbe {
    outcome: StdMutex<JellyfinFfmpegProbeOutcome>,
}

impl FakeJellyfinProbe {
    fn new(outcome: JellyfinFfmpegProbeOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome: StdMutex::new(outcome),
        })
    }

    fn set(&self, outcome: JellyfinFfmpegProbeOutcome) {
        *self.outcome.lock().unwrap() = outcome;
    }
}

impl JellyfinFfmpegProbe for FakeJellyfinProbe {
    fn probe_reported_ffmpeg<'a>(
        &'a self,
        _runtime: &'a PeerRuntime,
    ) -> BoxFuture<'a, JellyfinFfmpegProbeOutcome> {
        let out = self.outcome.lock().unwrap().clone();
        Box::pin(async move { out })
    }
}

fn sample_caps(
    pkg_ver: Option<&str>,
    ff_ver: Option<&str>,
    encoders: &[&str],
    nodes: &[(&str, &str, &str)],
) -> TranscodeCapabilities {
    let render_nodes: Vec<RenderNodeInfo> = nodes
        .iter()
        .map(|(path, vendor_id, vendor)| RenderNodeInfo {
            path: (*path).to_string(),
            vendor_id: Some((*vendor_id).to_string()),
            vendor: Some((*vendor).to_string()),
            vaapi_driver: None,
            vaapi_decode_codecs: Vec::new(),
            vaapi_encode_codecs: Vec::new(),
            supports_vpp: false,
        })
        .collect();
    let primary_render_node = render_nodes.first().map(|n| n.path.clone());
    TranscodeCapabilities {
        ffmpeg_path: "/usr/lib/jellyfin-ffmpeg/ffmpeg".to_string(),
        ffmpeg_version: ff_ver.map(ToString::to_string),
        ffmpeg_version_line: ff_ver.map(|v| format!("ffmpeg version {v}")),
        package_name: pkg_ver.map(|_| "jellyfin-ffmpeg7".to_string()),
        package_version: pkg_ver.map(ToString::to_string),
        encoders: encoders.iter().map(|s| (*s).to_string()).collect(),
        render_nodes,
        primary_render_node,
        worker_max_jobs: None,
        hw_decoders: Vec::new(),
        hw_encoders_verified: false,
        adapt_backend_mode: None,
        vulkan_compute: None,
        vulkan_device: None,
        vulkan_video: None,
        vulkan_video_decode_codecs: Vec::new(),
        vulkan_video_encode_codecs: Vec::new(),
    }
}

fn build_transcode_runtime(
    name: &str,
    runner: Arc<dyn PeerRunner>,
    transcode_runner: Arc<FakePeerTranscodeRunner>,
    public_transport: Arc<dyn super::PublicPairingTransport>,
    clock: &Arc<TestClock>,
) -> (Arc<PeerRuntime>, Arc<StdMutex<Connection>>) {
    let db_conn = open_isolated_peer_db();
    db_peers::ensure_peer_grant_schema_invariants(&db_conn.lock().unwrap())
        .expect("ensure peer grant schema invariants");
    let (revocation_tx, _) = broadcast::channel(64);
    let rt = Arc::new(PeerRuntime {
        db: PeerDb::Isolated(Arc::clone(&db_conn)),
        runner,
        storage_runner: Arc::new(FakePeerStorageRunner::new()),
        mount_health: MountHealthTracker::new(),
        transcode_runner,
        transcode_state: Arc::new(TranscodeRuntimeState::new()),
        public_transport,
        revocation_tx,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        link_ws_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        proxy_tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: PEER_LOCK_WAIT_TIMEOUT,
        listen_port: 0,
        max_conn_per_link: 64,
        max_ws_per_link: 16,
        proxy_header_timeout: Duration::from_secs(30),
        rtt_warn_ms: 25.0,
        server_name_override: Some(name.to_string()),
        version_override: Some("4.0.0-p9-test".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        interface_index_override: RwLock::new(None),
        bind_listener_in_handlers: true,
        management_router_override: None,
        allowed_fs_roots_override: None,
    });
    (rt, db_conn)
}

/// Inserts a matching active inbound grant on the worker node (`worker_db`) and corresponding
/// received grant + held credential on the controller node (`ctrl_db` / `ctrl_runner`).
#[allow(clippy::too_many_arguments)]
fn install_transcode_grant_pair(
    ctrl_db: &Arc<StdMutex<Connection>>,
    ctrl_runner: &Arc<FakePeerRunner>,
    ctrl_link_id: &str,
    worker_db: &Arc<StdMutex<Connection>>,
    worker_link_id: &str,
    worker_peer_name: &str,
    access: AccessMap,
    now_rfc3339: &str,
) -> (String, String, i64) {
    let grant_id = format!("grant-{}", Uuid::new_v4().simple());
    let raw_token = format!("gtok-{}", Uuid::new_v4().simple());
    let token_hash = sha256_prefixed(&raw_token);

    // Ensure dedicated `account_type = 'peer'` admin run-as user exists on worker DB.
    let run_as_uid: i64 = {
        let conn = worker_db.lock().unwrap();
        let username = format!("peer-{worker_peer_name}");
        conn.execute(
            "INSERT OR IGNORE INTO users (username, role, account_type) VALUES (?1, 'admin', 'peer')",
            rusqlite::params![username],
        )
        .expect("insert peer run-as user");
        let uid: i64 = conn
            .query_row(
                "SELECT id FROM users WHERE username = ?1",
                rusqlite::params![username],
                |r| r.get(0),
            )
            .expect("query peer run-as user id");
        db_peers::insert_peer_grant(
            &conn,
            &PeerGrant {
                id: grant_id.clone(),
                link_id: worker_link_id.to_string(),
                run_as_user_id: uid,
                access: access.clone(),
                token_hash: Some(token_hash),
                created_by: "alice".to_string(),
                created_at: now_rfc3339.to_string(),
                revoked_at: None,
            },
        )
        .expect("insert inbound peer grant");
        uid
    };

    {
        let conn = ctrl_db.lock().unwrap();
        db_peers::upsert_peer_received_grant(
            &conn,
            &PeerReceivedGrant {
                link_id: ctrl_link_id.to_string(),
                grant_id: grant_id.clone(),
                run_as_user_id: run_as_uid,
                access,
                created_by: "alice".to_string(),
                created_at: now_rfc3339.to_string(),
                generation: 1,
                revoked_at: None,
                credential_id: None,
                updated_at: now_rfc3339.to_string(),
            },
        )
        .expect("upsert received grant");
    }

    ctrl_runner.state.lock().unwrap().credentials.insert(
        (PeerCredentialSlot::GrantToken, ctrl_link_id.to_string()),
        raw_token.clone(),
    );

    (grant_id, raw_token, run_as_uid)
}

/// Writes an executable fake `ffmpeg` shell script supporting:
/// - normal encode mode (echoes stdin to stdout, logs args to stderr, optional `--exit N`,
///   and writes non-empty bytes to the final argument if it ends with `.ts`)
/// - sleep mode (`--sleep-pid-file <path>`: writes PID + spawns child sleep and sleeps 60s)
fn write_fake_ffmpeg_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).expect("write fake ffmpeg script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod 0755 fake ffmpeg");
    path
}

fn standard_fake_ffmpeg_body() -> &'static str {
    r#"#!/bin/sh
set -eu
EXIT_CODE=0
SLEEP_PID_FILE=""
LAST_ARG=""
PREV=""
for arg in "$@"; do
  if [ "$PREV" = "--exit-code" ]; then
    EXIT_CODE="$arg"
    PREV=""
    continue
  fi
  if [ "$PREV" = "--sleep-pid-file" ]; then
    SLEEP_PID_FILE="$arg"
    PREV=""
    continue
  fi
  case "$arg" in
    --exit-code|--sleep-pid-file)
      PREV="$arg"
      ;;
    *)
      LAST_ARG="$arg"
      ;;
  esac
done

if [ -n "$SLEEP_PID_FILE" ]; then
  echo "$$" > "$SLEEP_PID_FILE"
  sleep 60 &
  wait
  exit 0
fi

case "$LAST_ARG" in
  *.ts)
    printf 'FAKE_MPEGTS_PACKET_DATA_1234567890' > "$LAST_ARG"
    ;;
esac

printf 'stderr:args=%s\n' "$*" >&2
if [ ! -t 0 ]; then
  cat || true
fi
exit "$EXIT_CODE"
"#
}

/// Spawns a real `af_transcode::worker` listening on `worker_sock` backed by `fake_ffmpeg`,
/// returning a shutdown trigger and task handle.
fn spawn_real_worker(
    worker_sock: PathBuf,
    fake_ffmpeg: PathBuf,
    max_jobs: usize,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let mut cfg = WorkerConfig::for_paths(worker_sock, fake_ffmpeg.clone());
    cfg.max_concurrent_jobs = max_jobs;
    cfg.socket_mode = DEFAULT_WORKER_SOCKET_MODE;
    let bound = bind_worker_socket(&cfg).expect("bind real worker socket");
    let canonical_ffmpeg = fs::canonicalize(&fake_ffmpeg).expect("canonicalize fake ffmpeg");
    let (tx, mut rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _ = serve_worker_listener(bound, cfg, canonical_ffmpeg, async move {
            let _ = rx.changed().await;
        })
        .await;
    });
    (tx, task)
}

fn pid_is_alive(pid: i32) -> bool {
    // SAFETY: `kill(pid, 0)` only checks existence of `pid` without delivering a signal.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn audit_actions_list(db: &Arc<StdMutex<Connection>>) -> Vec<String> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT action FROM admin_audit_log ORDER BY id ASC")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn notification_rows(db: &Arc<StdMutex<Connection>>) -> Vec<(String, String)> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT title, message FROM notifications ORDER BY id ASC")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

async fn wait_for_job_count(db: &Arc<StdMutex<Connection>>, expected: usize) -> Vec<TranscodeJob> {
    let mut jobs = Vec::new();
    for _ in 0..50 {
        jobs = db_peers::list_transcode_jobs(&db.lock().unwrap(), 20).unwrap();
        if jobs.len() >= expected {
            return jobs;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    jobs
}

/// Helper to create a pipe with `input` written and write-end closed, returning an `OwnedFd`
/// suitable for passing to `af_transcode::shim::run_shim_protocol`.
fn make_stdin_pipe(input: &[u8]) -> std::os::fd::OwnedFd {
    use std::io::Write as _;
    use std::os::fd::FromRawFd;

    let mut fds = [0i32; 2];
    // SAFETY: `pipe` initializes the 2-element `fds` array on success.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() failed");
    // SAFETY: newly created pipe descriptors owned exclusively here.
    let read_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let mut write_file = unsafe { fs::File::from_raw_fd(fds[1]) };
    if !input.is_empty() {
        write_file.write_all(input).expect("write stdin pipe");
    }
    drop(write_file);
    read_fd
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Debian Policy §5.6.12 Version Comparison & Mismatch Alignment
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn debian_version_comparison_and_alignment_reports() {
    // Debian Policy §5.6.12 edge cases
    assert_eq!(
        compare_debian_versions("7.1.1-1-trixie", "7.1.1-2-trixie"),
        Ordering::Less
    );
    assert_eq!(
        compare_debian_versions("7.1.2-1-trixie", "7.1.10-1-trixie"),
        Ordering::Less
    );
    assert_eq!(
        compare_debian_versions("1:7.0-1", "9.9.9-9"),
        Ordering::Greater
    );
    assert_eq!(
        compare_debian_versions("7.1.1~rc1-1", "7.1.1-1"),
        Ordering::Less
    );
    assert_eq!(
        compare_debian_versions("8.1.3-1-trixie", "8.1.3-1-trixie"),
        Ordering::Equal
    );

    // Local older -> align_target = "local"
    let rep_local = evaluate_version_alignment(
        "seedbox-1",
        Some("8.1.3-1-trixie"),
        Some("8.1.3-Jellyfin"),
        "gpu-worker",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
    );
    assert!(rep_local.mismatch);
    assert_eq!(rep_local.align_target, Some("local"));
    assert_eq!(
        rep_local.message.as_deref(),
        Some("jellyfin-ffmpeg differs: seedbox-1 8.1.3-1-trixie vs gpu-worker 8.1.3-2-trixie")
    );

    // Peer older -> align_target = "peer"
    let rep_peer = evaluate_version_alignment(
        "seedbox-1",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        "gpu-worker",
        Some("8.1.3-1-trixie"),
        Some("8.1.3-Jellyfin"),
    );
    assert!(rep_peer.mismatch);
    assert_eq!(rep_peer.align_target, Some("peer"));
    assert_eq!(
        rep_peer.message.as_deref(),
        Some("jellyfin-ffmpeg differs: seedbox-1 8.1.3-2-trixie vs gpu-worker 8.1.3-1-trixie")
    );

    // Matching package & ffmpeg versions -> no mismatch
    let rep_match = evaluate_version_alignment(
        "seedbox-1",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        "gpu-worker",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
    );
    assert!(!rep_match.mismatch);
    assert!(rep_match.both_known);
    assert_eq!(rep_match.align_target, None);
    assert_eq!(rep_match.message, None);

    // Matching package version but differing raw ffmpeg_version still flags mismatch
    let rep_ff_diff = evaluate_version_alignment(
        "seedbox-1",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        "gpu-worker",
        Some("8.1.3-2-trixie"),
        Some("8.1.4-Jellyfin"),
    );
    assert!(rep_ff_diff.mismatch);
    assert_eq!(rep_ff_diff.align_target, Some("local"));

    // Unknown side -> both_known = false, mismatch = false
    let rep_unknown = evaluate_version_alignment(
        "seedbox-1",
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        "gpu-worker",
        None,
        None,
    );
    assert!(!rep_unknown.mismatch);
    assert!(!rep_unknown.both_known);
    assert_eq!(rep_unknown.align_target, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Weighted Selection, Eligibility Filtering, Cooldown Recovery & RunLocal Fallback
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn weighted_selection_and_eligibility_filtering_with_cooldown_recovery() {
    // Pure deterministic weighted-index distribution checks
    assert_eq!(select_weighted_index(&[], 0), None);
    let weights = [1u64, 4u64];
    let mut hits = [0usize; 2];
    for roll in 0..5 {
        let idx = select_weighted_index(&weights, roll).unwrap();
        hits[idx] += 1;
    }
    assert_eq!(
        hits,
        [1, 4],
        "weights [1, 4] must partition 0..5 exactly 1:4"
    );

    let ips = next_transcode_loopback_ips(3);
    let (ip_ctrl, ip_w1, ip_w2) = (ips[0], ips[1], ips[2]);
    let clock = TestClock::new(1_800_900_000);
    let tmp = ShortTempDir::new("sel");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    // Build controller + two worker nodes
    let runner_ctrl = FakePeerRunner::new(fixture_wg_pubkey(201), ip_ctrl, 51821);
    let runner_w1 = FakePeerRunner::new(fixture_wg_pubkey(202), ip_w1, 51821);
    let runner_w2 = FakePeerRunner::new(fixture_wg_pubkey(203), ip_w2, 51821);
    let tc_runner_ctrl = FakePeerTranscodeRunner::new_arc();
    let tc_runner_w1 = FakePeerTranscodeRunner::new_arc();
    let tc_runner_w2 = FakePeerTranscodeRunner::new_arc();

    let (rt_w1, db_w1) = build_transcode_runtime(
        "worker-intel",
        Arc::clone(&runner_w1) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_w1),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_w2, db_w2) = build_transcode_runtime(
        "worker-amd",
        Arc::clone(&runner_w2) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_w2),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );

    // Pair ctrl with worker-intel first, then worker-amd
    let (rt_ctrl, db_ctrl) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_ctrl) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_ctrl),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_w1),
            client_ip: SocketAddr::from(([198, 51, 100, 10], 45001)),
        }),
        &clock,
    );
    let (ctrl_w1_id, w1_ctrl_id, _) =
        pair_two_test_runtimes(&rt_ctrl, &rt_w1, ip_ctrl, ip_w1, "worker-intel").await;

    // Pair ctrl with worker-amd by creating a temporary pairing helper sharing the same DB/runner
    // (or directly inserting an active paired link + held link token on both sides).
    let ctrl_w2_id = format!("link-{}", Uuid::new_v4().simple());
    let w2_ctrl_id = format!("link-{}", Uuid::new_v4().simple());
    let link_tok_w2 = format!("ltok-{}", Uuid::new_v4().simple());
    let now_str = clock.now().to_rfc3339();
    let w2_handle = spawn_tunnel_listener(Arc::clone(&rt_w2), ip_w2, 0, None)
        .await
        .expect("spawn w2 tunnel listener");
    let w2_port = w2_handle.bound_addr.port();
    *rt_w2.listener_state.lock().await = Some(w2_handle);
    rt_ctrl
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_w2, w2_port);
    {
        let conn = db_w2.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &af_db::peers::PeerIdentity {
                wg_pubkey: fixture_wg_pubkey(203),
                tunnel_ip: ip_w2.to_string(),
                wg_port: 51821,
                created_at: now_str.clone(),
            },
        )
        .unwrap();
        db_peers::insert_peer_link(
            &conn,
            &af_db::peers::PeerLink {
                id: w2_ctrl_id.clone(),
                name: "jellyfin-main".to_string(),
                wg_pubkey: fixture_wg_pubkey(201),
                tunnel_ip: ip_ctrl.to_string(),
                endpoint: "10.90.0.1".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0-p9-test".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_str.clone()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: Some(sha256_prefixed(&link_tok_w2)),
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: now_str.clone(),
                updated_at: now_str.clone(),
            },
        )
        .unwrap();
    }
    {
        let conn = db_ctrl.lock().unwrap();
        db_peers::insert_peer_link(
            &conn,
            &af_db::peers::PeerLink {
                id: ctrl_w2_id.clone(),
                name: "worker-amd".to_string(),
                wg_pubkey: fixture_wg_pubkey(203),
                tunnel_ip: ip_w2.to_string(),
                endpoint: "10.90.0.3".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0-p9-test".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_str.clone()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: now_str.clone(),
                updated_at: now_str.clone(),
            },
        )
        .unwrap();
    }
    runner_ctrl.state.lock().unwrap().credentials.insert(
        (PeerCredentialSlot::LinkToken, ctrl_w2_id.clone()),
        link_tok_w2,
    );

    // Grant transcoding:write on both workers
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_ctrl,
        &runner_ctrl,
        &ctrl_w1_id,
        &db_w1,
        &w1_ctrl_id,
        "jellyfin-main",
        write_access.clone(),
        &now_str,
    );
    install_transcode_grant_pair(
        &db_ctrl,
        &runner_ctrl,
        &ctrl_w2_id,
        &db_w2,
        &w2_ctrl_id,
        "jellyfin-main",
        write_access,
        &now_str,
    );

    // Start real workers on distinct short Unix sockets
    let w1_sock = tmp.path.join("w1.sock");
    let w2_sock = tmp.path.join("w2.sock");
    // Pin each worker's DRM render node to the hardware its advertised capabilities claim, so
    // QSV/VA-API render-node selection does not depend on the host running the test (CI runners
    // expose no `/dev/dri`, and developer hosts may expose a different GPU vendor).
    let (w1_stop, w1_task) = spawn_real_worker_with_config(
        w1_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x8086".to_string()),
        }]),
    );
    let (w2_stop, w2_task) = spawn_real_worker_with_config(
        w2_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
    );
    rt_w1.transcode_state.set_worker_socket_override(w1_sock);
    rt_w2.transcode_state.set_worker_socket_override(w2_sock);

    // Configure matching local & remote capabilities:
    // - worker-intel has Intel QSV + VA-API (`h264_qsv`, `h264_vaapi`, `libx264`)
    // - worker-amd has AMD VA-API only (`h264_vaapi`, `libx264`) — NO `h264_qsv` and NO `h264_nvenc`
    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_qsv"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let w1_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_qsv"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let w2_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    rt_ctrl
        .transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_w1_id, w1_caps.clone());
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_w2_id, w2_caps);

    // Mark both workers enabled & parity_ok=true in DB (weight 1 vs weight 4)
    {
        let conn = db_ctrl.lock().unwrap();
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: ctrl_w1_id.clone(),
                enabled: true,
                weight: 1,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264","h264_vaapi","h264_qsv"]"#.to_string()),
                render_node: Some("/dev/dri/renderD128".to_string()),
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: ctrl_w2_id.clone(),
                enabled: true,
                weight: 4,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264","h264_vaapi"]"#.to_string()),
                render_node: Some("/dev/dri/renderD128".to_string()),
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
    }

    let disp_sock = tmp.path.join("disp.sock");
    rt_ctrl
        .transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_ctrl)
        .await
        .expect("start dispatcher");

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg.clone(),
        dispatcher_socket: disp_sock.clone(),
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // Case A: QSV job MUST route exclusively to worker-intel (worker-amd lacks h264_qsv & Intel GPU)
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let jobs = db_peers::list_transcode_jobs(&db_ctrl.lock().unwrap(), 10).unwrap();
        assert_eq!(jobs[0].link_id.as_deref(), Some(ctrl_w1_id.as_str()));
        assert!(!jobs[0].ran_locally);
    }

    // Case B: NVENC job -> NEITHER worker has h264_nvenc -> dispatcher replies RunLocal!
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_nvenc".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            }
        );
        let mut jobs = Vec::new();
        for _ in 0..40 {
            jobs = db_peers::list_transcode_jobs(&db_ctrl.lock().unwrap(), 10).unwrap();
            if jobs.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(jobs.len() >= 2, "expected 2 recorded jobs, got {jobs:?}");
        assert!(
            jobs[0].ran_locally,
            "expected newest job to be ran_locally: {jobs:?}"
        );
        assert_eq!(jobs[0].link_id, None);
    }

    // Case C: Unhealthy 60s cooldown skips worker-intel; advancing clock by 61s restores eligibility
    rt_ctrl
        .transcode_state
        .mark_worker_unhealthy(&ctrl_w1_id, clock.now());
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "worker-intel must be skipped while inside 60s unhealthy cooldown"
        );
    }

    clock.advance(61);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::RemoteExited(0),
            "worker-intel must recover automatically after 60s cooldown expires"
        );
    }

    // Case D: Package-version mismatch (even when ffmpeg_version matches!) excludes worker-intel
    let mut mismatched_w1 = w1_caps.clone();
    mismatched_w1.package_version = Some("8.1.3-1-trixie".to_string());
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_w1_id, mismatched_w1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "version-mismatched worker must be excluded"
        );
    }
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_w1_id, w1_caps);

    // Case E: At max_jobs excludes worker-intel
    let _g1 = rt_ctrl
        .transcode_state
        .try_acquire_job_slot(&ctrl_w1_id, 2)
        .expect("slot 1");
    let _g2 = rt_ctrl
        .transcode_state
        .try_acquire_job_slot(&ctrl_w1_id, 2)
        .expect("slot 2");
    assert!(rt_ctrl
        .transcode_state
        .try_acquire_job_slot(&ctrl_w1_id, 2)
        .is_none());
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            }
        );
    }
    drop(_g1);
    drop(_g2);

    // Case F: parity_ok=false excludes worker-intel
    db_ctrl
        .lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET parity_ok = 0 WHERE link_id = ?1",
            rusqlite::params![ctrl_w1_id],
        )
        .unwrap();
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "qsv".into(),
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "h264_qsv".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            }
        );
    }

    stop_dispatcher(&rt_ctrl).await;
    let _ = w1_stop.send(true);
    let _ = w2_stop.send(true);
    let _ = w1_task.await;
    let _ = w2_task.await;
    rt_ctrl.shutdown_all().await;
    rt_w1.shutdown_all().await;
    rt_w2.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. End-to-End Local Fixture Relay: Shim -> Dispatcher -> WS Tunnel -> Worker -> Fake FFmpeg
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn end_to_end_local_fixture_relay_stdout_stderr_stdin_and_exit_code() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_910_000);
    let tmp = ShortTempDir::new("e2e");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(211), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(212), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 11], 45011)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        write_access,
        &clock.now().to_rfc3339(),
    );

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg.clone(), 4);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    let caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(caps.clone()));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, caps);
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 2,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    // Verify dispatcher socket has restricted 0660 permissions (no world access)
    let sock_mode = fs::symlink_metadata(&disp_sock)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o660);

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // Successful remote encode with stdin -> stdout echo & stderr capture
    {
        let payload = b"hello-over-tunnel-stdin-payload";
        let stdin_fd = make_stdin_pipe(payload);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let decision = run_shim_protocol(
            &[
                "-i".into(),
                "pipe:0".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(decision, ShimDecision::RemoteExited(0));
        assert_eq!(stdout, payload);
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(
            stderr_str.contains("-protocol_whitelist file,pipe,fd,crypto,data,subfile")
                && stderr_str.contains("-i pipe:0 -c:v libx264 out.mkv"),
            "unexpected stderr: {stderr_str}"
        );
    }

    // Non-zero exit code propagation
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let decision = run_shim_protocol(
            &[
                "-i".into(),
                "in.mkv".into(),
                "--exit-code".into(),
                "42".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(decision, ShimDecision::RemoteExited(42));
    }

    // Verify transcode_jobs recorded both runs cleanly and worker audited both sessions
    let jobs = wait_for_job_count(&db_a, 2).await;
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].exit_code, Some(42));
    assert!(!jobs[0].ran_locally);
    assert_eq!(jobs[0].link_id.as_deref(), Some(a_link_id.as_str()));
    assert_eq!(jobs[1].exit_code, Some(0));
    assert!(!jobs[1].ran_locally);
    assert_eq!(rt_a.transcode_state.active_jobs_for(&a_link_id), 0);

    let worker_audits = audit_actions_list(&db_b);
    assert!(worker_audits.contains(&"peer_transcode_job_started".to_string()));
    assert!(worker_audits.contains(&"peer_transcode_job_finished".to_string()));

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Hard-Kill Disconnect Cleanup (Shim Drops Without Frame::Exit -> Worker Kills Process Group)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn hard_kill_disconnect_cleanup_kills_remote_ffmpeg_process_group() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_920_000);
    let tmp = ShortTempDir::new("kill");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());
    let pid_file = tmp.path.join("child.pid");

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(221), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(222), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 12], 45012)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        write_access,
        &clock.now().to_rfc3339(),
    );

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg, 4);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    let caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(caps.clone()));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, caps);
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 2,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    // Connect directly as a shim client, send Start, wait for Started & child PID, then drop socket!
    let mut stream = UnixStream::connect(&disp_sock).await.unwrap();
    write_frame(
        &mut stream,
        &Frame::Start(StartRequest {
            args: vec![
                "-i".into(),
                "movie.mkv".into(),
                "--sleep-pid-file".into(),
                pid_file.to_string_lossy().into_owned(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            cwd: tmp.path.to_string_lossy().into_owned(),
            env_subset: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let frame = read_frame(&mut stream).await.unwrap().unwrap();
    assert_eq!(frame, Frame::Started);

    // Wait for fake ffmpeg to record its PID
    let mut child_pid = None;
    for _ in 0..50 {
        if let Ok(raw) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = raw.trim().parse::<i32>() {
                child_pid = Some(pid);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let child_pid = child_pid.expect("fake ffmpeg should write its PID");
    assert!(
        pid_is_alive(child_pid),
        "child PID {child_pid} should be running"
    );
    assert_eq!(rt_a.transcode_state.active_jobs_for(&a_link_id), 1);

    // Simulate abrupt Jellyfin SIGKILL of shim by closing Unix socket with NO Frame::Exit.
    drop(stream);

    // Worker MUST kill child process group promptly & dispatcher must release job slot.
    let mut dead = false;
    for _ in 0..80 {
        if !pid_is_alive(child_pid) && rt_a.transcode_state.active_jobs_for(&a_link_id) == 0 {
            dead = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        dead,
        "remote ffmpeg PID {child_pid} must be killed and active slot released on shim disconnect"
    );

    let jobs = db_peers::list_transcode_jobs(&db_a.lock().unwrap(), 5).unwrap();
    assert_eq!(jobs.len(), 1);
    assert!(!jobs[0].ran_locally);
    assert!(jobs[0].exit_code.is_some_and(|c| c != 0));

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Mid-Job Revocation (LinkRevoked & GrantRevoked Kill Remote Worker Immediately)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mid_job_link_and_grant_revocation_kills_remote_ffmpeg_and_releases_permits() {
    for revoke_kind in ["link", "grant"] {
        let ips = next_transcode_loopback_ips(2);
        let (ip_a, ip_b) = (ips[0], ips[1]);
        let clock = TestClock::new(1_800_930_000);
        let tmp = ShortTempDir::new("rev");
        let fake_ffmpeg =
            write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());
        let pid_file = tmp.path.join("rev.pid");

        let runner_a = FakePeerRunner::new(fixture_wg_pubkey(231), ip_a, 51821);
        let runner_b = FakePeerRunner::new(fixture_wg_pubkey(232), ip_b, 51821);
        let (rt_b, db_b) = build_transcode_runtime(
            "gpu-worker",
            Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
            FakePeerTranscodeRunner::new_arc(),
            Arc::new(UnreachablePublicTransport),
            &clock,
        );
        let (rt_a, db_a) = build_transcode_runtime(
            "seedbox-1",
            Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
            FakePeerTranscodeRunner::new_arc(),
            Arc::new(RouterPublicTransport {
                target_runtime: Arc::clone(&rt_b),
                client_ip: SocketAddr::from(([198, 51, 100, 13], 45013)),
            }),
            &clock,
        );

        let (a_link_id, b_link_id, _) =
            pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
        let mut write_access = AccessMap::none();
        write_access.transcoding = af_db::peers::AccessLevel::Write;
        let (grant_id, _, run_as_uid) = install_transcode_grant_pair(
            &db_a,
            &runner_a,
            &a_link_id,
            &db_b,
            &b_link_id,
            "seedbox-1",
            write_access,
            &clock.now().to_rfc3339(),
        );

        let worker_sock = tmp.path.join("w.sock");
        let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg, 4);
        rt_b.transcode_state.set_worker_socket_override(worker_sock);

        let caps = sample_caps(
            Some("8.1.3-2-trixie"),
            Some("8.1.3-Jellyfin"),
            &["libx264"],
            &[],
        );
        rt_a.transcode_state
            .set_local_capabilities_override(Some(caps.clone()));
        rt_a.transcode_state
            .record_remote_capabilities(&a_link_id, caps);
        db_peers::upsert_transcode_worker(
            &db_a.lock().unwrap(),
            &af_db::peers::TranscodeWorker {
                link_id: a_link_id.clone(),
                enabled: true,
                weight: 1,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264"]"#.to_string()),
                render_node: None,
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();

        let disp_sock = tmp.path.join("d.sock");
        rt_a.transcode_state
            .set_dispatcher_socket_override(disp_sock.clone());
        ensure_dispatcher_started(&rt_a).await.unwrap();

        let mut stream = UnixStream::connect(&disp_sock).await.unwrap();
        write_frame(
            &mut stream,
            &Frame::Start(StartRequest {
                args: vec![
                    "-i".into(),
                    "movie.mkv".into(),
                    "--sleep-pid-file".into(),
                    pid_file.to_string_lossy().into_owned(),
                    "-c:v".into(),
                    "libx264".into(),
                    "out.mkv".into(),
                ],
                cwd: tmp.path.to_string_lossy().into_owned(),
                env_subset: Vec::new(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(read_frame(&mut stream).await.unwrap(), Some(Frame::Started));

        let mut child_pid = None;
        for _ in 0..50 {
            if let Ok(raw) = fs::read_to_string(&pid_file) {
                if let Ok(pid) = raw.trim().parse::<i32>() {
                    child_pid = Some(pid);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let child_pid = child_pid.expect("fake ffmpeg PID recorded");
        assert!(pid_is_alive(child_pid));

        // Broadcast revocation on worker side (simulating operator revoking link/grant on worker)
        if revoke_kind == "link" {
            let _ = rt_b.revocation_tx.send(RevocationEvent::LinkRevoked {
                link_id: b_link_id.clone(),
                peer_name: "seedbox-1".to_string(),
            });
        } else {
            db_b.lock()
                .unwrap()
                .execute(
                    "UPDATE peer_grants SET revoked_at = ?1 WHERE id = ?2",
                    rusqlite::params![clock.now().to_rfc3339(), grant_id],
                )
                .unwrap();
            let _ = rt_b.revocation_tx.send(RevocationEvent::GrantRevoked {
                link_id: b_link_id.clone(),
                grant_id: grant_id.clone(),
                run_as_user_id: run_as_uid,
            });
        }

        // Shim socket should observe termination promptly AND remote ffmpeg PID must die.
        let read_res = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut stream)).await;
        assert!(
            read_res.is_ok(),
            "shim must observe stream close promptly on {revoke_kind} revocation"
        );

        let mut cleaned = false;
        for _ in 0..80 {
            if !pid_is_alive(child_pid) && rt_a.transcode_state.active_jobs_for(&a_link_id) == 0 {
                cleaned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            cleaned,
            "remote ffmpeg PID {child_pid} must be terminated on {revoke_kind} revocation"
        );

        let worker_audits = audit_actions_list(&db_b);
        assert!(
            worker_audits.contains(&"peer_transcode_job_revoked".to_string()),
            "worker must audit peer_transcode_job_revoked for {revoke_kind}: {worker_audits:?}"
        );

        stop_dispatcher(&rt_a).await;
        let _ = w_stop.send(true);
        let _ = w_task.await;
        rt_a.shutdown_all().await;
        rt_b.shutdown_all().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Ambiguous Post-Start Drop/Timeout NEVER Emits Frame::RunLocal (No Duplicate Exec)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ambiguous_post_start_drop_or_timeout_never_emits_run_local() {
    for mode in ["hang_after_start", "drop_after_start"] {
        let ips = next_transcode_loopback_ips(2);
        let (ip_a, ip_b) = (ips[0], ips[1]);
        let clock = TestClock::new(1_800_940_000);
        let tmp = ShortTempDir::new("amb");
        let fake_ffmpeg =
            write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

        let runner_a = FakePeerRunner::new(fixture_wg_pubkey(241), ip_a, 51821);
        let (rt_a, db_a) = build_transcode_runtime(
            "seedbox-1",
            Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
            FakePeerTranscodeRunner::new_arc(),
            Arc::new(UnreachablePublicTransport),
            &clock,
        );

        let start_seen = Arc::new(Notify::new());
        let start_seen_c = Arc::clone(&start_seen);
        let mode_s = mode.to_string();

        // Bind a fake worker WS server on ip_b that accepts upgrade, receives complete Frame::Start,
        // and either hangs forever or abruptly drops without sending Frame::Started.
        let listener = TcpListener::bind(SocketAddr::new(ip_b, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            let app = Router::new().route(
                "/peer/v1/transcode/jobs",
                get(move |ws: WebSocketUpgrade| {
                    let seen = Arc::clone(&start_seen_c);
                    let m = mode_s.clone();
                    async move {
                        ws.on_upgrade(move |mut socket| async move {
                            if let Some(Ok(AxumWsMessage::Binary(bytes))) = socket.next().await {
                                if let Ok(Frame::Start(_)) = decode_frame_payload(&bytes) {
                                    seen.notify_one();
                                    if m == "hang_after_start" {
                                        tokio::time::sleep(Duration::from_secs(5)).await;
                                    } else {
                                        let _ = socket.send(AxumWsMessage::Close(None)).await;
                                    }
                                }
                            }
                        })
                    }
                }),
            );
            let _ = axum::serve(listener, app).await;
        });

        // Wire identity + active link + grant + matching caps on rt_a pointing at fake WS server
        let link_id = format!("link-{}", Uuid::new_v4().simple());
        let now_str = clock.now().to_rfc3339();
        {
            let conn = db_a.lock().unwrap();
            db_peers::upsert_peer_identity(
                &conn,
                &af_db::peers::PeerIdentity {
                    wg_pubkey: fixture_wg_pubkey(241),
                    tunnel_ip: ip_a.to_string(),
                    wg_port: 51821,
                    created_at: now_str.clone(),
                },
            )
            .unwrap();
            db_peers::insert_peer_link(
                &conn,
                &af_db::peers::PeerLink {
                    id: link_id.clone(),
                    name: "flaky-worker".to_string(),
                    wg_pubkey: fixture_wg_pubkey(242),
                    tunnel_ip: ip_b.to_string(),
                    endpoint: "10.90.0.2".to_string(),
                    wg_port: 51821,
                    state: "active".to_string(),
                    peer_version: Some("4.0.0-p9-test".to_string()),
                    peer_protocol: Some(1),
                    capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                    rtt_ms: Some(1.0),
                    last_ok_at: Some(now_str.clone()),
                    last_error: None,
                    consecutive_failures: 0,
                    inbound_token_hash: None,
                    pending_attempt_id: None,
                    pending_expires_at: None,
                    created_at: now_str.clone(),
                    updated_at: now_str.clone(),
                },
            )
            .unwrap();
            let mut access = AccessMap::none();
            access.transcoding = af_db::peers::AccessLevel::Write;
            db_peers::upsert_peer_received_grant(
                &conn,
                &PeerReceivedGrant {
                    link_id: link_id.clone(),
                    grant_id: "g-flaky".to_string(),
                    run_as_user_id: 2,
                    access,
                    created_by: "alice".to_string(),
                    created_at: now_str.clone(),
                    generation: 1,
                    revoked_at: None,
                    credential_id: None,
                    updated_at: now_str,
                },
            )
            .unwrap();
            db_peers::upsert_transcode_worker(
                &conn,
                &af_db::peers::TranscodeWorker {
                    link_id: link_id.clone(),
                    enabled: true,
                    weight: 1,
                    max_jobs: 2,
                    ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                    encoders: Some(r#"["libx264"]"#.to_string()),
                    render_node: None,
                    parity_ok: true,
                    parity_error: None,
                },
            )
            .unwrap();
        }
        {
            let mut st = runner_a.state.lock().unwrap();
            st.credentials.insert(
                (PeerCredentialSlot::LinkToken, link_id.clone()),
                "ltok-flaky".to_string(),
            );
            st.credentials.insert(
                (PeerCredentialSlot::GrantToken, link_id.clone()),
                "gtok-flaky".to_string(),
            );
        }
        rt_a.tunnel_port_overrides
            .write()
            .unwrap()
            .insert(ip_b, port);

        let caps = sample_caps(
            Some("8.1.3-2-trixie"),
            Some("8.1.3-Jellyfin"),
            &["libx264"],
            &[],
        );
        rt_a.transcode_state
            .set_local_capabilities_override(Some(caps.clone()));
        rt_a.transcode_state
            .record_remote_capabilities(&link_id, caps);
        rt_a.transcode_state
            .set_remote_start_timeout(Duration::from_millis(200));

        let disp_sock = tmp.path.join("d.sock");
        rt_a.transcode_state
            .set_dispatcher_socket_override(disp_sock.clone());
        ensure_dispatcher_started(&rt_a).await.unwrap();

        let shim_cfg = ShimConfig {
            real_ffmpeg: fake_ffmpeg,
            dispatcher_socket: disp_sock,
            handshake_timeout: Duration::from_secs(2),
            frame_write_timeout: Duration::from_secs(5),
        };
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let decision = run_shim_protocol(
            &[
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;

        assert!(
            matches!(decision, ShimDecision::RemoteFailed { .. }),
            "mode={mode}: dispatcher MUST NOT emit RunLocal after sending Start, got {decision:?}"
        );
        assert!(
            rt_a.transcode_state
                .active_unhealthy_until(&link_id, clock.now())
                .is_some(),
            "mode={mode}: flaky worker must be marked unhealthy for 60s"
        );
        let jobs = wait_for_job_count(&db_a, 1).await;
        assert_eq!(jobs.len(), 1);
        assert!(!jobs[0].ran_locally);
        assert_eq!(jobs[0].exit_code, Some(1));

        stop_dispatcher(&rt_a).await;
        server_task.abort();
        rt_a.shutdown_all().await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Pre-Start Unreachable Worker: Clean RunLocal Fallback & Multi-Worker Failover
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pre_start_unreachable_worker_falls_back_locally_or_fails_over() {
    let ips = next_transcode_loopback_ips(3);
    let (ip_a, ip_dead, ip_live) = (ips[0], ips[1], ips[2]);
    let clock = TestClock::new(1_800_950_000);
    let tmp = ShortTempDir::new("failover");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    // Allocate an immediately-closed port on ip_dead so connect() returns ECONNREFUSED instantly.
    let closed_port = {
        let l = TcpListener::bind(SocketAddr::new(ip_dead, 0))
            .await
            .unwrap();
        l.local_addr().unwrap().port()
    };

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(251), ip_a, 51821);
    let runner_live = FakePeerRunner::new(fixture_wg_pubkey(253), ip_live, 51821);

    let (rt_live, db_live) = build_transcode_runtime(
        "worker-live",
        Arc::clone(&runner_live) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_live),
            client_ip: SocketAddr::from(([198, 51, 100, 15], 45015)),
        }),
        &clock,
    );

    let (live_link_id, live_back_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_live, ip_a, ip_live, "worker-live").await;
    let now_str = clock.now().to_rfc3339();
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &live_link_id,
        &db_live,
        &live_back_id,
        "seedbox-1",
        write_access.clone(),
        &now_str,
    );

    // Insert dead worker on rt_a
    let dead_link_id = format!("link-{}", Uuid::new_v4().simple());
    {
        let conn = db_a.lock().unwrap();
        db_peers::insert_peer_link(
            &conn,
            &af_db::peers::PeerLink {
                id: dead_link_id.clone(),
                name: "worker-dead".to_string(),
                wg_pubkey: fixture_wg_pubkey(252),
                tunnel_ip: ip_dead.to_string(),
                endpoint: "10.90.0.2".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0-p9-test".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_str.clone()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: now_str.clone(),
                updated_at: now_str.clone(),
            },
        )
        .unwrap();
        db_peers::upsert_peer_received_grant(
            &conn,
            &PeerReceivedGrant {
                link_id: dead_link_id.clone(),
                grant_id: "g-dead".to_string(),
                run_as_user_id: 2,
                access: write_access,
                created_by: "alice".to_string(),
                created_at: now_str.clone(),
                generation: 1,
                revoked_at: None,
                credential_id: None,
                updated_at: now_str,
            },
        )
        .unwrap();
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: dead_link_id.clone(),
                enabled: true,
                weight: 100,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264"]"#.to_string()),
                render_node: None,
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
        // Start with live worker disabled so only dead worker is tried first.
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: live_link_id.clone(),
                enabled: false,
                weight: 1,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264"]"#.to_string()),
                render_node: None,
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
    }
    {
        let mut st = runner_a.state.lock().unwrap();
        st.credentials.insert(
            (PeerCredentialSlot::LinkToken, dead_link_id.clone()),
            "ltok-dead".to_string(),
        );
        st.credentials.insert(
            (PeerCredentialSlot::GrantToken, dead_link_id.clone()),
            "gtok-dead".to_string(),
        );
    }
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_dead, closed_port);

    let caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(caps.clone()));
    rt_a.transcode_state
        .record_remote_capabilities(&dead_link_id, caps.clone());
    rt_a.transcode_state
        .record_remote_capabilities(&live_link_id, caps);

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg.clone(), 4);
    rt_live
        .transcode_state
        .set_worker_socket_override(worker_sock);

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // Part 1: Only dead worker enabled -> pre-start unreachable -> safe RunLocal + 60s unhealthy
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "in.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            }
        );
        assert!(rt_a
            .transcode_state
            .active_unhealthy_until(&dead_link_id, clock.now())
            .is_some());
        let jobs = wait_for_job_count(&db_a, 1).await;
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].ran_locally);
    }

    // Part 2: Clear unhealthy on dead worker AND enable live worker -> dispatcher fails over
    // cleanly from unreachable dead worker to live worker without running locally!
    clock.advance(1);
    rt_a.transcode_state.clear_worker_unhealthy(&dead_link_id);
    db_a.lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET enabled = 1 WHERE link_id = ?1",
            rusqlite::params![live_link_id],
        )
        .unwrap();
    {
        let stdin_fd = make_stdin_pipe(b"failover-ok");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "pipe:0".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        assert_eq!(out, b"failover-ok");
        let jobs = wait_for_job_count(&db_a, 2).await;
        assert_eq!(jobs[0].link_id.as_deref(), Some(live_link_id.as_str()));
        assert!(!jobs[0].ran_locally);
    }

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_live.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Worker Endpoint GET /peer/v1/transcode/jobs Authz Matrix & Audit Logging
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn worker_tunnel_transcode_jobs_authz_matrix() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_960_000);

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(161), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(162), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 16], 45016)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let link_token = runner_a
        .state
        .lock()
        .unwrap()
        .credentials
        .get(&(PeerCredentialSlot::LinkToken, a_link_id.clone()))
        .cloned()
        .expect("held link token");

    async fn send_req(
        rt: Arc<PeerRuntime>,
        src_ip: IpAddr,
        ltok: Option<&str>,
        gtok: Option<&str>,
    ) -> StatusCode {
        let app = build_listener_router(rt);
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("/peer/v1/transcode/jobs");
        if let Some(t) = ltok {
            builder = builder.header(HEADER_LINK_TOKEN, t);
        }
        if let Some(t) = gtok {
            builder = builder.header(HEADER_GRANT_TOKEN, t);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(src_ip, 50000)));
        app.oneshot(req).await.unwrap().status()
    }

    // 1. Missing link token -> 401
    assert_eq!(
        send_req(Arc::clone(&rt_b), ip_a, None, None).await,
        StatusCode::UNAUTHORIZED
    );
    // 2. Wrong link token -> 401
    assert_eq!(
        send_req(Arc::clone(&rt_b), ip_a, Some("wrong-link-token"), None).await,
        StatusCode::UNAUTHORIZED
    );
    // 3. Wrong source tunnel IP -> 401
    assert_eq!(
        send_req(
            Arc::clone(&rt_b),
            IpAddr::V4(Ipv4Addr::new(127, 3, 250, 250)),
            Some(&link_token),
            None,
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // 4. Valid link token, NO active grant -> 403
    assert_eq!(
        send_req(Arc::clone(&rt_b), ip_a, Some(&link_token), Some("any")).await,
        StatusCode::FORBIDDEN
    );

    // 5. Grant with `transcoding: read` -> rejected (403)
    let mut read_access = AccessMap::none();
    read_access.transcoding = af_db::peers::AccessLevel::Read;
    let (read_gid, read_gtok, _) = install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        read_access,
        &clock.now().to_rfc3339(),
    );
    assert_eq!(
        send_req(Arc::clone(&rt_b), ip_a, Some(&link_token), Some(&read_gtok)).await,
        StatusCode::FORBIDDEN
    );

    // Revoke read grant and install `transcoding: write` grant
    db_b.lock()
        .unwrap()
        .execute(
            "UPDATE peer_grants SET revoked_at = ?1 WHERE id = ?2",
            rusqlite::params![clock.now().to_rfc3339(), read_gid],
        )
        .unwrap();
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    let (_write_gid, write_gtok, _) = install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        write_access,
        &clock.now().to_rfc3339(),
    );

    // 6. Missing grant token -> 403
    assert_eq!(
        send_req(Arc::clone(&rt_b), ip_a, Some(&link_token), None).await,
        StatusCode::FORBIDDEN
    );
    // 7. Wrong grant token -> 401
    assert_eq!(
        send_req(
            Arc::clone(&rt_b),
            ip_a,
            Some(&link_token),
            Some("bad-grant-secret"),
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    // 8. Valid link + valid `transcoding: write` grant, non-WS HTTP GET -> passes authz and
    //    reaches WS upgrade check (400 Bad Request, NOT 401/403).
    assert_eq!(
        send_req(
            Arc::clone(&rt_b),
            ip_a,
            Some(&link_token),
            Some(&write_gtok),
        )
        .await,
        StatusCode::BAD_REQUEST
    );

    // 9. Inactive run-as user (`sessions_revoked_after` / non-peer account_type) -> 403
    db_b.lock()
        .unwrap()
        .execute(
            "UPDATE users SET account_type = 'human' WHERE username = 'peer-seedbox-1'",
            [],
        )
        .unwrap();
    assert_eq!(
        send_req(
            Arc::clone(&rt_b),
            ip_a,
            Some(&link_token),
            Some(&write_gtok),
        )
        .await,
        StatusCode::FORBIDDEN
    );

    let actions = audit_actions_list(&db_b);
    assert!(
        actions
            .iter()
            .filter(|a| a.as_str() == "peer_transcode_denied")
            .count()
            >= 4,
        "expected audited peer_transcode_denied events, got {actions:?}"
    );

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Admin Settings GET/PUT, Rollback, Parity Test, Health Mismatch Dedup, Pruning & Revocation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_transcode_settings_enable_rollback_parity_mismatch_dedup_pruning_and_cleanup() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_970_000);
    let tmp = ShortTempDir::new("cfg");
    let parity_dir = tmp.path.join("transcodes");
    fs::create_dir_all(&parity_dir).unwrap();
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(171), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(172), ip_b, 51821);
    let tc_runner_a = FakePeerTranscodeRunner::new_arc();
    tc_runner_a.state.lock().unwrap().transcoding_temp_path =
        parity_dir.to_string_lossy().into_owned();
    let tc_runner_b = FakePeerTranscodeRunner::new_arc();
    tc_runner_b.state.lock().unwrap().transcoding_temp_path =
        parity_dir.to_string_lossy().into_owned();

    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_b),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_a),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 17], 45017)),
        }),
        &clock,
    );

    // 1. Dormant standalone startup: zero identity -> zero transcode runner calls, no dispatcher.
    start_with_runtime(Arc::clone(&rt_a)).await;
    assert_eq!(tc_runner_a.call_count(), 0);
    assert!(!rt_a.transcode_state.is_dispatcher_active().await);

    // Pair nodes & grant transcoding:write + updates:write
    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    access.updates = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    // Configure local/remote capabilities + isolated socket paths + injectable Jellyfin probe
    let disp_sock = tmp.path.join("d.sock");
    let worker_sock = tmp.path.join("w.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    rt_a.transcode_state
        .set_parity_dir_override(parity_dir.clone());
    rt_b.transcode_state
        .set_worker_socket_override(worker_sock.clone());
    let (w_stop, w_task) = spawn_real_worker(worker_sock, fake_ffmpeg, 4);

    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let remote_caps_older = sample_caps(
        Some("8.1.3-1-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps.clone()));
    rt_b.transcode_state
        .set_local_capabilities_override(Some(remote_caps_older.clone()));

    let jf_probe = FakeJellyfinProbe::new(JellyfinFfmpegProbeOutcome::Reported(
        "/usr/lib/jellyfin-ffmpeg/ffmpeg".to_string(),
    ));
    rt_a.transcode_state
        .set_jellyfin_probe(Arc::clone(&jf_probe) as Arc<dyn JellyfinFfmpegProbe>);

    // 2. Enabling when Jellyfin reports the wrong ffmpeg path MUST roll back via DisableJellyfin!
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "expected rollback conflict: {body}"
    );
    assert_eq!(tc_runner_a.count_action("enable_jellyfin"), 1);
    assert_eq!(tc_runner_a.count_action("disable_jellyfin"), 1);
    assert!(!rt_a.transcode_state.is_dispatcher_active().await);

    // 3. Once Jellyfin reports expected shim path, enable succeeds and starts dispatcher socket!
    jf_probe.set(JellyfinFfmpegProbeOutcome::Reported(
        DEFAULT_TRANSCODE_SHIM_PATH.to_string(),
    ));
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "enabled": true, "worker_service_enabled": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "enable transcode failed: {body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["dispatcher_active"], true);
    assert_eq!(body["shim_installed"], true);
    assert_eq!(body["jellyfin_dropin_enabled"], true);
    assert_eq!(body["worker_service_enabled"], true);
    assert_eq!(body["worker_service_active"], true);
    assert_eq!(
        body["jellyfin_reported_ffmpeg"],
        DEFAULT_TRANSCODE_SHIM_PATH
    );
    assert_eq!(body["local"]["server_name"], "seedbox-1");
    assert_eq!(body["local"]["package_version"], "8.1.3-2-trixie");

    // 4. Input validation rejections for invalid weights, max_jobs, and duplicate link_ids
    for bad in [
        json!({ "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 0, "max_jobs": 2 }] }),
        json!({ "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 101, "max_jobs": 2 }] }),
        json!({ "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 2, "max_jobs": 0 }] }),
        json!({ "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 2, "max_jobs": 65 }] }),
        json!({ "workers": [
            { "link_id": a_link_id, "enabled": true, "weight": 2, "max_jobs": 2 },
            { "link_id": a_link_id, "enabled": true, "weight": 3, "max_jobs": 2 }
        ] }),
    ] {
        let (bad_st, _) = call_admin(&rt_a, Method::PUT, "/transcode", Some(bad)).await;
        assert_eq!(bad_st, StatusCode::BAD_REQUEST);
    }

    // 5. Enable worker & run real 1-second clip / 5-second timeout parity test -> succeeds & cleans up temp file!
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({
            "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 3, "max_jobs": 4 }],
            "run_parity_test_link_id": a_link_id
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "parity PUT failed: {body}");
    assert_eq!(
        body["parity_result"]["ok"], true,
        "parity result failed: {body}"
    );
    assert_eq!(body["parity_result"]["link_id"], a_link_id);
    assert_eq!(tc_runner_a.count_action("export_transcode_dirs"), 1);

    // Temp .af-parity-*.ts file MUST have been cleaned up automatically.
    let leftover: Vec<_> = fs::read_dir(&parity_dir).unwrap().flatten().collect();
    assert!(leftover.is_empty(), "parity temp file leaked: {leftover:?}");

    // 6. Health loop tick fetches remote `transcode` caps from worker's tunnel /health, persists
    //    them, detects version mismatch, and emits DEDUPLICATED notification!
    run_health_tick(&rt_a).await;
    run_health_tick(&rt_a).await;
    let notifs_after_two = notification_rows(&db_a);
    let mismatch_notifs: Vec<_> = notifs_after_two
        .iter()
        .filter(|(title, _)| title.contains("jellyfin-ffmpeg mismatch"))
        .collect();
    assert_eq!(
        mismatch_notifs.len(),
        1,
        "mismatch notification must deduplicate across consecutive ticks: {notifs_after_two:?}"
    );
    assert!(mismatch_notifs[0].1.contains(
        "jellyfin-ffmpeg differs: seedbox-1 8.1.3-2-trixie vs gpu-worker 8.1.3-1-trixie"
    ));

    // Verify GET /api/v1/admin/peers/transcode surfaces mismatch, align_target="peer", and updates grant
    let (st, get_body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(st, StatusCode::OK);
    let w_view = &get_body["workers"][0];
    assert_eq!(w_view["link_id"], a_link_id);
    assert_eq!(w_view["parity_ok"], true);
    assert_eq!(w_view["weight"], 3);
    assert_eq!(w_view["max_jobs"], 4);
    assert_eq!(w_view["has_transcode_write_grant"], true);
    assert_eq!(w_view["has_updates_write_grant"], true);
    assert_eq!(w_view["ffmpeg_mismatch"], true);
    assert_eq!(w_view["align_target"], "peer");
    assert_eq!(w_view["eligible"], false);

    // Align remote worker version to match local -> next health tick clears mismatch!
    rt_b.transcode_state
        .set_local_capabilities_override(Some(local_caps));
    run_health_tick(&rt_a).await;
    let (st, aligned_body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(aligned_body["workers"][0]["ffmpeg_mismatch"], false);
    assert_eq!(
        aligned_body["workers"][0]["align_target"],
        serde_json::Value::Null
    );
    assert_eq!(aligned_body["workers"][0]["eligible"], true);

    // 7. Failing parity test (non-existent local parity dir) persists parity_ok=false + error
    rt_a.transcode_state
        .set_parity_dir_override(tmp.path.join("missing-dir"));
    let (st, fail_body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "run_parity_test_link_id": a_link_id })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(fail_body["parity_result"]["ok"], false);
    assert!(fail_body["parity_result"]["error"].as_str().is_some());
    assert_eq!(fail_body["workers"][0]["parity_ok"], false);
    assert_eq!(fail_body["workers"][0]["eligible"], false);

    // 8. 7-day transcode_jobs pruning
    {
        let conn = db_a.lock().unwrap();
        let old_ts = (clock.now() - ChronoDuration::days(8)).to_rfc3339();
        let fresh_ts = (clock.now() - ChronoDuration::days(2)).to_rfc3339();
        db_peers::insert_transcode_job(
            &conn,
            &TranscodeJob {
                id: "job-old".to_string(),
                link_id: Some(a_link_id.clone()),
                started_at: old_ts.clone(),
                ended_at: Some(old_ts),
                exit_code: Some(0),
                request_id: Some("req-old".to_string()),
                ran_locally: false,
            },
        )
        .unwrap();
        db_peers::insert_transcode_job(
            &conn,
            &TranscodeJob {
                id: "job-fresh".to_string(),
                link_id: Some(a_link_id.clone()),
                started_at: fresh_ts.clone(),
                ended_at: Some(fresh_ts),
                exit_code: Some(0),
                request_id: Some("req-fresh".to_string()),
                ran_locally: false,
            },
        )
        .unwrap();
    }
    let pruned = prune_old_transcode_jobs(&rt_a).await;
    assert_eq!(pruned, 1);
    let remaining_jobs = db_peers::list_transcode_jobs(&db_a.lock().unwrap(), 10).unwrap();
    assert_eq!(remaining_jobs.len(), 1);
    assert_eq!(remaining_jobs[0].id, "job-fresh");

    // 9. Revocation cleanup calls RemoveTranscodeExports for configured worker link,
    //    and is completely dormant for an unrelated link with no worker/mounts.
    let exports_before = tc_runner_a.count_action("remove_transcode_exports");
    cleanup_revoked_link_transcode_best_effort(&rt_a, "nonexistent-link").await;
    assert_eq!(
        tc_runner_a.count_action("remove_transcode_exports"),
        exports_before
    );
    cleanup_revoked_link_transcode_best_effort(&rt_a, &a_link_id).await;
    assert_eq!(
        tc_runner_a.count_action("remove_transcode_exports"),
        exports_before + 1
    );

    // 10. Disabling dispatcher + worker service tears down socket and units cleanly
    let (st, off_body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "enabled": false, "worker_service_enabled": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(off_body["enabled"], false);
    assert_eq!(off_body["dispatcher_active"], false);
    assert_eq!(off_body["worker_service_enabled"], false);
    assert!(
        !disp_sock.exists(),
        "dispatcher socket must be unlinked on disable"
    );

    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Blocker 1: Dispatcher Socket Group Propagation (`aetherflow:jellyfin` 0660)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn bind_dispatcher_socket_propagates_parent_group_ownership() {
    use std::os::unix::fs::MetadataExt;

    let tmp = ShortTempDir::new("grp");
    let egid = unsafe { libc::getegid() };
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0 as libc::gid_t; count.max(0) as usize];
    if count > 0 {
        let _ = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    }

    let expected_gid = if let Some(&supp_gid) = groups.iter().find(|&&g| g != egid) {
        let c_dir = std::ffi::CString::new(tmp.path.to_string_lossy().as_bytes()).unwrap();
        let rc = unsafe { libc::chown(c_dir.as_ptr(), (!0u32) as libc::uid_t, supp_gid) };
        assert_eq!(
            rc,
            0,
            "chown parent dir to supplementary group {supp_gid} failed: {}",
            std::io::Error::last_os_error()
        );
        supp_gid
    } else {
        egid
    };

    let sock_path = tmp.path.join("transcode.sock");
    let bound = bind_dispatcher_socket(&sock_path, 0o660).expect("bind dispatcher socket");
    let meta = fs::symlink_metadata(&sock_path).expect("stat published socket");
    assert_eq!(meta.gid(), expected_gid);
    assert_eq!(meta.mode() & 0o7777, 0o660);
    drop(bound);
    assert!(!sock_path.exists());
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Blocker 4: RFC 6455 §5.4 Interleaved Ping Inside Fragmented Binary Message
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ws_client_reader_preserves_fragmented_binary_across_interleaved_ping() {
    use tokio::io::AsyncWriteExt;

    let (mut writer, reader) = tokio::io::duplex(4096);
    let mut ws_reader = WsClientReader::new(reader);

    // Server frames (unmasked):
    // 1. Binary FIN=0 ("hello ")
    // 2. Ping   FIN=1 ("hb")
    // 3. Cont   FIN=0 ("world")
    // 4. Pong   FIN=1 ("ignored")
    // 5. Cont   FIN=1 ("!")
    let mut wire = Vec::new();
    wire.extend_from_slice(&[0x02, 6]);
    wire.extend_from_slice(b"hello ");
    wire.extend_from_slice(&[0x89, 2]);
    wire.extend_from_slice(b"hb");
    wire.extend_from_slice(&[0x00, 5]);
    wire.extend_from_slice(b"world");
    wire.extend_from_slice(&[0x8A, 7]);
    wire.extend_from_slice(b"ignored");
    wire.extend_from_slice(&[0x80, 1]);
    wire.extend_from_slice(b"!");
    writer.write_all(&wire).await.unwrap();
    writer.shutdown().await.unwrap();

    assert_eq!(
        ws_reader.read_message().await.unwrap(),
        Some(WsClientMessage::Ping(b"hb".to_vec()))
    );
    assert_eq!(
        ws_reader.read_message().await.unwrap(),
        Some(WsClientMessage::Binary(b"hello world!".to_vec()))
    );
    assert_eq!(ws_reader.read_message().await.unwrap(), None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Blocker 3: Cancel-Safe Concurrent Chunked Stdin/Stdout + Unrelated Revocations
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn relay_handles_concurrent_chunked_bidirectional_traffic_and_unrelated_revocations() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_980_000);
    let tmp = ShortTempDir::new("cc");

    // Fake ffmpeg that streams stdin to stdout while concurrently emitting stderr chunks.
    let fake_ffmpeg = write_fake_ffmpeg_script(
        &tmp.path,
        "ffmpeg",
        r#"#!/bin/sh
python3 -c '
import sys
out = sys.stdout.buffer
err = sys.stderr.buffer
inp = sys.stdin.buffer
n = 0
while True:
    chunk = inp.read(4096)
    if not chunk:
        break
    out.write(chunk)
    out.flush()
    n += 1
    if n % 4 == 0:
        err.write(f"frame={n}\n".encode())
        err.flush()
'
"#,
    );

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(181), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(182), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 18], 45018)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg.clone(), 4);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    let caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(caps.clone()));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, caps);
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 2,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    // Blast unrelated RevocationEvents onto both runtimes while 192 KiB streams bidirectionally.
    let rt_a_noise = Arc::clone(&rt_a);
    let rt_b_noise = Arc::clone(&rt_b);
    let noise_task = tokio::spawn(async move {
        for idx in 0..80 {
            let _ = rt_a_noise.revocation_tx.send(RevocationEvent::LinkRevoked {
                link_id: format!("unrelated-link-{idx}"),
                peer_name: "other".to_string(),
            });
            let _ = rt_b_noise
                .revocation_tx
                .send(RevocationEvent::GrantRevoked {
                    link_id: format!("unrelated-link-{idx}"),
                    grant_id: format!("g-{idx}"),
                    run_as_user_id: 999,
                });
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    let payload: Vec<u8> = (0..(192 * 1024)).map(|i| (i % 251) as u8).collect();
    let mut stream = UnixStream::connect(&disp_sock).await.unwrap();
    write_frame(
        &mut stream,
        &Frame::Start(StartRequest {
            args: vec![
                "-i".into(),
                "pipe:0".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.ts".into(),
            ],
            cwd: tmp.path.to_string_lossy().into_owned(),
            env_subset: Vec::new(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), Some(Frame::Started));

    let (mut shim_r, mut shim_w) = stream.into_split();
    let payload_send = payload.clone();
    let send_task = tokio::spawn(async move {
        for chunk in payload_send.chunks(3000) {
            write_frame(&mut shim_w, &Frame::Stdin(chunk.to_vec()))
                .await
                .unwrap();
        }
        write_frame(&mut shim_w, &Frame::StdinEof).await.unwrap();
        // Keep the Unix socket write half open until the read loop observes Frame::Exit
        // (matching `af-transcode` shim, since dropping `OwnedWriteHalf` calls `shutdown(SHUT_WR)`).
        shim_w
    });

    let mut received_out = Vec::with_capacity(payload.len());
    let mut received_err = Vec::new();
    let mut exit_code = None;
    while let Some(frame) = read_frame(&mut shim_r).await.unwrap() {
        match frame {
            Frame::Stdout(chunk) => received_out.extend_from_slice(&chunk),
            Frame::Stderr(chunk) => received_err.extend_from_slice(&chunk),
            Frame::Exit(code) => {
                exit_code = Some(code);
                break;
            }
            other => panic!("unexpected frame during concurrent stream: {other:?}"),
        }
    }
    let _shim_w = send_task.await.unwrap();
    let _ = noise_task.await;

    assert_eq!(exit_code, Some(0));
    assert_eq!(received_out, payload);
    assert!(String::from_utf8_lossy(&received_err).contains("frame="));
    assert!(
        rt_a.transcode_state
            .active_unhealthy_until(&a_link_id, clock.now())
            .is_none(),
        "concurrent chunked stream must not mark worker unhealthy"
    );

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Blocker 2 & Blocker 5: First-Enable API Restart, Runner Parity Cleanup,
//     Path Deduplication, Worker Mount/Bind Sync & Authz, Error Surfacing, Teardown
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn first_enable_api_restart_runner_parity_cleanup_and_worker_mount_sync_lifecycle() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_800_990_000);
    let tmp = ShortTempDir::new("b25");
    let shared_tc_dir = tmp.path.join("shared-tc");
    fs::create_dir_all(&shared_tc_dir).unwrap();
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    // Read-only parent dir simulates pre-drop-in `ProtectSystem=strict` (`EACCES`/`EROFS`).
    let ro_disp_dir = tmp.path.join("ro-disp");
    fs::create_dir_all(&ro_disp_dir).unwrap();
    fs::set_permissions(&ro_disp_dir, fs::Permissions::from_mode(0o500)).unwrap();

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(191), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(192), ip_b, 51821);
    let tc_runner_a = FakePeerTranscodeRunner::new_arc();
    let dir_s = shared_tc_dir.to_string_lossy().into_owned();
    {
        let mut st = tc_runner_a.state.lock().unwrap();
        // Deliberately set transcoding_temp_path == tmp_dir to verify deduplication!
        st.transcoding_temp_path = dir_s.clone();
        st.tmp_dir = dir_s.clone();
        st.cache_dir = dir_s.clone();
        st.api_restart_required_on_ensure_dir = true;
        st.api_restart_required_on_install_worker = true;
    }
    let tc_runner_b = FakePeerTranscodeRunner::new_arc();
    {
        let mut st = tc_runner_b.state.lock().unwrap();
        st.transcoding_temp_path = dir_s;
    }

    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_b),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_a),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 19], 45019)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    let (_, grant_token, _) = install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    // 1. Blocker 2 (controller A): read-only dispatcher dir triggers ScheduleApiRestart WITHOUT
    //    rolling back EnableJellyfin!
    rt_a.transcode_state
        .set_dispatcher_socket_override(ro_disp_dir.join("transcode.sock"));
    let jf_probe = FakeJellyfinProbe::new(JellyfinFfmpegProbeOutcome::Reported(
        DEFAULT_TRANSCODE_SHIM_PATH.to_string(),
    ));
    rt_a.transcode_state
        .set_jellyfin_probe(Arc::clone(&jf_probe) as Arc<dyn JellyfinFfmpegProbe>);

    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "first-time enable should schedule restart cleanly: {body}"
    );
    assert_eq!(body["api_restart_scheduled"], true);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["jellyfin_dropin_enabled"], true);
    assert_eq!(tc_runner_a.count_action("disable_jellyfin"), 0);
    assert_eq!(tc_runner_a.count_action("schedule_api_restart"), 1);

    // 2. Blocker 2 (worker B): InstallWorkerUnit with api_restart_required=true schedules restart.
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "worker_service_enabled": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["api_restart_scheduled"], true);
    assert_eq!(tc_runner_a.count_action("schedule_api_restart"), 2);

    // Restore permissions so ShortTempDir cleanup succeeds cleanly.
    fs::set_permissions(&ro_disp_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // 3. Blocker 5 + Blocker 2 (parity cleanup via runner):
    //    Seed B's export `/srv/media/movies` and A's media mount `/mnt/af-peers/gpu-worker/movies`.
    let now_str = clock.now().to_rfc3339();
    db_peers::insert_peer_export(
        &db_b.lock().unwrap(),
        &PeerExport {
            id: "exp-movies".to_string(),
            link_id: b_link_id.clone(),
            path: "/srv/media/movies".to_string(),
            writable: false,
            squash_uid: Some(1000),
            squash_gid: Some(1000),
            created_at: now_str,
        },
    )
    .unwrap();
    db_peers::insert_peer_mount(
        &db_a.lock().unwrap(),
        &PeerMount {
            id: "mnt-movies".to_string(),
            link_id: a_link_id.clone(),
            remote_path: "/srv/media/movies".to_string(),
            mount_path: "/mnt/af-peers/gpu-worker/movies".to_string(),
            unit_name: "mnt-af\\x2dpeers-gpu\\x2dworker-movies.mount".to_string(),
            writable: false,
            purpose: "media".to_string(),
            state: "mounted".to_string(),
            last_error: None,
        },
    )
    .unwrap();

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg, 4);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    // Do NOT set parity_dir_override on rt_a so production CleanupParityFile runner path executes!
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({
            "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 2, "max_jobs": 3 }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "enable worker failed: {body}");
    assert_eq!(body["parity_result"]["ok"], true, "parity failed: {body}");

    // Verify A exported deduplicated paths (1 path, not 3 duplicates!) AND called CleanupParityFile!
    let export_req = tc_runner_a
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .find_map(|c| match c {
            PeerTranscodeRequest::ExportTranscodeDirs { paths, .. } => Some(paths.clone()),
            _ => None,
        })
        .expect("ExportTranscodeDirs called");
    assert_eq!(
        export_req.len(),
        1,
        "duplicate transcode paths must be deduplicated"
    );
    assert_eq!(tc_runner_a.count_action("cleanup_parity_file"), 1);

    // Verify B received MountTranscodeDirs AND BindMedia AND persisted peer_mounts rows!
    assert_eq!(tc_runner_b.count_action("mount_transcode_dirs"), 1);
    assert_eq!(tc_runner_b.count_action("bind_media"), 1);
    let b_mounts = db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id).unwrap();
    assert!(b_mounts.iter().any(|m| m.purpose == "transcode"));
    assert!(b_mounts.iter().any(|m| {
        m.purpose == "transcode_bind"
            && m.remote_path == "/srv/media/movies"
            && m.mount_path == "/mnt/af-peers/gpu-worker/movies"
    }));

    // 4. Unauthorized arbitrary media bind over POST /peer/v1/transcode/mounts MUST be denied 403!
    let link_token = runner_a
        .state
        .lock()
        .unwrap()
        .credentials
        .get(&(PeerCredentialSlot::LinkToken, a_link_id.clone()))
        .cloned()
        .unwrap();
    let app_b = build_listener_router(Arc::clone(&rt_b));
    let mut bad_bind_req = Request::builder()
        .method(Method::POST)
        .uri("/peer/v1/transcode/mounts")
        .header(HEADER_LINK_TOKEN, &link_token)
        .header(HEADER_GRANT_TOKEN, &grant_token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "action": "sync",
                "transcode_paths": ["/var/cache/jellyfin/transcodes"],
                "media_binds": [{ "from": "/etc", "to": "/mnt/af-peers/gpu-worker/etc", "writable": false }]
            }))
            .unwrap(),
        ))
        .unwrap();
    bad_bind_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_a, 50001)));
    let bad_resp = app_b.oneshot(bad_bind_req).await.unwrap();
    assert_eq!(bad_resp.status(), StatusCode::FORBIDDEN);

    // 5. ExportTranscodeDirs failure MUST surface clearly (not silently swallowed!).
    tc_runner_a.state.lock().unwrap().fail_next.insert(
        "export_transcode_dirs",
        PeerTranscodeError::Runtime("exportfs failed".to_string()),
    );
    let (st, err_body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({
            "workers": [{ "link_id": a_link_id, "enabled": true, "weight": 2, "max_jobs": 3 }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(err_body["parity_result"]["ok"], false);
    assert!(err_body["parity_result"]["error"]
        .as_str()
        .unwrap_or_default()
        .contains("exportfs failed"));
    assert_eq!(err_body["workers"][0]["parity_ok"], false);

    // 6. Disabling worker B tears down remote transcode mounts & binds on B and removes exports on A!
    let (st, _) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({
            "workers": [{ "link_id": a_link_id, "enabled": false, "weight": 2, "max_jobs": 3 }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(tc_runner_a.count_action("remove_transcode_exports"), 1);
    assert_eq!(tc_runner_b.count_action("remove_transcode_mounts"), 1);
    assert_eq!(tc_runner_b.count_action("remove_bind_media"), 1);
    let b_mounts_after =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id).unwrap();
    assert!(
        b_mounts_after.is_empty(),
        "teardown must delete worker transcode & bind peer_mounts rows: {b_mounts_after:?}"
    );

    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. Bundle A (R4-ESC-01): Worker Mount Allowlist, Calling-Link Confinement,
//     Atomic Rollback on BindMedia / SQLite Failure, & Structured JSON Errors
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn worker_mount_allowlist_calling_link_confinement_and_atomic_rollback() {
    use axum::body::to_bytes;

    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_000_000);
    let now_str = clock.now().to_rfc3339();

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(201), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(202), ip_b, 51821);
    let tc_runner_a = FakePeerTranscodeRunner::new_arc();
    let tc_runner_b = FakePeerTranscodeRunner::new_arc();

    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_b),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_a),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 20], 45020)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    let (_, grant_token, _) = install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &now_str,
    );
    let link_token = runner_a
        .state
        .lock()
        .unwrap()
        .credentials
        .get(&(PeerCredentialSlot::LinkToken, a_link_id.clone()))
        .cloned()
        .unwrap();

    // Seed B with:
    // - Export `/srv/media/movies` and `/srv/media/shows` for calling link A ("seedbox-1")
    // - Media mount `/mnt/af-peers/seedbox-1/ctrl-movies` -> `/srv/media/ctrl-movies`
    // - Media mount for another link (`other-peer`) at `/mnt/af-peers/other-peer/secret`
    {
        let conn = db_b.lock().unwrap();
        for (id, path) in [
            ("exp-movies", "/srv/media/movies"),
            ("exp-shows", "/srv/media/shows"),
        ] {
            db_peers::insert_peer_export(
                &conn,
                &PeerExport {
                    id: id.to_string(),
                    link_id: b_link_id.clone(),
                    path: path.to_string(),
                    writable: false,
                    squash_uid: Some(1000),
                    squash_gid: Some(1000),
                    created_at: now_str.clone(),
                },
            )
            .unwrap();
        }
        db_peers::insert_peer_mount(
            &conn,
            &PeerMount {
                id: "mnt-ctrl-movies".to_string(),
                link_id: b_link_id.clone(),
                remote_path: "/srv/media/ctrl-movies".to_string(),
                mount_path: "/mnt/af-peers/seedbox-1/ctrl-movies".to_string(),
                unit_name: "mnt-af\\x2dpeers-seedbox\\x2d1-ctrl\\x2dmovies.mount".to_string(),
                writable: false,
                purpose: "media".to_string(),
                state: "mounted".to_string(),
                last_error: None,
            },
        )
        .unwrap();
        // Insert an out-of-root remote_path row to prove controller-holds-media allowlist rejects
        // it BEFORE calling af-runner even if requested explicitly!
        db_peers::insert_peer_mount(
            &conn,
            &PeerMount {
                id: "mnt-bad-ssh".to_string(),
                link_id: b_link_id.clone(),
                remote_path: "/home/admin/.ssh".to_string(),
                mount_path: "/mnt/af-peers/seedbox-1/ssh-leak".to_string(),
                unit_name: "mnt-af\\x2dpeers-seedbox\\x2d1-ssh\\x2dleak.mount".to_string(),
                writable: false,
                purpose: "media".to_string(),
                state: "mounted".to_string(),
                last_error: None,
            },
        )
        .unwrap();
    }

    async fn post_mounts(
        rt: &Arc<PeerRuntime>,
        src_ip: IpAddr,
        ltok: &str,
        gtok: &str,
        content_type: Option<&str>,
        raw_body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let app = build_listener_router(Arc::clone(rt));
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/peer/v1/transcode/mounts")
            .header(HEADER_LINK_TOKEN, ltok)
            .header(HEADER_GRANT_TOKEN, gtok);
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        let mut req = builder.body(Body::from(raw_body)).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(src_ip, 50020)));
        let resp = app.oneshot(req).await.unwrap();
        let st = resp.status();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let val = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
        (st, val)
    }

    // 1. Structured PeerError JSON on wrong content-type (415) & malformed JSON (400)
    let (st, body) = post_mounts(
        &rt_b,
        ip_a,
        &link_token,
        &grant_token,
        Some("text/plain"),
        br#"{"action":"teardown"}"#.to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(body["code"], "UNSUPPORTED_MEDIA_TYPE");

    let (st, body) = post_mounts(
        &rt_b,
        ip_a,
        &link_token,
        &grant_token,
        Some("application/json"),
        b"{not-valid-json".to_vec(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_REQUEST");

    // 2. Worker allowlist rejects non-Jellyfin `transcode_paths` BEFORE calling af-runner!
    for bad_path in [
        "/tmp/evil",
        "/etc/jellyfin",
        "/home/admin/.ssh",
        "/var/spool/cron/crontabs",
        "/var/cache/jellyfin/nested/deep",
        "/var/cache/jellyfin-evil",
    ] {
        let payload = serde_json::to_vec(&json!({
            "action": "sync",
            "transcode_paths": [bad_path],
            "media_binds": []
        }))
        .unwrap();
        let (st, body) = post_mounts(
            &rt_b,
            ip_a,
            &link_token,
            &grant_token,
            Some("application/json"),
            payload,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "expected 400 for non-allowlisted transcode_path={bad_path}, got {body}"
        );
        assert_eq!(body["code"], "INVALID_REQUEST");
    }
    assert_eq!(
        tc_runner_b.count_action("mount_transcode_dirs"),
        0,
        "non-allowlisted transcode_paths must be rejected before calling af-runner"
    );

    // 3. Calling-link confinement rejects cross-link shadowing & prefix-overlap on worker-holds-media
    for bad_to in [
        "/mnt/af-peers/other-peer/movies",
        "/mnt/af-peers/seedbox-10/movies",
        "/mnt/af-peers/gpu-worker2/movies",
    ] {
        let payload = serde_json::to_vec(&json!({
            "action": "sync",
            "transcode_paths": ["/var/cache/jellyfin/transcodes"],
            "media_binds": [{ "from": "/srv/media/movies", "to": bad_to, "writable": false }]
        }))
        .unwrap();
        let (st, body) = post_mounts(
            &rt_b,
            ip_a,
            &link_token,
            &grant_token,
            Some("application/json"),
            payload,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "expected 400 for cross-link bind to={bad_to}, got {body}"
        );
        assert_eq!(body["code"], "INVALID_REQUEST");
    }
    assert_eq!(tc_runner_b.count_action("bind_media"), 0);

    // 4. Controller-holds-media rejects cross-link `from` AND out-of-root `to` targets
    for (bad_from, bad_to) in [
        ("/mnt/af-peers/other-peer/secret", "/srv/media/secret"),
        ("/mnt/af-peers/seedbox-10/movies", "/srv/media/movies"),
        ("/mnt/af-peers/seedbox-1/ssh-leak", "/home/admin/.ssh"),
        (
            "/mnt/af-peers/seedbox-1/ssh-leak",
            "/var/spool/cron/crontabs",
        ),
        ("/mnt/af-peers/seedbox-1/ssh-leak", "/etc/movies"),
        ("/mnt/af-peers/seedbox-1/ssh-leak", "/root/movies"),
    ] {
        let payload = serde_json::to_vec(&json!({
            "action": "sync",
            "transcode_paths": ["/var/cache/jellyfin/transcodes"],
            "media_binds": [{ "from": bad_from, "to": bad_to, "writable": false }]
        }))
        .unwrap();
        let (st, body) = post_mounts(
            &rt_b,
            ip_a,
            &link_token,
            &grant_token,
            Some("application/json"),
            payload,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "expected 400 for controller-holds-media bind {bad_from} -> {bad_to}, got {body}"
        );
        assert_eq!(body["code"], "INVALID_REQUEST");
    }
    assert_eq!(tc_runner_b.count_action("bind_media"), 0);

    // 5. Atomic rollback when `BindMedia` fails after `MountTranscodeDirs` succeeded!
    tc_runner_b.state.lock().unwrap().fail_next.insert(
        "bind_media",
        PeerTranscodeError::Runtime("bind mount unit failed".to_string()),
    );
    let sync_payload = serde_json::to_vec(&json!({
        "action": "sync",
        "transcode_paths": ["/var/cache/jellyfin/transcodes", "/var/cache/jellyfin/custom-sub"],
        "media_binds": [
            { "from": "/srv/media/movies", "to": "/mnt/af-peers/gpu-worker/movies", "writable": false },
            { "from": "/mnt/af-peers/seedbox-1/ctrl-movies", "to": "/srv/media/ctrl-movies", "writable": false }
        ]
    }))
    .unwrap();
    let (st, body) = post_mounts(
        &rt_b,
        ip_a,
        &link_token,
        &grant_token,
        Some("application/json"),
        sync_payload.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "got {body}");
    assert_eq!(
        tc_runner_b.count_action("mount_transcode_dirs"),
        1,
        "MountTranscodeDirs ran before BindMedia failed"
    );
    assert_eq!(
        tc_runner_b.count_action("remove_transcode_mounts"),
        1,
        "MountTranscodeDirs MUST be rolled back via RemoveTranscodeMounts when BindMedia fails"
    );
    let tc_rows_after_rb: Vec<PeerMount> =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .into_iter()
            .filter(|m| m.purpose == "transcode" || m.purpose == "transcode_bind")
            .collect();
    assert!(
        tc_rows_after_rb.is_empty(),
        "no orphan transcode DB rows may exist after BindMedia rollback: {tc_rows_after_rb:?}"
    );

    // 6. Atomic rollback when SQLite IMMEDIATE transaction fails mid-replace!
    db_b.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_tb_insert BEFORE INSERT ON peer_mounts
             WHEN NEW.purpose = 'transcode_bind'
             BEGIN
                 SELECT RAISE(ABORT, 'injected sqlite tx failure');
             END;",
        )
        .unwrap();
    let (st, body) = post_mounts(
        &rt_b,
        ip_a,
        &link_token,
        &grant_token,
        Some("application/json"),
        sync_payload.clone(),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "got {body}");
    // Rollback must undo BOTH applied BindMedia mounts AND newly mounted MountTranscodeDirs!
    assert_eq!(tc_runner_b.count_action("remove_bind_media"), 2);
    assert_eq!(tc_runner_b.count_action("remove_transcode_mounts"), 2);
    // And SQLite transaction must have rolled back the `transcode` inserts too (0 transcode rows)!
    let rows_after_db_fail: Vec<PeerMount> =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .into_iter()
            .filter(|m| m.purpose == "transcode" || m.purpose == "transcode_bind")
            .collect();
    assert!(
        rows_after_db_fail.is_empty(),
        "SQLite transaction must roll back cleanly on partial insert error: {rows_after_db_fail:?}"
    );

    // Drop the injected trigger and confirm valid sync succeeds & passes `calling_link_segment`
    // while auto-skipping the out-of-root `/home/admin/.ssh` media mount!
    db_b.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_tb_insert;")
        .unwrap();
    tc_runner_b.state.lock().unwrap().calls.clear();
    let (st, body) = post_mounts(
        &rt_b,
        ip_a,
        &link_token,
        &grant_token,
        Some("application/json"),
        sync_payload,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "valid sync failed: {body}");

    let bind_calls: Vec<(String, String, Option<String>)> = tc_runner_b
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter_map(|c| match c {
            PeerTranscodeRequest::BindMedia {
                from,
                to,
                calling_link_segment,
                ..
            } => Some((from.clone(), to.clone(), calling_link_segment.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        bind_calls,
        vec![
            (
                "/srv/media/movies".to_string(),
                "/mnt/af-peers/gpu-worker/movies".to_string(),
                Some("gpu-worker".to_string()),
            ),
            (
                "/mnt/af-peers/seedbox-1/ctrl-movies".to_string(),
                "/srv/media/ctrl-movies".to_string(),
                Some("seedbox-1".to_string()),
            ),
        ],
        "BindMedia must pass exact calling_link_segment and skip out-of-root auto-binds"
    );

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Bundle B(d): Dispatcher RunLocal Bypass for Network Inputs & Protocol Whitelist
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dispatcher_returns_run_local_for_network_inputs_without_contacting_worker() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_010_000);
    let tmp = ShortTempDir::new("net");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(204), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(205), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 21], 45021)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    let worker_sock = tmp.path.join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg.clone(), 4);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    let caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(caps.clone()));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, caps);
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 4,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    for args in [
        vec![
            "-i".into(),
            "https://live.example.test/stream.m3u8".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.ts".into(),
        ],
        vec![
            "-i".into(),
            "rtsp://camera.lan/live".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.ts".into(),
        ],
        vec![
            "-protocol_whitelist".into(),
            "file,http,https,tcp".into(),
            "-i".into(),
            "/srv/media/local.mkv".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.ts".into(),
        ],
    ] {
        clock.advance(1);
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec =
            run_shim_protocol(&args, &shim_cfg, stdin_fd.as_raw_fd(), &mut out, &mut err).await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "expected RunLocal bypass for args={args:?}"
        );
    }

    // Worker must NEVER have been contacted for any of the network-input jobs.
    let worker_audits = audit_actions_list(&db_b);
    assert!(
        !worker_audits.contains(&"peer_transcode_job_started".to_string()),
        "network-input jobs must bypass worker completely: {worker_audits:?}"
    );
    let jobs = wait_for_job_count(&db_a, 3).await;
    assert_eq!(jobs.len(), 3);
    assert!(jobs.iter().all(|j| j.ran_locally && j.link_id.is_none()));

    // Normal local file input MUST still dispatch remotely!
    clock.advance(1);
    let stdin_fd = make_stdin_pipe(b"");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let dec = run_shim_protocol(
        &[
            "-i".into(),
            "/srv/media/movie.mkv".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.mkv".into(),
        ],
        &shim_cfg,
        stdin_fd.as_raw_fd(),
        &mut out,
        &mut err,
    )
    .await;
    assert_eq!(dec, ShimDecision::RemoteExited(0));
    assert!(audit_actions_list(&db_b).contains(&"peer_transcode_job_started".to_string()));

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Bundle B(b) & R5-ESC-02: Controller Auto-Clamping to `worker_max_jobs`,
//     `has_updates_write_grant` Marketplace Parity, & 180s > 150s Mount Timeout
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn controller_clamps_job_slots_to_advertised_worker_max_jobs_and_aligns_updates_grant() {
    // R5-ESC-02: controller HTTP timeout must strictly exceed worker runner client timeout (150s).
    assert!(
        TRANSCODE_MOUNT_SYNC_TIMEOUT > af_runner::peer_transcode::TRANSCODE_MOUNT_CLIENT_TIMEOUT,
        "controller mount sync timeout ({:?}) must exceed worker runner client timeout ({:?})",
        TRANSCODE_MOUNT_SYNC_TIMEOUT,
        af_runner::peer_transcode::TRANSCODE_MOUNT_CLIENT_TIMEOUT
    );

    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_020_000);
    let tmp = ShortTempDir::new("cap");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(206), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(207), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 22], 45022)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    // Grant `transcoding: write` + `marketplace: write` (with `updates: none`) to test alignment!
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    access.marketplace = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    let mut remote_caps = local_caps.clone();
    remote_caps.worker_max_jobs = Some(2);
    assert_eq!(effective_worker_max_jobs(16, Some(&remote_caps)), 2);
    assert_eq!(effective_worker_max_jobs(1, Some(&remote_caps)), 1);
    assert_eq!(effective_worker_max_jobs(16, None), 16);

    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, remote_caps);
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 16,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    // GET /transcode exposes `worker_max_jobs: 2`, `effective_max_jobs: 2`, and `has_updates_write_grant: true`
    let (st, body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(st, StatusCode::OK);
    let w = &body["workers"][0];
    assert_eq!(w["max_jobs"], 16);
    assert_eq!(w["worker_max_jobs"], 2);
    assert_eq!(w["effective_max_jobs"], 2);
    assert_eq!(w["has_updates_write_grant"], true);
    assert_eq!(w["eligible"], true);

    // try_acquire_job_slot clamps configured max_jobs=16 down to advertised worker_max_jobs=2
    let g1 = rt_a
        .transcode_state
        .try_acquire_job_slot(&a_link_id, 16)
        .expect("slot 1");
    let g2 = rt_a
        .transcode_state
        .try_acquire_job_slot(&a_link_id, 16)
        .expect("slot 2");
    assert!(
        rt_a.transcode_state
            .try_acquire_job_slot(&a_link_id, 16)
            .is_none(),
        "3rd slot must be refused because worker advertised worker_max_jobs=2"
    );

    // Dispatcher must also skip the saturated worker and emit RunLocal
    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };
    let stdin_fd = make_stdin_pipe(b"");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let dec = run_shim_protocol(
        &[
            "-i".into(),
            "in.mkv".into(),
            "-c:v".into(),
            "libx264".into(),
            "out.mkv".into(),
        ],
        &shim_cfg,
        stdin_fd.as_raw_fd(),
        &mut out,
        &mut err,
    )
    .await;
    assert_eq!(
        dec,
        ShimDecision::ExecLocal {
            reason: LocalFallbackReason::DispatcherRunLocal
        }
    );

    drop(g1);
    drop(g2);
    stop_dispatcher(&rt_a).await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. Bundle B(a) & R3-ESC-01: Controller/Worker Toggle-Off Teardown,
//     Inbound Grant Mount Cleanup, & Revocation Error Propagation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn disable_teardown_inbound_grant_cleanup_and_revocation_error_propagation() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_030_000);
    let tmp = ShortTempDir::new("tear");
    let now_str = clock.now().to_rfc3339();

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(208), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(209), ip_b, 51821);
    let tc_runner_a = FakePeerTranscodeRunner::new_arc();
    let tc_runner_b = FakePeerTranscodeRunner::new_arc();

    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_b),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_a),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 23], 45023)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &now_str,
    );

    // Seed worker B with `transcode`, `transcode_bind`, AND a P7 `media` mount row, plus
    // controller A with an enabled `transcode_workers` row and running dispatcher.
    {
        let conn = db_b.lock().unwrap();
        for (id, purpose, mp) in [
            ("b-tc-1", "transcode", "/var/cache/jellyfin/transcodes"),
            (
                "b-tb-1",
                "transcode_bind",
                "/mnt/af-peers/gpu-worker/movies",
            ),
            ("b-media-1", "media", "/mnt/af-peers/seedbox-1/library"),
        ] {
            db_peers::insert_peer_mount(
                &conn,
                &PeerMount {
                    id: id.to_string(),
                    link_id: b_link_id.clone(),
                    remote_path: mp.to_string(),
                    mount_path: mp.to_string(),
                    unit_name: format!("{id}.mount"),
                    writable: purpose == "transcode",
                    purpose: purpose.to_string(),
                    state: "mounted".to_string(),
                    last_error: None,
                },
            )
            .unwrap();
        }
    }
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 2,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264"]"#.to_string()),
            render_node: None,
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();
    rt_a.transcode_state
        .set_dispatcher_socket_override(tmp.path.join("d.sock"));
    ensure_dispatcher_started(&rt_a).await.unwrap();

    // 1. Controller toggle-off (`enabled: false`) tears down exports on A AND sends remote
    //    teardown to B (removing B's transcode/bind mounts while leaving B's P7 media mount!)
    //    AND marks worker `enabled = false, parity_ok = false` on A.
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "disable failed: {body}");
    assert_eq!(tc_runner_a.count_action("disable_jellyfin"), 1);
    assert_eq!(tc_runner_a.count_action("remove_transcode_exports"), 1);
    assert_eq!(tc_runner_b.count_action("remove_bind_media"), 1);
    assert_eq!(tc_runner_b.count_action("remove_transcode_mounts"), 1);
    let a_worker = db_peers::get_transcode_worker(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert!(!a_worker.enabled);
    assert!(!a_worker.parity_ok);
    let b_remaining =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id).unwrap();
    assert_eq!(b_remaining.len(), 1);
    assert_eq!(b_remaining[0].purpose, "media");

    // 1b. Controller toggle-off (`enabled: false`) MUST still succeed (200 OK) and remove local
    //     exports + mark worker disabled/parity_ok=false when the remote worker is offline!
    {
        db_peers::upsert_transcode_worker(
            &db_a.lock().unwrap(),
            &af_db::peers::TranscodeWorker {
                link_id: a_link_id.clone(),
                enabled: true,
                weight: 1,
                max_jobs: 2,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264"]"#.to_string()),
                render_node: None,
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
        // Point A's tunnel port override for B at a dead port so remote teardown fails cleanly.
        let dead_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let saved_port = rt_a
            .tunnel_port_overrides
            .write()
            .unwrap()
            .insert(ip_b, dead_port);
        tc_runner_a.state.lock().unwrap().calls.clear();
        let (st, body) = call_admin(
            &rt_a,
            Method::PUT,
            "/transcode",
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "controller disable must remain non-fatal when remote worker is offline: {body}"
        );
        assert_eq!(tc_runner_a.count_action("remove_transcode_exports"), 1);
        let a_worker_offline = db_peers::get_transcode_worker(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .unwrap();
        assert!(!a_worker_offline.enabled);
        assert!(!a_worker_offline.parity_ok);
        // Restore tunnel port override for subsequent steps.
        if let Some(port) = saved_port {
            rt_a.tunnel_port_overrides
                .write()
                .unwrap()
                .insert(ip_b, port);
        }
    }

    // 2. Worker toggle-off (`worker_service_enabled: false`) tears down ALL local
    //    `transcode_bind` (first) and `transcode` (second) mounts BEFORE `RemoveWorkerUnit`!
    {
        let conn = db_b.lock().unwrap();
        for (id, purpose, mp) in [
            ("b-tc-2", "transcode", "/var/cache/jellyfin/transcodes"),
            (
                "b-tb-2",
                "transcode_bind",
                "/mnt/af-peers/gpu-worker/movies",
            ),
        ] {
            db_peers::insert_peer_mount(
                &conn,
                &PeerMount {
                    id: id.to_string(),
                    link_id: b_link_id.clone(),
                    remote_path: mp.to_string(),
                    mount_path: mp.to_string(),
                    unit_name: format!("{id}.mount"),
                    writable: purpose == "transcode",
                    purpose: purpose.to_string(),
                    state: "mounted".to_string(),
                    last_error: None,
                },
            )
            .unwrap();
        }
    }
    tc_runner_b.state.lock().unwrap().calls.clear();
    let (st, body) = call_admin(
        &rt_b,
        Method::PUT,
        "/transcode",
        Some(json!({ "worker_service_enabled": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "worker disable failed: {body}");
    let actions_b: Vec<&'static str> = tc_runner_b
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .map(FakePeerTranscodeRunner::action_name)
        .collect();
    let idx_bind = actions_b
        .iter()
        .position(|a| *a == "remove_bind_media")
        .expect("RemoveBindMedia must run");
    let idx_tc = actions_b
        .iter()
        .position(|a| *a == "remove_transcode_mounts")
        .expect("RemoveTranscodeMounts must run");
    let idx_unit = actions_b
        .iter()
        .position(|a| *a == "remove_worker_unit")
        .expect("RemoveWorkerUnit must run");
    assert!(
        idx_bind < idx_tc && idx_tc < idx_unit,
        "expected RemoveBindMedia < RemoveTranscodeMounts < RemoveWorkerUnit, got {actions_b:?}"
    );
    let b_remaining2 =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id).unwrap();
    assert_eq!(b_remaining2.len(), 1);
    assert_eq!(b_remaining2[0].purpose, "media");

    // 3. `cleanup_worker_transcode_mounts_for_link` tears down binds & transcode mounts on
    //    inbound `transcoding: write` revocation and leaves media mounts untouched.
    {
        let conn = db_b.lock().unwrap();
        for (id, purpose, mp) in [
            ("b-tc-3", "transcode", "/var/cache/jellyfin/transcodes"),
            (
                "b-tb-3",
                "transcode_bind",
                "/mnt/af-peers/gpu-worker/movies",
            ),
        ] {
            db_peers::insert_peer_mount(
                &conn,
                &PeerMount {
                    id: id.to_string(),
                    link_id: b_link_id.clone(),
                    remote_path: mp.to_string(),
                    mount_path: mp.to_string(),
                    unit_name: format!("{id}.mount"),
                    writable: purpose == "transcode",
                    purpose: purpose.to_string(),
                    state: "mounted".to_string(),
                    last_error: None,
                },
            )
            .unwrap();
        }
    }
    tc_runner_b.state.lock().unwrap().calls.clear();
    cleanup_worker_transcode_mounts_for_link(&rt_b, &b_link_id, "revoke_transcoding_grant")
        .await
        .expect("worker mount cleanup should succeed");
    assert_eq!(tc_runner_b.count_action("remove_bind_media"), 1);
    assert_eq!(tc_runner_b.count_action("remove_transcode_mounts"), 1);
    let b_remaining3 =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id).unwrap();
    assert_eq!(b_remaining3.len(), 1);
    assert_eq!(b_remaining3[0].purpose, "media");

    // 4. `cleanup_revoked_link_transcode_locked` MUST propagate runner failures as `Err(PeerError)`
    //    and retain retryable DB state until the retry succeeds and deletes the rows!
    tc_runner_a.state.lock().unwrap().fail_next.insert(
        "remove_transcode_exports",
        PeerTranscodeError::Runtime("exportfs busy".to_string()),
    );
    let err = cleanup_revoked_link_transcode_locked(&rt_a, &a_link_id, "revoke_link")
        .await
        .expect_err("runner error MUST propagate instead of being swallowed");
    assert_eq!(err.code(), "PEER_INTERNAL_ERROR");
    assert!(
        db_peers::get_transcode_worker(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_some(),
        "transcode_workers row must stay until RemoveTranscodeExports succeeds so retry works"
    );

    // Retry succeeds and deletes the `transcode_workers` row completely.
    cleanup_revoked_link_transcode_locked(&rt_a, &a_link_id, "revoke_link")
        .await
        .expect("retry cleanup should succeed");
    assert!(
        db_peers::get_transcode_worker(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_none(),
        "transcode_workers row must be deleted after cleanup succeeds"
    );

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. R3-ESC-03 & R5-ESC-01: Skip No-Op `transcode_workers` Upserts &
//     Dispatcher Reconciliation After Transient Boot `InspectJellyfinPaths` Error
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_caps_skips_noop_db_writes_and_reconcile_dispatcher_recovers_after_boot_error() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_040_000);
    let tmp = ShortTempDir::new("rec");

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(210), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(211), ip_b, 51821);
    let tc_runner_a = FakePeerTranscodeRunner::new_arc();
    let (rt_b, _db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&tc_runner_a),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 24], 45024)),
        }),
        &clock,
    );

    let (a_link_id, _, _) = pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let link = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();

    // 1. R3-ESC-03: Attach SQLite audit counter trigger on `transcode_workers` writes.
    db_a.lock()
        .unwrap()
        .execute_batch(
            "CREATE TABLE tc_write_counter (n INTEGER NOT NULL);
             INSERT INTO tc_write_counter VALUES (0);
             CREATE TRIGGER tc_ins AFTER INSERT ON transcode_workers
             BEGIN UPDATE tc_write_counter SET n = n + 1; END;
             CREATE TRIGGER tc_upd AFTER UPDATE ON transcode_workers
             BEGIN UPDATE tc_write_counter SET n = n + 1; END;",
        )
        .unwrap();

    let count_writes = || -> i64 {
        db_a.lock()
            .unwrap()
            .query_row("SELECT n FROM tc_write_counter", [], |r| r.get(0))
            .unwrap()
    };

    let caps_v1 = sample_caps(
        Some("8.1.3-1-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    // First sync inserts row -> 1 write.
    handle_remote_health_transcode_caps(&rt_a, &link, caps_v1.clone()).await;
    assert_eq!(count_writes(), 1);
    // Subsequent identical health ticks MUST skip SQLite write completely -> still 1 write!
    handle_remote_health_transcode_caps(&rt_a, &link, caps_v1.clone()).await;
    handle_remote_health_transcode_caps(&rt_a, &link, caps_v1).await;
    assert_eq!(
        count_writes(),
        1,
        "identical remote transcode capabilities must not trigger SQLite write transactions"
    );

    // Changed version DOES trigger update -> 2 writes.
    let caps_v2 = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.4-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    handle_remote_health_transcode_caps(&rt_a, &link, caps_v2).await;
    assert_eq!(count_writes(), 2);

    // 2. R5-ESC-01: Transient boot `InspectJellyfinPaths` error recovers cleanly on next reconcile!
    {
        let mut st = tc_runner_a.state.lock().unwrap();
        st.shim_installed = true;
        st.dropin_enabled = true;
        st.fail_next.insert(
            "inspect_jellyfin_paths",
            PeerTranscodeError::Runtime("runner socket not ready yet".to_string()),
        );
    }
    let disp_sock = tmp.path.join("disp.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    rt_a.transcode_state
        .set_local_capabilities_override(Some(sample_caps(
            Some("8.1.3-2-trixie"),
            Some("8.1.3-Jellyfin"),
            &["libx264"],
            &[],
        )));

    // Boot attempt fails transiently -> dispatcher stays inactive
    reconcile_dispatcher_if_configured(&rt_a).await;
    assert!(!rt_a.transcode_state.is_dispatcher_active().await);

    // Subsequent health tick retries -> dispatcher starts automatically!
    reconcile_dispatcher_if_configured(&rt_a).await;
    assert!(rt_a.transcode_state.is_dispatcher_active().await);
    assert!(disp_sock.exists());

    // Once active, further reconcile calls take the fast path with zero extra runner calls.
    let inspect_calls_before = tc_runner_a.count_action("inspect_jellyfin_paths");
    reconcile_dispatcher_if_configured(&rt_a).await;
    assert_eq!(
        tc_runner_a.count_action("inspect_jellyfin_paths"),
        inspect_calls_before
    );

    stop_dispatcher(&rt_a).await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. Load/Latency Scoring, Local PID Tracking, LocalFirst/Balanced Overflow,
//     Silicon Decoder & Cross-Backend Eligibility, Admin Settings & /health Load
// ─────────────────────────────────────────────────────────────────────────────

fn make_socket_subdir(base: &Path, name: &str) -> PathBuf {
    let dir = base.join(name);
    fs::create_dir_all(&dir).expect("create socket subdir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700 socket subdir");
    dir
}

fn spawn_real_worker_with_config(
    worker_sock: PathBuf,
    fake_ffmpeg: PathBuf,
    max_jobs: usize,
    adapt_mode: af_transcode::BackendAdaptMode,
    render_nodes_override: Option<Vec<af_hardware::RenderNode>>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let mut cfg = WorkerConfig::for_paths(worker_sock, fake_ffmpeg.clone());
    cfg.max_concurrent_jobs = max_jobs;
    cfg.socket_mode = DEFAULT_WORKER_SOCKET_MODE;
    cfg.adapt_backend_mode = adapt_mode;
    cfg.render_nodes_override = render_nodes_override;
    let bound = bind_worker_socket(&cfg).expect("bind real worker socket");
    let canonical_ffmpeg = fs::canonicalize(&fake_ffmpeg).expect("canonicalize fake ffmpeg");
    let (tx, mut rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _ = serve_worker_listener(bound, cfg, canonical_ffmpeg, async move {
            let _ = rx.changed().await;
        })
        .await;
    });
    (tx, task)
}

#[test]
fn score_worker_candidate_balances_weights_slots_load_and_rtt() {
    // 1. Saturated worker returns 0.
    assert_eq!(score_worker_candidate(50, 4, 4, None, None, true), 0);
    assert_eq!(score_worker_candidate(50, 6, 4, None, None, false), 0);

    // 2. Idle workers with no load telemetry and absent/LAN RTT preserve exact weight ratios.
    let s1 = score_worker_candidate(1, 0, 4, None, None, false);
    let s4 = score_worker_candidate(4, 0, 4, None, Some(0.4), false);
    assert_eq!(s1, 100);
    assert_eq!(s4, 400);
    assert_eq!(s4, s1 * 4);

    // 3. Busy worker (3/4) is penalized 4x compared to idle worker (0/4).
    let idle = score_worker_candidate(50, 0, 4, None, Some(1.0), true);
    let busy = score_worker_candidate(50, 3, 4, None, Some(1.0), true);
    assert_eq!(idle, 5000);
    assert_eq!(busy, 1250);

    // 4. High GPU load heavily penalizes HW jobs, while ignoring GPU load on SW jobs.
    let high_gpu_low_cpu = WorkerLoadSnapshot {
        cpu_usage_pct: Some(10.0),
        gpu_usage_pct: Some(95.0),
    };
    let low_gpu_low_cpu = WorkerLoadSnapshot {
        cpu_usage_pct: Some(10.0),
        gpu_usage_pct: Some(5.0),
    };
    let hw_hot = score_worker_candidate(50, 0, 4, Some(&high_gpu_low_cpu), Some(1.0), true);
    let hw_cool = score_worker_candidate(50, 0, 4, Some(&low_gpu_low_cpu), Some(1.0), true);
    assert!(
        hw_hot < hw_cool / 2,
        "high GPU load must strongly penalize HW job: hot={hw_hot}, cool={hw_cool}"
    );
    let sw_gpu_hot = score_worker_candidate(50, 0, 4, Some(&high_gpu_low_cpu), Some(1.0), false);
    let sw_gpu_cool = score_worker_candidate(50, 0, 4, Some(&low_gpu_low_cpu), Some(1.0), false);
    assert_eq!(
        sw_gpu_hot, sw_gpu_cool,
        "SW job scoring must depend on CPU, not GPU"
    );

    // 5. High CPU load penalizes SW jobs.
    let high_cpu = WorkerLoadSnapshot {
        cpu_usage_pct: Some(95.0),
        gpu_usage_pct: Some(0.0),
    };
    let sw_cpu_hot = score_worker_candidate(50, 0, 4, Some(&high_cpu), Some(1.0), false);
    assert!(
        sw_cpu_hot < sw_gpu_cool / 4,
        "high CPU load must heavily penalize SW job: hot={sw_cpu_hot}, cool={sw_gpu_cool}"
    );

    // 6. High WAN RTT (144 ms) is heavily penalized relative to LAN (0.4 ms).
    let lan = score_worker_candidate(50, 0, 4, None, Some(0.4), true);
    let mid = score_worker_candidate(50, 0, 4, None, Some(25.0), true);
    let wan = score_worker_candidate(50, 0, 4, None, Some(144.0), true);
    assert_eq!(lan, 5000);
    assert_eq!(mid, 4250);
    assert!(
        wan < lan / 5,
        "144ms WAN RTT must be heavily penalized vs 0.4ms LAN: wan={wan}, lan={lan}"
    );

    // 7. NaN/Inf load or RTT values never panic or produce 0 for a worker with free slots.
    let weird = WorkerLoadSnapshot {
        cpu_usage_pct: Some(f64::NAN),
        gpu_usage_pct: Some(f64::INFINITY),
    };
    assert_eq!(
        score_worker_candidate(10, 0, 2, Some(&weird), Some(f64::NAN), true),
        1000
    );
}

#[test]
fn balanced_local_baseline_weight_tracks_remote_configured_weights() {
    assert_eq!(balanced_local_baseline_weight(&[]), 1);
    assert_eq!(balanced_local_baseline_weight(&[1]), 1);
    assert_eq!(balanced_local_baseline_weight(&[1, 1]), 1);
    assert_eq!(balanced_local_baseline_weight(&[50]), 50);
    assert_eq!(balanced_local_baseline_weight(&[20, 80]), 50);
    assert_eq!(balanced_local_baseline_weight(&[1, 2]), 2);
    assert_eq!(balanced_local_baseline_weight(&[0, 500]), 51);
}

#[test]
fn try_claim_local_job_slot_enforces_cap_atomically_and_reclaims_exited_pids() {
    let state = TranscodeRuntimeState::new();
    let mut child1 = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .expect("spawn child1");
    let mut child2 = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .expect("spawn child2");
    let pid1 = child1.id() as i32;
    let pid2 = child2.id() as i32;

    assert!(!state.try_claim_local_job_slot(Some(pid1), 0));
    assert!(state.try_claim_local_job_slot(Some(pid1), 1));
    assert_eq!(state.prune_and_count_local_jobs(), 1);
    // Second concurrent PID must be denied atomically at local_max_jobs = 1.
    assert!(!state.try_claim_local_job_slot(Some(pid2), 1));
    assert_eq!(state.prune_and_count_local_jobs(), 1);

    let _ = child1.kill();
    let _ = child1.wait();
    // Once child1 exits, child2 can claim the freed slot atomically.
    assert!(state.try_claim_local_job_slot(Some(pid2), 1));
    assert_eq!(state.prune_and_count_local_jobs(), 1);

    let _ = child2.kill();
    let _ = child2.wait();
    assert_eq!(state.prune_and_count_local_jobs(), 0);
}

#[test]
fn proc_stat_parser_and_local_pid_tracking_prune_dead_children_and_ignore_self() {
    // Process name containing spaces and nested parentheses
    let sample = "4242 (ffmpeg (hdr)) S 1 4242 4242 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 987654321 123456 500";
    assert_eq!(
        parse_proc_stat_state_and_starttime(sample),
        Some(('S', 987654321))
    );

    let self_stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    let (self_state, self_start) =
        parse_proc_stat_state_and_starttime(&self_stat).expect("parse /proc/self/stat");
    assert!(matches!(self_state, 'R' | 'S'));
    assert!(self_start > 0);

    let state = TranscodeRuntimeState::new();
    // Must ignore self PID so in-process tests never pin the test runner.
    state.record_local_job_pid(Some(std::process::id() as i32));
    assert_eq!(state.prune_and_count_local_jobs(), 0);

    // Spawn a real child process, track its PID, confirm count == 1 while alive, then 0 after exit.
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("5")
        .spawn()
        .expect("spawn sleep child");
    let child_pid = child.id() as i32;
    state.record_local_job_pid(Some(child_pid));
    assert_eq!(state.prune_and_count_local_jobs(), 1);

    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(state.prune_and_count_local_jobs(), 0);
}

#[tokio::test]
async fn local_first_and_balanced_dispatch_policies_overflow_and_load_balance() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_050_000);
    let tmp = ShortTempDir::new("pol");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(214), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(215), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 25], 45025)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "jellyfin-main",
        access,
        &clock.now().to_rfc3339(),
    );

    let worker_sock = make_socket_subdir(&tmp.path, "w").join("w.sock");
    let (w_stop, w_task) = spawn_real_worker(worker_sock.clone(), fake_ffmpeg.clone(), 8);
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    let mut local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    local_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    let mut remote_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    remote_caps.hw_decoders = vec!["h264".into(), "hevc".into(), "av1".into()];

    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_a.transcode_state
        .set_local_load_override(Some(WorkerLoadSnapshot {
            cpu_usage_pct: Some(10.0),
            gpu_usage_pct: Some(10.0),
        }));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, remote_caps);
    rt_a.transcode_state.record_remote_load(
        &a_link_id,
        WorkerLoadSnapshot {
            cpu_usage_pct: Some(10.0),
            gpu_usage_pct: Some(10.0),
        },
    );
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 50,
            max_jobs: 4,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264","h264_vaapi"]"#.to_string()),
            render_node: Some("/dev/dri/renderD128".to_string()),
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let disp_sock = tmp.path.join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // 1. Configure `local_first` with `local_max_jobs = 2` via Admin PUT.
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "dispatch_policy": "local_first", "local_max_jobs": 2 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT local_first failed: {body}");
    assert_eq!(body["dispatch_policy"], "local_first");
    assert_eq!(body["local_max_jobs"], 2);

    // Below local_max_jobs (0 and 1): dispatches locally without touching worker!
    for active in [0usize, 1usize] {
        rt_a.transcode_state
            .set_local_active_jobs_override(Some(active));
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "movie.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "local_first with local_active={active} < 2 must run locally"
        );
    }
    assert!(
        !audit_actions_list(&db_b).contains(&"peer_transcode_job_started".to_string()),
        "local_first below capacity must not contact remote worker"
    );

    // At local_max_jobs (2 >= 2): overflows cleanly to remote worker!
    rt_a.transcode_state.set_local_active_jobs_override(Some(2));
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "movie.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::RemoteExited(0),
            "local_first at local_active=2 >= local_max_jobs must overflow to remote worker"
        );
    }

    // Even at local_active=0, if local lacks AV1 HW decode while remote has AV1, overflow to remote!
    rt_a.transcode_state.set_local_active_jobs_override(Some(0));
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-hwaccel".into(),
                "vaapi".into(),
                "-c:v".into(),
                "av1".into(),
                "-i".into(),
                "av1_movie.mkv".into(),
                "-c:v".into(),
                "h264_vaapi".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::RemoteExited(0),
            "local_first must overflow to remote worker when local lacks required hw_decoder"
        );
    }

    // 2. Switch to `balanced` policy: both local and remote are considered when local has free slots.
    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "dispatch_policy": "balanced", "local_max_jobs": 2 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT balanced failed: {body}");
    assert_eq!(body["dispatch_policy"], "balanced");

    rt_a.transcode_state.set_local_active_jobs_override(Some(0));
    let mut local_hits = 0usize;
    let mut remote_hits = 0usize;
    for _ in 0..40 {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "movie.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        match dec {
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal,
            } => local_hits += 1,
            ShimDecision::RemoteExited(0) => remote_hits += 1,
            other => panic!("unexpected balanced decision: {other:?}"),
        }
    }
    assert!(
        local_hits > 0 && remote_hits > 0,
        "balanced mode with equal weights must dispatch to both local ({local_hits}) and remote ({remote_hits})"
    );

    // Balanced with default worker weight = 1 must also distribute evenly (no 98% local bias).
    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 1,
            max_jobs: 4,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264","h264_vaapi"]"#.to_string()),
            render_node: Some("/dev/dri/renderD128".to_string()),
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();
    let mut default_w_local_hits = 0usize;
    let mut default_w_remote_hits = 0usize;
    for _ in 0..40 {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "movie.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        match dec {
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal,
            } => default_w_local_hits += 1,
            ShimDecision::RemoteExited(0) => default_w_remote_hits += 1,
            other => panic!("unexpected default-weight balanced decision: {other:?}"),
        }
    }
    assert!(
        default_w_local_hits > 0 && default_w_remote_hits >= 5,
        "balanced mode with default weight=1 must share work with remote worker (local={default_w_local_hits}, remote={default_w_remote_hits})"
    );

    // Balanced with saturated local_active >= local_max_jobs must route exclusively remote.
    rt_a.transcode_state.set_local_active_jobs_override(Some(2));
    for _ in 0..5 {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &[
                "-i".into(),
                "movie.mkv".into(),
                "-c:v".into(),
                "libx264".into(),
                "out.mkv".into(),
            ],
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
    }

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn silicon_hw_decoders_and_cross_backend_adaptation_eligibility() {
    let ips = next_transcode_loopback_ips(4);
    let (ip_ctrl, ip_hd630, ip_rdna2, ip_cpu) = (ips[0], ips[1], ips[2], ips[3]);
    let clock = TestClock::new(1_801_060_000);
    let tmp = ShortTempDir::new("adpt");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_ctrl = FakePeerRunner::new(fixture_wg_pubkey(216), ip_ctrl, 51821);
    let runner_hd630 = FakePeerRunner::new(fixture_wg_pubkey(217), ip_hd630, 51821);
    let runner_rdna2 = FakePeerRunner::new(fixture_wg_pubkey(218), ip_rdna2, 51821);
    let runner_cpu = FakePeerRunner::new(fixture_wg_pubkey(219), ip_cpu, 51821);

    let (rt_hd630, db_hd630) = build_transcode_runtime(
        "worker-hd630",
        Arc::clone(&runner_hd630) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_rdna2, db_rdna2) = build_transcode_runtime(
        "worker-rdna2",
        Arc::clone(&runner_rdna2) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_cpu, db_cpu) = build_transcode_runtime(
        "worker-cpu",
        Arc::clone(&runner_cpu) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_ctrl, db_ctrl) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_ctrl) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_hd630),
            client_ip: SocketAddr::from(([198, 51, 100, 26], 45026)),
        }),
        &clock,
    );

    let (ctrl_hd630_id, hd630_ctrl_id, _) =
        pair_two_test_runtimes(&rt_ctrl, &rt_hd630, ip_ctrl, ip_hd630, "worker-hd630").await;

    // Helper to directly wire additional paired worker nodes to rt_ctrl.
    let now_str = clock.now().to_rfc3339();
    let wire_extra_worker = |rt_w: &Arc<PeerRuntime>,
                             db_w: &Arc<StdMutex<Connection>>,
                             ip_w: IpAddr,
                             pubkey_seed: u8,
                             name: &str| {
        let rt_ctrl_c = Arc::clone(&rt_ctrl);
        let db_ctrl_c = Arc::clone(&db_ctrl);
        let runner_ctrl_c = Arc::clone(&runner_ctrl);
        let rt_w_c = Arc::clone(rt_w);
        let db_w_c = Arc::clone(db_w);
        let now_s = now_str.clone();
        let name_s = name.to_string();
        async move {
            let ctrl_lid = format!("link-{}", Uuid::new_v4().simple());
            let w_lid = format!("link-{}", Uuid::new_v4().simple());
            let ltok = format!("ltok-{}", Uuid::new_v4().simple());
            let handle = spawn_tunnel_listener(Arc::clone(&rt_w_c), ip_w, 0, None)
                .await
                .expect("spawn extra worker listener");
            let port = handle.bound_addr.port();
            *rt_w_c.listener_state.lock().await = Some(handle);
            rt_ctrl_c
                .tunnel_port_overrides
                .write()
                .unwrap()
                .insert(ip_w, port);
            {
                let conn = db_w_c.lock().unwrap();
                db_peers::upsert_peer_identity(
                    &conn,
                    &af_db::peers::PeerIdentity {
                        wg_pubkey: fixture_wg_pubkey(pubkey_seed),
                        tunnel_ip: ip_w.to_string(),
                        wg_port: 51821,
                        created_at: now_s.clone(),
                    },
                )
                .unwrap();
                db_peers::insert_peer_link(
                    &conn,
                    &af_db::peers::PeerLink {
                        id: w_lid.clone(),
                        name: "jellyfin-main".to_string(),
                        wg_pubkey: fixture_wg_pubkey(216),
                        tunnel_ip: ip_ctrl.to_string(),
                        endpoint: "10.90.0.1".to_string(),
                        wg_port: 51821,
                        state: "active".to_string(),
                        peer_version: Some("4.0.0-p9-test".to_string()),
                        peer_protocol: Some(1),
                        capabilities: Some(
                            r#"["links","grants","storage","transcode"]"#.to_string(),
                        ),
                        rtt_ms: Some(1.0),
                        last_ok_at: Some(now_s.clone()),
                        last_error: None,
                        consecutive_failures: 0,
                        inbound_token_hash: Some(sha256_prefixed(&ltok)),
                        pending_attempt_id: None,
                        pending_expires_at: None,
                        created_at: now_s.clone(),
                        updated_at: now_s.clone(),
                    },
                )
                .unwrap();
            }
            {
                let conn = db_ctrl_c.lock().unwrap();
                db_peers::insert_peer_link(
                    &conn,
                    &af_db::peers::PeerLink {
                        id: ctrl_lid.clone(),
                        name: name_s,
                        wg_pubkey: fixture_wg_pubkey(pubkey_seed),
                        tunnel_ip: ip_w.to_string(),
                        endpoint: "10.90.0.9".to_string(),
                        wg_port: 51821,
                        state: "active".to_string(),
                        peer_version: Some("4.0.0-p9-test".to_string()),
                        peer_protocol: Some(1),
                        capabilities: Some(
                            r#"["links","grants","storage","transcode"]"#.to_string(),
                        ),
                        rtt_ms: Some(1.0),
                        last_ok_at: Some(now_s.clone()),
                        last_error: None,
                        consecutive_failures: 0,
                        inbound_token_hash: None,
                        pending_attempt_id: None,
                        pending_expires_at: None,
                        created_at: now_s.clone(),
                        updated_at: now_s.clone(),
                    },
                )
                .unwrap();
            }
            runner_ctrl_c
                .state
                .lock()
                .unwrap()
                .credentials
                .insert((PeerCredentialSlot::LinkToken, ctrl_lid.clone()), ltok);
            let mut write_access = AccessMap::none();
            write_access.transcoding = af_db::peers::AccessLevel::Write;
            install_transcode_grant_pair(
                &db_ctrl_c,
                &runner_ctrl_c,
                &ctrl_lid,
                &db_w_c,
                &w_lid,
                "jellyfin-main",
                write_access,
                &now_s,
            );
            (ctrl_lid, w_lid)
        }
    };

    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_ctrl,
        &runner_ctrl,
        &ctrl_hd630_id,
        &db_hd630,
        &hd630_ctrl_id,
        "jellyfin-main",
        write_access,
        &now_str,
    );
    let (ctrl_rdna2_id, _) =
        wire_extra_worker(&rt_rdna2, &db_rdna2, ip_rdna2, 218, "worker-rdna2").await;
    let (ctrl_cpu_id, _) = wire_extra_worker(&rt_cpu, &db_cpu, ip_cpu, 219, "worker-cpu").await;

    let hd630_sock = make_socket_subdir(&tmp.path, "hd").join("w.sock");
    let rdna2_sock = make_socket_subdir(&tmp.path, "rd").join("w.sock");
    let cpu_sock = make_socket_subdir(&tmp.path, "cp").join("w.sock");
    let (hd_stop, hd_task) = spawn_real_worker_with_config(
        hd630_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x8086".to_string()),
        }]),
    );
    let (rd_stop, rd_task) = spawn_real_worker_with_config(
        rdna2_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Gpu,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
    );
    let (cp_stop, cp_task) = spawn_real_worker_with_config(
        cpu_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::All,
        Some(vec![]),
    );
    rt_hd630
        .transcode_state
        .set_worker_socket_override(hd630_sock);
    rt_rdna2
        .transcode_state
        .set_worker_socket_override(rdna2_sock);
    rt_cpu.transcode_state.set_worker_socket_override(cpu_sock);

    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_qsv"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let mut hd630_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_qsv"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    hd630_caps.hw_decoders = vec!["h264".into(), "hevc".into(), "vp9".into()];
    hd630_caps.hw_encoders_verified = true;

    let mut rdna2_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    rdna2_caps.hw_decoders = vec!["h264".into(), "hevc".into(), "vp9".into(), "av1".into()];
    rdna2_caps.hw_encoders_verified = true;
    rdna2_caps.adapt_backend_mode = None; // Start Off

    let mut cpu_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264"],
        &[],
    );
    cpu_caps.adapt_backend_mode = Some(af_transcode::BackendAdaptMode::Gpu); // Not All yet

    rt_ctrl
        .transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_hd630_id, hd630_caps.clone());
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_rdna2_id, rdna2_caps.clone());
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_cpu_id, cpu_caps.clone());

    {
        let conn = db_ctrl.lock().unwrap();
        for (lid, encs, node, weight) in [
            (
                &ctrl_hd630_id,
                r#"["libx264","h264_vaapi","h264_qsv"]"#,
                Some("/dev/dri/renderD128"),
                100i64,
            ),
            (
                &ctrl_rdna2_id,
                r#"["libx264","h264_vaapi"]"#,
                Some("/dev/dri/renderD128"),
                10i64,
            ),
            (&ctrl_cpu_id, r#"["libx264"]"#, None, 10i64),
        ] {
            db_peers::upsert_transcode_worker(
                &conn,
                &af_db::peers::TranscodeWorker {
                    link_id: lid.clone(),
                    enabled: true,
                    weight,
                    max_jobs: 4,
                    ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                    encoders: Some(encs.to_string()),
                    render_node: node.map(ToString::to_string),
                    parity_ok: true,
                    parity_error: None,
                },
            )
            .unwrap();
        }
    }

    let disp_sock = make_socket_subdir(&tmp.path, "dp").join("d.sock");
    rt_ctrl
        .transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_ctrl).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // Case 1: AV1 HW decode job skips HD 630 (weight=100, lacks "av1") and picks RDNA 2 (has "av1").
    let av1_args: Vec<String> = vec![
        "-hwaccel".into(),
        "vaapi".into(),
        "-c:v".into(),
        "av1".into(),
        "-i".into(),
        "av1.mkv".into(),
        "-c:v".into(),
        "h264_vaapi".into(),
        "out.mkv".into(),
    ];
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &av1_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let jobs = wait_for_job_count(&db_ctrl, 1).await;
        assert_eq!(
            jobs[0].link_id.as_deref(),
            Some(ctrl_rdna2_id.as_str()),
            "AV1 HW decode must skip HD 630 and route to RDNA 2"
        );
    }

    // Case 2: Backward compatibility — older worker reporting empty `hw_decoders: []` remains eligible!
    db_ctrl
        .lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET enabled = 0 WHERE link_id = ?1",
            rusqlite::params![ctrl_rdna2_id],
        )
        .unwrap();
    let mut legacy_hd630 = hd630_caps.clone();
    legacy_hd630.hw_decoders = Vec::new();
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_hd630_id, legacy_hd630);
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &av1_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let jobs = wait_for_job_count(&db_ctrl, 2).await;
        assert_eq!(
            jobs[0].link_id.as_deref(),
            Some(ctrl_hd630_id.as_str()),
            "older worker with empty hw_decoders must stay backward-compatible"
        );
    }

    // Case 3: Cross-backend adaptation for QSV job!
    // Disable HD 630 (Intel QSV) and re-enable RDNA 2 (AMD VA-API) + CPU-only worker.
    {
        let conn = db_ctrl.lock().unwrap();
        conn.execute(
            "UPDATE transcode_workers SET enabled = 0 WHERE link_id = ?1",
            rusqlite::params![ctrl_hd630_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE transcode_workers SET enabled = 1 WHERE link_id = ?1",
            rusqlite::params![ctrl_rdna2_id],
        )
        .unwrap();
    }
    let qsv_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "qsv=qs:/dev/dri/renderD128".into(),
        "-hwaccel".into(),
        "qsv".into(),
        "-i".into(),
        "movie.mkv".into(),
        "-c:v".into(),
        "h264_qsv".into(),
        "out.mkv".into(),
    ];

    // 3a. RDNA 2 has adapt_backend_mode = None (Off) and CPU has Gpu -> NEITHER eligible -> RunLocal!
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &qsv_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "QSV job must skip AMD worker when adapt_backend_mode is Off"
        );
    }

    // 3b. Enable adapt_backend_mode = Some(Gpu) on RDNA 2 -> selected and adapted to h264_vaapi!
    rdna2_caps.adapt_backend_mode = Some(af_transcode::BackendAdaptMode::Gpu);
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_rdna2_id, rdna2_caps);
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &qsv_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let stderr_str = String::from_utf8_lossy(&err);
        assert!(
            stderr_str.contains("h264_vaapi"),
            "AMD worker should adapt QSV job to h264_vaapi, got stderr: {stderr_str}"
        );
        let jobs = wait_for_job_count(&db_ctrl, 4).await;
        assert_eq!(jobs[0].link_id.as_deref(), Some(ctrl_rdna2_id.as_str()));
    }

    // 3c. Disable RDNA 2, enable adapt_backend_mode = Some(All) on CPU-only worker -> overflows to CPU!
    db_ctrl
        .lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET enabled = 0 WHERE link_id = ?1",
            rusqlite::params![ctrl_rdna2_id],
        )
        .unwrap();
    cpu_caps.adapt_backend_mode = Some(af_transcode::BackendAdaptMode::All);
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_cpu_id, cpu_caps);
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &qsv_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let stderr_str = String::from_utf8_lossy(&err);
        assert!(
            stderr_str.contains("libx264"),
            "CPU worker with adapt_backend_mode=All should adapt QSV job to libx264, got stderr: {stderr_str}"
        );
        let jobs = wait_for_job_count(&db_ctrl, 5).await;
        assert_eq!(jobs[0].link_id.as_deref(), Some(ctrl_cpu_id.as_str()));
    }

    stop_dispatcher(&rt_ctrl).await;
    let _ = hd_stop.send(true);
    let _ = rd_stop.send(true);
    let _ = cp_stop.send(true);
    let _ = hd_task.await;
    let _ = rd_task.await;
    let _ = cp_task.await;
    rt_ctrl.shutdown_all().await;
    rt_hd630.shutdown_all().await;
    rt_rdna2.shutdown_all().await;
    rt_cpu.shutdown_all().await;
}

#[tokio::test]
async fn admin_transcode_policy_roundtrip_validation_and_health_load_telemetry() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_070_000);

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(224), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(225), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 27], 45027)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    let mut local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    local_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    local_caps.hw_encoders_verified = true;
    local_caps.adapt_backend_mode = Some(af_transcode::BackendAdaptMode::PreferQsv);

    let mut worker_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    worker_caps.hw_decoders = vec!["h264".into(), "hevc".into(), "av1".into()];
    worker_caps.hw_encoders_verified = true;
    worker_caps.adapt_backend_mode = Some(af_transcode::BackendAdaptMode::Gpu);

    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_a.transcode_state
        .set_local_load_override(Some(WorkerLoadSnapshot {
            cpu_usage_pct: Some(18.5),
            gpu_usage_pct: Some(22.0),
        }));
    rt_a.transcode_state.set_local_active_jobs_override(Some(1));

    rt_b.transcode_state
        .set_local_capabilities_override(Some(worker_caps));
    rt_b.transcode_state
        .set_local_load_override(Some(WorkerLoadSnapshot {
            cpu_usage_pct: Some(42.5),
            gpu_usage_pct: Some(71.0),
        }));

    // 1. Health tick polls worker's tunnel GET /health and populates remote load + capabilities!
    run_health_tick(&rt_a).await;
    assert_eq!(
        rt_a.transcode_state.remote_load_for(&a_link_id),
        Some(WorkerLoadSnapshot {
            cpu_usage_pct: Some(42.5),
            gpu_usage_pct: Some(71.0),
        })
    );

    // 2. GET /api/v1/admin/peers/transcode returns defaults + full local/worker telemetry fields.
    let (st, body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(st, StatusCode::OK, "GET /transcode failed: {body}");
    assert_eq!(body["dispatch_policy"], "remote_first");
    assert_eq!(body["local_max_jobs"], 2);
    assert_eq!(body["local_active_jobs"], 1);
    assert_eq!(body["local"]["hw_decoders"], json!(["h264", "hevc"]));
    assert_eq!(body["local"]["hw_encoders_verified"], true);
    assert_eq!(body["local"]["adapt_backend_mode"], "prefer_qsv");
    assert_eq!(body["local"]["cpu_usage_pct"], 18.5);
    assert_eq!(body["local"]["gpu_usage_pct"], 22.0);

    let w = &body["workers"][0];
    assert_eq!(w["hw_decoders"], json!(["h264", "hevc", "av1"]));
    assert_eq!(w["hw_encoders_verified"], true);
    assert_eq!(w["adapt_backend_mode"], "gpu");
    assert_eq!(w["cpu_usage_pct"], 42.5);
    assert_eq!(w["gpu_usage_pct"], 71.0);
    assert!(
        w["rtt_ms"].as_f64().is_some(),
        "expected finite rtt_ms on worker view: {w}"
    );

    // 3. Partial & full PUT round-trip preserves untouched field and writes audit entry.
    let (st, p1) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "dispatch_policy": "local_first" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT policy-only failed: {p1}");
    assert_eq!(p1["dispatch_policy"], "local_first");
    assert_eq!(p1["local_max_jobs"], 2);

    let (st, p2) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "local_max_jobs": 5 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT local_max_jobs-only failed: {p2}");
    assert_eq!(p2["dispatch_policy"], "local_first");
    assert_eq!(p2["local_max_jobs"], 5);

    let (st, p3) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "dispatch_policy": "balanced", "local_max_jobs": 3 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT both failed: {p3}");
    assert_eq!(p3["dispatch_policy"], "balanced");
    assert_eq!(p3["local_max_jobs"], 3);

    let audits = audit_actions_list(&db_a);
    assert_eq!(
        audits
            .iter()
            .filter(|a| a.as_str() == "peer_transcode_policy_updated")
            .count(),
        3
    );

    // 4. Invalid dispatch_policy and out-of-range local_max_jobs return 400 INVALID_REQUEST
    //    and leave persisted settings untouched.
    for bad in [
        json!({ "dispatch_policy": "bogus_policy" }),
        json!({ "dispatch_policy": "" }),
        json!({ "local_max_jobs": 0 }),
        json!({ "local_max_jobs": -2 }),
        json!({ "local_max_jobs": 65 }),
    ] {
        let (bad_st, bad_body) = call_admin(&rt_a, Method::PUT, "/transcode", Some(bad)).await;
        assert_eq!(bad_st, StatusCode::BAD_REQUEST, "expected 400: {bad_body}");
        assert_eq!(bad_body["code"], "INVALID_REQUEST");
    }
    let (st, after_bad) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(after_bad["dispatch_policy"], "balanced");
    assert_eq!(after_bad["local_max_jobs"], 3);

    // 5. clear_link_state removes cached remote_load as well.
    rt_a.transcode_state.clear_link_state(&a_link_id);
    assert_eq!(rt_a.transcode_state.remote_load_for(&a_link_id), None);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. Separated Vulkan Compute vs. Vulkan Video Routing & Admin API Views
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn spawn_real_worker_with_vulkan_config(
    worker_sock: PathBuf,
    fake_ffmpeg: PathBuf,
    max_jobs: usize,
    adapt_mode: af_transcode::BackendAdaptMode,
    render_nodes_override: Option<Vec<af_hardware::RenderNode>>,
    vulkan_compute: bool,
    vulkan_video: bool,
    capabilities_override: Option<TranscodeCapabilities>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let mut cfg = WorkerConfig::for_paths(worker_sock, fake_ffmpeg.clone());
    cfg.max_concurrent_jobs = max_jobs;
    cfg.socket_mode = DEFAULT_WORKER_SOCKET_MODE;
    cfg.adapt_backend_mode = adapt_mode;
    cfg.render_nodes_override = render_nodes_override;
    cfg.vulkan_compute = vulkan_compute;
    cfg.vulkan_video = vulkan_video;
    cfg.capabilities_override = capabilities_override;
    let bound = bind_worker_socket(&cfg).expect("bind real worker socket");
    let canonical_ffmpeg = fs::canonicalize(&fake_ffmpeg).expect("canonicalize fake ffmpeg");
    let (tx, mut rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _ = serve_worker_listener(bound, cfg, canonical_ffmpeg, async move {
            let _ = rx.changed().await;
        })
        .await;
    });
    (tx, task)
}

#[allow(clippy::too_many_arguments)]
async fn wire_extra_transcode_worker(
    rt_ctrl: &Arc<PeerRuntime>,
    db_ctrl: &Arc<StdMutex<Connection>>,
    runner_ctrl: &Arc<FakePeerRunner>,
    ip_ctrl: IpAddr,
    ctrl_pubkey_seed: u8,
    rt_w: &Arc<PeerRuntime>,
    db_w: &Arc<StdMutex<Connection>>,
    ip_w: IpAddr,
    worker_pubkey_seed: u8,
    worker_name: &str,
    now_rfc3339: &str,
) -> (String, String) {
    let ctrl_lid = format!("link-{}", Uuid::new_v4().simple());
    let w_lid = format!("link-{}", Uuid::new_v4().simple());
    let ltok = format!("ltok-{}", Uuid::new_v4().simple());
    let handle = spawn_tunnel_listener(Arc::clone(rt_w), ip_w, 0, None)
        .await
        .expect("spawn extra worker listener");
    let port = handle.bound_addr.port();
    *rt_w.listener_state.lock().await = Some(handle);
    rt_ctrl
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_w, port);
    {
        let conn = db_w.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &af_db::peers::PeerIdentity {
                wg_pubkey: fixture_wg_pubkey(worker_pubkey_seed),
                tunnel_ip: ip_w.to_string(),
                wg_port: 51821,
                created_at: now_rfc3339.to_string(),
            },
        )
        .unwrap();
        db_peers::insert_peer_link(
            &conn,
            &af_db::peers::PeerLink {
                id: w_lid.clone(),
                name: "jellyfin-main".to_string(),
                wg_pubkey: fixture_wg_pubkey(ctrl_pubkey_seed),
                tunnel_ip: ip_ctrl.to_string(),
                endpoint: "10.90.0.1".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0-p9-test".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_rfc3339.to_string()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: Some(sha256_prefixed(&ltok)),
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: now_rfc3339.to_string(),
                updated_at: now_rfc3339.to_string(),
            },
        )
        .unwrap();
    }
    {
        let conn = db_ctrl.lock().unwrap();
        db_peers::insert_peer_link(
            &conn,
            &af_db::peers::PeerLink {
                id: ctrl_lid.clone(),
                name: worker_name.to_string(),
                wg_pubkey: fixture_wg_pubkey(worker_pubkey_seed),
                tunnel_ip: ip_w.to_string(),
                endpoint: "10.90.0.9".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0-p9-test".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links","grants","storage","transcode"]"#.to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_rfc3339.to_string()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: now_rfc3339.to_string(),
                updated_at: now_rfc3339.to_string(),
            },
        )
        .unwrap();
    }
    runner_ctrl
        .state
        .lock()
        .unwrap()
        .credentials
        .insert((PeerCredentialSlot::LinkToken, ctrl_lid.clone()), ltok);
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        db_ctrl,
        runner_ctrl,
        &ctrl_lid,
        db_w,
        &w_lid,
        "jellyfin-main",
        write_access,
        now_rfc3339,
    );
    (ctrl_lid, w_lid)
}

#[tokio::test]
async fn vulkan_compute_libplacebo_routing_skips_disabled_worker_and_preserves_non_video_worker() {
    let ips = next_transcode_loopback_ips(3);
    let (ip_ctrl, ip_no_vk, ip_vk_compute) = (ips[0], ips[1], ips[2]);
    let clock = TestClock::new(1_801_080_000);
    let tmp = ShortTempDir::new("vkc");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_ctrl = FakePeerRunner::new(fixture_wg_pubkey(230), ip_ctrl, 51821);
    let runner_no_vk = FakePeerRunner::new(fixture_wg_pubkey(231), ip_no_vk, 51821);
    let runner_vk_compute = FakePeerRunner::new(fixture_wg_pubkey(232), ip_vk_compute, 51821);

    let (rt_no_vk, db_no_vk) = build_transcode_runtime(
        "worker-no-vk",
        Arc::clone(&runner_no_vk) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_vk_compute, db_vk_compute) = build_transcode_runtime(
        "worker-vk-compute",
        Arc::clone(&runner_vk_compute) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_ctrl, db_ctrl) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_ctrl) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_no_vk),
            client_ip: SocketAddr::from(([198, 51, 100, 28], 45028)),
        }),
        &clock,
    );

    let (ctrl_no_vk_id, no_vk_ctrl_id, _) =
        pair_two_test_runtimes(&rt_ctrl, &rt_no_vk, ip_ctrl, ip_no_vk, "worker-no-vk").await;
    let now_str = clock.now().to_rfc3339();
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_ctrl,
        &runner_ctrl,
        &ctrl_no_vk_id,
        &db_no_vk,
        &no_vk_ctrl_id,
        "jellyfin-main",
        write_access,
        &now_str,
    );
    let (ctrl_vk_compute_id, _) = wire_extra_transcode_worker(
        &rt_ctrl,
        &db_ctrl,
        &runner_ctrl,
        ip_ctrl,
        230,
        &rt_vk_compute,
        &db_vk_compute,
        ip_vk_compute,
        232,
        "worker-vk-compute",
        &now_str,
    )
    .await;

    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let mut no_vk_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    no_vk_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    no_vk_caps.hw_encoders_verified = true;
    no_vk_caps.vulkan_compute = Some(false);
    no_vk_caps.vulkan_video = Some(false);

    let mut vk_compute_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    vk_compute_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    vk_compute_caps.hw_encoders_verified = true;
    vk_compute_caps.vulkan_compute = Some(true);
    vk_compute_caps.vulkan_device = Some("AMD Radeon Graphics".to_string());
    vk_compute_caps.vulkan_video = Some(false);

    let no_vk_sock = make_socket_subdir(&tmp.path, "nv").join("w.sock");
    let vk_compute_sock = make_socket_subdir(&tmp.path, "vc").join("w.sock");
    let (nv_stop, nv_task) = spawn_real_worker_with_vulkan_config(
        no_vk_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        false,
        false,
        Some(no_vk_caps.clone()),
    );
    let (vc_stop, vc_task) = spawn_real_worker_with_vulkan_config(
        vk_compute_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        true,
        false,
        Some(vk_compute_caps.clone()),
    );
    rt_no_vk
        .transcode_state
        .set_worker_socket_override(no_vk_sock);
    rt_vk_compute
        .transcode_state
        .set_worker_socket_override(vk_compute_sock);

    rt_ctrl
        .transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_no_vk_id, no_vk_caps);
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_vk_compute_id, vk_compute_caps);

    {
        let conn = db_ctrl.lock().unwrap();
        for (lid, weight) in [(&ctrl_no_vk_id, 100i64), (&ctrl_vk_compute_id, 10i64)] {
            db_peers::upsert_transcode_worker(
                &conn,
                &af_db::peers::TranscodeWorker {
                    link_id: lid.clone(),
                    enabled: true,
                    weight,
                    max_jobs: 4,
                    ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                    encoders: Some(r#"["libx264","h264_vaapi"]"#.to_string()),
                    render_node: Some("/dev/dri/renderD128".to_string()),
                    parity_ok: true,
                    parity_error: None,
                },
            )
            .unwrap();
        }
    }

    let disp_sock = make_socket_subdir(&tmp.path, "dp").join("d.sock");
    rt_ctrl
        .transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_ctrl).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    let hdr_placebo_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "vaapi=va:/dev/dri/renderD128".into(),
        "-init_hw_device".into(),
        "vulkan=vk@va".into(),
        "-hwaccel".into(),
        "vaapi".into(),
        "-hwaccel_output_format".into(),
        "vaapi".into(),
        "-c:v".into(),
        "hevc".into(),
        "-i".into(),
        "hdr_movie.mkv".into(),
        "-vf".into(),
        "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=bt.2390:format=nv12,hwmap=derive_device=vaapi:reverse=1".into(),
        "-c:v".into(),
        "h264_vaapi".into(),
        "out.mkv".into(),
    ];

    // Repeated dispatches must skip worker-no-vk (weight=100, vulkan_compute=false) and route
    // exclusively to worker-vk-compute (vulkan_compute=true, vulkan_video=false).
    for expected_jobs in 1..=3 {
        clock.advance(1);
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &hdr_placebo_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let jobs = wait_for_job_count(&db_ctrl, expected_jobs).await;
        assert_eq!(
            jobs[0].link_id.as_deref(),
            Some(ctrl_vk_compute_id.as_str()),
            "VA-API + libplacebo HDR job must skip vulkan_compute=false worker and pick vulkan_compute=true, vulkan_video=false worker"
        );
    }
    assert!(
        !audit_actions_list(&db_no_vk).contains(&"peer_transcode_job_started".to_string()),
        "worker with vulkan_compute=false must never receive a libplacebo job"
    );

    // Disabling worker-vk-compute leaves only worker-no-vk -> must fall back locally.
    db_ctrl
        .lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET enabled = 0 WHERE link_id = ?1",
            rusqlite::params![ctrl_vk_compute_id],
        )
        .unwrap();
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &hdr_placebo_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "HDR libplacebo job must fall back locally when only a vulkan_compute=false worker is enabled"
        );
    }
    assert!(
        !audit_actions_list(&db_no_vk).contains(&"peer_transcode_job_started".to_string()),
        "worker-no-vk must still never be invoked"
    );

    stop_dispatcher(&rt_ctrl).await;
    let _ = nv_stop.send(true);
    let _ = vc_stop.send(true);
    let _ = nv_task.await;
    let _ = vc_task.await;
    rt_ctrl.shutdown_all().await;
    rt_no_vk.shutdown_all().await;
    rt_vk_compute.shutdown_all().await;
}

#[tokio::test]
async fn vulkan_video_decode_and_encode_require_vulkan_video_and_matching_codecs() {
    let ips = next_transcode_loopback_ips(3);
    let (ip_ctrl, ip_compute_only, ip_vk_video) = (ips[0], ips[1], ips[2]);
    let clock = TestClock::new(1_801_090_000);
    let tmp = ShortTempDir::new("vkv");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_ctrl = FakePeerRunner::new(fixture_wg_pubkey(233), ip_ctrl, 51821);
    let runner_compute_only = FakePeerRunner::new(fixture_wg_pubkey(234), ip_compute_only, 51821);
    let runner_vk_video = FakePeerRunner::new(fixture_wg_pubkey(235), ip_vk_video, 51821);

    let (rt_compute_only, db_compute_only) = build_transcode_runtime(
        "worker-compute-only",
        Arc::clone(&runner_compute_only) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_vk_video, db_vk_video) = build_transcode_runtime(
        "worker-vk-video",
        Arc::clone(&runner_vk_video) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_ctrl, db_ctrl) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_ctrl) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_compute_only),
            client_ip: SocketAddr::from(([198, 51, 100, 29], 45029)),
        }),
        &clock,
    );

    let (ctrl_compute_only_id, compute_only_ctrl_id, _) = pair_two_test_runtimes(
        &rt_ctrl,
        &rt_compute_only,
        ip_ctrl,
        ip_compute_only,
        "worker-compute-only",
    )
    .await;
    let now_str = clock.now().to_rfc3339();
    let mut write_access = AccessMap::none();
    write_access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_ctrl,
        &runner_ctrl,
        &ctrl_compute_only_id,
        &db_compute_only,
        &compute_only_ctrl_id,
        "jellyfin-main",
        write_access,
        &now_str,
    );
    let (ctrl_vk_video_id, _) = wire_extra_transcode_worker(
        &rt_ctrl,
        &db_ctrl,
        &runner_ctrl,
        ip_ctrl,
        233,
        &rt_vk_video,
        &db_vk_video,
        ip_vk_video,
        235,
        "worker-vk-video",
        &now_str,
    )
    .await;

    let local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let mut compute_only_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_vulkan"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    compute_only_caps.hw_decoders = vec!["h264".into(), "hevc".into(), "av1".into()];
    compute_only_caps.hw_encoders_verified = true;
    compute_only_caps.vulkan_compute = Some(true);
    compute_only_caps.vulkan_device = Some("AMD Radeon Graphics".to_string());
    compute_only_caps.vulkan_video = Some(false);

    let mut vk_video_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi", "h264_vulkan", "hevc_vulkan"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    vk_video_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    vk_video_caps.hw_encoders_verified = true;
    vk_video_caps.vulkan_compute = Some(true);
    vk_video_caps.vulkan_device = Some("AMD Radeon RX Graphics".to_string());
    vk_video_caps.vulkan_video = Some(true);
    vk_video_caps.vulkan_video_decode_codecs = vec!["h264".into(), "av1".into()];
    vk_video_caps.vulkan_video_encode_codecs = vec!["h264".into()];

    let co_sock = make_socket_subdir(&tmp.path, "co").join("w.sock");
    let vv_sock = make_socket_subdir(&tmp.path, "vv").join("w.sock");
    let (co_stop, co_task) = spawn_real_worker_with_vulkan_config(
        co_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        true,
        false,
        Some(compute_only_caps.clone()),
    );
    let (vv_stop, vv_task) = spawn_real_worker_with_vulkan_config(
        vv_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        true,
        true,
        Some(vk_video_caps.clone()),
    );
    rt_compute_only
        .transcode_state
        .set_worker_socket_override(co_sock);
    rt_vk_video
        .transcode_state
        .set_worker_socket_override(vv_sock);

    rt_ctrl
        .transcode_state
        .set_local_capabilities_override(Some(local_caps));
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_compute_only_id, compute_only_caps);
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_vk_video_id, vk_video_caps.clone());

    {
        let conn = db_ctrl.lock().unwrap();
        // Start with only worker-compute-only enabled (worker-vk-video disabled).
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: ctrl_compute_only_id.clone(),
                enabled: true,
                weight: 100,
                max_jobs: 4,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(r#"["libx264","h264_vaapi","h264_vulkan"]"#.to_string()),
                render_node: Some("/dev/dri/renderD128".to_string()),
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
        db_peers::upsert_transcode_worker(
            &conn,
            &af_db::peers::TranscodeWorker {
                link_id: ctrl_vk_video_id.clone(),
                enabled: false,
                weight: 10,
                max_jobs: 4,
                ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
                encoders: Some(
                    r#"["libx264","h264_vaapi","h264_vulkan","hevc_vulkan"]"#.to_string(),
                ),
                render_node: Some("/dev/dri/renderD128".to_string()),
                parity_ok: true,
                parity_error: None,
            },
        )
        .unwrap();
    }

    let disp_sock = make_socket_subdir(&tmp.path, "dp").join("d.sock");
    rt_ctrl
        .transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_ctrl).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    let vk_decode_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "vulkan=vk".into(),
        "-hwaccel".into(),
        "vulkan".into(),
        "-hwaccel_output_format".into(),
        "vulkan".into(),
        "-c:v".into(),
        "av1".into(),
        "-i".into(),
        "av1.mkv".into(),
        "-c:v".into(),
        "libx264".into(),
        "out.mkv".into(),
    ];
    let vk_encode_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "vulkan=vk".into(),
        "-i".into(),
        "movie.mkv".into(),
        "-c:v".into(),
        "h264_vulkan".into(),
        "out.mkv".into(),
    ];
    let vk_both_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "vulkan=vk".into(),
        "-hwaccel".into(),
        "vulkan".into(),
        "-hwaccel_output_format".into(),
        "vulkan".into(),
        "-c:v".into(),
        "av1".into(),
        "-i".into(),
        "av1.mkv".into(),
        "-c:v".into(),
        "h264_vulkan".into(),
        "out.mkv".into(),
    ];

    // 1. With only worker-compute-only (vulkan_compute=true, vulkan_video=false), both Vulkan
    //    Video decode and encode jobs are rejected and fall back locally.
    for args in [&vk_decode_args, &vk_encode_args, &vk_both_args] {
        clock.advance(1);
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec =
            run_shim_protocol(args, &shim_cfg, stdin_fd.as_raw_fd(), &mut out, &mut err).await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "vulkan_compute=true + vulkan_video=false worker must reject Vulkan Video job"
        );
    }
    assert!(
        !audit_actions_list(&db_compute_only).contains(&"peer_transcode_job_started".to_string()),
        "worker-compute-only must never be dispatched Vulkan Video jobs"
    );

    // 2. Enable worker-vk-video (vulkan_video=true, decode=[h264, av1], encode=[h264], encoders has h264_vulkan).
    //    All three matching Vulkan Video jobs must route to worker-vk-video, skipping worker-compute-only (weight=100).
    db_ctrl
        .lock()
        .unwrap()
        .execute(
            "UPDATE transcode_workers SET enabled = 1 WHERE link_id = ?1",
            rusqlite::params![ctrl_vk_video_id],
        )
        .unwrap();
    let mut job_total = 3usize;
    for args in [&vk_decode_args, &vk_encode_args, &vk_both_args] {
        clock.advance(1);
        job_total += 1;
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec =
            run_shim_protocol(args, &shim_cfg, stdin_fd.as_raw_fd(), &mut out, &mut err).await;
        assert_eq!(dec, ShimDecision::RemoteExited(0));
        let jobs = wait_for_job_count(&db_ctrl, job_total).await;
        assert_eq!(
            jobs[0].link_id.as_deref(),
            Some(ctrl_vk_video_id.as_str()),
            "matching Vulkan Video job must select worker-vk-video"
        );
    }
    assert!(
        !audit_actions_list(&db_compute_only).contains(&"peer_transcode_job_started".to_string()),
        "worker-compute-only must remain untouched when worker-vk-video handles Vulkan Video jobs"
    );

    // 3. Unmatched Vulkan Video decode codec (hevc) or encode codec (hevc_vulkan) must be rejected.
    let vk_unmatched_decode: Vec<String> = vec![
        "-init_hw_device".into(),
        "vulkan=vk".into(),
        "-hwaccel".into(),
        "vulkan".into(),
        "-c:v".into(),
        "hevc".into(),
        "-i".into(),
        "hevc.mkv".into(),
        "-c:v".into(),
        "libx264".into(),
        "out.mkv".into(),
    ];
    let vk_unmatched_encode: Vec<String> = vec![
        "-init_hw_device".into(),
        "vulkan=vk".into(),
        "-i".into(),
        "movie.mkv".into(),
        "-c:v".into(),
        "hevc_vulkan".into(),
        "out.mkv".into(),
    ];
    for args in [&vk_unmatched_decode, &vk_unmatched_encode] {
        clock.advance(1);
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec =
            run_shim_protocol(args, &shim_cfg, stdin_fd.as_raw_fd(), &mut out, &mut err).await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "unmatched Vulkan Video decode/encode codec must be rejected"
        );
    }

    // 4. Removing h264_vulkan from worker-vk-video's encoders rejects -c:v h264_vulkan even when
    //    vulkan_video=true and vulkan_video_encode_codecs=["h264"].
    let mut missing_enc_caps = vk_video_caps;
    missing_enc_caps.encoders = vec!["libx264".into(), "h264_vaapi".into()];
    rt_ctrl
        .transcode_state
        .record_remote_capabilities(&ctrl_vk_video_id, missing_enc_caps);
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &vk_encode_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "h264_vulkan job must be rejected when worker encoders omit h264_vulkan"
        );
    }

    stop_dispatcher(&rt_ctrl).await;
    let _ = co_stop.send(true);
    let _ = vv_stop.send(true);
    let _ = co_task.await;
    let _ = vv_task.await;
    rt_ctrl.shutdown_all().await;
    rt_compute_only.shutdown_all().await;
    rt_vk_video.shutdown_all().await;
}

#[tokio::test]
async fn local_first_overflows_vaapi_libplacebo_hdr_job_when_local_lacks_vulkan_compute() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_100_000);
    let tmp = ShortTempDir::new("vkl");
    let fake_ffmpeg = write_fake_ffmpeg_script(&tmp.path, "ffmpeg", standard_fake_ffmpeg_body());

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(236), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(237), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "jellyfin-main",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 30], 45030)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "jellyfin-main",
        access,
        &clock.now().to_rfc3339(),
    );

    let mut local_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    local_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    local_caps.vulkan_compute = Some(false);
    local_caps.vulkan_video = Some(false);

    let mut remote_caps = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    remote_caps.hw_decoders = vec!["h264".into(), "hevc".into()];
    remote_caps.vulkan_compute = Some(true);
    remote_caps.vulkan_device = Some("AMD Radeon Graphics".to_string());
    remote_caps.vulkan_video = Some(false);

    let worker_sock = make_socket_subdir(&tmp.path, "w").join("w.sock");
    let (w_stop, w_task) = spawn_real_worker_with_vulkan_config(
        worker_sock.clone(),
        fake_ffmpeg.clone(),
        4,
        af_transcode::BackendAdaptMode::Off,
        Some(vec![af_hardware::RenderNode {
            path: PathBuf::from("/dev/dri/renderD128"),
            vendor_id: Some("0x1002".to_string()),
        }]),
        true,
        false,
        Some(remote_caps.clone()),
    );
    rt_b.transcode_state.set_worker_socket_override(worker_sock);

    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps.clone()));
    rt_a.transcode_state.set_local_active_jobs_override(Some(0));
    rt_a.transcode_state
        .record_remote_capabilities(&a_link_id, remote_caps);

    db_peers::upsert_transcode_worker(
        &db_a.lock().unwrap(),
        &af_db::peers::TranscodeWorker {
            link_id: a_link_id.clone(),
            enabled: true,
            weight: 50,
            max_jobs: 4,
            ffmpeg_version: Some("8.1.3-Jellyfin".to_string()),
            encoders: Some(r#"["libx264","h264_vaapi"]"#.to_string()),
            render_node: Some("/dev/dri/renderD128".to_string()),
            parity_ok: true,
            parity_error: None,
        },
    )
    .unwrap();

    let (st, body) = call_admin(
        &rt_a,
        Method::PUT,
        "/transcode",
        Some(json!({ "dispatch_policy": "local_first", "local_max_jobs": 2 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT local_first failed: {body}");

    let disp_sock = make_socket_subdir(&tmp.path, "d").join("d.sock");
    rt_a.transcode_state
        .set_dispatcher_socket_override(disp_sock.clone());
    ensure_dispatcher_started(&rt_a).await.unwrap();

    let shim_cfg = ShimConfig {
        real_ffmpeg: fake_ffmpeg,
        dispatcher_socket: disp_sock,
        handshake_timeout: Duration::from_secs(2),
        frame_write_timeout: Duration::from_secs(5),
    };

    // Plain VA-API SDR job still runs locally under local_first when local_active=0.
    let sdr_vaapi_args: Vec<String> = vec![
        "-hwaccel".into(),
        "vaapi".into(),
        "-c:v".into(),
        "hevc".into(),
        "-i".into(),
        "sdr.mkv".into(),
        "-c:v".into(),
        "h264_vaapi".into(),
        "out.mkv".into(),
    ];
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &sdr_vaapi_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "plain VA-API job should remain local under local_first"
        );
    }

    // VA-API + libplacebo HDR job must overflow to the remote vulkan_compute=true worker even at local_active=0!
    let hdr_placebo_args: Vec<String> = vec![
        "-init_hw_device".into(),
        "vaapi=va:/dev/dri/renderD128".into(),
        "-init_hw_device".into(),
        "vulkan=vk@va".into(),
        "-hwaccel".into(),
        "vaapi".into(),
        "-hwaccel_output_format".into(),
        "vaapi".into(),
        "-c:v".into(),
        "hevc".into(),
        "-i".into(),
        "hdr.mkv".into(),
        "-vf".into(),
        "hwmap=derive_device=vulkan,libplacebo=w=1920:h=1080:tonemapping=bt.2390:format=nv12,hwmap=derive_device=vaapi:reverse=1".into(),
        "-c:v".into(),
        "h264_vaapi".into(),
        "out.mkv".into(),
    ];
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &hdr_placebo_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::RemoteExited(0),
            "local_first must overflow VA-API + libplacebo HDR job when local vulkan_compute=false"
        );
        let jobs = wait_for_job_count(&db_a, 2).await;
        assert_eq!(jobs[0].link_id.as_deref(), Some(a_link_id.as_str()));
    }

    // Once local host reports vulkan_compute=true (with vulkan_video=false), HDR job runs locally under local_first.
    local_caps.vulkan_compute = Some(true);
    rt_a.transcode_state
        .set_local_capabilities_override(Some(local_caps));
    clock.advance(1);
    {
        let stdin_fd = make_stdin_pipe(b"");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let dec = run_shim_protocol(
            &hdr_placebo_args,
            &shim_cfg,
            stdin_fd.as_raw_fd(),
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(
            dec,
            ShimDecision::ExecLocal {
                reason: LocalFallbackReason::DispatcherRunLocal
            },
            "local_first should run VA-API + libplacebo HDR job locally when local vulkan_compute=true"
        );
    }

    stop_dispatcher(&rt_a).await;
    let _ = w_stop.send(true);
    let _ = w_task.await;
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn admin_transcode_get_exposes_and_omits_vulkan_capabilities() {
    let ips = next_transcode_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = TestClock::new(1_801_110_000);

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(238), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(239), ip_b, 51821);
    let (rt_b, db_b) = build_transcode_runtime(
        "gpu-worker",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
    );
    let (rt_a, db_a) = build_transcode_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerTranscodeRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 31], 45031)),
        }),
        &clock,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;
    let mut access = AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    install_transcode_grant_pair(
        &db_a,
        &runner_a,
        &a_link_id,
        &db_b,
        &b_link_id,
        "seedbox-1",
        access,
        &clock.now().to_rfc3339(),
    );

    let unprobed_local = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x8086", "intel")],
    );
    let unprobed_worker = sample_caps(
        Some("8.1.3-2-trixie"),
        Some("8.1.3-Jellyfin"),
        &["libx264", "h264_vaapi"],
        &[("/dev/dri/renderD128", "0x1002", "amd")],
    );
    rt_a.transcode_state
        .set_local_capabilities_override(Some(unprobed_local.clone()));
    rt_b.transcode_state
        .set_local_capabilities_override(Some(unprobed_worker.clone()));

    // 1. Unprobed (None / empty): all 5 Vulkan fields are cleanly omitted on both local and workers.
    run_health_tick(&rt_a).await;
    let (st, unprobed_body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "GET /transcode (unprobed) failed: {unprobed_body}"
    );
    let local_unprobed_obj = unprobed_body["local"].as_object().expect("local object");
    let worker_unprobed_obj = unprobed_body["workers"][0]
        .as_object()
        .expect("worker object");
    for key in [
        "vulkan_compute",
        "vulkan_device",
        "vulkan_video",
        "vulkan_video_decode_codecs",
        "vulkan_video_encode_codecs",
    ] {
        assert!(
            !local_unprobed_obj.contains_key(key),
            "unprobed local should omit '{key}': {unprobed_body}"
        );
        assert!(
            !worker_unprobed_obj.contains_key(key),
            "unprobed worker should omit '{key}': {unprobed_body}"
        );
    }

    // 2. Populated Vulkan fields propagate from local_caps and remote /health into GET /transcode.
    let mut probed_local = unprobed_local;
    probed_local.vulkan_compute = Some(true);
    probed_local.vulkan_device = Some("Intel UHD Graphics 630".to_string());
    probed_local.vulkan_video = Some(true);
    probed_local.vulkan_video_decode_codecs = vec!["h264".into(), "hevc".into()];
    probed_local.vulkan_video_encode_codecs = vec!["h264".into()];

    let mut probed_worker = unprobed_worker;
    probed_worker.vulkan_compute = Some(true);
    probed_worker.vulkan_device = Some("AMD Radeon Graphics".to_string());
    probed_worker.vulkan_video = Some(true);
    probed_worker.vulkan_video_decode_codecs = vec!["h264".into(), "hevc".into(), "av1".into()];
    probed_worker.vulkan_video_encode_codecs = vec!["h264".into()];

    rt_a.transcode_state
        .set_local_capabilities_override(Some(probed_local));
    rt_b.transcode_state
        .set_local_capabilities_override(Some(probed_worker.clone()));

    clock.advance(20);
    run_health_tick(&rt_a).await;
    let (st, probed_body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "GET /transcode (probed) failed: {probed_body}"
    );

    assert_eq!(probed_body["local"]["vulkan_compute"], true);
    assert_eq!(
        probed_body["local"]["vulkan_device"],
        "Intel UHD Graphics 630"
    );
    assert_eq!(probed_body["local"]["vulkan_video"], true);
    assert_eq!(
        probed_body["local"]["vulkan_video_decode_codecs"],
        json!(["h264", "hevc"])
    );
    assert_eq!(
        probed_body["local"]["vulkan_video_encode_codecs"],
        json!(["h264"])
    );

    let worker = &probed_body["workers"][0];
    assert_eq!(worker["vulkan_compute"], true);
    assert_eq!(worker["vulkan_device"], "AMD Radeon Graphics");
    assert_eq!(worker["vulkan_video"], true);
    assert_eq!(
        worker["vulkan_video_decode_codecs"],
        json!(["h264", "hevc", "av1"])
    );
    assert_eq!(worker["vulkan_video_encode_codecs"], json!(["h264"]));

    // 3. When vulkan_video=false with empty codec lists, booleans/device appear while empty vecs stay omitted.
    let mut compute_only_worker = probed_worker;
    compute_only_worker.vulkan_video = Some(false);
    compute_only_worker.vulkan_video_decode_codecs.clear();
    compute_only_worker.vulkan_video_encode_codecs.clear();
    rt_b.transcode_state
        .set_local_capabilities_override(Some(compute_only_worker));
    clock.advance(20);
    run_health_tick(&rt_a).await;

    let (st, partial_body) = call_admin(&rt_a, Method::GET, "/transcode", None).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "GET /transcode (partial) failed: {partial_body}"
    );
    let partial_worker = partial_body["workers"][0]
        .as_object()
        .expect("partial worker object");
    assert_eq!(partial_worker.get("vulkan_compute"), Some(&json!(true)));
    assert_eq!(
        partial_worker.get("vulkan_device"),
        Some(&json!("AMD Radeon Graphics"))
    );
    assert_eq!(partial_worker.get("vulkan_video"), Some(&json!(false)));
    assert!(!partial_worker.contains_key("vulkan_video_decode_codecs"));
    assert!(!partial_worker.contains_key("vulkan_video_encode_codecs"));

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}
