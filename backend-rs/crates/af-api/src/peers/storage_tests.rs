use super::health::{run_health_tick, WG_HANDSHAKE_STALE_SECS};
use super::storage::{
    enforce_plex_peer_mount_safety_at_base, probe_mounts_while_link_degraded,
    recommended_library_path, resolve_export_owner_mapping, validate_media_library_path_with_base,
    validate_remote_export_path, MediaLibraryPathError, MountHealthTracker, PeerStorageRunner,
    MOUNT_STATE_ERROR, MOUNT_STATE_MOUNTED, MOUNT_STATE_STOPPED,
};
use super::tests::{
    call_admin, fixture_wg_pubkey, open_isolated_peer_db, pair_two_test_runtimes, FakeClock,
    FakePeerRunner, RouterPublicTransport, UnreachablePublicTransport,
};
use super::{
    admin_routes_with_runtime, start_with_runtime, KeyedAsyncLockPool, PeerDb, PeerRunner,
    PeerRuntime, TunnelTransportBinding, HEADER_GRANT_TOKEN, HEADER_LINK_TOKEN,
    PEER_LOCK_WAIT_TIMEOUT,
};
use crate::auth::AuthUser;
use af_db::peers::{self as db_peers, PeerExport, PeerMount};
use af_runner::{
    systemd_escape_mount_unit, validate_peer_mount_path, PeerCredentialSecret, PeerCredentialSlot,
    PeerExportsWriteResponse, PeerMountRemoveResponse, PeerMountStateResponse,
    PeerMountWriteResponse, PeerNfsdConfigResponse, PeerSentinelProbeResponse,
    PeerSentinelResponse, PeerStorageError, PeerStorageExportSpec, PeerStoragePackagesResponse,
    PeerStorageRequest, PeerStorageResponse, PEER_NFSD_SERVICE_UNIT, PEER_SENTINEL_FILE_NAME,
    PEER_STORAGE_PACKAGES,
};
use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures::future::BoxFuture;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex as TokioMutex, Notify};
use tower::ServiceExt;
use uuid::Uuid;

static STORAGE_LOOPBACK_OCTET: AtomicU16 = AtomicU16::new(20);

fn next_storage_loopback_ips(count: usize) -> Vec<IpAddr> {
    let base = STORAGE_LOOPBACK_OCTET.fetch_add(count as u16, Ordering::SeqCst);
    (0..count)
        .map(|offset| {
            let n = base + offset as u16;
            let hi = (n / 200) as u8;
            let lo = (n % 200) as u8 + 10;
            IpAddr::V4(Ipv4Addr::new(127, 2, hi, lo))
        })
        .collect()
}

struct TempFixtureDir {
    path: PathBuf,
}

impl TempFixtureDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("create temp fixture dir");
        Self { path }
    }
}

impl Drop for TempFixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug, Clone)]
pub(super) struct FakeMountRecord {
    pub(super) tunnel_ip: String,
    pub(super) remote_path: String,
    pub(super) unit_name: String,
    pub(super) writable: bool,
    pub(super) active: bool,
}

#[derive(Default)]
pub(super) struct FakeStorageState {
    pub(super) calls: Vec<PeerStorageRequest>,
    pub(super) nfsd_tunnel_ip: Option<String>,
    pub(super) exports_by_link: HashMap<String, (String, Vec<PeerStorageExportSpec>)>,
    pub(super) mounts: HashMap<String, FakeMountRecord>,
    pub(super) owner_overrides: HashMap<String, (u32, u32)>,
    pub(super) sentinel_probes: HashMap<String, VecDeque<Result<(), String>>>,
    pub(super) default_probe_healthy: bool,
    pub(super) fail_next: HashMap<&'static str, PeerStorageError>,
    pub(super) block_once: Option<(&'static str, Arc<Notify>, Arc<Notify>)>,
}

pub(super) struct FakePeerStorageRunner {
    pub(super) state: StdMutex<FakeStorageState>,
}

impl FakePeerStorageRunner {
    pub(super) fn new() -> Self {
        Self {
            state: StdMutex::new(FakeStorageState {
                default_probe_healthy: true,
                ..Default::default()
            }),
        }
    }

    fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn action_name(req: &PeerStorageRequest) -> &'static str {
        match req {
            PeerStorageRequest::EnsurePackages => "ensure_packages",
            PeerStorageRequest::ConfigureNfsd { .. } => "configure_nfsd",
            PeerStorageRequest::WriteExports { .. } => "write_exports",
            PeerStorageRequest::RemoveExports { .. } => "remove_exports",
            PeerStorageRequest::EnsureSentinel { .. } => "ensure_sentinel",
            PeerStorageRequest::ProbeSentinel { .. } => "probe_sentinel",
            PeerStorageRequest::WriteMount { .. } => "write_mount",
            PeerStorageRequest::WriteBindMount { .. } => "write_bind_mount",
            PeerStorageRequest::RemoveMount { .. } => "remove_mount",
            PeerStorageRequest::StartMount { .. } => "start_mount",
            PeerStorageRequest::StopMount { .. } => "stop_mount",
            PeerStorageRequest::MountStatus { .. } => "mount_status",
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

    fn exports_for_link(&self, link_id: &str) -> Option<(String, Vec<PeerStorageExportSpec>)> {
        self.state
            .lock()
            .unwrap()
            .exports_by_link
            .get(link_id)
            .cloned()
    }

    fn mount_record(&self, mount_path: &str) -> Option<FakeMountRecord> {
        self.state.lock().unwrap().mounts.get(mount_path).cloned()
    }

    fn mount_count(&self) -> usize {
        self.state.lock().unwrap().mounts.len()
    }

    fn set_owner_override(&self, path: &str, uid: u32, gid: u32) {
        self.state
            .lock()
            .unwrap()
            .owner_overrides
            .insert(path.to_string(), (uid, gid));
    }

    fn fail_next_action(&self, action: &'static str, err: PeerStorageError) {
        self.state.lock().unwrap().fail_next.insert(action, err);
    }

    fn push_probe_result(&self, mount_path: &str, outcome: Result<(), String>) {
        self.state
            .lock()
            .unwrap()
            .sentinel_probes
            .entry(mount_path.to_string())
            .or_default()
            .push_back(outcome);
    }

    fn block_once_on(&self, action: &'static str, entered: Arc<Notify>, release: Arc<Notify>) {
        self.state.lock().unwrap().block_once = Some((action, entered, release));
    }
}

impl PeerStorageRunner for FakePeerStorageRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerStorageRequest,
    ) -> BoxFuture<'a, Result<PeerStorageResponse, PeerStorageError>> {
        let action = Self::action_name(req);
        Box::pin(async move {
            let block = {
                let mut st = self.state.lock().unwrap();
                if st.block_once.as_ref().is_some_and(|(a, _, _)| *a == action) {
                    st.block_once.take()
                } else {
                    None
                }
            };
            if let Some((_, entered, release)) = block {
                entered.notify_waiters();
                release.notified().await;
            }

            let mut st = self.state.lock().unwrap();
            st.calls.push(req.clone());

            if let Some(err) = st.fail_next.remove(action) {
                return Err(err);
            }

            match req {
                PeerStorageRequest::EnsurePackages => {
                    Ok(PeerStorageResponse::Packages(PeerStoragePackagesResponse {
                        installed: true,
                        already_installed: true,
                        packages: PEER_STORAGE_PACKAGES
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        versions: HashMap::new(),
                    }))
                }
                PeerStorageRequest::ConfigureNfsd { tunnel_ip } => {
                    let changed = st.nfsd_tunnel_ip.as_deref() != Some(tunnel_ip.as_str());
                    st.nfsd_tunnel_ip = Some(tunnel_ip.clone());
                    Ok(PeerStorageResponse::NfsdConfigured(
                        PeerNfsdConfigResponse {
                            config_path: "/etc/nfs.conf.d/aetherflow-peers.conf".to_string(),
                            tunnel_ip: tunnel_ip.clone(),
                            service_unit: PEER_NFSD_SERVICE_UNIT.to_string(),
                            service_state: "active".to_string(),
                            changed,
                        },
                    ))
                }
                PeerStorageRequest::EnsureSentinel {
                    path,
                    require_non_root_owner,
                } => {
                    let (owner_uid, owner_gid) =
                        if let Some((u, g)) = st.owner_overrides.get(path).copied() {
                            (u, g)
                        } else {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                let meta = fs::metadata(path).map_err(|e| {
                                    PeerStorageError::InvalidInput(format!(
                                        "Export path stat failed: {e}"
                                    ))
                                })?;
                                (meta.uid(), meta.gid())
                            }
                            #[cfg(not(unix))]
                            {
                                (1000, 1000)
                            }
                        };
                    if *require_non_root_owner && (owner_uid == 0 || owner_gid == 0) {
                        return Err(PeerStorageError::InvalidInput(format!(
                            "Writable peer export directory '{path}' must be owned by a non-root user and group (found uid={owner_uid}, gid={owner_gid})"
                        )));
                    }
                    Ok(PeerStorageResponse::SentinelEnsured(PeerSentinelResponse {
                        path: path.clone(),
                        sentinel_path: format!("{path}/{PEER_SENTINEL_FILE_NAME}"),
                        created: true,
                        owner_uid,
                        owner_gid,
                    }))
                }
                PeerStorageRequest::WriteExports {
                    link,
                    tunnel_ip,
                    exports,
                } => {
                    if exports.is_empty() {
                        let removed = st.exports_by_link.remove(link).is_some();
                        Ok(PeerStorageResponse::ExportsWritten(
                            PeerExportsWriteResponse {
                                link: link.clone(),
                                exports_path: format!(
                                    "/etc/exports.d/aetherflow-peer-{link}.exports"
                                ),
                                tunnel_ip: None,
                                export_count: 0,
                                changed: removed,
                                removed,
                            },
                        ))
                    } else {
                        st.exports_by_link
                            .insert(link.clone(), (tunnel_ip.clone(), exports.clone()));
                        Ok(PeerStorageResponse::ExportsWritten(
                            PeerExportsWriteResponse {
                                link: link.clone(),
                                exports_path: format!(
                                    "/etc/exports.d/aetherflow-peer-{link}.exports"
                                ),
                                tunnel_ip: Some(tunnel_ip.clone()),
                                export_count: exports.len(),
                                changed: true,
                                removed: false,
                            },
                        ))
                    }
                }
                PeerStorageRequest::RemoveExports { link } => {
                    let removed = st.exports_by_link.remove(link).is_some();
                    Ok(PeerStorageResponse::ExportsWritten(
                        PeerExportsWriteResponse {
                            link: link.clone(),
                            exports_path: format!("/etc/exports.d/aetherflow-peer-{link}.exports"),
                            tunnel_ip: None,
                            export_count: 0,
                            changed: removed,
                            removed,
                        },
                    ))
                }
                PeerStorageRequest::WriteMount {
                    mount_path,
                    tunnel_ip,
                    remote_path,
                    writable,
                } => {
                    validate_peer_mount_path(mount_path)?;
                    let unit_name = systemd_escape_mount_unit(mount_path)?;
                    st.mounts.insert(
                        mount_path.clone(),
                        FakeMountRecord {
                            tunnel_ip: tunnel_ip.clone(),
                            remote_path: remote_path.clone(),
                            unit_name: unit_name.clone(),
                            writable: *writable,
                            active: false,
                        },
                    );
                    Ok(PeerStorageResponse::MountWritten(PeerMountWriteResponse {
                        unit_name,
                        mount_path: mount_path.clone(),
                        what: format!("{tunnel_ip}:{remote_path}"),
                        fs_type: "nfs4".to_string(),
                        options: if *writable {
                            "rw,vers=4.2,proto=tcp,soft,timeo=50,retrans=2,noexec,nosuid,nodev,_netdev"
                                .to_string()
                        } else {
                            "ro,vers=4.2,proto=tcp,soft,timeo=50,retrans=2,noexec,nosuid,nodev,_netdev"
                                .to_string()
                        },
                        writable: *writable,
                        changed: true,
                    }))
                }
                PeerStorageRequest::WriteBindMount {
                    source_path,
                    mount_path,
                    writable,
                } => {
                    validate_peer_mount_path(mount_path)?;
                    let unit_name = systemd_escape_mount_unit(mount_path)?;
                    st.mounts.insert(
                        mount_path.clone(),
                        FakeMountRecord {
                            tunnel_ip: String::new(),
                            remote_path: source_path.clone(),
                            unit_name: unit_name.clone(),
                            writable: *writable,
                            active: false,
                        },
                    );
                    Ok(PeerStorageResponse::MountWritten(PeerMountWriteResponse {
                        unit_name,
                        mount_path: mount_path.clone(),
                        what: source_path.clone(),
                        fs_type: "none".to_string(),
                        options: if *writable {
                            "bind,rw,noexec,nosuid,nodev".to_string()
                        } else {
                            "bind,ro,noexec,nosuid,nodev".to_string()
                        },
                        writable: *writable,
                        changed: true,
                    }))
                }
                PeerStorageRequest::StartMount { mount_path } => {
                    let rec = st.mounts.get_mut(mount_path).ok_or_else(|| {
                        PeerStorageError::NotFound(format!("Mount unit not found for {mount_path}"))
                    })?;
                    rec.active = true;
                    Ok(PeerStorageResponse::MountState(PeerMountStateResponse {
                        unit_name: rec.unit_name.clone(),
                        mount_path: mount_path.clone(),
                        exists: true,
                        active: true,
                        unit_state: "active".to_string(),
                    }))
                }
                PeerStorageRequest::StopMount { mount_path } => {
                    let rec = st.mounts.get_mut(mount_path).ok_or_else(|| {
                        PeerStorageError::NotFound(format!("Mount unit not found for {mount_path}"))
                    })?;
                    rec.active = false;
                    Ok(PeerStorageResponse::MountState(PeerMountStateResponse {
                        unit_name: rec.unit_name.clone(),
                        mount_path: mount_path.clone(),
                        exists: true,
                        active: false,
                        unit_state: "inactive".to_string(),
                    }))
                }
                PeerStorageRequest::RemoveMount { mount_path } => {
                    let unit_name = systemd_escape_mount_unit(mount_path)?;
                    let removed = st.mounts.remove(mount_path).is_some();
                    Ok(PeerStorageResponse::MountRemoved(PeerMountRemoveResponse {
                        unit_name,
                        mount_path: mount_path.clone(),
                        removed,
                        stopped: true,
                        mount_dir_removed: removed,
                    }))
                }
                PeerStorageRequest::MountStatus { mount_path } => {
                    let unit_name = systemd_escape_mount_unit(mount_path)?;
                    let (exists, active) = st
                        .mounts
                        .get(mount_path)
                        .map(|r| (true, r.active))
                        .unwrap_or((false, false));
                    Ok(PeerStorageResponse::MountState(PeerMountStateResponse {
                        unit_name,
                        mount_path: mount_path.clone(),
                        exists,
                        active,
                        unit_state: if active { "active" } else { "inactive" }.to_string(),
                    }))
                }
                PeerStorageRequest::ProbeSentinel { mount_path, .. } => {
                    let sentinel_path = format!("{mount_path}/{PEER_SENTINEL_FILE_NAME}");
                    let scripted = st
                        .sentinel_probes
                        .get_mut(mount_path)
                        .and_then(VecDeque::pop_front);
                    let active = st.mounts.get(mount_path).is_some_and(|r| r.active);
                    let outcome = match scripted {
                        Some(res) => res,
                        None if !active => Err("mount unit is not active".to_string()),
                        None if st.default_probe_healthy => Ok(()),
                        None => Err("sentinel probe failed".to_string()),
                    };
                    match outcome {
                        Ok(()) => Ok(PeerStorageResponse::SentinelProbed(
                            PeerSentinelProbeResponse {
                                mount_path: mount_path.clone(),
                                sentinel_path,
                                healthy: true,
                                timed_out: false,
                                error: None,
                            },
                        )),
                        Err(msg) => {
                            let timed_out = msg.contains("timed out");
                            Ok(PeerStorageResponse::SentinelProbed(
                                PeerSentinelProbeResponse {
                                    mount_path: mount_path.clone(),
                                    sentinel_path,
                                    healthy: false,
                                    timed_out,
                                    error: Some(msg),
                                },
                            ))
                        }
                    }
                }
            }
        })
    }
}

fn build_storage_runtime(
    name: &str,
    runner: Arc<dyn PeerRunner>,
    storage_runner: Arc<dyn PeerStorageRunner>,
    public_transport: Arc<dyn super::PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    allowed_roots: Option<Vec<PathBuf>>,
) -> (Arc<PeerRuntime>, Arc<StdMutex<Connection>>) {
    let db_conn = open_isolated_peer_db();
    let (revocation_tx, _) = broadcast::channel(64);
    let rt = Arc::new(PeerRuntime {
        db: PeerDb::Isolated(Arc::clone(&db_conn)),
        runner,
        storage_runner,
        mount_health: MountHealthTracker::new(),
        transcode_runner: Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new()),
        transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
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
        version_override: Some("4.0.0-p7-test".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        interface_index_override: RwLock::new(None),
        bind_listener_in_handlers: true,
        management_router_override: None,
        allowed_fs_roots_override: allowed_roots,
    });
    (rt, db_conn)
}

async fn call_admin_full(
    rt: &Arc<PeerRuntime>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let app = admin_routes_with_runtime(Arc::clone(rt));
    let mut builder = Request::builder().method(method).uri(uri);
    let req_body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let mut req = builder.body(req_body).unwrap();
    req.extensions_mut().insert(AuthUser {
        user_id: 1,
        username: "alice".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41000))));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 128 * 1024).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }))
    };
    (status, headers, json)
}

fn audit_actions(db: &Arc<StdMutex<Connection>>) -> Vec<String> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT action FROM admin_audit_log ORDER BY id ASC")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn notification_titles(db: &Arc<StdMutex<Connection>>) -> Vec<String> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT title FROM notifications ORDER BY id ASC")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Export CRUD, Read-Only Default, Writable Owner Mapping & Path Validation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn export_crud_read_only_default_writable_owner_mapping_and_validation() {
    let tmp = TempFixtureDir::new("af-p7-exports");
    let movies = tmp.path.join("movies");
    let shows = tmp.path.join("shows");
    let root_owned_sim = tmp.path.join("root-owned");
    let regular_file = tmp.path.join("note.txt");
    let symlink_dir = tmp.path.join("movies-link");
    let with_colon = tmp.path.join("Movies:4K");
    let with_control = tmp.path.join("movies\u{85}restored");
    fs::create_dir_all(&movies).unwrap();
    fs::create_dir_all(&shows).unwrap();
    fs::create_dir_all(&root_owned_sim).unwrap();
    fs::create_dir_all(&with_colon).unwrap();
    fs::create_dir_all(&with_control).unwrap();
    fs::write(&regular_file, b"hello").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&movies, &symlink_dir).unwrap();

    let outside_tmp = TempFixtureDir::new("af-p7-outside");
    let outside_dir = outside_tmp.path.join("secret");
    fs::create_dir_all(&outside_dir).unwrap();

    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_900_000);
    let pk_a = fixture_wg_pubkey(151);
    let pk_b = fixture_wg_pubkey(152);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    let (rt_b, db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, _db_a) = build_storage_runtime(
        "app-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 41], 41200)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (_a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;

    // Missing link returns 404 PEER_NOT_FOUND before path validation.
    let (st, _, missing_err) = call_admin_full(
        &rt_b,
        Method::POST,
        "/p7-missing-peer/exports",
        Some(json!({ "path": "/var/tmp/nonexistent-dir" })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(missing_err["code"], "PEER_NOT_FOUND");

    // Unknown JSON fields rejected.
    let (st, _, err) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies.to_string_lossy(), "squash_uid": 1000 })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], "INVALID_REQUEST");

    // Path validation rejections: non-existent, file, symlink, traversal, /mnt/af-peers, /etc, outside roots.
    for bad_path in [&with_colon, &with_control] {
        assert!(
            validate_remote_export_path(bad_path.to_str().unwrap(), "media-b", "test").is_err()
        );
    }
    for bad_path in [
        tmp.path
            .join("does-not-exist")
            .to_string_lossy()
            .to_string(),
        regular_file.to_string_lossy().to_string(),
        symlink_dir.to_string_lossy().to_string(),
        format!("{}/../movies", movies.display()),
        "/mnt/af-peers/media-2/movies".to_string(),
        "/etc".to_string(),
        "/".to_string(),
        "/tmp".to_string(),
        outside_dir.to_string_lossy().to_string(),
        with_colon.to_string_lossy().to_string(),
        with_control.to_string_lossy().to_string(),
    ] {
        let (st, _, err) = call_admin_full(
            &rt_b,
            Method::POST,
            &format!("/{b_link_id}/exports"),
            Some(json!({ "path": bad_path })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "expected 400 for bad_path={bad_path}, got {err}"
        );
        assert_eq!(err["code"], "INVALID_REQUEST");
    }
    assert_eq!(
        storage_b.call_count(),
        0,
        "rejected paths must not invoke storage runner"
    );

    // Owner mapping unit check: read-only returns (None, None); writable refuses root uid or gid.
    assert_eq!(
        resolve_export_owner_mapping(false, 0, 0, "media-b", "test").unwrap(),
        (None, None)
    );
    assert!(resolve_export_owner_mapping(true, 0, 1000, "media-b", "test").is_err());
    assert!(resolve_export_owner_mapping(true, 1000, 0, "media-b", "test").is_err());
    assert_eq!(
        resolve_export_owner_mapping(true, 1001, 1002, "media-b", "test").unwrap(),
        (Some(1001), Some(1002))
    );

    // Create default (read-only) export by omitting `writable`.
    let movies_canon = fs::canonicalize(&movies)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let (st, hdrs, created_ro) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies.to_string_lossy() })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "created_ro={created_ro}");
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let ro_export: PeerExport = serde_json::from_value(created_ro["export"].clone()).unwrap();
    assert_eq!(ro_export.link_id, b_link_id);
    assert_eq!(ro_export.path, movies_canon);
    assert!(!ro_export.writable);
    assert_eq!(ro_export.squash_uid, None);
    assert_eq!(ro_export.squash_gid, None);

    // Runner saw EnsurePackages -> ConfigureNfsd(ip_b) -> EnsureSentinel(require_non_root=false) -> WriteExports(ip_a).
    let (written_ip, written_specs) = storage_b.exports_for_link(&b_link_id).unwrap();
    assert_eq!(written_ip, ip_a.to_string());
    assert_eq!(written_specs.len(), 1);
    assert!(!written_specs[0].writable);
    assert_eq!(written_specs[0].squash_uid, None);
    assert_eq!(written_specs[0].squash_gid, None);

    // Duplicate path rejected with 409 PEER_CONFLICT.
    let (st, _, dup_err) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies.to_string_lossy(), "writable": false })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(dup_err["code"], "PEER_CONFLICT");

    // Writable export rejected if authoritative runner EnsureSentinel reports uid 0 or gid 0.
    let root_sim_canon = fs::canonicalize(&root_owned_sim)
        .unwrap()
        .to_string_lossy()
        .to_string();
    storage_b.set_owner_override(&root_sim_canon, 0, 1000);
    let (st, _, root_err) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": root_owned_sim.to_string_lossy(), "writable": true })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "root_err={root_err}");
    assert_eq!(root_err["code"], "INVALID_REQUEST");

    // Opt-in writable export with non-root owner auto-derives squash_uid / squash_gid.
    let shows_canon = fs::canonicalize(&shows)
        .unwrap()
        .to_string_lossy()
        .to_string();
    storage_b.set_owner_override(&shows_canon, 1024, 1025);
    let (st, _, created_rw) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": shows.to_string_lossy(), "writable": true })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "created_rw={created_rw}");
    let rw_export: PeerExport = serde_json::from_value(created_rw["export"].clone()).unwrap();
    assert!(rw_export.writable);
    assert_eq!(rw_export.squash_uid, Some(1024));
    assert_eq!(rw_export.squash_gid, Some(1025));

    // GET /exports lists both exports with Cache-Control: no-store.
    let (st, hdrs, list_body) =
        call_admin_full(&rt_b, Method::GET, &format!("/{b_link_id}/exports"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(list_body["exports"].as_array().unwrap().len(), 2);

    // Deleting first export rewrites drop-in with remaining export.
    let (st, hdrs, _) = call_admin_full(
        &rt_b,
        Method::DELETE,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "export_id": ro_export.id })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let (_, remaining_specs) = storage_b.exports_for_link(&b_link_id).unwrap();
    assert_eq!(remaining_specs.len(), 1);
    assert_eq!(remaining_specs[0].path, shows_canon);

    // Deleting last export invokes RemoveExports and empties DB.
    let (st, _, _) = call_admin_full(
        &rt_b,
        Method::DELETE,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "export_id": rw_export.id })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(storage_b.exports_for_link(&b_link_id).is_none());
    assert_eq!(storage_b.count_action("remove_exports"), 1);

    // Deleting missing export returns 404 PEER_NOT_FOUND.
    let (st, _, not_found) = call_admin_full(
        &rt_b,
        Method::DELETE,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "export_id": rw_export.id })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(not_found["code"], "PEER_NOT_FOUND");

    let audits = audit_actions(&db_b);
    assert!(audits.iter().any(|a| a == "peer_export_created"));
    assert!(audits.iter().any(|a| a == "peer_export_deleted"));

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Export Lifecycle Rollback (Runner Failure & SQLite Commit/Delete Failure)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn export_lifecycle_rollback_on_runner_and_sqlite_failures() {
    let tmp = TempFixtureDir::new("af-p7-export-rb");
    let dir1 = tmp.path.join("dir1");
    let dir2 = tmp.path.join("dir2");
    fs::create_dir_all(&dir1).unwrap();
    fs::create_dir_all(&dir2).unwrap();

    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_901_000);
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(153), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(154), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    let (rt_b, db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, _db_a) = build_storage_runtime(
        "app-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 42], 41201)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (_a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;

    // 1. Runner WriteExports failure leaves SQLite clean.
    storage_b.fail_next_action(
        "write_exports",
        PeerStorageError::Runtime("exportfs failed".to_string()),
    );
    let (st, _, _) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": dir1.to_string_lossy() })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        db_peers::list_peer_exports_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .is_empty()
    );
    assert!(storage_b.exports_for_link(&b_link_id).is_none());

    // 2. SQLite INSERT failure after WriteExports rolls back runner exports via RemoveExports.
    db_b.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_export_insert BEFORE INSERT ON peer_exports \
             BEGIN SELECT RAISE(ABORT, 'injected export insert failure'); END;",
        )
        .unwrap();
    let (st, _, _) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": dir1.to_string_lossy() })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        storage_b.exports_for_link(&b_link_id).is_none(),
        "runner must roll back staged export on SQLite commit failure"
    );
    assert_eq!(storage_b.count_action("remove_exports"), 1);

    db_b.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_export_insert;")
        .unwrap();

    // Create dir1 cleanly, then fail SQLite insert on dir2 -> runner must restore dir1 only!
    let (st, _, created1) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": dir1.to_string_lossy() })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let export1_id = created1["export"]["id"].as_str().unwrap().to_string();
    let dir1_canon = fs::canonicalize(&dir1)
        .unwrap()
        .to_string_lossy()
        .to_string();

    db_b.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_export_insert BEFORE INSERT ON peer_exports \
             BEGIN SELECT RAISE(ABORT, 'injected second insert failure'); END;",
        )
        .unwrap();
    let (st, _, _) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": dir2.to_string_lossy() })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, restored_specs) = storage_b.exports_for_link(&b_link_id).unwrap();
    assert_eq!(restored_specs.len(), 1);
    assert_eq!(restored_specs[0].path, dir1_canon);
    db_b.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_export_insert;")
        .unwrap();

    // 3. SQLite DELETE failure after RemoveExports rolls back runner by restoring dir1.
    db_b.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_export_delete BEFORE DELETE ON peer_exports \
             BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
        )
        .unwrap();
    let (st, _, _) = call_admin_full(
        &rt_b,
        Method::DELETE,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "export_id": export1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, specs_after_del_rb) = storage_b.exports_for_link(&b_link_id).unwrap();
    assert_eq!(specs_after_del_rb.len(), 1);
    assert_eq!(specs_after_del_rb[0].path, dir1_canon);
    db_b.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_export_delete;")
        .unwrap();

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Tunnel Export Catalog Auth & Cross-Link Isolation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tunnel_export_catalog_enforces_link_auth_and_blocks_cross_link_discovery() {
    let tmp = TempFixtureDir::new("af-p7-catalog");
    let dir_for_a = tmp.path.join("only-for-a");
    let dir_for_c = tmp.path.join("only-for-c");
    fs::create_dir_all(&dir_for_a).unwrap();
    fs::create_dir_all(&dir_for_c).unwrap();

    let ips = next_storage_loopback_ips(3);
    let (ip_a, ip_b, ip_c) = (ips[0], ips[1], ips[2]);
    let clock = FakeClock::new(1_800_902_000);
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(155), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(156), ip_b, 51821);
    let runner_c = FakePeerRunner::new(fixture_wg_pubkey(157), ip_c, 51821);

    let (rt_b, _db_b) = build_storage_runtime(
        "hub-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerStorageRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, _db_a) = build_storage_runtime(
        "peer-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        FakePeerStorageRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 43], 41202)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_c, _db_c) = build_storage_runtime(
        "peer-c",
        Arc::clone(&runner_c) as Arc<dyn PeerRunner>,
        FakePeerStorageRunner::new_arc(),
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 44], 41203)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (a_link_id, b_link_a_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "hub-b").await;
    let (c_link_id, b_link_c_id, _) =
        pair_two_test_runtimes(&rt_c, &rt_b, ip_c, ip_b, "hub-b").await;

    // Export distinct folders on hub-b for peer-a vs peer-c.
    let (st_a, _, _) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_a_id}/exports"),
        Some(json!({ "path": dir_for_a.to_string_lossy() })),
    )
    .await;
    assert_eq!(st_a, StatusCode::CREATED);
    let (st_c, _, _) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_c_id}/exports"),
        Some(json!({ "path": dir_for_c.to_string_lossy() })),
    )
    .await;
    assert_eq!(st_c, StatusCode::CREATED);

    let dir_a_canon = fs::canonicalize(&dir_for_a)
        .unwrap()
        .to_string_lossy()
        .to_string();
    let dir_c_canon = fs::canonicalize(&dir_for_c)
        .unwrap()
        .to_string_lossy()
        .to_string();

    // Peer A calling GET /peer/v1/exports (even with ?link_id=<c>) sees ONLY A's export.
    let a_tok = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();
    let (st, body, _) = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            &format!("/peer/v1/exports?link_id={b_link_c_id}"),
            Some(&PeerCredentialSecret::new(a_tok.clone())),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    let a_catalog: Value = serde_json::from_slice(&body).unwrap();
    let a_exports = a_catalog["exports"].as_array().unwrap();
    assert_eq!(a_exports.len(), 1);
    assert_eq!(a_exports[0]["path"], dir_a_canon);

    // Peer C sees ONLY C's export.
    let c_tok = runner_c
        .credential(PeerCredentialSlot::LinkToken, &c_link_id)
        .unwrap();
    let (st, body, _) = rt_c
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/peer/v1/exports",
            Some(&PeerCredentialSecret::new(c_tok.clone())),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);
    let c_catalog: Value = serde_json::from_slice(&body).unwrap();
    let c_exports = c_catalog["exports"].as_array().unwrap();
    assert_eq!(c_exports.len(), 1);
    assert_eq!(c_exports[0]["path"], dir_c_canon);

    // Wrong token (C's token from A's tunnel IP) -> 401 PEER_UNAUTHORIZED.
    let (st, body, _) = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/peer/v1/exports",
            Some(&PeerCredentialSecret::new(c_tok)),
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["code"],
        "PEER_UNAUTHORIZED"
    );

    // Missing link token -> 401 PEER_UNAUTHORIZED.
    let (st, _, _) = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/peer/v1/exports",
            None,
            None,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // POST /peer/v1/exports -> 403 PEER_ROUTE_UNCLASSIFIED (not GET).
    let (st, body, _) = rt_a
        .send_tunnel_request(
            Method::POST,
            &ip_b.to_string(),
            "/peer/v1/exports",
            Some(&PeerCredentialSecret::new(a_tok.clone())),
            Some(b"{}".to_vec()),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["code"],
        "PEER_ROUTE_UNCLASSIFIED"
    );

    // Grant token header without X-AF-Link-Token must not authenticate /peer/v1/exports.
    let listener_router = super::listener::build_listener_router(Arc::clone(&rt_b));
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/peer/v1/exports")
        .header(HEADER_GRANT_TOKEN, "some-grant-token")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_a, 49152)));
    let resp = listener_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Unregistered source IP -> 401 PEER_UNAUTHORIZED.
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/peer/v1/exports")
        .header(HEADER_LINK_TOKEN, &a_tok)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 2, 99, 99], 49153))));
    let resp = listener_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Deleting link A->B on peer A delivers revoke-notice to hub-b (marking hub-b's row `revoked`),
    // so subsequent GET /peer/v1/exports from A returns 403 LINK_REVOKED; deleting the row on hub-b
    // removes it completely so GET /peer/v1/exports returns 401 PEER_UNAUTHORIZED.
    let (del_st, _) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}"), None).await;
    assert_eq!(del_st, StatusCode::OK);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/peer/v1/exports")
        .header(HEADER_LINK_TOKEN, &a_tok)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_a, 49154)));
    let resp = listener_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err_json: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(err_json["code"], "LINK_REVOKED");

    let (del_b_st, _) = call_admin(&rt_b, Method::DELETE, &format!("/{b_link_a_id}"), None).await;
    assert_eq!(del_b_st, StatusCode::OK);
    let mut req2 = Request::builder()
        .method(Method::GET)
        .uri("/peer/v1/exports")
        .header(HEADER_LINK_TOKEN, &a_tok)
        .body(Body::empty())
        .unwrap();
    req2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_a, 49155)));
    let resp2 = listener_router.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    rt_c.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Mount CRUD, Catalog Resolution, Policy Enforcement, Disambiguation & Rollback
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mount_crud_catalog_resolution_permissions_disambiguation_and_rollback() {
    let tmp = TempFixtureDir::new("af-p7-mounts");
    let movies_primary = tmp.path.join("primary/movies");
    let movies_alt = tmp.path.join("alt/movies");
    let shows_rw = tmp.path.join("shows");
    fs::create_dir_all(&movies_primary).unwrap();
    fs::create_dir_all(&movies_alt).unwrap();
    fs::create_dir_all(&shows_rw).unwrap();

    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_903_000);
    let pk_a = fixture_wg_pubkey(158);
    let pk_b = fixture_wg_pubkey(159);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    let shows_canon = fs::canonicalize(&shows_rw)
        .unwrap()
        .to_string_lossy()
        .to_string();
    storage_b.set_owner_override(&shows_canon, 1001, 1001);

    let (rt_b, _db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, db_a) = build_storage_runtime(
        "app-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 45], 41204)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    runner_b.set_peer_live_state(&pk_a, true, Some(5));
    run_health_tick(&rt_a).await;

    // Seed three exports on media-b: ro movies_primary, ro movies_alt (same basename!), rw shows_rw.
    let (_, _, exp_movies_1) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies_primary.to_string_lossy() })),
    )
    .await;
    let exp_movies_1_id = exp_movies_1["export"]["id"].as_str().unwrap().to_string();
    let (_, _, exp_movies_2) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies_alt.to_string_lossy() })),
    )
    .await;
    let exp_movies_2_id = exp_movies_2["export"]["id"].as_str().unwrap().to_string();
    let (_, _, exp_shows_rw) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": shows_rw.to_string_lossy(), "writable": true })),
    )
    .await;
    let exp_shows_rw_id = exp_shows_rw["export"]["id"].as_str().unwrap().to_string();

    // GET /mounts on app-a fetches live remote catalog over pinned tunnel.
    let (st, hdrs, list_initial) =
        call_admin_full(&rt_a, Method::GET, &format!("/{a_link_id}/mounts"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(list_initial["mounts"].as_array().unwrap().len(), 0);
    assert_eq!(
        list_initial["available_exports"].as_array().unwrap().len(),
        3
    );
    assert!(list_initial.get("exports_error").is_none());

    // Browser-supplied remote_path / tunnel_ip / options rejected (deny_unknown_fields).
    for bad_body in [
        json!({ "export_id": exp_movies_1_id, "remote_path": "/etc" }),
        json!({ "export_id": exp_movies_1_id, "tunnel_ip": "10.99.0.99" }),
        json!({ "export_id": exp_movies_1_id, "options": "rw,suid,exec" }),
        json!({ "export_id": exp_movies_1_id, "mount_path": "/tmp/evil" }),
    ] {
        let (st, _, err) = call_admin_full(
            &rt_a,
            Method::POST,
            &format!("/{a_link_id}/mounts"),
            Some(bad_body),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(err["code"], "INVALID_REQUEST");
    }

    // Missing link returns 404 PEER_NOT_FOUND.
    let (st, _, err) = call_admin_full(
        &rt_a,
        Method::POST,
        "/p7-missing-peer/mounts",
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(err["code"], "PEER_NOT_FOUND");

    // Unknown export_id returns 404 PEER_NOT_FOUND.
    let (st, _, err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": "nonexistent-export-id" })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(err["code"], "PEER_NOT_FOUND");

    // Requesting writable=true on read-only remote export -> 403 PEER_SCOPE_DENIED.
    let (st, _, err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id, "writable": true })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], "PEER_SCOPE_DENIED");
    assert_eq!(storage_a.call_count(), 0);

    // Stale WireGuard handshake blocks mount creation before touching storage runner.
    runner_a.set_peer_live_state(&pk_b, true, Some(WG_HANDSHAKE_STALE_SECS + 10));
    let (st, _, err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert_eq!(err["code"], "LINK_DOWN");
    assert_eq!(storage_a.call_count(), 0);
    runner_a.set_peer_live_state(&pk_b, true, Some(5));

    // Rollback 1: StartMount failure removes staged unit and leaves DB clean.
    storage_a.fail_next_action(
        "start_mount",
        PeerStorageError::Runtime("systemctl start failed".to_string()),
    );
    let (st, _, _) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(storage_a.mount_count(), 0);
    assert!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_empty()
    );

    // Rollback 2: ProbeSentinel failure stops + removes unit, returns 503 LINK_DOWN, leaves DB clean.
    storage_a.push_probe_result(
        "/mnt/af-peers/media-b/movies",
        Err("sentinel probe timed out after 5000ms".to_string()),
    );
    let (st, _, err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert_eq!(err["code"], "LINK_DOWN");
    assert_eq!(storage_a.mount_count(), 0);
    assert!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_empty()
    );

    // Rollback 3: SQLite INSERT failure after StartMount + ProbeSentinel stops + removes unit.
    db_a.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_mount_insert BEFORE INSERT ON peer_mounts \
             BEGIN SELECT RAISE(ABORT, 'injected mount insert failure'); END;",
        )
        .unwrap();
    let (st, _, _) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(storage_a.mount_count(), 0);
    db_a.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_mount_insert;")
        .unwrap();

    // Create default read-only mount for primary movies.
    let (st, hdrs, created_m1) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "created_m1={created_m1}");
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let m1: PeerMount = serde_json::from_value(created_m1["mount"].clone()).unwrap();
    assert_eq!(m1.mount_path, "/mnt/af-peers/media-b/movies");
    assert!(!m1.writable);
    assert_eq!(m1.state, MOUNT_STATE_MOUNTED);
    assert_eq!(m1.purpose, "media");
    assert!(m1.last_error.is_none());

    // Duplicate remote export rejected with 409 PEER_CONFLICT.
    let (st, _, dup_err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_1_id })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(dup_err["code"], "PEER_CONFLICT");

    // Second export with identical basename ("movies") gets cleanly disambiguated mount path.
    let (st, _, created_m2) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_movies_2_id })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "created_m2={created_m2}");
    let m2: PeerMount = serde_json::from_value(created_m2["mount"].clone()).unwrap();
    assert_ne!(m2.mount_path, m1.mount_path);
    assert!(m2.mount_path.starts_with("/mnt/af-peers/media-b/movies-"));

    // Opt-in writable mount succeeds when remote export is writable.
    let (st, _, created_m3) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": exp_shows_rw_id, "writable": true })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "created_m3={created_m3}");
    let m3: PeerMount = serde_json::from_value(created_m3["mount"].clone()).unwrap();
    assert!(m3.writable);
    assert_eq!(m3.mount_path, "/mnt/af-peers/media-b/shows");
    let rec3 = storage_a.mount_record(&m3.mount_path).unwrap();
    assert!(rec3.writable);
    assert_eq!(rec3.tunnel_ip, ip_b.to_string());
    assert_eq!(rec3.remote_path, shows_canon);

    // When remote listener is stopped (unreachable), GET /mounts still returns all 3 local mounts
    // alongside empty `available_exports` and typed `exports_error`.
    rt_b.shutdown_all().await;
    let (st, _, list_degraded) =
        call_admin_full(&rt_a, Method::GET, &format!("/{a_link_id}/mounts"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_degraded["mounts"].as_array().unwrap().len(), 3);
    assert_eq!(
        list_degraded["available_exports"].as_array().unwrap().len(),
        0
    );
    assert_eq!(list_degraded["exports_error"]["code"], "LINK_DOWN");

    // DELETE /mounts stops + removes unit and deletes SQLite row.
    let (st, hdrs, _) = call_admin_full(
        &rt_a,
        Method::DELETE,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "mount_id": m1.id })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(hdrs.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert!(storage_a.mount_record(&m1.mount_path).is_none());
    assert_eq!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .len(),
        2
    );

    let audits = audit_actions(&db_a);
    assert!(audits.iter().any(|a| a == "peer_mount_created"));
    assert!(audits.iter().any(|a| a == "peer_mount_deleted"));

    rt_a.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Health Loop Gating: WireGuard Removal, Stale Handshake, 2x Sentinel & Recovery
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_gating_stops_on_wg_removal_stale_handshake_two_sentinel_failures_and_recovers() {
    let tmp = TempFixtureDir::new("af-p7-health");
    let movies = tmp.path.join("movies");
    fs::create_dir_all(&movies).unwrap();

    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_904_000);
    let pk_a = fixture_wg_pubkey(160);
    let pk_b = fixture_wg_pubkey(161);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    let (rt_b, _db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, db_a) = build_storage_runtime(
        "app-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 46], 41205)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    runner_b.set_peer_live_state(&pk_a, true, Some(5));
    run_health_tick(&rt_a).await;

    let (_, _, exp) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies.to_string_lossy() })),
    )
    .await;
    let export_id = exp["export"]["id"].as_str().unwrap().to_string();
    let (st, _, created_m) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": export_id })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let mount_id = created_m["mount"]["id"].as_str().unwrap().to_string();
    let mount_path = created_m["mount"]["mount_path"]
        .as_str()
        .unwrap()
        .to_string();

    // Case A: Explicit WireGuard peer removal (`present_live == false`) stops mount on 1st tick!
    runner_a.set_peer_live_state(&pk_b, false, None);
    let stops_before = storage_a.count_action("stop_mount");
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 1);
    assert!(!storage_a.mount_record(&mount_path).unwrap().active);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_STOPPED);
    assert!(m.last_error.as_deref().unwrap_or("").contains("link down"));

    // Second tick while still down does NOT spam StopMount for already-stopped mount.
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 1);

    // Restoring live WireGuard peer recovers mount automatically on next tick.
    runner_a.set_peer_live_state(&pk_b, true, Some(3));
    run_health_tick(&rt_a).await;
    assert!(storage_a.mount_record(&mount_path).unwrap().active);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_MOUNTED);
    assert!(m.last_error.is_none());

    // Case B: Stale WireGuard handshake (> 180s) stops mount immediately on 1st tick and recovers.
    runner_a.set_peer_live_state(&pk_b, true, Some(WG_HANDSHAKE_STALE_SECS + 15));
    let stops_before = storage_a.count_action("stop_mount");
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 1);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_STOPPED);

    runner_a.set_peer_live_state(&pk_b, true, Some(2));
    run_health_tick(&rt_a).await;
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_MOUNTED);

    // Case C: Single transient sentinel failure warns but does NOT stop; next success resets counter.
    let stops_before = storage_a.count_action("stop_mount");
    storage_a.push_probe_result(&mount_path, Err("temporary NFS timeout".to_string()));
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before);
    assert_eq!(rt_a.mount_health.failure_count(&mount_id), 1);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_MOUNTED);
    assert!(m.last_error.as_deref().unwrap_or("").contains("1/2"));

    // Next tick healthy -> resets counter and clears last_error.
    storage_a.push_probe_result(&mount_path, Ok(()));
    run_health_tick(&rt_a).await;
    assert_eq!(rt_a.mount_health.failure_count(&mount_id), 0);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_MOUNTED);
    assert!(m.last_error.is_none());

    // Case D: Two consecutive sentinel failures stop the mount on the 2nd tick.
    storage_a.push_probe_result(&mount_path, Err("sentinel missing #1".to_string()));
    storage_a.push_probe_result(&mount_path, Err("sentinel missing #2".to_string()));
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before);
    assert_eq!(rt_a.mount_health.failure_count(&mount_id), 1);

    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 1);
    assert!(!storage_a.mount_record(&mount_path).unwrap().active);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_STOPPED);
    assert!(m
        .last_error
        .as_deref()
        .unwrap_or("")
        .contains("2 consecutive"));

    // Case E: Recovery attempt where StartMount succeeds but ProbeSentinel STILL fails
    // MUST immediately re-stop the mount so an unverified/empty folder is never exposed.
    let stops_before = storage_a.count_action("stop_mount");
    storage_a.push_probe_result(&mount_path, Err("remote nfsd still down".to_string()));
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 1);
    assert!(!storage_a.mount_record(&mount_path).unwrap().active);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_STOPPED);

    // Case F: Recovery succeeds when sentinel returns healthy.
    storage_a.push_probe_result(&mount_path, Ok(()));
    run_health_tick(&rt_a).await;
    assert!(storage_a.mount_record(&mount_path).unwrap().active);
    let m = db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
        .unwrap()
        .unwrap();
    assert_eq!(m.state, MOUNT_STATE_MOUNTED);
    assert!(m.last_error.is_none());

    // An unconfirmed stop must be retried while the link remains degraded.
    let link = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    let mount_state = || {
        db_peers::get_peer_mount(&db_a.lock().unwrap(), &mount_id)
            .unwrap()
            .unwrap()
    };
    let stops_before = storage_a.count_action("stop_mount");
    storage_a.push_probe_result(&mount_path, Err("sentinel missing".to_string()));
    storage_a.push_probe_result(&mount_path, Err("sentinel still missing".to_string()));
    storage_a.fail_next_action("stop_mount", PeerStorageError::Busy("stop busy".into()));
    probe_mounts_while_link_degraded(&rt_a, &link, "tunnel health unavailable").await;
    probe_mounts_while_link_degraded(&rt_a, &link, "tunnel health unavailable").await;
    assert_eq!(mount_state().state, MOUNT_STATE_ERROR);
    assert!(storage_a.mount_record(&mount_path).unwrap().active);
    probe_mounts_while_link_degraded(&rt_a, &link, "tunnel health unavailable").await;
    assert_eq!(storage_a.count_action("stop_mount"), stops_before + 2);
    assert_eq!(mount_state().state, MOUNT_STATE_STOPPED);
    assert!(!storage_a.mount_record(&mount_path).unwrap().active);

    // A failed recovery rollback cannot report a stopped mount or start it again immediately.
    storage_a.push_probe_result(&mount_path, Err("recovery probe failed".into()));
    storage_a.fail_next_action("stop_mount", PeerStorageError::Busy("rollback busy".into()));
    run_health_tick(&rt_a).await;
    let mount = mount_state();
    assert_eq!(mount.state, MOUNT_STATE_ERROR);
    assert!(mount.last_error.unwrap().contains("rollback busy"));
    assert!(storage_a.mount_record(&mount_path).unwrap().active);
    let starts_before = storage_a.count_action("start_mount");
    run_health_tick(&rt_a).await;
    assert_eq!(storage_a.count_action("start_mount"), starts_before);
    assert_eq!(mount_state().state, MOUNT_STATE_STOPPED);
    assert!(!storage_a.mount_record(&mount_path).unwrap().active);
    run_health_tick(&rt_a).await;
    assert_eq!(mount_state().state, MOUNT_STATE_MOUNTED);

    let titles = notification_titles(&db_a);
    assert!(titles.iter().any(|t| t.contains("Peer mount stopped")));
    assert!(titles.iter().any(|t| t.contains("Peer mount recovered")));
    let audits = audit_actions(&db_a);
    assert!(audits.iter().any(|a| a == "peer_mount_stopped"));
    assert!(audits.iter().any(|a| a == "peer_mount_recovered"));

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Scoped Revocation Cleanup, Other-Link Preservation & Durable Transient Retry
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scoped_revocation_cleanup_and_transient_retry_preserve_other_links() {
    let tmp = TempFixtureDir::new("af-p7-revoke");
    let a_export_b = tmp.path.join("a-for-b");
    let a_export_c = tmp.path.join("a-for-c");
    let b_export_a = tmp.path.join("b-for-a");
    let c_export_a = tmp.path.join("c-for-a");
    for d in [&a_export_b, &a_export_c, &b_export_a, &c_export_a] {
        fs::create_dir_all(d).unwrap();
    }

    let ips = next_storage_loopback_ips(3);
    let (ip_a, ip_b, ip_c) = (ips[0], ips[1], ips[2]);
    let clock = FakeClock::new(1_800_905_000);
    let pk_a = fixture_wg_pubkey(162);
    let pk_b = fixture_wg_pubkey(163);
    let pk_c = fixture_wg_pubkey(164);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_c = FakePeerRunner::new(pk_c.clone(), ip_c, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();
    let storage_c = FakePeerStorageRunner::new_arc();

    let (rt_b, db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, db_a) = build_storage_runtime(
        "hub-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 47], 41206)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (a_link_b, b_link_a, _) = pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;

    let (rt_c, _db_c) = build_storage_runtime(
        "media-c",
        Arc::clone(&runner_c) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_c) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_a),
            client_ip: SocketAddr::from(([198, 51, 100, 48], 41207)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (c_link_a, a_link_c, _) = pair_two_test_runtimes(&rt_c, &rt_a, ip_c, ip_a, "hub-a").await;
    // Rename link on hub-a to "media-c" for clear mount path derivation.
    db_a.lock()
        .unwrap()
        .execute(
            "UPDATE peer_links SET name = 'media-c' WHERE id = ?1",
            rusqlite::params![a_link_c],
        )
        .unwrap();

    runner_a.set_peer_live_state(&pk_b, true, Some(4));
    runner_a.set_peer_live_state(&pk_c, true, Some(4));
    runner_b.set_peer_live_state(&pk_a, true, Some(4));
    runner_c.set_peer_live_state(&pk_a, true, Some(4));
    run_health_tick(&rt_a).await;

    // Create exports on A->B, A->C, B->A, C->A and mounts on A from both B and C.
    assert_eq!(
        call_admin_full(
            &rt_a,
            Method::POST,
            &format!("/{a_link_b}/exports"),
            Some(json!({ "path": a_export_b.to_string_lossy() })),
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call_admin_full(
            &rt_a,
            Method::POST,
            &format!("/{a_link_c}/exports"),
            Some(json!({ "path": a_export_c.to_string_lossy() })),
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let (_, _, exp_b) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_a}/exports"),
        Some(json!({ "path": b_export_a.to_string_lossy() })),
    )
    .await;
    let (_, _, exp_c) = call_admin_full(
        &rt_c,
        Method::POST,
        &format!("/{c_link_a}/exports"),
        Some(json!({ "path": c_export_a.to_string_lossy() })),
    )
    .await;

    let (st_mb, _, mount_b_body) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_b}/mounts"),
        Some(json!({ "export_id": exp_b["export"]["id"].as_str().unwrap() })),
    )
    .await;
    assert_eq!(st_mb, StatusCode::CREATED);
    let mount_b_path = mount_b_body["mount"]["mount_path"]
        .as_str()
        .unwrap()
        .to_string();

    let (st_mc, _, mount_c_body) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_c}/mounts"),
        Some(json!({ "export_id": exp_c["export"]["id"].as_str().unwrap() })),
    )
    .await;
    assert_eq!(st_mc, StatusCode::CREATED);
    let mount_c_path = mount_c_body["mount"]["mount_path"]
        .as_str()
        .unwrap()
        .to_string();

    // Inject transient Busy failure on RemoveMount during deletion of link A<->B!
    storage_a.fail_next_action(
        "remove_mount",
        PeerStorageError::Busy("systemd lock busy".to_string()),
    );

    let (del_st, del_body) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_b}"), None).await;
    assert_eq!(
        del_st,
        StatusCode::SERVICE_UNAVAILABLE,
        "del_body={del_body}"
    );
    assert_eq!(del_body["code"], "PEER_BUSY");

    // WireGuard peer and credentials for B MUST ALREADY be removed immediately despite storage Busy!
    assert!(!runner_a.has_peer(&pk_b));
    assert!(runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_b)
        .is_none());

    // Link A<->B export was already removed; mount row remains stopped awaiting retry;
    // remote media-b received revoke-notice and cleaned up B's export scoped to A!
    assert!(storage_a.exports_for_link(&a_link_b).is_none());
    assert!(
        db_peers::list_peer_exports_for_link(&db_a.lock().unwrap(), &a_link_b)
            .unwrap()
            .is_empty()
    );
    assert!(storage_b.exports_for_link(&b_link_a).is_none());
    assert!(
        db_peers::list_peer_exports_for_link(&db_b.lock().unwrap(), &b_link_a)
            .unwrap()
            .is_empty()
    );

    let pending_mounts =
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_b).unwrap();
    assert_eq!(pending_mounts.len(), 1);
    assert_eq!(pending_mounts[0].state, MOUNT_STATE_STOPPED);

    // Next health tick retries pending revocation cleanup -> removes mount unit, deletes DB row,
    // and deletes the completed revoking link row!
    run_health_tick(&rt_a).await;
    assert!(storage_a.mount_record(&mount_b_path).is_none());
    assert!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_b)
            .unwrap()
            .is_empty()
    );
    assert!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_b)
            .unwrap()
            .is_none(),
        "revoking link row must be finalized/deleted once retry cleanup finishes"
    );

    // Link A<->C's mounts, exports, runner state, and WireGuard peer MUST remain 100% intact!
    assert!(runner_a.has_peer(&pk_c));
    assert!(storage_a.mount_record(&mount_c_path).unwrap().active);
    assert_eq!(storage_a.exports_for_link(&a_link_c).unwrap().1.len(), 1);
    assert_eq!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_c)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db_peers::list_peer_exports_for_link(&db_a.lock().unwrap(), &a_link_c)
            .unwrap()
            .len(),
        1
    );

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    rt_c.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Concurrent Mount Creation vs Link Revocation (No Leaked Units or DB Rows)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_mount_creation_and_link_revocation_leave_no_leaked_state() {
    let tmp = TempFixtureDir::new("af-p7-race");
    let movies = tmp.path.join("movies");
    fs::create_dir_all(&movies).unwrap();

    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_906_000);
    let pk_a = fixture_wg_pubkey(165);
    let pk_b = fixture_wg_pubkey(166);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    let (rt_b, _db_b) = build_storage_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        Some(vec![tmp.path.clone()]),
    );
    let (rt_a, db_a) = build_storage_runtime(
        "app-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 49], 41208)),
        }),
        &clock,
        Some(vec![tmp.path.clone()]),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-b").await;
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    runner_b.set_peer_live_state(&pk_a, true, Some(5));
    run_health_tick(&rt_a).await;

    let (_, _, exp) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies.to_string_lossy() })),
    )
    .await;
    let export_id = exp["export"]["id"].as_str().unwrap().to_string();

    // Pause POST /mounts right inside WriteMount (holding link_lock), then launch DELETE /peers/:id.
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    storage_a.block_once_on("write_mount", Arc::clone(&entered), Arc::clone(&release));

    let rt_a_mount = Arc::clone(&rt_a);
    let link_for_mount = a_link_id.clone();
    let mount_task = tokio::spawn(async move {
        call_admin_full(
            &rt_a_mount,
            Method::POST,
            &format!("/{link_for_mount}/mounts"),
            Some(json!({ "export_id": export_id })),
        )
        .await
    });

    entered.notified().await;

    let rt_a_del = Arc::clone(&rt_a);
    let link_for_del = a_link_id.clone();
    let delete_task = tokio::spawn(async move {
        call_admin(&rt_a_del, Method::DELETE, &format!("/{link_for_del}"), None).await
    });

    tokio::time::sleep(Duration::from_millis(30)).await;
    release.notify_waiters();

    let (mount_res, del_res) = tokio::join!(mount_task, delete_task);
    let (mount_st, _, _) = mount_res.unwrap();
    let (del_st, _) = del_res.unwrap();
    assert_eq!(mount_st, StatusCode::CREATED);
    assert_eq!(del_st, StatusCode::OK);

    // After both complete, DELETE must have waited for link_lock and cleaned up the mount completely!
    assert_eq!(
        storage_a.mount_count(),
        0,
        "no mount units may leak after concurrent create + revoke"
    );
    assert!(
        db_peers::list_peer_mounts_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_empty(),
        "no peer_mounts rows may remain after concurrent create + revoke"
    );

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Standalone Dormancy & Zero Storage Calls When No Exports/Mounts Configured
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn standalone_dormancy_and_zero_storage_calls_without_mounts_or_exports() {
    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_907_000);
    let pk_a = fixture_wg_pubkey(167);
    let pk_b = fixture_wg_pubkey(168);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();

    // 1. Standalone server (no peer identity, no links): zero network and zero storage calls.
    let (rt_standalone, _) = build_storage_runtime(
        "standalone",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        None,
    );
    start_with_runtime(Arc::clone(&rt_standalone)).await;
    run_health_tick(&rt_standalone).await;
    assert_eq!(runner_a.call_count(), 0);
    assert_eq!(storage_a.call_count(), 0);
    rt_standalone.shutdown_all().await;

    // 2. Paired links with NO mounts/exports: health ticks, WG removal, and link revocation
    // make ZERO storage runner calls.
    let (rt_b, _) = build_storage_runtime(
        "peer-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        None,
    );
    let (rt_a, _) = build_storage_runtime(
        "peer-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 50], 41209)),
        }),
        &clock,
        None,
    );
    let (a_link_id, _, _) = pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "peer-b").await;
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    run_health_tick(&rt_a).await;
    runner_a.set_peer_live_state(&pk_b, false, None);
    run_health_tick(&rt_a).await;
    let (del_st, _) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}"), None).await;
    assert_eq!(del_st, StatusCode::OK);
    assert_eq!(storage_a.call_count(), 0);
    assert_eq!(storage_b.call_count(), 0);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Historical P6 Compatibility When Remote Peer Lacks "storage" Capability
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn p6_historical_compatibility_when_peer_lacks_storage_capability() {
    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_800_908_000);
    let pk_a = fixture_wg_pubkey(169);
    let pk_b = fixture_wg_pubkey(170);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();

    let (rt_b, _) = build_storage_runtime(
        "legacy-p6-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        FakePeerStorageRunner::new_arc(),
        Arc::new(UnreachablePublicTransport),
        &clock,
        None,
    );
    let (rt_a, db_a) = build_storage_runtime(
        "p7-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 51], 41210)),
        }),
        &clock,
        None,
    );

    let (a_link_id, _, _) = pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "legacy-p6-b").await;
    runner_a.set_peer_live_state(&pk_b, true, Some(4));

    // Simulate a P6 remote peer advertising protocol 1 and ["links", "grants"] (no "storage").
    db_a.lock()
        .unwrap()
        .execute(
            "UPDATE peer_links SET peer_protocol = 1, capabilities = '[\"links\",\"grants\"]' WHERE id = ?1",
            rusqlite::params![a_link_id],
        )
        .unwrap();

    // GET /admin/peers reports limited compatibility with missing_capabilities=["storage", "transcode"].
    let (st, peers_list) = call_admin(&rt_a, Method::GET, "/", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(peers_list["peers"][0]["compatibility"], "limited");
    assert_eq!(
        peers_list["peers"][0]["missing_capabilities"],
        json!(["storage", "transcode"])
    );

    // GET /mounts degrades cleanly with exports_error.code == VERSION_INCOMPATIBLE.
    let (st, _, mounts_body) =
        call_admin_full(&rt_a, Method::GET, &format!("/{a_link_id}/mounts"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(mounts_body["available_exports"], json!([]));
    assert_eq!(mounts_body["exports_error"]["code"], "VERSION_INCOMPATIBLE");

    // POST /mounts fails cleanly with 422 VERSION_INCOMPATIBLE and touches neither tunnel nor runner.
    let (st, _, mount_err) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": "some-export" })),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(mount_err["code"], "VERSION_INCOMPATIBLE");
    assert_eq!(storage_a.call_count(), 0);

    // Meanwhile, P5/P6 grants STILL succeed cleanly against a peer lacking "storage"!
    let (grant_st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
    )
    .await;
    assert_eq!(grant_st, StatusCode::OK);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Media Safety Hooks: Subfolder Enforcement, Sentinel & Plex Empty-Trash
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn media_safety_hooks_subfolder_sentinel_and_plex_auto_empty_trash() {
    let tmp = TempFixtureDir::new("af-p7-media-safety");
    let mounts_base = tmp.path.join("af-peers");
    let mount_root = mounts_base.join("media-2").join("movies");
    let library_dir = mount_root.join("library");
    let local_dir = tmp.path.join("local-media");
    fs::create_dir_all(&library_dir).unwrap();
    fs::create_dir_all(&local_dir).unwrap();

    assert_eq!(
        recommended_library_path("/mnt/af-peers/media-2/movies"),
        "/mnt/af-peers/media-2/movies/library"
    );

    // Ordinary local path passes untouched.
    assert!(validate_media_library_path_with_base(&local_dir, &mounts_base).is_ok());

    // Base dir, peer dir, and mount root itself MUST be rejected as MountRootDisallowed.
    assert!(matches!(
        validate_media_library_path_with_base(&mounts_base, &mounts_base),
        Err(MediaLibraryPathError::MountRootDisallowed(_))
    ));
    assert!(matches!(
        validate_media_library_path_with_base(&mounts_base.join("media-2"), &mounts_base),
        Err(MediaLibraryPathError::MountRootDisallowed(_))
    ));
    assert!(matches!(
        validate_media_library_path_with_base(&mount_root, &mounts_base),
        Err(MediaLibraryPathError::MountRootDisallowed(_))
    ));

    // Interior subfolder WITHOUT .af-peer-sentinel MUST be rejected as MountUnavailable.
    assert!(matches!(
        validate_media_library_path_with_base(&library_dir, &mounts_base),
        Err(MediaLibraryPathError::MountUnavailable(_))
    ));

    // Symlink sentinel is refused.
    let sentinel = mount_root.join(PEER_SENTINEL_FILE_NAME);
    let decoy = tmp.path.join("decoy");
    fs::write(&decoy, b"decoy").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&decoy, &sentinel).unwrap();
        assert!(matches!(
            validate_media_library_path_with_base(&library_dir, &mounts_base),
            Err(MediaLibraryPathError::MountUnavailable(_))
        ));
        fs::remove_file(&sentinel).unwrap();
    }

    // Regular .af-peer-sentinel allows interior subfolder.
    fs::write(&sentinel, b"aetherflow-peer-sentinel\n").unwrap();
    assert!(validate_media_library_path_with_base(&library_dir, &mounts_base).is_ok());
    // Even with sentinel present, mount root itself is STILL disallowed!
    assert!(matches!(
        validate_media_library_path_with_base(&mount_root, &mounts_base),
        Err(MediaLibraryPathError::MountRootDisallowed(_))
    ));

    // Fake loopback Plex HTTP server verifying PUT /:/prefs?autoEmptyTrash=0 behavior.
    let sections_payload: Arc<StdMutex<Value>> = Arc::new(StdMutex::new(json!({
        "MediaContainer": {
            "Directory": [
                { "Location": [{ "path": "/srv/local/movies" }] }
            ]
        }
    })));
    let prefs_calls: Arc<StdMutex<Vec<(String, String)>>> = Arc::new(StdMutex::new(Vec::new()));
    let section_calls = Arc::new(AtomicUsize::new(0));

    let sections_state = Arc::clone(&sections_payload);
    let section_requests = Arc::clone(&section_calls);
    let prefs_state = Arc::clone(&prefs_calls);
    let plex_app = Router::new()
        .route(
            "/identity",
            get(|| async {
                Json(json!({ "MediaContainer": { "machineIdentifier": "pinned-plex" } }))
            }),
        )
        .route(
            "/library/sections",
            get(move |headers: axum::http::HeaderMap| {
                section_requests.fetch_add(1, Ordering::Relaxed);
                let st = Arc::clone(&sections_state);
                async move {
                    let tok = headers
                        .get("X-Plex-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if tok != "test-plex-token" {
                        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "auth" })));
                    }
                    (StatusCode::OK, Json(st.lock().unwrap().clone()))
                }
            }),
        )
        .route(
            "/:colon/prefs",
            put(
                move |axum::extract::Path(colon): axum::extract::Path<String>,
                      headers: axum::http::HeaderMap,
                      axum::extract::RawQuery(query): axum::extract::RawQuery| {
                    let st = Arc::clone(&prefs_state);
                    async move {
                        assert_eq!(colon, ":", "Plex prefs endpoint must be /:/prefs");
                        let tok = headers
                            .get("X-Plex-Token")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        st.lock().unwrap().push((tok, query.unwrap_or_default()));
                        StatusCode::OK
                    }
                },
            ),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, plex_app).await;
    });
    let plex_url = format!("http://{addr}");

    // 1. Only local libraries -> zero PUT /:/prefs calls.
    let local_only = enforce_plex_peer_mount_safety_at_base(
        &plex_url,
        "test-plex-token",
        "pinned-plex",
        "/mnt/af-peers",
    )
    .await
    .unwrap();
    assert!(local_only.peer_libraries.is_empty());
    assert!(!local_only.auto_empty_trash_disabled);
    assert!(prefs_calls.lock().unwrap().is_empty());

    // 2. Peer-mounted libraries present -> disables autoEmptyTrash=0 and warns on mount root.
    *sections_payload.lock().unwrap() = json!({
        "MediaContainer": {
            "Directory": [
                { "Location": [{ "path": "/mnt/af-peers/media-2/movies/library" }] },
                { "Location": [{ "path": "/mnt/af-peers/media-2/shows" }] }
            ]
        }
    });
    let wrong_identity = enforce_plex_peer_mount_safety_at_base(
        &plex_url,
        "test-plex-token",
        "different-server",
        "/mnt/af-peers",
    )
    .await
    .unwrap_err();
    assert!(wrong_identity.contains("Plex server identity changed"));
    assert_eq!(section_calls.load(Ordering::Relaxed), 1);
    assert!(prefs_calls.lock().unwrap().is_empty());

    let peer_outcome = enforce_plex_peer_mount_safety_at_base(
        &plex_url,
        "test-plex-token",
        "pinned-plex",
        "/mnt/af-peers",
    )
    .await
    .unwrap();
    assert!(peer_outcome.auto_empty_trash_disabled);
    assert_eq!(peer_outcome.peer_libraries.len(), 2);
    assert_eq!(
        peer_outcome.mount_root_warnings,
        vec!["/mnt/af-peers/media-2/shows".to_string()]
    );
    let recorded_puts = prefs_calls.lock().unwrap().clone();
    assert_eq!(recorded_puts.len(), 1);
    assert_eq!(recorded_puts[0].0, "test-plex-token");
    assert_eq!(recorded_puts[0].1, "autoEmptyTrash=0");

    server_task.abort();
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Full Router Integration: Admin Auth, CSRF, Proxy Denial & No Legacy Alias
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn router_permissions_csrf_proxy_denial_and_no_legacy_alias_for_p7_storage_routes() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-p7-router-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        std::env::set_var(key, &root);
    }
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("p7-router.sqlite"));
    }
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::remove_var("CSRF_DISABLED");
    af_db::init_db().unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "INSERT INTO users(id, username, role) VALUES (1, 'p7-admin', 'admin');
             INSERT INTO users(id, username, role) VALUES (2, 'p7-member', 'user');",
        )
        .unwrap();
    }

    let mut hdrs = axum::http::HeaderMap::new();
    hdrs.insert(header::USER_AGENT, "p7-router-test".parse().unwrap());
    let (admin_jwt, _) = crate::auth::create_standard_jwt(1, &hdrs).unwrap();
    let (member_jwt, _) = crate::auth::create_standard_jwt(2, &hdrs).unwrap();

    let app = crate::routes::build_router();

    // 1. Unauthenticated -> 401 on all 6 storage endpoints.
    for (method, uri, body) in [
        (Method::GET, "/api/v1/admin/peers/missing/exports", None),
        (
            Method::POST,
            "/api/v1/admin/peers/missing/exports",
            Some(r#"{"path":"/srv/movies"}"#),
        ),
        (
            Method::DELETE,
            "/api/v1/admin/peers/missing/exports",
            Some(r#"{"export_id":"e1"}"#),
        ),
        (Method::GET, "/api/v1/admin/peers/missing/mounts", None),
        (
            Method::POST,
            "/api/v1/admin/peers/missing/mounts",
            Some(r#"{"export_id":"e1"}"#),
        ),
        (
            Method::DELETE,
            "/api/v1/admin/peers/missing/mounts",
            Some(r#"{"mount_id":"m1"}"#),
        ),
    ] {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(header::HOST, "localhost");
        let req_body = if let Some(raw) = body {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(raw.to_string())
        } else {
            Body::empty()
        };
        let resp = app
            .clone()
            .oneshot(b.body(req_body).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 on unauth {method} {uri}"
        );
    }

    // 2. Non-admin member -> 403 on exports and mounts.
    for uri in [
        "/api/v1/admin/peers/missing/exports",
        "/api/v1/admin/peers/missing/mounts",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "p7-router-test")
                    .header(header::AUTHORIZATION, format!("Bearer {member_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for non-admin {uri}"
        );
    }

    // 3. Cookie-authenticated POST/DELETE WITHOUT CSRF header -> 403.
    for (method, uri, body) in [
        (
            Method::POST,
            "/api/v1/admin/peers/missing/exports",
            r#"{"path":"/srv/movies"}"#,
        ),
        (
            Method::DELETE,
            "/api/v1/admin/peers/missing/exports",
            r#"{"export_id":"e1"}"#,
        ),
        (
            Method::POST,
            "/api/v1/admin/peers/missing/mounts",
            r#"{"export_id":"e1"}"#,
        ),
        (
            Method::DELETE,
            "/api/v1/admin/peers/missing/mounts",
            r#"{"mount_id":"m1"}"#,
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "p7-router-test")
                    .header(
                        header::COOKIE,
                        format!("aetherflow_session={admin_jwt}; csrf_token=p7-csrf-secret"),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "expected 403 missing CSRF on {method} {uri}"
        );
    }

    // 4. Cookie-authenticated POST WITH valid CSRF header passes middleware and hits handler (404 PEER_NOT_FOUND).
    let with_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/peers/p7-missing-peer/exports")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p7-router-test")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; csrf_token=p7-csrf-secret"),
                )
                .header("X-CSRF-Token", "p7-csrf-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"/var/tmp/nonexistent"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(with_csrf.status(), StatusCode::NOT_FOUND);
    let err_json: Value =
        serde_json::from_slice(&to_bytes(with_csrf.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(err_json["code"], "PEER_NOT_FOUND");

    // 5. Legacy /api/admin/peers/... alias MUST NOT exist (404).
    for uri in [
        "/api/admin/peers/missing/exports",
        "/api/admin/peers/missing/mounts",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "p7-router-test")
                    .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "legacy alias {uri} must remain unregistered"
        );
    }

    // 6. Browser management proxy rejects /api/v1/peers/:id/admin/peers/... with 403 PEER_SCOPE_DENIED.
    for (method, uri, body) in [
        (
            Method::GET,
            "/api/v1/peers/link-1/admin/peers/link-2/exports",
            None,
        ),
        (
            Method::POST,
            "/api/v1/peers/link-1/admin/peers/link-2/exports",
            Some(r#"{"path":"/srv/movies"}"#),
        ),
        (
            Method::GET,
            "/api/v1/peers/link-1/admin/peers/link-2/mounts",
            None,
        ),
        (
            Method::POST,
            "/api/v1/peers/link-1/admin/peers/link-2/mounts",
            Some(r#"{"export_id":"e1"}"#),
        ),
    ] {
        let mut b = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(header::HOST, "localhost")
            .header(header::USER_AGENT, "p7-router-test")
            .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"));
        let req_body = if let Some(raw) = body {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(raw.to_string())
        } else {
            Body::empty()
        };
        let resp = app
            .clone()
            .oneshot(b.body(req_body).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "proxy must reject {method} {uri}"
        );
        let body_json: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 16 * 1024).await.unwrap()).unwrap();
        assert_eq!(body_json["code"], "PEER_SCOPE_DENIED");
    }

    // 7. PeerPrincipal direct call to local admin storage route -> 403 PEER_SCOPE_DENIED.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "INSERT INTO users(id, username, role, account_type) VALUES (3, 'peer-run-as', 'admin', 'peer');
             INSERT INTO user_quotas(user_id, username, status) VALUES (3, 'peer-run-as', 'active');",
        )
        .unwrap();
    }
    let mut peer_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/admin/peers/missing/exports")
        .header(header::HOST, "localhost")
        .body(Body::empty())
        .unwrap();
    peer_req.extensions_mut().insert(AuthUser {
        user_id: 3,
        username: "peer-run-as".to_string(),
        role: "admin".to_string(),
        jti: "peer-jti".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    peer_req
        .extensions_mut()
        .insert(crate::auth::PeerPrincipal {
            link_id: "link-1".to_string(),
            link_name: "peer-1".to_string(),
            local_server: "local-host".to_string(),
            grant_id: "grant-1".to_string(),
            run_as_user_id: 3,
            run_as_username: "peer-run-as".to_string(),
            access: af_db::peers::AccessMap::read_write_all(),
            origin_operator: Some("alice".to_string()),
            request_id: "req-1".to_string(),
        });
    let peer_resp = app.clone().oneshot(peer_req).await.unwrap();
    assert_eq!(peer_resp.status(), StatusCode::FORBIDDEN);
    let peer_err: Value =
        serde_json::from_slice(&to_bytes(peer_resp.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(peer_err["code"], "PEER_SCOPE_DENIED");

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn storage_mount_and_export_changes_auto_resync_active_transcode_worker_and_reject_bad_json()
{
    let ips = next_storage_loopback_ips(2);
    let (ip_a, ip_b) = (ips[0], ips[1]);
    let clock = FakeClock::new(1_801_050_000);
    let now_str = (clock.as_fn())().to_rfc3339();

    let export_root = TempFixtureDir::new("p7-resync-exp");
    let movies_dir = export_root.path.join("movies");
    let a_export_dir = export_root.path.join("ctrl-media");
    fs::create_dir_all(&movies_dir).unwrap();
    fs::create_dir_all(&a_export_dir).unwrap();

    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(191), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(192), ip_b, 51821);
    let storage_a = FakePeerStorageRunner::new_arc();
    let storage_b = FakePeerStorageRunner::new_arc();
    let tc_runner_a = Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new());
    let tc_runner_b = Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new());
    {
        let mut st = tc_runner_a.state.lock().unwrap();
        st.shim_installed = true;
        st.dropin_enabled = true;
    }

    let (rt_b, db_b) = {
        let db_conn = open_isolated_peer_db();
        db_peers::ensure_peer_grant_schema_invariants(&db_conn.lock().unwrap()).unwrap();
        let (revocation_tx, _) = broadcast::channel(64);
        let rt = Arc::new(PeerRuntime {
            db: PeerDb::Isolated(Arc::clone(&db_conn)),
            runner: Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
            storage_runner: Arc::clone(&storage_b) as Arc<dyn PeerStorageRunner>,
            mount_health: MountHealthTracker::new(),
            transcode_runner: Arc::clone(&tc_runner_b)
                as Arc<dyn super::transcode::PeerTranscodeRunner>,
            transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
            public_transport: Arc::new(UnreachablePublicTransport),
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
            server_name_override: Some("gpu-worker".to_string()),
            version_override: Some("4.0.0-p9-test".to_string()),
            tunnel_binding: TunnelTransportBinding::LoopbackFixture,
            tunnel_request_timeout: Duration::from_secs(3),
            tunnel_port_overrides: RwLock::new(HashMap::new()),
            interface_index_override: RwLock::new(None),
            bind_listener_in_handlers: true,
            management_router_override: None,
            allowed_fs_roots_override: Some(vec![export_root.path.clone()]),
        });
        (rt, db_conn)
    };
    let (rt_a, db_a) = {
        let db_conn = open_isolated_peer_db();
        db_peers::ensure_peer_grant_schema_invariants(&db_conn.lock().unwrap()).unwrap();
        let (revocation_tx, _) = broadcast::channel(64);
        let rt = Arc::new(PeerRuntime {
            db: PeerDb::Isolated(Arc::clone(&db_conn)),
            runner: Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
            storage_runner: Arc::clone(&storage_a) as Arc<dyn PeerStorageRunner>,
            mount_health: MountHealthTracker::new(),
            transcode_runner: Arc::clone(&tc_runner_a)
                as Arc<dyn super::transcode::PeerTranscodeRunner>,
            transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
            public_transport: Arc::new(RouterPublicTransport {
                target_runtime: Arc::clone(&rt_b),
                client_ip: SocketAddr::from(([198, 51, 100, 25], 45025)),
            }),
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
            server_name_override: Some("seedbox-1".to_string()),
            version_override: Some("4.0.0-p9-test".to_string()),
            tunnel_binding: TunnelTransportBinding::LoopbackFixture,
            tunnel_request_timeout: Duration::from_secs(3),
            tunnel_port_overrides: RwLock::new(HashMap::new()),
            interface_index_override: RwLock::new(None),
            bind_listener_in_handlers: true,
            management_router_override: None,
            allowed_fs_roots_override: Some(vec![export_root.path.clone()]),
        });
        (rt, db_conn)
    };

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "gpu-worker").await;

    // 1. Structured PeerError JSON on wrong content-type (415) & malformed JSON (400)
    let app_a = admin_routes_with_runtime(Arc::clone(&rt_a));
    let mut ct_req = Request::builder()
        .method(Method::POST)
        .uri(format!("/{a_link_id}/exports"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"path":"/srv/media"}"#))
        .unwrap();
    ct_req.extensions_mut().insert(AuthUser {
        user_id: 1,
        username: "alice".to_string(),
        role: "admin".to_string(),
        jti: "jti-1".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });
    ct_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41010))));
    let ct_resp = app_a.clone().oneshot(ct_req).await.unwrap();
    assert_eq!(ct_resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let ct_json: Value =
        serde_json::from_slice(&to_bytes(ct_resp.into_body(), 16 * 1024).await.unwrap()).unwrap();
    assert_eq!(ct_json["code"], "UNSUPPORTED_MEDIA_TYPE");

    // 2. Grant `transcoding: write` from B -> A and enable B as a transcode worker on A.
    let grant_token = format!("gtok-{}", Uuid::new_v4().simple());
    let grant_id = format!("grant-{}", Uuid::new_v4().simple());
    let mut access = af_db::peers::AccessMap::none();
    access.transcoding = af_db::peers::AccessLevel::Write;
    {
        let conn = db_b.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO users (username, role, account_type) VALUES ('peer-seedbox-1', 'admin', 'peer')",
            [],
        )
        .unwrap();
        let uid: i64 = conn
            .query_row(
                "SELECT id FROM users WHERE username = 'peer-seedbox-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        db_peers::insert_peer_grant(
            &conn,
            &af_db::peers::PeerGrant {
                id: grant_id.clone(),
                link_id: b_link_id.clone(),
                run_as_user_id: uid,
                access: access.clone(),
                token_hash: Some(super::pairing::sha256_prefixed(&grant_token)),
                created_by: "alice".to_string(),
                created_at: now_str.clone(),
                revoked_at: None,
            },
        )
        .unwrap();
    }
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_received_grant(
            &conn,
            &af_db::peers::PeerReceivedGrant {
                link_id: a_link_id.clone(),
                grant_id,
                run_as_user_id: 2,
                access,
                created_by: "alice".to_string(),
                created_at: now_str.clone(),
                generation: 1,
                revoked_at: None,
                credential_id: None,
                updated_at: now_str.clone(),
            },
        )
        .unwrap();
        db_peers::upsert_transcode_worker(
            &conn,
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
    }
    runner_a.state.lock().unwrap().credentials.insert(
        (PeerCredentialSlot::GrantToken, a_link_id.clone()),
        grant_token,
    );

    // Export `movies_dir` on B to A.
    let (st, _, exp_body) = call_admin_full(
        &rt_b,
        Method::POST,
        &format!("/{b_link_id}/exports"),
        Some(json!({ "path": movies_dir.to_string_lossy(), "writable": false })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "export on B failed: {exp_body}");
    let export_id = exp_body["export"]["id"].as_str().unwrap().to_string();

    // 3. Create peer mount on A -> MUST auto-resync `/peer/v1/transcode/mounts` onto B!
    let (st, _, mnt_body) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "export_id": export_id, "writable": false })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "mount on A failed: {mnt_body}");
    let mount_id = mnt_body["mount"]["id"].as_str().unwrap().to_string();
    let mount_path = mnt_body["mount"]["mount_path"]
        .as_str()
        .unwrap()
        .to_string();

    let b_binds: Vec<PeerMount> =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .into_iter()
            .filter(|m| m.purpose == "transcode_bind")
            .collect();
    assert_eq!(
        b_binds.len(),
        1,
        "creating a peer mount on controller MUST auto-resync worker transcode bind mounts"
    );
    assert_eq!(b_binds[0].mount_path, mount_path);

    // 4. Delete peer mount on A -> MUST auto-resync `/peer/v1/transcode/mounts` removing stale bind!
    let (st, _, _) = call_admin_full(
        &rt_a,
        Method::DELETE,
        &format!("/{a_link_id}/mounts"),
        Some(json!({ "mount_id": mount_id })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let b_binds_after: Vec<PeerMount> =
        db_peers::list_peer_mounts_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .into_iter()
            .filter(|m| m.purpose == "transcode_bind")
            .collect();
    assert!(
        b_binds_after.is_empty(),
        "deleting a peer mount on controller MUST remove stale worker bind mount: {b_binds_after:?}"
    );

    // 5. Export create & delete on controller A also trigger bounded best-effort resync cleanly!
    let sync_before = tc_runner_b
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| {
            matches!(
                c,
                af_runner::PeerTranscodeRequest::MountTranscodeDirs { .. }
            )
        })
        .count();
    let (st, _, a_exp) = call_admin_full(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/exports"),
        Some(json!({ "path": a_export_dir.to_string_lossy(), "writable": false })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "export on A failed: {a_exp}");
    let a_exp_id = a_exp["export"]["id"].as_str().unwrap().to_string();
    let sync_after_create = tc_runner_b
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| {
            matches!(
                c,
                af_runner::PeerTranscodeRequest::MountTranscodeDirs { .. }
            )
        })
        .count();
    assert_eq!(sync_after_create, sync_before + 1);

    let (st, _, _) = call_admin_full(
        &rt_a,
        Method::DELETE,
        &format!("/{a_link_id}/exports"),
        Some(json!({ "export_id": a_exp_id })),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let sync_after_delete = tc_runner_b
        .state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| {
            matches!(
                c,
                af_runner::PeerTranscodeRequest::MountTranscodeDirs { .. }
            )
        })
        .count();
    assert_eq!(sync_after_delete, sync_before + 2);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[test]
fn dynamic_system_gid_warning_flags_writable_system_gids_only() {
    use super::storage::dynamic_system_gid_warning;

    let warn = dynamic_system_gid_warning(true, Some(983))
        .expect("writable system GID 983 must emit cross-host alignment warning");
    assert!(warn.contains("GID 983"), "{warn}");
    assert!(warn.contains("2775"), "{warn}");

    assert!(dynamic_system_gid_warning(true, Some(1)).is_some());
    assert!(dynamic_system_gid_warning(true, Some(999)).is_some());
    assert!(dynamic_system_gid_warning(true, Some(1000)).is_none());
    assert!(dynamic_system_gid_warning(true, Some(2000)).is_none());
    assert!(dynamic_system_gid_warning(false, Some(983)).is_none());
    assert!(dynamic_system_gid_warning(true, None).is_none());
}
