use super::errors::{redact_sensitive_text, PeerError, PeerErrorBody};
use super::health::{
    check_single_link, evaluate_compatibility, run_health_tick, CompatibilityStatus,
    WG_HANDSHAKE_STALE_SECS,
};
use super::listener::{
    build_listener_router, spawn_tunnel_listener, TUNNEL_INTERNAL_BODY_LIMIT_BYTES,
};
use super::pairing::{
    cleanup_expired_pending, derive_comparison_code, pending_issuer_credential_id,
    start_pairing_with_link_id, validate_public_https_url, HelloPhase, HelloRequest, HelloResponse,
    PairingPayload, PublicPairingRequest, PublicPairingResponse, StartPairingReq,
    PAIRING_WINDOW_TTL_SECS,
};
use super::{
    admin_routes_with_runtime, public_routes_with_runtime, start_with_runtime, KeyedAsyncLockPool,
    PeerDb, PeerRunner, PeerRuntime, ProductionPublicPairingTransport, PublicPairingTransport,
    RevocationEvent, TunnelTransportBinding, HEADER_GRANT_TOKEN, HEADER_ORIGIN_OPERATOR,
    PEER_LOCK_WAIT_TIMEOUT, PEER_PROTOCOL_VERSION, PUBLIC_PAIRING_BODY_LIMIT_BYTES,
};
use crate::auth::AuthUser;
use af_db::peers::{self as db_peers, PeerIdentity, PeerLink};
use af_runner::{
    PeerCredentialDeleteResponse, PeerCredentialReadResponse, PeerCredentialSecret,
    PeerCredentialSlot, PeerCredentialWriteResponse, PeerEnsurePackagesResponse,
    PeerIdentityResponse, PeerLinkCredentialsDeleteResponse, PeerMutationResponse,
    PeerNetworkError, PeerNetworkRequest, PeerNetworkResponse, PeerStatusPeer, PeerStatusResponse,
};
use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::BoxFuture;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;
use tokio::sync::{broadcast, Mutex as TokioMutex, Notify};
use tower::ServiceExt;
use url::Url;

#[path = "grant_lifecycle_tests.rs"]
mod grant_lifecycle_tests;

static LOOPBACK_IP_OCTET: AtomicU16 = AtomicU16::new(20);

fn next_loopback_pair() -> (IpAddr, IpAddr) {
    let base = LOOPBACK_IP_OCTET.fetch_add(2, Ordering::SeqCst);
    let a_hi = (base / 200) as u8;
    let a_lo = (base % 200) as u8 + 10;
    let b_lo = a_lo + 1;
    (
        IpAddr::V4(Ipv4Addr::new(127, 1, a_hi, a_lo)),
        IpAddr::V4(Ipv4Addr::new(127, 1, a_hi, b_lo)),
    )
}

fn fixture_wg_pubkey(seed: u8) -> String {
    let mut bytes = [0u8; 32];
    for (idx, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_add(idx as u8).max(1);
    }
    STANDARD.encode(bytes)
}

fn open_isolated_peer_db() -> Arc<StdMutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory sqlite");
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT DEFAULT '',
            email TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'admin',
            sessions_revoked_after INTEGER NOT NULL DEFAULT 0,
            account_type TEXT NOT NULL DEFAULT 'human'
        );
        CREATE TABLE user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE active_sessions (
            jti TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ip_address TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            expires_at TEXT NOT NULL,
            last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
            family_id TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE revoked_tokens (
            jti TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL,
            family_id TEXT,
            user_id INTEGER
        );
        CREATE TABLE mfa_challenges (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL,
            credential_ver INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            detail TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            level TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE peer_identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            wg_pubkey TEXT NOT NULL,
            tunnel_ip TEXT NOT NULL,
            wg_port INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE peer_links (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            wg_pubkey TEXT NOT NULL UNIQUE,
            tunnel_ip TEXT NOT NULL UNIQUE,
            endpoint TEXT NOT NULL,
            wg_port INTEGER NOT NULL,
            state TEXT NOT NULL,
            peer_version TEXT,
            peer_protocol INTEGER,
            capabilities TEXT,
            rtt_ms REAL,
            last_ok_at TEXT,
            last_error TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            inbound_token_hash TEXT,
            pending_attempt_id TEXT,
            pending_expires_at INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE peer_grants (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
            run_as_user_id INTEGER NOT NULL,
            access TEXT NOT NULL,
            token_hash TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE TABLE peer_received_grants (
            link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
            grant_id TEXT NOT NULL,
            run_as_user_id INTEGER NOT NULL,
            access TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 0,
            revoked_at TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE peer_grant_epochs (
            link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
            issuer_generation INTEGER NOT NULL DEFAULT 0,
            active_op_id TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE peer_pairing_windows (
            id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER
        );
        CREATE TABLE peer_pairing_attempts (
            id TEXT PRIMARY KEY,
            window_id TEXT,
            remote_name TEXT,
            remote_pubkey TEXT,
            remote_tunnel_ip TEXT,
            remote_endpoint TEXT,
            source_ip TEXT,
            status TEXT NOT NULL,
            error_code TEXT,
            expires_at INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE peer_exports (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            writable INTEGER NOT NULL DEFAULT 0,
            squash_uid INTEGER,
            squash_gid INTEGER,
            created_at TEXT NOT NULL
        );
        CREATE TABLE peer_mounts (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
            remote_path TEXT NOT NULL,
            mount_path TEXT NOT NULL UNIQUE,
            unit_name TEXT NOT NULL,
            writable INTEGER NOT NULL DEFAULT 0,
            purpose TEXT NOT NULL,
            state TEXT NOT NULL,
            last_error TEXT
        );
        CREATE TABLE transcode_workers (
            link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
            enabled INTEGER NOT NULL DEFAULT 0,
            weight INTEGER NOT NULL DEFAULT 1,
            max_jobs INTEGER NOT NULL DEFAULT 2,
            ffmpeg_version TEXT,
            encoders TEXT,
            render_node TEXT,
            parity_ok INTEGER NOT NULL DEFAULT 0,
            parity_error TEXT
        );
        CREATE TABLE transcode_jobs (
            id TEXT PRIMARY KEY,
            link_id TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            exit_code INTEGER,
            request_id TEXT,
            ran_locally INTEGER NOT NULL
        );
        "#,
    )
    .expect("initialize isolated peer schema");
    Arc::new(StdMutex::new(conn))
}

#[derive(Default)]
struct FakeRunnerState {
    pubkey: String,
    tunnel_ip: String,
    wg_port: u16,
    identity_created: bool,
    peers: HashMap<String, FakeWgPeer>,
    credentials: HashMap<(PeerCredentialSlot, String), String>,
    calls: Vec<String>,
    next_add_error: Option<PeerNetworkError>,
    next_remove_error: Option<PeerNetworkError>,
    next_identity_error: Option<PeerNetworkError>,
    next_delete_cred_error: Option<PeerNetworkError>,
    next_delete_link_creds_error: Option<PeerNetworkError>,
}

#[derive(Clone)]
struct FakeWgPeer {
    pubkey: String,
    endpoint: String,
    tunnel_ip: String,
    present_live: bool,
    handshake_age_secs: Option<u64>,
}

struct FakePeerRunner {
    state: StdMutex<FakeRunnerState>,
}

impl FakePeerRunner {
    fn new(pubkey: String, tunnel_ip: IpAddr, wg_port: u16) -> Arc<Self> {
        Arc::new(Self {
            state: StdMutex::new(FakeRunnerState {
                pubkey,
                tunnel_ip: tunnel_ip.to_string(),
                wg_port,
                ..Default::default()
            }),
        })
    }

    fn call_count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }

    fn remove_peer_call_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.as_str() == "remove_peer")
            .count()
    }

    fn add_peer_call_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.as_str() == "add_peer")
            .count()
    }

    fn set_endpoint_call_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.as_str() == "set_endpoint")
            .count()
    }

    fn write_cred_call_count(&self, slot: PeerCredentialSlot) -> usize {
        let prefix = format!("write_cred:{slot:?}:");
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.starts_with(&prefix))
            .count()
    }

    fn has_peer(&self, pubkey: &str) -> bool {
        self.state.lock().unwrap().peers.contains_key(pubkey)
    }

    fn insert_preexisting_peer(&self, pubkey: &str, tunnel_ip: &str, endpoint: &str) {
        self.state.lock().unwrap().peers.insert(
            pubkey.to_string(),
            FakeWgPeer {
                pubkey: pubkey.to_string(),
                endpoint: endpoint.to_string(),
                tunnel_ip: tunnel_ip.to_string(),
                present_live: true,
                handshake_age_secs: Some(5),
            },
        );
    }

    fn credential(&self, slot: PeerCredentialSlot, id: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .credentials
            .get(&(slot, id.to_string()))
            .cloned()
    }

    fn set_peer_live_state(
        &self,
        pubkey: &str,
        present_live: bool,
        handshake_age_secs: Option<u64>,
    ) {
        if let Some(peer) = self.state.lock().unwrap().peers.get_mut(pubkey) {
            peer.present_live = present_live;
            peer.handshake_age_secs = handshake_age_secs;
        }
    }

    fn set_next_add_error(&self, err: PeerNetworkError) {
        self.state.lock().unwrap().next_add_error = Some(err);
    }

    fn set_next_remove_error(&self, err: PeerNetworkError) {
        self.state.lock().unwrap().next_remove_error = Some(err);
    }

    fn set_next_delete_cred_error(&self, err: PeerNetworkError) {
        self.state.lock().unwrap().next_delete_cred_error = Some(err);
    }

    fn set_next_delete_link_creds_error(&self, err: PeerNetworkError) {
        self.state.lock().unwrap().next_delete_link_creds_error = Some(err);
    }
}

impl PeerRunner for FakePeerRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerNetworkRequest,
    ) -> BoxFuture<'a, Result<PeerNetworkResponse, PeerNetworkError>> {
        let res = (|| -> Result<PeerNetworkResponse, PeerNetworkError> {
            let mut st = self.state.lock().unwrap();
            match req {
                PeerNetworkRequest::EnsureIdentity {
                    avoid_tunnel_ips,
                    wg_port,
                    ..
                } => {
                    st.calls.push("ensure_identity".to_string());
                    if let Some(err) = st.next_identity_error.take() {
                        return Err(err);
                    }
                    if avoid_tunnel_ips.iter().any(|ip| ip == &st.tunnel_ip) {
                        return Err(PeerNetworkError::TunnelIpConflict(
                            "TUNNEL_IP_CONFLICT: configured tunnel IP collides with peer"
                                .to_string(),
                        ));
                    }
                    if let Some(p) = wg_port {
                        st.wg_port = *p;
                    }
                    let created = !st.identity_created;
                    st.identity_created = true;
                    Ok(PeerNetworkResponse::Identity(PeerIdentityResponse {
                        interface: "afpeer0".to_string(),
                        public_key: st.pubkey.clone(),
                        tunnel_ip: st.tunnel_ip.clone(),
                        tunnel_cidr: "127.1.0.0/16".to_string(),
                        interface_address: format!("{}/16", st.tunnel_ip),
                        wg_port: st.wg_port,
                        service_state: "active".to_string(),
                        created,
                    }))
                }
                PeerNetworkRequest::AddPeer {
                    pubkey,
                    endpoint,
                    port,
                    tunnel_ip,
                } => {
                    st.calls.push("add_peer".to_string());
                    if let Some(err) = st.next_add_error.take() {
                        return Err(err);
                    }
                    if tunnel_ip == &st.tunnel_ip {
                        return Err(PeerNetworkError::TunnelIpConflict(
                            "TUNNEL_IP_CONFLICT: collides with server IP".to_string(),
                        ));
                    }
                    if let Some(existing) = st.peers.get(pubkey) {
                        if existing.tunnel_ip == *tunnel_ip {
                            return Err(PeerNetworkError::PeerAlreadyExists(
                                "PEER_ALREADY_EXISTS: matching peer exists".to_string(),
                            ));
                        }
                        return Err(PeerNetworkError::Conflict(
                            "CONFLICT: peer exists with different tunnel IP".to_string(),
                        ));
                    }
                    if st.peers.values().any(|p| p.tunnel_ip == *tunnel_ip) {
                        return Err(PeerNetworkError::TunnelIpConflict(
                            "TUNNEL_IP_CONFLICT: peer tunnel IP overlaps".to_string(),
                        ));
                    }
                    let formatted_ep = format!("{endpoint}:{port}");
                    st.peers.insert(
                        pubkey.clone(),
                        FakeWgPeer {
                            pubkey: pubkey.clone(),
                            endpoint: formatted_ep.clone(),
                            tunnel_ip: tunnel_ip.clone(),
                            present_live: true,
                            handshake_age_secs: None,
                        },
                    );
                    Ok(PeerNetworkResponse::Mutation(PeerMutationResponse {
                        interface: "afpeer0".to_string(),
                        pubkey: pubkey.clone(),
                        applied_live: true,
                        service_state: "active".to_string(),
                        tunnel_ip: Some(tunnel_ip.clone()),
                        allowed_ips: Some(format!("{tunnel_ip}/32")),
                        endpoint: Some(formatted_ep),
                        message: "Peer added".to_string(),
                    }))
                }
                PeerNetworkRequest::RemovePeer { pubkey } => {
                    st.calls.push("remove_peer".to_string());
                    if let Some(err) = st.next_remove_error.take() {
                        return Err(err);
                    }
                    if st.peers.remove(pubkey).is_none() {
                        return Err(PeerNetworkError::PeerNotFound(
                            "PEER_NOT_FOUND: peer does not exist".to_string(),
                        ));
                    }
                    Ok(PeerNetworkResponse::Mutation(PeerMutationResponse {
                        interface: "afpeer0".to_string(),
                        pubkey: pubkey.clone(),
                        applied_live: true,
                        service_state: "active".to_string(),
                        tunnel_ip: None,
                        allowed_ips: None,
                        endpoint: None,
                        message: "Peer removed".to_string(),
                    }))
                }
                PeerNetworkRequest::SetEndpoint {
                    pubkey,
                    endpoint,
                    port,
                } => {
                    st.calls.push("set_endpoint".to_string());
                    let Some(peer) = st.peers.get_mut(pubkey) else {
                        return Err(PeerNetworkError::PeerNotFound(
                            "PEER_NOT_FOUND: peer does not exist".to_string(),
                        ));
                    };
                    let formatted_ep = format!("{endpoint}:{port}");
                    peer.endpoint = formatted_ep.clone();
                    let allowed = format!("{}/32", peer.tunnel_ip);
                    Ok(PeerNetworkResponse::Mutation(PeerMutationResponse {
                        interface: "afpeer0".to_string(),
                        pubkey: pubkey.clone(),
                        applied_live: true,
                        service_state: "active".to_string(),
                        tunnel_ip: None,
                        allowed_ips: Some(allowed),
                        endpoint: Some(formatted_ep),
                        message: "Endpoint updated".to_string(),
                    }))
                }
                PeerNetworkRequest::Status => {
                    st.calls.push("status".to_string());
                    let peers: Vec<PeerStatusPeer> = st
                        .peers
                        .values()
                        .map(|p| PeerStatusPeer {
                            public_key: p.pubkey.clone(),
                            endpoint: p.endpoint.clone(),
                            allowed_ips: format!("{}/32", p.tunnel_ip),
                            latest_handshake: "0".to_string(),
                            latest_handshake_epoch: 0,
                            handshake_age_secs: p.handshake_age_secs,
                            transfer_rx: "0".to_string(),
                            transfer_tx: "0".to_string(),
                            persistent_keepalive: 25,
                            active: p.present_live
                                && p.handshake_age_secs
                                    .is_some_and(|age| age <= WG_HANDSHAKE_STALE_SECS),
                            persistent: true,
                            present_live: p.present_live,
                        })
                        .collect();
                    Ok(PeerNetworkResponse::Status(PeerStatusResponse {
                        installed: true,
                        state: "running".to_string(),
                        interface: "afpeer0".to_string(),
                        public_key: st.pubkey.clone(),
                        listen_port: st.wg_port.to_string(),
                        tunnel_ip: st.tunnel_ip.clone(),
                        tunnel_cidr: "127.1.0.0/16".to_string(),
                        interface_address: format!("{}/16", st.tunnel_ip),
                        service_state: "active".to_string(),
                        config_available: st.identity_created,
                        key_available: st.identity_created,
                        route_prefix_ready: true,
                        peers,
                        error: None,
                    }))
                }
                PeerNetworkRequest::EnsurePackages => {
                    st.calls.push("ensure_packages".to_string());
                    Ok(PeerNetworkResponse::Packages(PeerEnsurePackagesResponse {
                        installed: true,
                        already_installed: true,
                        packages: vec!["wireguard-tools".to_string()],
                        versions: HashMap::new(),
                    }))
                }
                PeerNetworkRequest::WriteCredential { slot, id, value } => {
                    st.calls.push(format!("write_cred:{slot:?}:{id}"));
                    st.credentials.insert((*slot, id.clone()), value.clone());
                    Ok(PeerNetworkResponse::CredentialWritten(
                        PeerCredentialWriteResponse {
                            slot: *slot,
                            id: id.clone(),
                            written: true,
                        },
                    ))
                }
                PeerNetworkRequest::ReadCredential { slot, id } => {
                    st.calls.push(format!("read_cred:{slot:?}:{id}"));
                    let val = st.credentials.get(&(*slot, id.clone())).cloned();
                    Ok(PeerNetworkResponse::CredentialRead(
                        PeerCredentialReadResponse {
                            slot: *slot,
                            id: id.clone(),
                            present: val.is_some(),
                            value: val.map(PeerCredentialSecret::new),
                        },
                    ))
                }
                PeerNetworkRequest::DeleteCredential { slot, id } => {
                    st.calls.push(format!("delete_cred:{slot:?}:{id}"));
                    if let Some(err) = st.next_delete_cred_error.take() {
                        return Err(err);
                    }
                    let deleted = st.credentials.remove(&(*slot, id.clone())).is_some();
                    Ok(PeerNetworkResponse::CredentialDeleted(
                        PeerCredentialDeleteResponse {
                            slot: *slot,
                            id: id.clone(),
                            deleted,
                        },
                    ))
                }
                PeerNetworkRequest::DeleteLinkCredentials { link_id } => {
                    st.calls.push(format!("delete_link_creds:{link_id}"));
                    if let Some(err) = st.next_delete_link_creds_error.take() {
                        return Err(err);
                    }
                    let link_deleted = st
                        .credentials
                        .remove(&(PeerCredentialSlot::LinkToken, link_id.clone()))
                        .is_some();
                    let grant_deleted = st
                        .credentials
                        .remove(&(PeerCredentialSlot::GrantToken, link_id.clone()))
                        .is_some();
                    Ok(PeerNetworkResponse::LinkCredentialsDeleted(
                        PeerLinkCredentialsDeleteResponse {
                            link_id: link_id.clone(),
                            link_token_deleted: link_deleted,
                            grant_token_deleted: grant_deleted,
                        },
                    ))
                }
            }
        })();
        Box::pin(async move { res })
    }
}

/// Test-only public pairing transport that forwards validated `https://` requests directly into
/// a target runtime's real `public_routes_with_runtime` Axum router (exercising the 4 KiB body
/// limit, rate limiter, JSON parsing, and atomic single-use DB transaction).
struct RouterPublicTransport {
    target_runtime: Arc<PeerRuntime>,
    client_ip: SocketAddr,
}

impl PublicPairingTransport for RouterPublicTransport {
    fn post_pairing_request<'a>(
        &'a self,
        url: Url,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
        let target = Arc::clone(&self.target_runtime);
        let client_ip = self.client_ip;
        Box::pin(async move {
            if url.scheme() != "https" {
                return Err("Public pairing requires https://".to_string());
            }
            let path = url.path().strip_prefix("/api/v1").unwrap_or(url.path());
            let app = public_routes_with_runtime(target);
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .map_err(|e| e.to_string())?;
            req.extensions_mut().insert(ConnectInfo(client_ip));
            let resp = app.oneshot(req).await.map_err(|e| e.to_string())?;
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), 64 * 1024)
                .await
                .map_err(|e| e.to_string())?;
            Ok((status, bytes.to_vec()))
        })
    }
}

struct UnreachablePublicTransport;

impl PublicPairingTransport for UnreachablePublicTransport {
    fn post_pairing_request<'a>(
        &'a self,
        _url: Url,
        _body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
        Box::pin(async { Err("simulated TLS/connect failure".to_string()) })
    }
}

struct FakeClock {
    epoch: AtomicI64,
    monotonic_secs: AtomicU64,
}

impl FakeClock {
    fn new(start: i64) -> Arc<Self> {
        Arc::new(Self {
            epoch: AtomicI64::new(start),
            monotonic_secs: AtomicU64::new(100),
        })
    }

    fn advance(&self, secs: i64) {
        self.epoch.fetch_add(secs, Ordering::SeqCst);
        if secs > 0 {
            self.monotonic_secs.fetch_add(secs as u64, Ordering::SeqCst);
        }
    }

    fn shift_wall_clock_only(&self, delta_secs: i64) {
        self.epoch.fetch_add(delta_secs, Ordering::SeqCst);
    }

    fn as_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> DateTime<Utc> + Send + Sync> {
        let clock = Arc::clone(self);
        Arc::new(move || {
            DateTime::<Utc>::from_timestamp(clock.epoch.load(Ordering::SeqCst), 0)
                .expect("valid test timestamp")
        })
    }

    fn as_monotonic_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> Duration + Send + Sync> {
        let clock = Arc::clone(self);
        Arc::new(move || Duration::from_secs(clock.monotonic_secs.load(Ordering::SeqCst)))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_test_runtime_with_db_and_timeout(
    name: &str,
    db_conn: Arc<StdMutex<Connection>>,
    runner: Arc<dyn PeerRunner>,
    public_transport: Arc<dyn PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    bind_listener: bool,
    tunnel_binding: TunnelTransportBinding,
    lock_wait_timeout: Duration,
) -> Arc<PeerRuntime> {
    let (revocation_tx, _) = broadcast::channel(64);
    Arc::new(PeerRuntime {
        db: PeerDb::Isolated(db_conn),
        runner,
        public_transport,
        revocation_tx,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout,
        listen_port: 0,
        max_conn_per_link: 64,
        rtt_warn_ms: 25.0,
        server_name_override: Some(name.to_string()),
        version_override: Some("4.0.0-test".to_string()),
        tunnel_binding,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: bind_listener,
        management_router_override: None,
    })
}

fn build_test_runtime_with_binding(
    name: &str,
    runner: Arc<dyn PeerRunner>,
    public_transport: Arc<dyn PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    bind_listener: bool,
    tunnel_binding: TunnelTransportBinding,
) -> (Arc<PeerRuntime>, Arc<StdMutex<Connection>>) {
    let db_conn = open_isolated_peer_db();
    let rt = build_test_runtime_with_db_and_timeout(
        name,
        Arc::clone(&db_conn),
        runner,
        public_transport,
        clock,
        bind_listener,
        tunnel_binding,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    (rt, db_conn)
}

fn build_test_runtime(
    name: &str,
    runner: Arc<dyn PeerRunner>,
    public_transport: Arc<dyn PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    bind_listener: bool,
) -> (Arc<PeerRuntime>, Arc<StdMutex<Connection>>) {
    build_test_runtime_with_binding(
        name,
        runner,
        public_transport,
        clock,
        bind_listener,
        TunnelTransportBinding::LoopbackFixture,
    )
}

fn admin_user() -> AuthUser {
    AuthUser {
        user_id: 1,
        username: "alice".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

async fn call_admin(
    rt: &Arc<PeerRuntime>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
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
    req.extensions_mut().insert(admin_user());
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 128 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, json)
}

fn audit_entries_text(conn: &Arc<StdMutex<Connection>>) -> String {
    let guard = conn.lock().unwrap();
    let mut stmt = guard
        .prepare("SELECT action, target_type, target_id, detail, ip_address FROM admin_audit_log")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |r| {
            Ok(format!(
                "{}|{}|{}|{}|{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?
            ))
        })
        .unwrap()
        .flatten()
        .collect();
    rows.join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Pairing String Codec, Strict HTTPS Validation & Typed Errors
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pairing_string_round_trip_redacts_code_and_rejects_malformed_or_non_https() {
    let payload = PairingPayload {
        https_url: "https://media-2.example.test:8443".to_string(),
        wg_pubkey: fixture_wg_pubkey(7),
        endpoint: "10.50.0.2".to_string(),
        wg_port: 51821,
        tunnel_ip: "10.231.0.2".to_string(),
        code: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    };
    let encoded = payload.encode().unwrap();
    assert!(encoded.starts_with("afpair1:"));
    let decoded = PairingPayload::decode(&encoded, "seedbox-1").unwrap();
    assert_eq!(decoded, payload);
    assert!(!format!("{payload:?}").contains(&payload.code));

    // Reject HTTP, embedded credentials, query, fragment, non-root path
    for bad_url in [
        "http://media-2.example.test",
        "https://user:pass@media-2.example.test",
        "https://media-2.example.test/subpath",
        "https://media-2.example.test/?q=1",
        "https://media-2.example.test/#frag",
        "ftp://media-2.example.test",
    ] {
        assert!(
            validate_public_https_url(bad_url, "seedbox-1", "test").is_err(),
            "expected rejection for {bad_url}"
        );
    }

    // Bad prefix & bad base64
    assert_eq!(
        PairingPayload::decode("wrong:abc", "seedbox-1")
            .unwrap_err()
            .code(),
        "INVALID_REQUEST"
    );
    assert_eq!(
        PairingPayload::decode("afpair1:not-valid-json", "seedbox-1")
            .unwrap_err()
            .code(),
        "INVALID_REQUEST"
    );
}

#[tokio::test]
async fn strict_public_pairing_transport_rejects_http_and_non_tls_servers() {
    let transport = ProductionPublicPairingTransport::new();
    let http_err = transport
        .post_pairing_request(
            Url::parse("http://127.0.0.1:8080/api/v1/peer-pairing/request").unwrap(),
            b"{}".to_vec(),
        )
        .await
        .unwrap_err();
    assert!(http_err.contains("https://"));

    // Plain TCP listener speaking HTTP (no valid TLS cert) must fail strict TLS validation.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/api/v1/peer-pairing/request",
            axum::routing::post(|| async { (StatusCode::OK, "{}") }),
        );
        let _ = axum::serve(listener, app).await;
    });
    let tls_err = transport
        .post_pairing_request(
            Url::parse(&format!(
                "https://127.0.0.1:{}/api/v1/peer-pairing/request",
                addr.port()
            ))
            .unwrap(),
            b"{}".to_vec(),
        )
        .await
        .unwrap_err();
    server.abort();
    assert!(!tls_err.is_empty());
}

#[tokio::test]
async fn typed_peer_errors_emit_structured_json_and_redact_secrets() {
    let secret_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let leaked_input = format!(
        "failed with afpair1:eyJjb2RlIjoiMTIzIn0 x-af-link-token: {secret_hex} PrivateKey=ABC123"
    );
    let redacted = redact_sensitive_text(&leaked_input);
    assert!(!redacted.contains("afpair1:"));
    assert!(!redacted.contains(secret_hex));
    assert!(!redacted.contains("ABC123"));

    let cases = [
        (
            PeerError::code_expired("b", "step"),
            "CODE_EXPIRED",
            StatusCode::GONE,
        ),
        (
            PeerError::code_used("b", "step"),
            "CODE_USED",
            StatusCode::CONFLICT,
        ),
        (
            PeerError::window_closed("b", "step"),
            "WINDOW_CLOSED",
            StatusCode::GONE,
        ),
        (
            PeerError::key_mismatch("b", "step", "mismatch"),
            "KEY_MISMATCH",
            StatusCode::CONFLICT,
        ),
        (
            PeerError::tunnel_ip_conflict("b", "step", "overlap"),
            "TUNNEL_IP_CONFLICT",
            StatusCode::CONFLICT,
        ),
        (
            PeerError::endpoint_unreachable("b", "step", "down"),
            "ENDPOINT_UNREACHABLE",
            StatusCode::BAD_GATEWAY,
        ),
        (
            PeerError::handshake_timeout("b", "step", "timeout"),
            "HANDSHAKE_TIMEOUT",
            StatusCode::GATEWAY_TIMEOUT,
        ),
        (
            PeerError::version_incompatible("b", "step", "old"),
            "VERSION_INCOMPATIBLE",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            PeerError::clock_skew("b", "step", 420),
            "CLOCK_SKEW",
            StatusCode::BAD_REQUEST,
        ),
        (
            PeerError::peer_scope_denied("b", "step", "denied"),
            "PEER_SCOPE_DENIED",
            StatusCode::FORBIDDEN,
        ),
        (
            PeerError::peer_route_unclassified("b", "step", "unknown"),
            "PEER_ROUTE_UNCLASSIFIED",
            StatusCode::FORBIDDEN,
        ),
        (
            PeerError::link_down("b", "step", "down"),
            "LINK_DOWN",
            StatusCode::BAD_GATEWAY,
        ),
        (
            PeerError::link_revoked("b", "step", "revoked"),
            "LINK_REVOKED",
            StatusCode::FORBIDDEN,
        ),
        (
            PeerError::rate_limited("b", "step"),
            "RATE_LIMITED",
            StatusCode::TOO_MANY_REQUESTS,
        ),
    ];

    for (err, expected_code, expected_status) in cases {
        let resp = err.into_response();
        assert_eq!(resp.status(), expected_status);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        if expected_code == "RATE_LIMITED" {
            assert_eq!(resp.headers()[header::RETRY_AFTER], "60");
        }
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: PeerErrorBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.code, expected_code);
        assert_eq!(parsed.server, "b");
        assert!(!parsed.step.is_empty());
        assert!(!parsed.message.is_empty());
        assert!(!parsed.action.is_empty());

        let roundtripped = PeerError::from_remote_http(expected_status, &body, "fallback", "step");
        assert_eq!(roundtripped.code(), expected_code);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Code Expiry, Single-Use Reuse, Closed Windows, Rate Limits, Clock Skew,
//    Version Incompatibility & 4 KiB Body Cap
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pairing_window_lifecycle_expiry_reuse_closed_rate_limit_skew_and_body_cap() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(11);
    let pk_b = fixture_wg_pubkey(12);
    let clock = FakeClock::new(1_800_000_000);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        runner_b,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );

    let call_public = |ip: [u8; 4], body: Vec<u8>| {
        let rt = Arc::clone(&rt_b);
        async move {
            let app = public_routes_with_runtime(rt);
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/peer-pairing/request")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((ip, 50000))));
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let val: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
            (status, val)
        }
    };

    // A) 4 KiB body limit enforced on public bootstrap endpoint.
    let oversized = vec![b'x'; PUBLIC_PAIRING_BODY_LIMIT_BYTES + 64];
    let (status, _) = call_public([203, 0, 113, 1], oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // B) Closed window when none opened -> WINDOW_CLOSED.
    let make_req = |code: &str, ts: i64, proto: i64| {
        serde_json::to_vec(&PublicPairingRequest {
            code: code.to_string(),
            name: "seedbox-1".to_string(),
            wg_pubkey: pk_a.clone(),
            endpoint: "10.0.0.1".to_string(),
            wg_port: 51821,
            tunnel_ip: ip_a.to_string(),
            version: "4.0.0".to_string(),
            peer_protocol: proto,
            timestamp: ts,
        })
        .unwrap()
    };
    let dummy_code = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (status, val) = call_public([203, 0, 113, 2], make_req(dummy_code, 1_800_000_000, 1)).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(val["code"], "WINDOW_CLOSED");

    // C) Open a window, verify raw code is NOT stored in DB or audit log, then close explicitly -> WINDOW_CLOSED.
    let (status, opened1) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.0.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let p1 =
        PairingPayload::decode(opened1["pairing_string"].as_str().unwrap(), "seedbox-1").unwrap();
    {
        let conn = db_b.lock().unwrap();
        let stored_hash: String = conn
            .query_row(
                "SELECT code_hash FROM peer_pairing_windows WHERE id = ?1",
                rusqlite::params![opened1["window_id"].as_str().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stored_hash.starts_with("sha256:"));
        assert_ne!(stored_hash, p1.code);
        assert!(!stored_hash.contains(&p1.code));
    }
    assert!(!audit_entries_text(&db_b).contains(&p1.code));

    let (status, _) = call_admin(&rt_b, Method::DELETE, "/pairing-window", None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, val) = call_public([203, 0, 113, 3], make_req(&p1.code, 1_800_000_000, 1)).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(val["code"], "WINDOW_CLOSED");

    // D) Open a second window and let it expire (> 10 minutes) -> CODE_EXPIRED.
    let (status, opened2) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.0.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let p2 =
        PairingPayload::decode(opened2["pairing_string"].as_str().unwrap(), "seedbox-1").unwrap();
    clock.advance(PAIRING_WINDOW_TTL_SECS + 5);
    let now_after_exp = clock.epoch.load(Ordering::SeqCst);
    let (status, val) = call_public([203, 0, 113, 4], make_req(&p2.code, now_after_exp, 1)).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(val["code"], "CODE_EXPIRED");

    // E) Open a third window: test CLOCK_SKEW (> 300s), VERSION_INCOMPATIBLE, then valid single-use consume, then CODE_USED replay.
    let (status, opened3) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.0.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let p3 =
        PairingPayload::decode(opened3["pairing_string"].as_str().unwrap(), "seedbox-1").unwrap();
    let now3 = clock.epoch.load(Ordering::SeqCst);

    for timestamp in [now3 - 305, i64::MIN, i64::MAX] {
        let (status, val) = call_public([203, 0, 113, 5], make_req(&p3.code, timestamp, 1)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(val["code"], "CLOCK_SKEW");
    }

    let (status, val) = call_public([203, 0, 113, 5], make_req(&p3.code, now3, 0)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(val["code"], "VERSION_INCOMPATIBLE");

    // Concurrent single-use consumption race: 4 simultaneous requests with the same code.
    let futures: Vec<_> = (0..4)
        .map(|i| call_public([203, 0, 113, 20 + i], make_req(&p3.code, now3, 1)))
        .collect();
    let results = futures::future::join_all(futures).await;
    let ok_count = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    let used_count = results
        .iter()
        .filter(|(s, v)| *s == StatusCode::CONFLICT && v["code"] == "CODE_USED")
        .count();
    assert_eq!(
        ok_count, 1,
        "exactly one caller must consume the single-use code"
    );
    assert_eq!(used_count, 3, "all concurrent replays must get CODE_USED");

    // Sequential replay also returns CODE_USED.
    let (status, val) = call_public([203, 0, 113, 30], make_req(&p3.code, now3, 1)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(val["code"], "CODE_USED");

    // F) Per-source-IP rate limit: 5 requests / minute allowed, 6th returns 429 RATE_LIMITED.
    let rl_ip = [203, 0, 113, 99];
    for attempt in 0..5 {
        let (status, val) = call_public(rl_ip, make_req(dummy_code, now3, 1)).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "attempt {} should not be rate limited: {val}",
            attempt + 1
        );
    }
    let (status, val) = call_public(rl_ip, make_req(dummy_code, now3, 1)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(val["code"], "RATE_LIMITED");

    // Different source IP is unaffected.
    let (status, val) = call_public([203, 0, 113, 100], make_req(dummy_code, now3, 1)).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(val["code"], "WINDOW_CLOSED");

    // Advancing clock past 60s resets the rate limit window.
    clock.advance(61);
    let (status, val) = call_public(rl_ip, make_req(dummy_code, now3 + 61, 1)).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(val["code"], "WINDOW_CLOSED");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Full End-to-End Two-Server Pairing, Listener Isolation, Health, Endpoint
//    Editing, Revocation & Re-Pairing with Real Local Listeners + Fake Runner
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn end_to_end_pairing_health_listener_isolation_endpoint_edit_and_revocation() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(31);
    let pk_b = fixture_wg_pubkey(32);
    let clock = FakeClock::new(1_800_100_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 10], 45000)),
        }),
        &clock,
        true,
    );

    // Subscribe to revocation broadcasts on both servers before pairing/revocation.
    let mut rev_rx_a = rt_a.subscribe_revocations();
    let mut rev_rx_b = rt_b.subscribe_revocations();

    // Step 1: Server B opens pairing window -> initializes B identity & binds B's tunnel listener on ip_b.
    let (status, win_resp) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let pairing_string = win_resp["pairing_string"].as_str().unwrap().to_string();
    let decoded_win = PairingPayload::decode(&pairing_string, "seedbox-1").unwrap();
    let b_bound_addr = rt_b
        .listener_state
        .lock()
        .await
        .as_ref()
        .expect("B listener started after identity creation")
        .bound_addr;
    assert_eq!(b_bound_addr.ip(), ip_b);

    // Step 2 & 3: Server A starts pairing -> initializes A identity, binds A's tunnel listener on ip_a,
    // adds B to A's afpeer0, calls B's public pairing endpoint, records attempt & comparison code.
    let (status, pair_resp) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": pairing_string,
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "pair_resp={pair_resp}");
    let a_link_id = pair_resp["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair_resp["attempt_id"].as_str().unwrap().to_string();
    let a_comparison = pair_resp["comparison_code"].as_str().unwrap().to_string();
    assert_eq!(a_comparison, derive_comparison_code(&pk_a, &pk_b));
    assert_eq!(a_comparison.len(), 6);
    assert!(runner_a.has_peer(&pk_b));

    let a_bound_addr = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .expect("A listener started after identity creation")
        .bound_addr;
    assert_eq!(a_bound_addr.ip(), ip_a);

    // Wire ephemeral test ports so real HTTP traffic flows strictly to each server's bound tunnel IP.
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_bound_addr.port());
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_bound_addr.port());

    // Pre-activation check: B cannot call GET /health on A while link is still pending.
    let (pre_health_status, _, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
            )),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(pre_health_status, StatusCode::UNAUTHORIZED);

    // Verify B's admin listing shows the pending attempt with matching comparison code.
    let (status, b_list_pending) = call_admin(&rt_b, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        b_list_pending["pairing_attempts"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        b_list_pending["pairing_attempts"][0]["comparison_code"],
        a_comparison
    );

    // Step 4 & 5: Server B confirms -> bootstrap + acknowledge over A's real tunnel listener!
    let (status, confirm_resp) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm_resp={confirm_resp}");
    assert_eq!(confirm_resp["state"], "active");
    let b_link_id = confirm_resp["link_id"].as_str().unwrap().to_string();

    // Verify independent link tokens on A and B, and that PendingIssuerToken files were removed!
    let a_held_for_b = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .expect("A holds B's incoming link token");
    let b_held_for_a = runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .expect("B holds A's incoming link token");
    assert_ne!(a_held_for_b, b_held_for_a);
    let a_pending_cred_key = pending_issuer_credential_id(&a_link_id);
    let b_pending_cred_key = pending_issuer_credential_id(&b_link_id);
    assert!(
        runner_a
            .credential(PeerCredentialSlot::PendingIssuerToken, &a_pending_cred_key)
            .is_none()
            && runner_a
                .credential(PeerCredentialSlot::PendingIssuerToken, &attempt_id)
                .is_none(),
        "A must remove temporary issuer credential after acknowledgement and never use bare attempt_id"
    );
    assert!(
        runner_b
            .credential(PeerCredentialSlot::PendingIssuerToken, &b_pending_cred_key)
            .is_none()
            && runner_b
                .credential(PeerCredentialSlot::PendingIssuerToken, &attempt_id)
                .is_none(),
        "B must remove temporary issuer credential after activation and never use bare attempt_id"
    );

    // Verify no raw tokens, pairing codes, or comparison codes leaked into DB audit logs or admin listing.
    let (status, a_list) = call_admin(&rt_a, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    let a_list_str = serde_json::to_string(&a_list).unwrap();
    let a_audit = audit_entries_text(&db_a);
    let b_audit = audit_entries_text(&db_b);
    for secret in [
        &decoded_win.code,
        &a_comparison,
        &a_held_for_b,
        &b_held_for_a,
    ] {
        assert!(
            !a_list_str.contains(secret),
            "secret leaked in A admin list"
        );
        assert!(!a_audit.contains(secret), "secret leaked in A audit log");
        assert!(!b_audit.contains(secret), "secret leaked in B audit log");
    }

    // Verify authenticated acknowledge retry on A works before expiry and fails after expiry!
    let ack_retry_body = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Acknowledge,
        attempt_id: attempt_id.clone(),
        wg_pubkey: pk_b.clone(),
        tunnel_ip: Some(ip_b.to_string()),
        version: "4.0.0-test".to_string(),
        peer_protocol: PEER_PROTOCOL_VERSION,
        capabilities: vec!["links".to_string()],
        link_token: None,
    })
    .unwrap();
    let (retry_status, retry_body, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/peer/v1/hello",
            Some(&PeerCredentialSecret::new(b_held_for_a.clone())),
            Some(ack_retry_body.clone()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(retry_status, StatusCode::OK);
    let retry_json: Value = serde_json::from_slice(&retry_body).unwrap();
    assert_eq!(retry_json["acknowledged"], true);

    // Unauthenticated bootstrap after activation must fail closed.
    let bad_boot_body = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Bootstrap,
        attempt_id: attempt_id.clone(),
        wg_pubkey: pk_b.clone(),
        tunnel_ip: Some(ip_b.to_string()),
        version: "4.0.0-test".to_string(),
        peer_protocol: PEER_PROTOCOL_VERSION,
        capabilities: vec!["links".to_string()],
        link_token: Some(PeerCredentialSecret::new(a_held_for_b.clone())),
    })
    .unwrap();
    let (bad_boot_status, _, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/peer/v1/hello",
            None,
            Some(bad_boot_body),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(bad_boot_status, StatusCode::UNAUTHORIZED);

    // Tunnel listener isolation: active link credentials cannot access management or unknown routes!
    let (mgmt_status, mgmt_body, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/api/v1/admin/services",
            Some(&PeerCredentialSecret::new(b_held_for_a.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(mgmt_status, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&mgmt_body).unwrap()["code"],
        "PEER_SCOPE_DENIED"
    );

    let (unk_status, unk_body, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/peer/v1/not-a-p3-route",
            Some(&PeerCredentialSecret::new(b_held_for_a.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(unk_status, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&unk_body).unwrap()["code"],
        "PEER_ROUTE_UNCLASSIFIED"
    );
    let audit = audit_entries_text(&db_a);
    assert!(audit.contains("unclassified tunnel request"));
    assert!(!audit.contains("/peer/v1/not-a-p3-route"));

    // Wrong HTTP method on a registered listener route also fails closed (never leaks bare 405).
    let (bad_method_unauth, _, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/health",
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(bad_method_unauth, StatusCode::UNAUTHORIZED);

    let (bad_method_auth, bad_method_body, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(b_held_for_a.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(bad_method_auth, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&bad_method_body).unwrap()["code"],
        "PEER_ROUTE_UNCLASSIFIED"
    );

    // Wrong link token from valid source IP fails with 401 and is audited.
    let (bad_tok_status, _, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            )),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(bad_tok_status, StatusCode::UNAUTHORIZED);
    assert!(audit_entries_text(&db_a).contains("peer_listener_denied"));

    // Valid authenticated link view succeeds.
    let (link_view_status, link_view_body, _) = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/peer/v1/link",
            Some(&PeerCredentialSecret::new(a_held_for_b.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(link_view_status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&link_view_body).unwrap()["state"],
        "active"
    );

    // Health tick with `present_live == true` and `handshake_age_secs == None` (awaiting first
    // handshake) performs authenticated tunnel GET /health and updates RTT & capabilities.
    run_health_tick(&rt_a).await;
    let a_link_after_health = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_link_after_health.state, "active");
    assert_eq!(a_link_after_health.peer_protocol, Some(1));
    assert!(a_link_after_health.rtt_ms.is_some());
    assert_eq!(
        a_link_after_health.capabilities.as_deref(),
        Some(r#"["links","grants"]"#)
    );

    // `present_live == false` (explicitly removed from live afpeer0) marks link down on first tick!
    runner_a.set_peer_live_state(&pk_b, false, None);
    run_health_tick(&rt_a).await;
    let a_link_down = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_link_down.state, "down");
    assert_eq!(a_link_down.consecutive_failures, 1);

    // Restoring live peer with fresh handshake recovers the link to active on next tick.
    runner_a.set_peer_live_state(&pk_b, true, Some(12));
    run_health_tick(&rt_a).await;
    let a_link_recovered = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_link_recovered.state, "active");
    assert_eq!(a_link_recovered.consecutive_failures, 0);

    // Stale handshake (> 180s) marks link down.
    runner_a.set_peer_live_state(&pk_b, true, Some(WG_HANDSHAKE_STALE_SECS + 5));
    run_health_tick(&rt_a).await;
    let a_link_stale = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_link_stale.state, "down");
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    run_health_tick(&rt_a).await;

    // Endpoint edit (`PUT /api/v1/admin/peers/:id/endpoint`).
    let (ep_status, ep_resp) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/endpoint"),
        Some(json!({ "endpoint": "10.20.30.40", "wg_port": 51899 })),
    )
    .await;
    assert_eq!(ep_status, StatusCode::OK, "ep_resp={ep_resp}");
    assert_eq!(ep_resp["peer"]["endpoint"], "10.20.30.40");
    assert_eq!(ep_resp["peer"]["wg_port"], 51899);
    assert!(audit_entries_text(&db_a).contains("peer_endpoint_updated"));

    // After expiry, authenticated acknowledge retry is rejected with CODE_EXPIRED.
    clock.advance(PAIRING_WINDOW_TTL_SECS + 10);
    let (exp_ack_status, exp_ack_body, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/peer/v1/hello",
            Some(&PeerCredentialSecret::new(b_held_for_a.clone())),
            Some(ack_retry_body),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(exp_ack_status, StatusCode::GONE);
    assert_eq!(
        serde_json::from_slice::<Value>(&exp_ack_body).unwrap()["code"],
        "CODE_EXPIRED"
    );

    // Link revocation from B (`DELETE /api/v1/admin/peers/:id`):
    // delivers authenticated `/peer/v1/revoke-notice` to A, removes WG peers & credentials on both,
    // broadcasts RevocationEvent on both, and records audit entries.
    let (del_status, del_resp) =
        call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}"), None).await;
    assert_eq!(del_status, StatusCode::OK, "del_resp={del_resp}");
    assert_eq!(del_resp["revoked"], true);
    assert_eq!(del_resp["notice_delivered"], true);
    assert!(!runner_b.has_peer(&pk_a));
    assert!(runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .is_none());
    assert!(db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .is_none());

    // A shows "Link revoked by media-2", cleared inbound hash, removed WG peer & credentials.
    let a_revoked = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_revoked.state, "revoked_unowned");
    assert_eq!(
        a_revoked.last_error.as_deref(),
        Some("Link revoked by media-2")
    );
    assert!(a_revoked.inbound_token_hash.is_none());
    assert!(!runner_a.has_peer(&pk_b));
    assert!(runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .is_none());

    assert_eq!(
        rev_rx_b.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: b_link_id.clone(),
            peer_name: "seedbox-1".to_string(),
        }
    );
    assert_eq!(
        rev_rx_a.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: a_link_id.clone(),
            peer_name: "media-2".to_string(),
        }
    );
    assert!(audit_entries_text(&db_b).contains("peer_link_revoked"));
    assert!(audit_entries_text(&db_a).contains("peer_link_revoked_by_remote"));

    // Subsequent tunnel health call with old token fails closed.
    let (post_rev_status, post_rev_body, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(b_held_for_a)),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(post_rev_status, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&post_rev_body).unwrap()["code"],
        "LINK_REVOKED"
    );

    // Re-pairing after revocation works cleanly without stale revoked-row conflicts!
    let (status, win2) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair2) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win2["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "re-pair failed: {pair2}");
    let attempt2 = pair2["attempt_id"].as_str().unwrap();
    let (status, confirm2) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt2}/confirm"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-pair confirm failed: {confirm2}");
    assert_eq!(confirm2["state"], "active");

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Wrong Tunnel Source, Cross-Attempt Rejection, Retries, Runner Edge Cases
//    (PeerAlreadyExists, PeerNotFound, TunnelIpConflict, Busy) & Cleanup
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn attempt_binding_wrong_source_retries_runner_reconciliation_and_cleanup() {
    let (ip_a, ip_b) = next_loopback_pair();
    let wrong_ip = IpAddr::V4(Ipv4Addr::new(127, 2, 0, 99));
    let pk_a = fixture_wg_pubkey(51);
    let pk_b = fixture_wg_pubkey(52);
    let clock = FakeClock::new(1_800_200_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 11], 45001)),
        }),
        &clock,
        true,
    );

    // Open window & start pairing.
    let (status, win) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let a_link_id = pair["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair["attempt_id"].as_str().unwrap().to_string();
    let a_bound_addr = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr;

    // 1. Direct router check on A's listener: wrong source IP with valid attempt_id & pubkey -> 401!
    let a_listener = build_listener_router(Arc::clone(&rt_a));
    let b_token_1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hello_payload = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Bootstrap,
        attempt_id: attempt_id.clone(),
        wg_pubkey: pk_b.clone(),
        tunnel_ip: None,
        version: "4.0.0".to_string(),
        peer_protocol: 1,
        capabilities: vec!["links".to_string()],
        link_token: Some(PeerCredentialSecret::new(b_token_1.to_string())),
    })
    .unwrap();
    let mut wrong_src_req = Request::builder()
        .method(Method::POST)
        .uri("/peer/v1/hello")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(hello_payload.clone()))
        .unwrap();
    wrong_src_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(wrong_ip, 51000)));
    let resp = a_listener.clone().oneshot(wrong_src_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Correct source IP but wrong attempt_id -> 401 (credentials cannot cross attempts).
    let wrong_att_payload = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Bootstrap,
        attempt_id: "different-attempt-id-999".to_string(),
        wg_pubkey: pk_b.clone(),
        tunnel_ip: Some(ip_b.to_string()),
        version: "4.0.0".to_string(),
        peer_protocol: 1,
        capabilities: vec!["links".to_string()],
        link_token: Some(PeerCredentialSecret::new(b_token_1.to_string())),
    })
    .unwrap();
    let mut wrong_att_req = Request::builder()
        .method(Method::POST)
        .uri("/peer/v1/hello")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(wrong_att_payload))
        .unwrap();
    wrong_att_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_b, 51001)));
    let resp = a_listener.clone().oneshot(wrong_att_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Bootstrap retry on A reuses exact same issued token; presenting a different B token fails!
    let send_bootstrap = |tok: &str| {
        let app = a_listener.clone();
        let body = serde_json::to_vec(&HelloRequest {
            phase: HelloPhase::Bootstrap,
            attempt_id: attempt_id.clone(),
            wg_pubkey: pk_b.clone(),
            tunnel_ip: Some(ip_b.to_string()),
            version: "4.0.0".to_string(),
            peer_protocol: 1,
            capabilities: vec!["links".to_string()],
            link_token: Some(PeerCredentialSecret::new(tok.to_string())),
        })
        .unwrap();
        async move {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/peer/v1/hello")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip_b, 51002)));
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
            let val: Value = serde_json::from_slice(&bytes).unwrap();
            (status, val)
        }
    };
    let (s1, v1) = send_bootstrap(b_token_1).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, v2) = send_bootstrap(b_token_1).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        v1["link_token"], v2["link_token"],
        "bootstrap retry must reuse A's issued token"
    );

    let (s_diff, _) =
        send_bootstrap("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").await;
    assert_eq!(s_diff, StatusCode::UNAUTHORIZED);

    // 4. Confirm on B when runner returns Busy -> 503 PEER_BUSY without destroying attempt.
    runner_b.set_next_add_error(PeerNetworkError::Busy("busy".to_string()));
    let (busy_status, busy_val) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(busy_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(busy_val["code"], "PEER_BUSY");

    // 5. Confirm on B when A's tunnel port is not yet reachable -> HANDSHAKE_TIMEOUT (keeps pending peer & PendingIssuerToken).
    // Point B at an unused closed loopback port first.
    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, closed_port);

    // Note: earlier direct bootstrap stored `b_token_1` in A's LinkToken; clear A's pending held
    // token so B's real minted token from confirm can cleanly pair on retry!
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::DeleteLinkCredentials {
            link_id: a_link_id.clone(),
        })
        .await;

    let (to_status, to_val) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(to_status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(to_val["code"], "HANDSHAKE_TIMEOUT");
    assert!(
        runner_b.has_peer(&pk_a),
        "transient timeout retains pending peer for retry"
    );
    let b_pending_link_id = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(attempt_id.as_str()))
        .expect("B pending link exists for retry")
        .id;
    let b_pending_cred_key = pending_issuer_credential_id(&b_pending_link_id);
    assert!(
        runner_b
            .credential(PeerCredentialSlot::PendingIssuerToken, &attempt_id)
            .is_none(),
        "B must not store PendingIssuerToken under bare attempt_id"
    );
    let b_pending_tok_1 = runner_b
        .credential(PeerCredentialSlot::PendingIssuerToken, &b_pending_cred_key)
        .expect("B retains link-namespaced PendingIssuerToken for retry");

    // 6. Retry confirm on B now that A's real tunnel port is reachable:
    // runner_b's AddPeer returns PeerAlreadyExists -> B reconciles against pending attempt, reuses
    // exact same PendingIssuerToken, and completes pairing!
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_bound_addr.port());
    let (ok_status, ok_val) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "confirm retry failed: {ok_val}");
    assert_eq!(ok_val["state"], "active");
    // Verify A stored B's exact reused token from the first confirm attempt!
    assert_eq!(
        runner_a
            .credential(PeerCredentialSlot::LinkToken, &a_link_id)
            .as_deref(),
        Some(b_pending_tok_1.as_str())
    );
    // And verify PeerNotFound during delete is treated as completed cleanup!
    let b_link_id = ok_val["link_id"].as_str().unwrap().to_string();
    runner_b.set_next_remove_error(PeerNetworkError::PeerNotFound("already absent".to_string()));
    let (del_status, del_val) =
        call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}"), None).await;
    assert_eq!(
        del_status,
        StatusCode::OK,
        "PeerNotFound should count as completed cleanup: {del_val}"
    );

    // 7. Test cancellation cleanup AND expiry cleanup AND TunnelIpConflict cleanup!
    let (status, win_cancel) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair_cancel) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_cancel["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let cancel_attempt = pair_cancel["attempt_id"].as_str().unwrap().to_string();
    let (status, _) = call_admin(
        &rt_a,
        Method::DELETE,
        &format!("/pairing/{cancel_attempt}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!runner_a.has_peer(&pk_b));
    assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
        .unwrap()
        .is_empty());
    let (status, _) = call_admin(
        &rt_b,
        Method::DELETE,
        &format!("/pairing/{cancel_attempt}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        db_peers::get_pairing_attempt(&db_b.lock().unwrap(), &cancel_attempt)
            .unwrap()
            .unwrap()
            .status,
        "cancelled"
    );

    // 8. Expiry sweep cleans up expired pending links, peers, and temporary issuer tokens.
    let (status, win_exp) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair_exp) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_exp["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let exp_attempt = pair_exp["attempt_id"].as_str().unwrap().to_string();
    assert!(runner_a.has_peer(&pk_b));

    clock.advance(PAIRING_WINDOW_TTL_SECS + 5);
    cleanup_expired_pending(&rt_a).await;
    cleanup_expired_pending(&rt_b).await;
    assert!(!runner_a.has_peer(&pk_b));
    assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
        .unwrap()
        .is_empty());
    assert_eq!(
        db_peers::get_pairing_attempt(&db_b.lock().unwrap(), &exp_attempt)
            .unwrap()
            .unwrap()
            .status,
        "expired"
    );

    // 9. TunnelIpConflict from runner surfaces typed 409 TUNNEL_IP_CONFLICT and cleans up!
    let (status, win_conflict) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    runner_a.set_next_add_error(PeerNetworkError::TunnelIpConflict(
        "TUNNEL_IP_CONFLICT: simulated collision".to_string(),
    ));
    let (conflict_status, conflict_val) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_conflict["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict_val["code"], "TUNNEL_IP_CONFLICT");

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Compatibility Matrix & Dormant Standalone Startup
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn compatibility_matrix_reports_compatible_limited_incompatible_and_unknown() {
    assert_eq!(
        evaluate_compatibility(None, &[]).status,
        CompatibilityStatus::Unknown
    );
    assert_eq!(
        evaluate_compatibility(Some(0), &["links".to_string()]).status,
        CompatibilityStatus::Incompatible
    );
    let limited = evaluate_compatibility(Some(1), &[]);
    assert_eq!(limited.status, CompatibilityStatus::Limited);
    assert_eq!(
        limited.missing_capabilities,
        vec!["links".to_string(), "grants".to_string()]
    );

    let p3_link_only = evaluate_compatibility(Some(1), &["links".to_string()]);
    assert_eq!(p3_link_only.status, CompatibilityStatus::Limited);
    assert_eq!(
        p3_link_only.missing_capabilities,
        vec!["grants".to_string()]
    );

    let compat = evaluate_compatibility(Some(1), &["links".to_string(), "grants".to_string()]);
    assert_eq!(compat.status, CompatibilityStatus::Compatible);
    assert!(compat.missing_capabilities.is_empty());
}

#[tokio::test]
async fn standalone_startup_is_dormant_until_identity_is_configured() {
    let (ip_a, _) = next_loopback_pair();
    let clock = FakeClock::new(1_800_300_000);
    let runner = FakePeerRunner::new(fixture_wg_pubkey(71), ip_a, 51821);
    let (rt, _) = build_test_runtime(
        "standalone-host",
        Arc::clone(&runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );

    start_with_runtime(Arc::clone(&rt)).await;
    assert!(
        rt.listener_state.lock().await.is_none(),
        "listener must not bind without configured peer identity"
    );
    run_health_tick(&rt).await;
    assert_eq!(
        runner.call_count(),
        0,
        "dormant standalone mode must not call privileged runner"
    );
    rt.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Router Integration: Versioned-Only Peer Routes, Admin/CSRF Guards,
//    4 KiB Public Bootstrap Limit & Retired Legacy Cluster Routes
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn versioned_router_enforces_admin_csrf_guards_excludes_legacy_alias_and_retires_legacy_cluster(
) {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-peer-router-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        std::env::set_var(key, &root);
    }
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("fixture.sqlite"));
    }
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::remove_var("CSRF_DISABLED");
    af_db::init_db().unwrap();

    let conn = af_db::get_conn().unwrap();
    conn.execute_batch(
        "INSERT INTO users(id, username, role) VALUES (1, 'peer-admin', 'admin');
         INSERT INTO users(id, username, role) VALUES (2, 'peer-member', 'user');",
    )
    .unwrap();
    drop(conn);

    let mut hdrs = axum::http::HeaderMap::new();
    hdrs.insert(header::USER_AGENT, "peer-router-test".parse().unwrap());
    let (admin_jwt, _) = crate::auth::create_standard_jwt(1, &hdrs).unwrap();
    let (member_jwt, _) = crate::auth::create_standard_jwt(2, &hdrs).unwrap();

    let app = crate::routes::build_router();

    // 1. Public /health advertises ["links"] before any identity is configured.
    let health_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header(header::HOST, "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    let health_json: Value =
        serde_json::from_slice(&to_bytes(health_resp.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(health_json["peer_protocol"], 1);
    assert_eq!(health_json["capabilities"], json!(["links", "grants"]));

    // 2. Unauthenticated request to /api/v1/admin/peers -> 401.
    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/peers")
                .header(header::HOST, "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // 3. Non-admin member request to /api/v1/admin/peers -> 403.
    let member_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/peers")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "peer-router-test")
                .header(header::AUTHORIZATION, format!("Bearer {member_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(member_resp.status(), StatusCode::FORBIDDEN);

    // 4. Admin request to /api/v1/admin/peers -> 200 OK with empty peer list and null identity.
    let admin_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/peers")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "peer-router-test")
                .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_resp.status(), StatusCode::OK);
    let admin_json: Value =
        serde_json::from_slice(&to_bytes(admin_resp.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert!(admin_json["identity"].is_null());
    assert_eq!(admin_json["peers"], json!([]));
    assert_eq!(admin_json["capabilities"], json!(["links", "grants"]));

    // 5. Cookie-authenticated POST to /api/v1/admin/peers/pairing-window WITHOUT CSRF token -> 403!
    let no_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/peers/pairing-window")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "peer-router-test")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; csrf_token=expected-csrf"),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
    let no_csrf_body = to_bytes(no_csrf.into_body(), 4096).await.unwrap();
    assert!(
        String::from_utf8_lossy(&no_csrf_body).contains("Invalid CSRF token"),
        "expected CSRF rejection body, got {}",
        String::from_utf8_lossy(&no_csrf_body)
    );

    // 5b. Cookie-authenticated DELETE /api/v1/admin/peers/pairing-window WITH matching CSRF token passes auth+CSRF!
    let with_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/admin/peers/pairing-window")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "peer-router-test")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; csrf_token=expected-csrf"),
                )
                .header("X-CSRF-Token", "expected-csrf")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(with_csrf.status(), StatusCode::OK);

    // 6. Legacy /api/admin/peers and /api/peer-pairing/request must NOT be registered as peer routes.
    let legacy_admin = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/admin/peers")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "peer-router-test")
                .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy_admin.status(), StatusCode::NOT_FOUND);

    let legacy_pub = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/peer-pairing/request")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy_pub.status(), StatusCode::NOT_FOUND);

    // 7. Public /api/v1/peer-pairing/request works outside auth/CSRF, enforces 4 KiB limit, and returns WINDOW_CLOSED.
    let pub_oversized = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/peer-pairing/request")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'a'; PUBLIC_PAIRING_BODY_LIMIT_BYTES + 16]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let pub_body = serde_json::to_vec(&PublicPairingRequest {
        code: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        name: "seedbox-1".to_string(),
        wg_pubkey: fixture_wg_pubkey(91),
        endpoint: "10.0.0.1".to_string(),
        wg_port: 51821,
        tunnel_ip: "10.231.0.5".to_string(),
        version: "4.0.0".to_string(),
        peer_protocol: 1,
        timestamp: Utc::now().timestamp(),
    })
    .unwrap();
    let pub_closed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/peer-pairing/request")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(pub_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pub_closed.status(), StatusCode::GONE);
    let pub_closed_json: Value =
        serde_json::from_slice(&to_bytes(pub_closed.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(pub_closed_json["code"], "WINDOW_CLOSED");

    // 8. Legacy cluster routes are retired on both /api/v1 and /api legacy aliases.
    for (method, path, payload) in [
        (Method::GET, "/api/v1/admin/cluster/nodes", None),
        (Method::GET, "/api/admin/cluster/nodes", None),
        (Method::POST, "/api/v1/admin/cluster/enroll", Some("{}")),
        (Method::POST, "/api/admin/cluster/enroll", Some("{}")),
        (Method::GET, "/api/v1/admin/cluster/commands", None),
        (Method::GET, "/api/admin/cluster/commands", None),
        (Method::DELETE, "/api/v1/admin/cluster/nodes/node-1", None),
        (Method::DELETE, "/api/admin/cluster/nodes/node-1", None),
        (
            Method::GET,
            "/api/v1/admin/cluster/nodes/node-1/metrics",
            None,
        ),
        (Method::GET, "/api/admin/cluster/nodes/node-1/metrics", None),
        (
            Method::POST,
            "/api/v1/admin/cluster/nodes/node-1/commands",
            Some(r#"{"cmd_type":"ping","target":""}"#),
        ),
        (
            Method::POST,
            "/api/admin/cluster/nodes/node-1/commands",
            Some(r#"{"cmd_type":"ping","target":""}"#),
        ),
    ] {
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(header::HOST, "localhost")
            .header(header::USER_AGENT, "peer-router-test")
            .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"));
        let body = match payload {
            Some(json_body) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(json_body)
            }
            None => Body::empty(),
        };
        let resp = app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "expected retired legacy cluster route {method} {path} to return 404"
        );
    }

    // 9. Auth, media, backup, and settings routes remain intact on both /api/v1 and /api aliases.
    for (path, expect_legacy_deprecation) in [
        ("/api/v1/auth/session", false),
        ("/api/auth/session", true),
        ("/api/v1/admin/mediaflow/queue", false),
        ("/api/admin/mediaflow/queue", true),
        ("/api/v1/admin/backup/list", false),
        ("/api/admin/backup/list", true),
        ("/api/v1/admin/settings", false),
        ("/api/admin/settings", true),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "peer-router-test")
                    .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "expected unaffected route {path} to remain 200 OK"
        );
        if expect_legacy_deprecation {
            assert_eq!(
                resp.headers()
                    .get("Deprecation")
                    .and_then(|v| v.to_str().ok()),
                Some("true"),
                "expected legacy alias {path} to carry Deprecation header"
            );
        }
    }

    // 10. Peer runtime startup stays dormant on an unlinked fresh database without legacy cluster startup.
    let global_rt = PeerRuntime::global();
    super::start().await;
    assert!(
        global_rt.listener_state.lock().await.is_none(),
        "dormant peer startup must not bind tunnel listener without configured peer identity"
    );
    run_health_tick(&global_rt).await;
    assert!(
        global_rt.listener_state.lock().await.is_none(),
        "dormant peer health tick must leave tunnel listener unbound"
    );
    super::shutdown().await;

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn peer_link_debug_and_serialization_never_expose_inbound_token_hash() {
    let link = PeerLink {
        id: "link-1".to_string(),
        name: "media-2".to_string(),
        wg_pubkey: fixture_wg_pubkey(88),
        tunnel_ip: "10.231.0.2".to_string(),
        endpoint: "10.0.0.2".to_string(),
        wg_port: 51821,
        state: "active".to_string(),
        peer_version: Some("4.0.0".to_string()),
        peer_protocol: Some(1),
        capabilities: Some(r#"["links"]"#.to_string()),
        rtt_ms: Some(1.5),
        last_ok_at: Some(Utc::now().to_rfc3339()),
        last_error: None,
        consecutive_failures: 0,
        inbound_token_hash: Some("sha256:super-secret-digest".to_string()),
        pending_attempt_id: None,
        pending_expires_at: None,
        created_at: (Utc::now() - ChronoDuration::minutes(5)).to_rfc3339(),
        updated_at: Utc::now().to_rfc3339(),
    };
    assert!(!format!("{link:?}").contains("super-secret-digest"));
    assert!(!serde_json::to_string(&link)
        .unwrap()
        .contains("super-secret-digest"));
}

#[tokio::test]
async fn tunnel_client_rejects_redirects_and_listener_enforces_per_link_concurrency_cap() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_800_400_000);
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(101), ip_a, 51821);
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        runner_a,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );

    // 1. Local TCP server returning 302 redirect: send_tunnel_request must NOT follow redirects.
    let redir_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_b, 0))
        .await
        .unwrap();
    let redir_port = redir_listener.local_addr().unwrap().port();
    let redir_task = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "http://127.0.0.1:9/redirected")],
                )
            }),
        );
        let _ = axum::serve(redir_listener, app).await;
    });

    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, redir_port);

    // Without configured local peer_identity, send_tunnel_request must fail closed!
    let missing_id_err = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert!(
        missing_id_err.message().contains("missing"),
        "expected fail-closed missing identity error, got {}",
        missing_id_err.message()
    );

    // Configure local peer_identity for ip_a, then verify redirects are refused.
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: fixture_wg_pubkey(101),
                tunnel_ip: ip_a.to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }

    let redir_err = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    redir_task.abort();
    assert!(
        redir_err.message().contains("redirect"),
        "expected redirect refusal, got {}",
        redir_err.message()
    );

    // 2. Per-link concurrency limit: holding the single permit causes 503 PEER_BUSY + audit.
    let token = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    {
        let conn = db_a.lock().unwrap();
        db_peers::insert_peer_link(
            &conn,
            &PeerLink {
                id: "cap-link-1".to_string(),
                name: "media-2".to_string(),
                wg_pubkey: fixture_wg_pubkey(102),
                tunnel_ip: ip_b.to_string(),
                endpoint: "10.0.0.2".to_string(),
                wg_port: 51821,
                state: "active".to_string(),
                peer_version: Some("4.0.0".to_string()),
                peer_protocol: Some(1),
                capabilities: Some(r#"["links"]"#.to_string()),
                rtt_ms: None,
                last_ok_at: None,
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: Some(super::pairing::sha256_prefixed(token)),
                pending_attempt_id: None,
                pending_expires_at: None,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    // Exhaust all permits for `cap-link-1`.
    let mut held_permits = Vec::new();
    while let Some(p) = rt_a.acquire_link_permit("cap-link-1") {
        held_permits.push(p);
    }
    assert_eq!(held_permits.len(), rt_a.max_conn_per_link);

    let listener_app = build_listener_router(Arc::clone(&rt_a));
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header(super::HEADER_LINK_TOKEN, token)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_b, 52000)));
    let resp = listener_app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["code"], "PEER_BUSY");
    assert!(audit_entries_text(&db_a).contains("PEER_BUSY"));
    drop(held_permits);
}

#[tokio::test]
async fn confirm_retry_after_lost_ack_reply_and_revocation_without_notice_shows_down() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(111);
    let pk_b = fixture_wg_pubkey(112);
    let clock = FakeClock::new(1_800_500_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 22], 45002)),
        }),
        &clock,
        true,
    );

    let (status, win) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let a_link_id = pair["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair["attempt_id"].as_str().unwrap().to_string();

    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    let b_port = rt_b
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_port);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);

    // Run full confirm once to activate A and B, then simulate B having crashed/timed out right
    // after receiving A's token (before activating B locally) and verify retrying confirm succeeds
    // via authenticated acknowledge retry reusing the stored LinkToken!
    let (status, confirm1) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let b_link_id = confirm1["link_id"].as_str().unwrap().to_string();
    let original_b_held = runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();

    // Roll back ONLY B's DB state to pre-ack confirming while keeping B's stored LinkToken and WG peer.
    {
        let conn = db_b.lock().unwrap();
        let mut att = db_peers::get_pairing_attempt(&conn, &attempt_id)
            .unwrap()
            .unwrap();
        att.status = "confirming".to_string();
        db_peers::update_pairing_attempt(&conn, &att).unwrap();
        let mut link = db_peers::get_peer_link(&conn, &b_link_id).unwrap().unwrap();
        link.state = "pending_owned".to_string();
        link.pending_attempt_id = Some(attempt_id.clone());
        link.pending_expires_at = Some(att.expires_at);
        db_peers::update_peer_link(&conn, &link).unwrap();
    }

    let (status, confirm_retry) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ack-only confirm retry failed: {confirm_retry}"
    );
    assert_eq!(confirm_retry["state"], "active");
    assert_eq!(
        runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .as_deref(),
        Some(original_b_held.as_str())
    );

    // Now simulate revocation on B while A's listener is shut down (revoke notice cannot be delivered).
    rt_a.shutdown_all().await;
    let (del_status, del_resp) =
        call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}"), None).await;
    assert_eq!(del_status, StatusCode::OK);
    assert_eq!(del_resp["revoked"], true);
    assert_eq!(del_resp["notice_delivered"], false);
    assert!(!runner_b.has_peer(&pk_a));

    // On A (which missed the revoke notice), next health tick sees B reject the old token and
    // marks the link as "down" (NOT "revoked").
    run_health_tick(&rt_a).await;
    let a_link_after = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_link_after.state, "down");

    rt_b.shutdown_all().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Review Blocker Regressions (Blockers 1–8)
// ─────────────────────────────────────────────────────────────────────────────

fn audit_row_count(conn: &Arc<StdMutex<Connection>>) -> i64 {
    conn.lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM admin_audit_log", [], |r| r.get(0))
        .unwrap()
}

fn notification_row_count(conn: &Arc<StdMutex<Connection>>) -> i64 {
    conn.lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
        .unwrap()
}

struct ControlledPublicTransport {
    responder: Arc<dyn Fn(PublicPairingRequest) -> (StatusCode, Vec<u8>) + Send + Sync>,
}

impl PublicPairingTransport for ControlledPublicTransport {
    fn post_pairing_request<'a>(
        &'a self,
        url: Url,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
        let responder = Arc::clone(&self.responder);
        Box::pin(async move {
            if url.scheme() != "https" {
                return Err("Public pairing requires https://".to_string());
            }
            let req: PublicPairingRequest =
                serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            Ok((responder)(req))
        })
    }
}

async fn pair_two_test_runtimes(
    rt_a: &Arc<PeerRuntime>,
    rt_b: &Arc<PeerRuntime>,
    ip_a: IpAddr,
    ip_b: IpAddr,
    a_name_for_b: &str,
) -> (String, String, String) {
    let (status, win) = call_admin(
        rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://peer-b.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "open window failed: {win}");
    let (status, pair) = call_admin(
        rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win["pairing_string"].as_str().unwrap(),
            "name": a_name_for_b,
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "start_pairing failed: {pair}");
    let a_link_id = pair["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair["attempt_id"].as_str().unwrap().to_string();

    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    let b_port = rt_b
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_port);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);

    let (status, confirm) = call_admin(
        rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm_pairing failed: {confirm}");
    let b_link_id = confirm["link_id"].as_str().unwrap().to_string();
    (a_link_id, b_link_id, attempt_id)
}

// Blocker 1: Interleaved late health completion preserves revoke state, cleared digest,
// and newly edited endpoint without emitting spurious notifications.
#[tokio::test]
async fn interleaved_late_health_completion_preserves_revocation_cleared_digest_and_new_endpoint() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(121);
    let pk_b = fixture_wg_pubkey(122);
    let clock = FakeClock::new(1_800_600_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, _db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 31], 45100)),
        }),
        &clock,
        true,
    );

    let (a_link_id, _b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-2").await;
    let b_held_for_a = runner_b
        .credential(PeerCredentialSlot::LinkToken, &_b_link_id)
        .unwrap();

    // Build a gated loopback health server on ip_b so we can deterministically stall a health
    // probe in flight and interleave concurrent endpoint edits and revocation notices.
    let probe_entered = Arc::new(Notify::new());
    let release_probe = Arc::new(Notify::new());
    let respond_ok = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let entered_c = Arc::clone(&probe_entered);
    let release_c = Arc::clone(&release_probe);
    let ok_flag = Arc::clone(&respond_ok);

    let gate_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_b, 0))
        .await
        .unwrap();
    let gate_port = gate_listener.local_addr().unwrap().port();
    let gate_task = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let entered = Arc::clone(&entered_c);
                let release = Arc::clone(&release_c);
                let ok = Arc::clone(&ok_flag);
                async move {
                    entered.notify_one();
                    release.notified().await;
                    if ok.load(Ordering::SeqCst) {
                        (
                            StatusCode::OK,
                            axum::Json(json!({
                                "status": "ok",
                                "version": "4.0.0-stalled",
                                "peer_protocol": 1,
                                "capabilities": ["links"]
                            })),
                        )
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(json!({ "error": "boom" })),
                        )
                    }
                }
            }),
        );
        let _ = axum::serve(gate_listener, app).await;
    });

    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, gate_port);

    // 1A. Endpoint edit while health probe is stalled mid-flight: late 200 OK health completion
    // must preserve the new endpoint and wg_port while updating health columns.
    let link_snapshot_1 = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    let rt_a_probe1 = Arc::clone(&rt_a);
    let probe_handle_1 = tokio::spawn(async move {
        check_single_link(&rt_a_probe1, link_snapshot_1, None).await;
    });

    probe_entered.notified().await;

    let (ep_status, ep_resp) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/endpoint"),
        Some(json!({ "endpoint": "10.99.88.77", "wg_port": 51999 })),
    )
    .await;
    assert_eq!(ep_status, StatusCode::OK, "ep_resp={ep_resp}");

    release_probe.notify_one();
    probe_handle_1.await.unwrap();

    let after_ep = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(after_ep.endpoint, "10.99.88.77");
    assert_eq!(after_ep.wg_port, 51999);
    assert_eq!(after_ep.peer_version.as_deref(), Some("4.0.0-stalled"));
    assert_eq!(after_ep.state, "active");

    // 1B. Revocation while health probe is stalled mid-flight (link initially "down" so a late
    // 200 OK probe would have both overwritten revoked state AND emitted a recovery notification).
    {
        let conn = db_a.lock().unwrap();
        conn.execute(
            "UPDATE peer_links SET state = 'down' WHERE id = ?1",
            rusqlite::params![a_link_id],
        )
        .unwrap();
    }
    let link_snapshot_2 = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    let rt_a_probe2 = Arc::clone(&rt_a);
    let probe_handle_2 = tokio::spawn(async move {
        check_single_link(&rt_a_probe2, link_snapshot_2, None).await;
    });

    probe_entered.notified().await;

    // Deliver authenticated revoke notice to A while probe 2 is stalled.
    let (rev_status, _, _) = rt_b
        .send_tunnel_request(
            Method::POST,
            &ip_a.to_string(),
            "/peer/v1/revoke-notice",
            Some(&PeerCredentialSecret::new(b_held_for_a)),
            Some(b"{}".to_vec()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(rev_status, StatusCode::OK);
    let notif_count_after_revoke = notification_row_count(&db_a);

    // Now release the stalled healthy probe AND also test a late failing probe on a revoked row.
    release_probe.notify_one();
    probe_handle_2.await.unwrap();

    let after_rev = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(after_rev.state, "revoked_unowned");
    assert!(after_rev.inbound_token_hash.is_none());
    assert_eq!(after_rev.endpoint, "10.99.88.77");
    assert_eq!(
        after_rev.last_error.as_deref(),
        Some("Link revoked by media-2")
    );
    assert_eq!(
        notification_row_count(&db_a),
        notif_count_after_revoke,
        "late uncommitted health probe must not emit notifications"
    );

    // Late failing probe against a stale snapshot also preserves revoked state and digest.
    // Re-seed a temporary outbound token in the fake runner so the probe actually reaches the
    // stalled /health endpoint and returns HTTP 500 instead of short-circuiting on missing token.
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::WriteCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: a_link_id.clone(),
            value: "0101010101010101010101010101010101010101010101010101010101010101".to_string(),
        })
        .await;
    respond_ok.store(false, Ordering::SeqCst);
    let mut stale_active_snapshot = after_rev.clone();
    stale_active_snapshot.state = "active".to_string();
    let rt_a_probe3 = Arc::clone(&rt_a);
    let probe_handle_3 = tokio::spawn(async move {
        check_single_link(&rt_a_probe3, stale_active_snapshot, None).await;
    });
    probe_entered.notified().await;
    release_probe.notify_one();
    probe_handle_3.await.unwrap();

    let after_fail_probe = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(after_fail_probe.state, "revoked_unowned");
    assert!(after_fail_probe.inbound_token_hash.is_none());
    assert_eq!(notification_row_count(&db_a), notif_count_after_revoke);

    gate_task.abort();
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// Blocker 2: Temporary issuer credentials are namespaced by local link owner and isolated across
// opposite pairing roles; recording a colliding remote attempt ID is rejected without harming
// existing local attempts or links.
#[tokio::test]
async fn temporary_issuer_credentials_are_owner_namespaced_and_isolated_across_opposite_roles() {
    let (ip_x, ip_c) = next_loopback_pair();
    let (ip_d, ip_e) = next_loopback_pair();
    let pk_x = fixture_wg_pubkey(131);
    let pk_c = fixture_wg_pubkey(132);
    let pk_d = fixture_wg_pubkey(133);
    let pk_e = fixture_wg_pubkey(134);
    let clock = FakeClock::new(1_800_700_000);

    let runner_x = FakePeerRunner::new(pk_x.clone(), ip_x, 51821);
    let runner_c = FakePeerRunner::new(pk_c.clone(), ip_c, 51821);
    let runner_d = FakePeerRunner::new(pk_d.clone(), ip_d, 51821);

    let (rt_d, _db_d) = build_test_runtime(
        "peer-d",
        Arc::clone(&runner_d) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );

    struct SwitchablePublicTransport {
        normal_target: Arc<PeerRuntime>,
        colliding_attempt: Arc<StdMutex<Option<String>>>,
        colliding_pubkey: Arc<StdMutex<String>>,
        clock: Arc<FakeClock>,
    }

    impl PublicPairingTransport for SwitchablePublicTransport {
        fn post_pairing_request<'a>(
            &'a self,
            url: Url,
            body: Vec<u8>,
        ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
            let normal_target = Arc::clone(&self.normal_target);
            let forced_att = self.colliding_attempt.lock().unwrap().clone();
            let remote_pk = self.colliding_pubkey.lock().unwrap().clone();
            let now_ts = self.clock.epoch.load(Ordering::SeqCst);
            Box::pin(async move {
                if url.scheme() != "https" {
                    return Err("Public pairing requires https://".to_string());
                }
                if let Some(att_id) = forced_att {
                    let req: PublicPairingRequest =
                        serde_json::from_slice(&body).map_err(|e| e.to_string())?;
                    let resp = PublicPairingResponse {
                        attempt_id: att_id,
                        comparison_code: derive_comparison_code(&req.wg_pubkey, &remote_pk),
                        expires_at: now_ts + PAIRING_WINDOW_TTL_SECS,
                        server_name: "colliding-peer".to_string(),
                        version: "4.0.0-test".to_string(),
                        peer_protocol: PEER_PROTOCOL_VERSION,
                    };
                    return Ok((StatusCode::OK, serde_json::to_vec(&resp).unwrap()));
                }
                let app = public_routes_with_runtime(normal_target);
                let mut http_req = Request::builder()
                    .method(Method::POST)
                    .uri("/peer-pairing/request")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap();
                http_req
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from(([198, 51, 100, 41], 45200))));
                let resp = app.oneshot(http_req).await.unwrap();
                let status = resp.status();
                let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
                Ok((status, bytes.to_vec()))
            })
        }
    }

    let colliding_attempt_slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    let colliding_pk_slot: Arc<StdMutex<String>> = Arc::new(StdMutex::new(pk_e.clone()));
    let x_transport = Arc::new(SwitchablePublicTransport {
        normal_target: Arc::clone(&rt_d),
        colliding_attempt: Arc::clone(&colliding_attempt_slot),
        colliding_pubkey: Arc::clone(&colliding_pk_slot),
        clock: Arc::clone(&clock),
    });

    let (rt_x, db_x) = build_test_runtime(
        "server-x",
        Arc::clone(&runner_x) as Arc<dyn PeerRunner>,
        x_transport,
        &clock,
        true,
    );
    let (rt_c, _db_c) = build_test_runtime(
        "peer-c",
        Arc::clone(&runner_c) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_x),
            client_ip: SocketAddr::from(([198, 51, 100, 42], 45201)),
        }),
        &clock,
        true,
    );

    // 2A. Server X acts as RESPONDER (B-role) for Peer C.
    let (status, win_x) = call_admin(
        &rt_x,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://server-x.example.test", "endpoint": "10.20.0.1" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair_c_to_x) = call_admin(
        &rt_c,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_x["pairing_string"].as_str().unwrap(),
            "name": "server-x",
            "endpoint": "10.20.0.2"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let att_c_to_x = pair_c_to_x["attempt_id"].as_str().unwrap().to_string();

    // Point X to an unreachable port for C so X's confirm mints & retains X's B-role
    // PendingIssuerToken and stops at HANDSHAKE_TIMEOUT.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    rt_x.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_c, closed_port);

    let (status, _) = call_admin(
        &rt_x,
        Method::POST,
        &format!("/pairing/{att_c_to_x}/confirm"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);

    let x_resp_link_id = db_peers::list_peer_links(&db_x.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att_c_to_x.as_str()))
        .unwrap()
        .id;
    let x_resp_cred_key = pending_issuer_credential_id(&x_resp_link_id);
    let x_resp_tok = runner_x
        .credential(PeerCredentialSlot::PendingIssuerToken, &x_resp_cred_key)
        .expect("X responder PendingIssuerToken stored under local link owner key");
    assert!(
        runner_x
            .credential(PeerCredentialSlot::PendingIssuerToken, &att_c_to_x)
            .is_none(),
        "PendingIssuerToken must never be keyed by bare attempt_id"
    );

    // The responder retains its local attempt while both inbound hello phases are denied.
    let x_listener = build_listener_router(Arc::clone(&rt_x));
    for phase in [HelloPhase::Bootstrap, HelloPhase::Acknowledge] {
        let bootstrap = matches!(phase, HelloPhase::Bootstrap);
        let hello = HelloRequest {
            phase,
            attempt_id: att_c_to_x.clone(),
            wg_pubkey: pk_c.clone(),
            tunnel_ip: Some(ip_c.to_string()),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
            capabilities: vec!["links".to_string()],
            link_token: bootstrap.then(|| PeerCredentialSecret::new("ab".repeat(32))),
        };
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/peer/v1/hello")
            .header(header::CONTENT_TYPE, "application/json");
        if !bootstrap {
            request = request.header("X-AF-Link-Token", &x_resp_tok);
        }
        let mut request = request
            .body(Body::from(serde_json::to_vec(&hello).unwrap()))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip_c, 59010)));
        let response = x_listener.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], "PEER_UNAUTHORIZED");
        assert!(body.get("link_token").is_none());
    }
    assert!(runner_x
        .credential(PeerCredentialSlot::LinkToken, &x_resp_link_id)
        .is_none());
    assert_eq!(
        db_peers::get_peer_link(&db_x.lock().unwrap(), &x_resp_link_id)
            .unwrap()
            .unwrap()
            .state,
        "pending_owned"
    );
    let (list_st, list_val) = call_admin(&rt_x, Method::GET, "/", None).await;
    assert_eq!(list_st, StatusCode::OK);
    let x_resp_view = list_val["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == x_resp_link_id)
        .unwrap();
    assert_eq!(
        x_resp_view["state"], "pending",
        "admin JSON must project internal pending_owned state as public 'pending'"
    );

    // 2B. Collision test (opposite role): Server X initiates pairing to Peer E whose reply tries
    // to reuse X's active local responder attempt_id (`att_c_to_x`)! Must fail with 409 and leave
    // X's responder attempt, link, WG peer, and PendingIssuerToken completely intact!
    let fake_e_payload = PairingPayload {
        https_url: "https://colliding.example.test".to_string(),
        wg_pubkey: pk_e.clone(),
        endpoint: "10.20.0.5".to_string(),
        wg_port: 51821,
        tunnel_ip: ip_e.to_string(),
        code: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
    }
    .encode()
    .unwrap();
    *colliding_attempt_slot.lock().unwrap() = Some(att_c_to_x.clone());
    *colliding_pk_slot.lock().unwrap() = pk_e.clone();

    let (coll_status, coll_val) = call_admin(
        &rt_x,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": fake_e_payload,
            "name": "peer-e",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(coll_status, StatusCode::CONFLICT, "coll_val={coll_val}");
    assert_eq!(coll_val["code"], "PEER_CONFLICT");
    assert!(
        !runner_x.has_peer(&pk_e),
        "failed colliding A-role attempt must clean up its own WG peer"
    );
    assert_eq!(
        runner_x
            .credential(PeerCredentialSlot::PendingIssuerToken, &x_resp_cred_key)
            .as_deref(),
        Some(x_resp_tok.as_str()),
        "existing opposite-role responder credential must remain intact"
    );
    assert!(
        runner_x.has_peer(&pk_c),
        "existing opposite-role responder WG peer must remain intact"
    );

    // 2C. Simultaneously coexist in opposite roles: X initiates pairing to Peer D while keeping
    // X's responder pairing for Peer C pending!
    *colliding_attempt_slot.lock().unwrap() = None;
    let (status, win_d) = call_admin(
        &rt_d,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://peer-d.example.test", "endpoint": "10.20.0.4" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair_x_to_d) = call_admin(
        &rt_x,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_d["pairing_string"].as_str().unwrap(),
            "name": "peer-d",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let x_init_link_id = pair_x_to_d["link_id"].as_str().unwrap().to_string();
    let att_x_to_d = pair_x_to_d["attempt_id"].as_str().unwrap().to_string();

    // Also verify a distinct A-role pairing to Peer E cannot reuse `att_x_to_d`!
    *colliding_attempt_slot.lock().unwrap() = Some(att_x_to_d.clone());
    *colliding_pk_slot.lock().unwrap() = pk_e.clone();
    let (coll2_status, coll2_val) = call_admin(
        &rt_x,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": fake_e_payload,
            "name": "peer-e",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(coll2_status, StatusCode::CONFLICT, "coll2_val={coll2_val}");
    assert_eq!(coll2_val["code"], "PEER_CONFLICT");
    assert!(!runner_x.has_peer(&pk_e));
    *colliding_attempt_slot.lock().unwrap() = None;

    // Trigger Bootstrap hello from D to X so X ALSO mints its initiator PendingIssuerToken.
    let x_port = rt_x
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_d.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_x, x_port);
    let d_boot_body = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Bootstrap,
        attempt_id: att_x_to_d.clone(),
        wg_pubkey: pk_d.clone(),
        tunnel_ip: Some(ip_d.to_string()),
        version: "4.0.0-test".to_string(),
        peer_protocol: PEER_PROTOCOL_VERSION,
        capabilities: vec!["links".to_string()],
        link_token: Some(PeerCredentialSecret::new(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
        )),
    })
    .unwrap();
    let (boot_status, _, _) = rt_d
        .send_tunnel_request(
            Method::POST,
            &ip_x.to_string(),
            "/peer/v1/hello",
            None,
            Some(d_boot_body),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(boot_status, StatusCode::OK);

    let x_init_cred_key = pending_issuer_credential_id(&x_init_link_id);
    let x_init_tok = runner_x
        .credential(PeerCredentialSlot::PendingIssuerToken, &x_init_cred_key)
        .expect("X initiator PendingIssuerToken stored under its own local link key");
    assert_ne!(x_init_cred_key, x_resp_cred_key);
    assert_ne!(x_init_tok, x_resp_tok);

    // Cancelling X's initiator pairing with D deletes ONLY X's initiator credential, preserving
    // X's responder credential so C's confirm retry succeeds cleanly!
    let (cancel_status, _) = call_admin(
        &rt_x,
        Method::DELETE,
        &format!("/pairing/{att_x_to_d}"),
        None,
    )
    .await;
    assert_eq!(cancel_status, StatusCode::OK);
    assert!(runner_x
        .credential(PeerCredentialSlot::PendingIssuerToken, &x_init_cred_key)
        .is_none());
    assert_eq!(
        runner_x
            .credential(PeerCredentialSlot::PendingIssuerToken, &x_resp_cred_key)
            .as_deref(),
        Some(x_resp_tok.as_str())
    );

    let c_port = rt_c
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_x.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_c, c_port);
    let (final_status, final_val) = call_admin(
        &rt_x,
        Method::POST,
        &format!("/pairing/{att_c_to_x}/confirm"),
        None,
    )
    .await;
    assert_eq!(final_status, StatusCode::OK, "final_val={final_val}");
    assert_eq!(final_val["state"], "active");

    rt_x.shutdown_all().await;
    rt_c.shutdown_all().await;
    rt_d.shutdown_all().await;
}

// Blocker 3A: Public 5/min limiter runs before body parsing, counts malformed/wrong-media-type/
// oversized requests, uses monotonic elapsed time, emits sanitized typed no-store errors, and
// performs zero DB/audit work at 429.
#[tokio::test]
async fn public_pairing_limiter_counts_invalid_bodies_uses_monotonic_clock_and_skips_db_at_429() {
    let (_ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_800_800_000);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(141), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        runner_b,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );

    let send_raw = |ip: [u8; 4], content_type: Option<&'static str>, body: Vec<u8>| {
        let rt = Arc::clone(&rt_b);
        async move {
            let app = public_routes_with_runtime(rt);
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/peer-pairing/request");
            if let Some(ct) = content_type {
                builder = builder.header(header::CONTENT_TYPE, ct);
            }
            let mut req = builder.body(Body::from(body)).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from((ip, 55000))));
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let cache_ctrl = resp
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let retry_after = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let val: Value = serde_json::from_slice(&bytes).expect("sanitized typed JSON body");
            (status, cache_ctrl, retry_after, val)
        }
    };

    let src = [203, 0, 113, 88];
    // 1. Malformed JSON counts against allowance, returns sanitized 400 with no-store.
    let (s1, cc1, _, v1) =
        send_raw(src, Some("application/json"), b"{bad-json-secret".to_vec()).await;
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    assert_eq!(cc1.as_deref(), Some("no-store"));
    assert_eq!(v1["code"], "INVALID_REQUEST");
    assert!(!v1["message"].as_str().unwrap().contains("bad-json-secret"));

    // 2. Wrong media type counts against allowance, returns sanitized 415 with no-store.
    let (s2, cc2, _, v2) = send_raw(src, Some("text/plain"), b"{}".to_vec()).await;
    assert_eq!(s2, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(cc2.as_deref(), Some("no-store"));
    assert_eq!(v2["code"], "UNSUPPORTED_MEDIA_TYPE");

    // 3. Oversized (> 4 KiB) counts against allowance, returns sanitized 413 with no-store.
    let (s3, cc3, _, v3) = send_raw(
        src,
        Some("application/json"),
        vec![b'x'; PUBLIC_PAIRING_BODY_LIMIT_BYTES + 128],
    )
    .await;
    assert_eq!(s3, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(cc3.as_deref(), Some("no-store"));
    assert_eq!(v3["code"], "PAYLOAD_TOO_LARGE");

    // 4. Missing Content-Type counts against allowance, returns 415.
    let (s4, cc4, _, v4) = send_raw(src, None, b"{}".to_vec()).await;
    assert_eq!(s4, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(cc4.as_deref(), Some("no-store"));
    assert_eq!(v4["code"], "UNSUPPORTED_MEDIA_TYPE");

    // 5. Unknown-field JSON counts against allowance, returns 400.
    let (s5, cc5, _, v5) = send_raw(src, Some("application/json"), b"{\"nope\":1}".to_vec()).await;
    assert_eq!(s5, StatusCode::BAD_REQUEST);
    assert_eq!(cc5.as_deref(), Some("no-store"));
    assert_eq!(v5["code"], "INVALID_REQUEST");

    let audits_before_429 = audit_row_count(&db_b);
    assert_eq!(audits_before_429, 5);

    // 6. All subsequent requests (even oversized or wrong-media-type) hit 429 BEFORE body parsing
    // and perform ZERO database/audit work!
    for (ct, payload) in [
        (Some("application/json"), b"{bad".to_vec()),
        (
            Some("text/plain"),
            vec![b'z'; PUBLIC_PAIRING_BODY_LIMIT_BYTES + 256],
        ),
    ] {
        let (s, cc, ra, v) = send_raw(src, ct, payload).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(cc.as_deref(), Some("no-store"));
        assert_eq!(ra.as_deref(), Some("60"));
        assert_eq!(v["code"], "RATE_LIMITED");
    }
    assert_eq!(
        audit_row_count(&db_b),
        audits_before_429,
        "429 rejections must perform zero database/audit writes"
    );

    // Wall-clock jump backward or forward must NOT bypass the monotonic limiter.
    clock.shift_wall_clock_only(300);
    let (s_wall_fwd, _, _, v_wall_fwd) =
        send_raw(src, Some("application/json"), b"{}".to_vec()).await;
    assert_eq!(s_wall_fwd, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v_wall_fwd["code"], "RATE_LIMITED");
    assert_eq!(audit_row_count(&db_b), audits_before_429);

    clock.shift_wall_clock_only(-600);
    let (s_wall_back, _, _, v_wall_back) =
        send_raw(src, Some("application/json"), b"{}".to_vec()).await;
    assert_eq!(s_wall_back, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v_wall_back["code"], "RATE_LIMITED");
    assert_eq!(audit_row_count(&db_b), audits_before_429);

    // Advancing monotonic clock past 60s admits requests again.
    clock.advance(61);
    let (s_after, _, _, _) = send_raw(src, Some("text/plain"), b"{}".to_vec()).await;
    assert_eq!(s_after, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(audit_row_count(&db_b), audits_before_429 + 1);
}

// Blocker 3B: Trusted versus untrusted forwarding via normal `routes::build_router()`, invalid
// body admission counting, and unchanged audit count at 429.
#[tokio::test(flavor = "current_thread")]
async fn public_pairing_trusted_vs_untrusted_forwarding_via_normal_router() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-peer-fwd-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        std::env::set_var(key, &root);
    }
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("fixture.sqlite"));
    }
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::remove_var("TRUSTED_PROXIES");
    std::env::remove_var("TRUST_PROXY_HEADERS");
    af_db::init_db().unwrap();

    let app = crate::routes::build_router();
    let db_audit_count = || -> i64 {
        let conn = af_db::get_conn().unwrap();
        conn.query_row("SELECT COUNT(*) FROM admin_audit_log", [], |r| r.get(0))
            .unwrap()
    };

    // 1. Untrusted peer (198.51.100.50) spoofing a DIFFERENT X-Forwarded-For on every request:
    // normal router strips untrusted forwarding headers so all 5 invalid requests count against
    // 198.51.100.50, and the 6th is rejected with 429 and zero DB audit writes.
    let untrusted_peer = SocketAddr::from(([198, 51, 100, 50], 41000));
    for i in 1..=5u8 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/peer-pairing/request")
            .header(header::HOST, "localhost")
            .header(
                header::CONTENT_TYPE,
                if i % 2 == 0 {
                    "text/plain"
                } else {
                    "application/json"
                },
            )
            .header("X-Forwarded-For", format!("203.0.113.{i}"))
            .body(Body::from("{malformed"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(untrusted_peer));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    }

    let audits_before_untrusted_429 = db_audit_count();
    let mut req6 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/peer-pairing/request")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", "203.0.113.99")
        .body(Body::from(vec![b'a'; PUBLIC_PAIRING_BODY_LIMIT_BYTES + 64]))
        .unwrap();
    req6.extensions_mut().insert(ConnectInfo(untrusted_peer));
    let resp6 = app.clone().oneshot(req6).await.unwrap();
    assert_eq!(resp6.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp6.headers()[header::CACHE_CONTROL], "no-store");
    let body6: Value =
        serde_json::from_slice(&to_bytes(resp6.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body6["code"], "RATE_LIMITED");
    assert_eq!(
        db_audit_count(),
        audits_before_untrusted_429,
        "untrusted-peer 429 must not write audit rows"
    );

    // 2. Trusted loopback reverse proxy (127.0.0.1): keys by rightmost untrusted hop in
    // X-Forwarded-For, ignoring spoofed leftmost hops, while keeping distinct clients isolated.
    let trusted_proxy = SocketAddr::from(([127, 0, 0, 1], 42000));
    for i in 1..=5u8 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/peer-pairing/request")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Forwarded-For", format!("198.51.100.{i}, 203.0.113.70"))
            .body(Body::from("{bad"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(trusted_proxy));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    let audits_before_trusted_429 = db_audit_count();
    let mut proxied_6 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/peer-pairing/request")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", "198.51.100.250, 203.0.113.70")
        .body(Body::from("{bad"))
        .unwrap();
    proxied_6
        .extensions_mut()
        .insert(ConnectInfo(trusted_proxy));
    let proxied_6_resp = app.clone().oneshot(proxied_6).await.unwrap();
    assert_eq!(proxied_6_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(db_audit_count(), audits_before_trusted_429);

    // A different client behind the same trusted loopback proxy is unaffected.
    let mut other_client = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/peer-pairing/request")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Forwarded-For", "203.0.113.71")
        .body(Body::from("{bad"))
        .unwrap();
    other_client
        .extensions_mut()
        .insert(ConnectInfo(trusted_proxy));
    let other_resp = app.oneshot(other_client).await.unwrap();
    assert_eq!(other_resp.status(), StatusCode::BAD_REQUEST);

    let _ = std::fs::remove_dir_all(root);
}

// Blocker 4: Concurrent confirm & bootstrap serialize and reuse one token pair, lost ack followed
// by health tick marking A `down` still permits bounded authenticated ack retry, ack response
// fields are strictly validated, and one exclusive expiry boundary holds everywhere.
#[tokio::test]
async fn concurrent_confirm_bootstrap_lost_ack_after_health_down_ack_validation_and_exact_expiry() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(151);
    let pk_b = fixture_wg_pubkey(152);
    let clock = FakeClock::new(1_800_900_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 51], 45300)),
        }),
        &clock,
        true,
    );

    // Start pairing (A -> B).
    let (status, win) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let a_link_id = pair["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair["attempt_id"].as_str().unwrap().to_string();

    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    let b_port = rt_b
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_port);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);

    // 4A. Concurrent Bootstrap requests on A serialize and return the exact same issued token.
    let b_boot_tok = "1212121212121212121212121212121212121212121212121212121212121212";
    let boot_futs: Vec<_> = (0..4)
        .map(|_| {
            let rt_b_c = Arc::clone(&rt_b);
            let att = attempt_id.clone();
            let pk = pk_b.clone();
            let ip_a_s = ip_a.to_string();
            let ip_b_s = ip_b.to_string();
            async move {
                let body = serde_json::to_vec(&HelloRequest {
                    phase: HelloPhase::Bootstrap,
                    attempt_id: att,
                    wg_pubkey: pk,
                    tunnel_ip: Some(ip_b_s),
                    version: "4.0.0-test".to_string(),
                    peer_protocol: PEER_PROTOCOL_VERSION,
                    capabilities: vec!["links".to_string()],
                    link_token: Some(PeerCredentialSecret::new(b_boot_tok.to_string())),
                })
                .unwrap();
                let (st, resp_bytes, _) = rt_b_c
                    .send_tunnel_request(
                        Method::POST,
                        &ip_a_s,
                        "/peer/v1/hello",
                        None,
                        Some(body),
                        Duration::from_secs(3),
                    )
                    .await
                    .unwrap();
                let parsed: Value = serde_json::from_slice(&resp_bytes).unwrap();
                (st, parsed)
            }
        })
        .collect();
    let boot_results = futures::future::join_all(boot_futs).await;
    let first_tok = boot_results[0].1["link_token"]
        .as_str()
        .unwrap()
        .to_string();
    for (st, val) in &boot_results {
        assert_eq!(*st, StatusCode::OK, "concurrent bootstrap failed: {val}");
        assert_eq!(val["link_token"].as_str(), Some(first_tok.as_str()));
    }

    // Clear A's held B token from the direct bootstrap test so B's real concurrent confirms run cleanly.
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::DeleteLinkCredentials {
            link_id: a_link_id.clone(),
        })
        .await;

    // 4B. Concurrent confirm_pairing calls on B serialize cleanly with a single token pair.
    let confirm_futs: Vec<_> = (0..4)
        .map(|_| {
            let rt = Arc::clone(&rt_b);
            let uri = format!("/pairing/{attempt_id}/confirm");
            async move { call_admin(&rt, Method::POST, &uri, None).await }
        })
        .collect();
    let confirm_results = futures::future::join_all(confirm_futs).await;
    let b_link_id = confirm_results[0].1["link_id"]
        .as_str()
        .unwrap()
        .to_string();
    for (st, val) in &confirm_results {
        assert_eq!(*st, StatusCode::OK, "concurrent confirm failed: {val}");
        assert_eq!(val["link_id"].as_str(), Some(b_link_id.as_str()));
        assert_eq!(val["confirmed"], true);
    }

    // 4C. Lost ack reply followed by health tick marking A `down`, then bounded authenticated ack
    // retry succeeds and subsequent health tick recovers A to `active`!
    {
        let conn = db_b.lock().unwrap();
        let mut att = db_peers::get_pairing_attempt(&conn, &attempt_id)
            .unwrap()
            .unwrap();
        att.status = "confirming".to_string();
        db_peers::update_pairing_attempt(&conn, &att).unwrap();
        let mut link = db_peers::get_peer_link(&conn, &b_link_id).unwrap().unwrap();
        link.state = "pending_owned".to_string();
        link.pending_attempt_id = Some(attempt_id.clone());
        link.pending_expires_at = Some(att.expires_at);
        db_peers::update_peer_link(&conn, &link).unwrap();
    }

    // A's health tick runs while B is still `pending`: B rejects `/health` (401), so A becomes `down`.
    run_health_tick(&rt_a).await;
    let a_down = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        a_down.state, "down",
        "health tick while B is pending must mark A down"
    );

    // B retries confirmation (sends authenticated Acknowledge while A is `down` within expiry!).
    let (retry_status, retry_val) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(
        retry_status,
        StatusCode::OK,
        "authenticated ack retry must succeed even after health marked A down: {retry_val}"
    );
    assert_eq!(retry_val["state"], "active");

    // Next health tick on A sees B active and recovers A cleanly to `active`.
    run_health_tick(&rt_a).await;
    let a_recovered = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_recovered.state, "active");

    // 4D. Ack response validation on B (wrong pubkey, wrong phase, wrong attempt, bad protocol,
    // acknowledged=false, unexpected link_token).
    let (ip_a2, ip_b2) = next_loopback_pair();
    let pk_a2 = fixture_wg_pubkey(153);
    let pk_b2 = fixture_wg_pubkey(154);
    let runner_b2 = FakePeerRunner::new(pk_b2.clone(), ip_b2, 51821);
    let (rt_b2, db_b2) = build_test_runtime(
        "media-ack-check",
        Arc::clone(&runner_b2) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );
    {
        let conn = db_b2.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_b2.clone(),
                tunnel_ip: ip_b2.to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }

    let bad_ack_cases: Vec<(&str, HelloResponse, &str)> = vec![
        (
            "wrong_pubkey",
            HelloResponse {
                phase: HelloPhase::Acknowledge,
                attempt_id: "att-bad-0".to_string(),
                acknowledged: true,
                state: "active".to_string(),
                wg_pubkey: fixture_wg_pubkey(199),
                version: "4.0.0".to_string(),
                peer_protocol: 1,
                capabilities: vec!["links".to_string()],
                link_token: None,
            },
            "KEY_MISMATCH",
        ),
        (
            "wrong_phase",
            HelloResponse {
                phase: HelloPhase::Bootstrap,
                attempt_id: "att-bad-1".to_string(),
                acknowledged: true,
                state: "active".to_string(),
                wg_pubkey: pk_a2.clone(),
                version: "4.0.0".to_string(),
                peer_protocol: 1,
                capabilities: vec!["links".to_string()],
                link_token: None,
            },
            "VERSION_INCOMPATIBLE",
        ),
        (
            "wrong_attempt",
            HelloResponse {
                phase: HelloPhase::Acknowledge,
                attempt_id: "different-attempt".to_string(),
                acknowledged: true,
                state: "active".to_string(),
                wg_pubkey: pk_a2.clone(),
                version: "4.0.0".to_string(),
                peer_protocol: 1,
                capabilities: vec!["links".to_string()],
                link_token: None,
            },
            "VERSION_INCOMPATIBLE",
        ),
        (
            "bad_protocol",
            HelloResponse {
                phase: HelloPhase::Acknowledge,
                attempt_id: "att-bad-3".to_string(),
                acknowledged: true,
                state: "active".to_string(),
                wg_pubkey: pk_a2.clone(),
                version: "4.0.0".to_string(),
                peer_protocol: 0,
                capabilities: vec!["links".to_string()],
                link_token: None,
            },
            "VERSION_INCOMPATIBLE",
        ),
        (
            "unexpected_token",
            HelloResponse {
                phase: HelloPhase::Acknowledge,
                attempt_id: "att-bad-4".to_string(),
                acknowledged: true,
                state: "active".to_string(),
                wg_pubkey: pk_a2.clone(),
                version: "4.0.0".to_string(),
                peer_protocol: 1,
                capabilities: vec!["links".to_string()],
                link_token: Some(PeerCredentialSecret::new(
                    "9999999999999999999999999999999999999999999999999999999999999999".to_string(),
                )),
            },
            "VERSION_INCOMPATIBLE",
        ),
    ];

    let active_ack_reply: Arc<StdMutex<HelloResponse>> = Arc::new(StdMutex::new(HelloResponse {
        phase: HelloPhase::Acknowledge,
        attempt_id: String::new(),
        acknowledged: false,
        state: "pending".to_string(),
        wg_pubkey: pk_a2.clone(),
        version: "4.0.0".to_string(),
        peer_protocol: 1,
        capabilities: vec!["links".to_string()],
        link_token: None,
    }));
    let ack_reply_c = Arc::clone(&active_ack_reply);
    let pk_a2_c = pk_a2.clone();
    let mock_a_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_a2, 0))
        .await
        .unwrap();
    let mock_a_port = mock_a_listener.local_addr().unwrap().port();
    let mock_a_task = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/peer/v1/hello",
            axum::routing::post(move |axum::Json(req): axum::Json<HelloRequest>| {
                let ack_slot = Arc::clone(&ack_reply_c);
                let pk = pk_a2_c.clone();
                async move {
                    match req.phase {
                        HelloPhase::Bootstrap => axum::Json(HelloResponse {
                            phase: HelloPhase::Bootstrap,
                            attempt_id: req.attempt_id,
                            acknowledged: false,
                            state: "pending".to_string(),
                            wg_pubkey: pk,
                            version: "4.0.0".to_string(),
                            peer_protocol: 1,
                            capabilities: vec!["links".to_string()],
                            link_token: Some(PeerCredentialSecret::new(
                                "abababababababababababababababababababababababababababababababab"
                                    .to_string(),
                            )),
                        }),
                        HelloPhase::Acknowledge => {
                            let guard = ack_slot.lock().unwrap();
                            axum::Json(HelloResponse {
                                phase: guard.phase,
                                attempt_id: guard.attempt_id.clone(),
                                acknowledged: guard.acknowledged,
                                state: guard.state.clone(),
                                wg_pubkey: guard.wg_pubkey.clone(),
                                version: guard.version.clone(),
                                peer_protocol: guard.peer_protocol,
                                capabilities: guard.capabilities.clone(),
                                link_token: guard.link_token.clone(),
                            })
                        }
                    }
                }
            }),
        );
        let _ = axum::serve(mock_a_listener, app).await;
    });
    rt_b2
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a2, mock_a_port);

    for (idx, (label, bad_reply, expected_code)) in bad_ack_cases.into_iter().enumerate() {
        let att_id = format!("att-bad-{idx}");
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        {
            let conn = db_b2.lock().unwrap();
            db_peers::insert_pairing_attempt(
                &conn,
                &af_db::peers::PairingAttempt {
                    id: att_id.clone(),
                    window_id: None,
                    remote_name: Some(format!("peer-{idx}")),
                    remote_pubkey: Some(pk_a2.clone()),
                    remote_tunnel_ip: Some(ip_a2.to_string()),
                    remote_endpoint: Some("10.10.0.1:51821".to_string()),
                    source_ip: Some("198.51.100.5".to_string()),
                    status: "pending".to_string(),
                    error_code: None,
                    expires_at: now_ts + 300,
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap();
        }
        *active_ack_reply.lock().unwrap() = bad_reply;
        let (st, val) = call_admin(
            &rt_b2,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        assert_ne!(st, StatusCode::OK, "case {label} should fail: {val}");
        assert_eq!(
            val["code"], expected_code,
            "case {label} produced wrong error code: {val}"
        );
        assert!(
            !runner_b2.has_peer(&pk_a2),
            "case {label} must clean up pending WG peer"
        );
    }
    mock_a_task.abort();

    // 4E. Exact exclusive expiry boundary (`now_ts == expires_at` is expired everywhere).
    let (ip_ea, ip_eb) = next_loopback_pair();
    let pk_ea = fixture_wg_pubkey(155);
    let pk_eb = fixture_wg_pubkey(156);
    let runner_ea = FakePeerRunner::new(pk_ea.clone(), ip_ea, 51821);
    let runner_eb = FakePeerRunner::new(pk_eb.clone(), ip_eb, 51821);
    let (rt_eb, _db_eb) = build_test_runtime(
        "exp-b",
        Arc::clone(&runner_eb) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_ea, _db_ea) = build_test_runtime(
        "exp-a",
        Arc::clone(&runner_ea) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_eb),
            client_ip: SocketAddr::from(([198, 51, 100, 55], 45305)),
        }),
        &clock,
        true,
    );
    let (status, win_exact) = call_admin(
        &rt_eb,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://exp-b.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pair_exact) = call_admin(
        &rt_ea,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_exact["pairing_string"].as_str().unwrap(),
            "name": "exp-b",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let exact_att = pair_exact["attempt_id"].as_str().unwrap().to_string();
    let exact_exp = pair_exact["expires_at"].as_i64().unwrap();
    let ea_port = rt_ea
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_eb
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_ea, ea_port);

    // Advance to exact `now_ts == expires_at`: BOTH hello on A and confirm on B reject with CODE_EXPIRED!
    let delta_to_exact = exact_exp - clock.epoch.load(Ordering::SeqCst);
    clock.advance(delta_to_exact);
    assert_eq!(clock.epoch.load(Ordering::SeqCst), exact_exp);

    let boot_exact_body = serde_json::to_vec(&HelloRequest {
        phase: HelloPhase::Bootstrap,
        attempt_id: exact_att.clone(),
        wg_pubkey: pk_eb.clone(),
        tunnel_ip: Some(ip_eb.to_string()),
        version: "4.0.0-test".to_string(),
        peer_protocol: 1,
        capabilities: vec!["links".to_string()],
        link_token: Some(PeerCredentialSecret::new(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string(),
        )),
    })
    .unwrap();
    let (hello_exact_st, hello_exact_bytes, _) = rt_eb
        .send_tunnel_request(
            Method::POST,
            &ip_ea.to_string(),
            "/peer/v1/hello",
            None,
            Some(boot_exact_body),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(hello_exact_st, StatusCode::GONE);
    assert_eq!(
        serde_json::from_slice::<Value>(&hello_exact_bytes).unwrap()["code"],
        "CODE_EXPIRED"
    );

    let (confirm_exact_st, confirm_exact_val) = call_admin(
        &rt_eb,
        Method::POST,
        &format!("/pairing/{exact_att}/confirm"),
        None,
    )
    .await;
    assert_eq!(confirm_exact_st, StatusCode::GONE);
    assert_eq!(confirm_exact_val["code"], "CODE_EXPIRED");

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    rt_ea.shutdown_all().await;
    rt_eb.shutdown_all().await;
}

// Blocker 5: Ownership-checked rollback/cleanup, AddPeer conflict & already-present peer tracking,
// post-AddPeer failures, old attempt cancellation vs later active link, and transient credential
// cleanup failure retaining durable ownership for retry.
#[tokio::test]
async fn rollback_cleanup_ownership_add_peer_conflict_old_cancel_and_transient_cred_failure() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(161);
    let pk_b = fixture_wg_pubkey(162);
    let clock = FakeClock::new(1_801_000_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a_unreachable, db_a_unreach) = build_test_runtime(
        "seedbox-unreach",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );

    let (status, win) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let pstr = win["pairing_string"].as_str().unwrap().to_string();

    // 5A. AddPeer Conflict (unrelated pre-existing WG peer for pk_b at a different tunnel IP):
    // start_pairing must fail WITHOUT removing the pre-existing WG peer!
    runner_a.insert_preexisting_peer(&pk_b, "127.9.9.9", "10.9.9.9:51821");
    let (st, val) = call_admin(
        &rt_a_unreachable,
        Method::POST,
        "/pair",
        Some(json!({ "pairing_string": pstr, "name": "media-2", "endpoint": "10.10.0.1" })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "expected conflict: {val}");
    assert!(
        runner_a.has_peer(&pk_b),
        "AddPeer Conflict must NEVER remove an unrelated pre-existing WireGuard peer"
    );
    assert!(db_peers::list_peer_links(&db_a_unreach.lock().unwrap())
        .unwrap()
        .is_empty());

    // 5B. Already-present matching peer + post-AddPeer failure (UnreachablePublicTransport):
    // rollback must delete the pending DB link ONLY and preserve the already-present WG peer!
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_b.clone(),
        })
        .await;
    runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.10.0.2:51821");
    let (st, val) = call_admin(
        &rt_a_unreachable,
        Method::POST,
        "/pair",
        Some(json!({ "pairing_string": pstr, "name": "media-2", "endpoint": "10.10.0.1" })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert_eq!(val["code"], "ENDPOINT_UNREACHABLE");
    assert!(
        runner_a.has_peer(&pk_b),
        "post-AddPeer rollback must NOT remove a peer that was already present before start_pairing"
    );
    assert!(db_peers::list_peer_links(&db_a_unreach.lock().unwrap())
        .unwrap()
        .is_empty());

    // Clean pre-existing peer so normal pairing creates it fresh.
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_b.clone(),
        })
        .await;
    rt_a_unreachable.shutdown_all().await;

    // 5C. Old attempt cancellation must NOT touch a later active link for the same peer!
    let (rt_a, _db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 61], 45400)),
        }),
        &clock,
        true,
    );

    // Attempt 1 created on B, cancelled on A (so Attempt 1 remains unconfirmed/pending on B).
    let (st, pair1) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({ "pairing_string": pstr, "name": "media-2", "endpoint": "10.10.0.1" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let old_attempt_id = pair1["attempt_id"].as_str().unwrap().to_string();
    let (st, _) = call_admin(
        &rt_a,
        Method::DELETE,
        &format!("/pairing/{old_attempt_id}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Attempt 2 completes full pairing and activates link between A and B.
    let (_a_link_id, b_link_id, _att2) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-2").await;
    assert!(runner_b.has_peer(&pk_a));
    let b_active_tok = runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();

    // Now cancel OLD attempt 1 on B! Active link & WG peer & LinkToken must stay 100% intact!
    let (st, _) = call_admin(
        &rt_b,
        Method::DELETE,
        &format!("/pairing/{old_attempt_id}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        db_peers::get_pairing_attempt(&db_b.lock().unwrap(), &old_attempt_id)
            .unwrap()
            .unwrap()
            .status,
        "cancelled"
    );
    assert!(
        runner_b.has_peer(&pk_a),
        "cancelling an old attempt must NEVER remove a later active link's WireGuard peer"
    );
    assert_eq!(
        runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .as_deref(),
        Some(b_active_tok.as_str())
    );
    assert_eq!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .unwrap()
            .state,
        "active"
    );

    // 5D. Transient credential cleanup failure during cancel & post-activation retains durable
    // cleanup ownership and completes cleanly on retry/sweep!
    let (st, _) = call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}"), None).await;
    assert_eq!(st, StatusCode::OK);

    let (st, win3) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair3) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win3["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let att3 = pair3["attempt_id"].as_str().unwrap().to_string();

    // Point B at closed port so confirm creates b_link + PendingIssuerToken, then fails timeout.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, closed_port);
    let (st, _) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{att3}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);

    let b_pend_link_id = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att3.as_str()))
        .unwrap()
        .id;
    let b_pend_cred_key = pending_issuer_credential_id(&b_pend_link_id);
    assert!(runner_b
        .credential(PeerCredentialSlot::PendingIssuerToken, &b_pend_cred_key)
        .is_some());

    // Inject transient failure on DeleteCredential(PendingIssuerToken) during cancel!
    runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("transient cred lock".to_string()));
    let (cancel_err_st, cancel_err_val) =
        call_admin(&rt_b, Method::DELETE, &format!("/pairing/{att3}"), None).await;
    assert_eq!(cancel_err_st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(cancel_err_val["code"], "PEER_BUSY");
    // Pending link row MUST remain durably in SQLite (with pending_expires_at = 0) and
    // PendingIssuerToken is still tracked for retry!
    let retained = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_pend_link_id)
        .unwrap()
        .expect("pending link must stay durable when credential cleanup fails");
    assert_eq!(retained.pending_expires_at, Some(0));
    assert!(runner_b
        .credential(PeerCredentialSlot::PendingIssuerToken, &b_pend_cred_key)
        .is_some());

    // Sweep (or retry) completes cleanup and deletes the row + credential!
    cleanup_expired_pending(&rt_b).await;
    assert!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_pend_link_id)
            .unwrap()
            .is_none()
    );
    assert!(runner_b
        .credential(PeerCredentialSlot::PendingIssuerToken, &b_pend_cred_key)
        .is_none());

    // Also test post-activation transient DeleteCredential failure -> sweep retries & clears!
    let (st, _) = call_admin(&rt_a, Method::DELETE, &format!("/pairing/{att3}"), None).await;
    assert_eq!(st, StatusCode::OK);
    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);
    runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("post-ack busy".to_string()));
    let (_a_lid4, b_lid4, _att4) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "media-2").await;
    let b_cred4 = pending_issuer_credential_id(&b_lid4);
    assert!(
        runner_b
            .credential(PeerCredentialSlot::PendingIssuerToken, &b_cred4)
            .is_some(),
        "transient delete failure left PendingIssuerToken present"
    );
    let b_row4 = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_lid4)
        .unwrap()
        .unwrap();
    assert_eq!(b_row4.state, "active");
    assert_eq!(
        b_row4.pending_expires_at,
        Some(0),
        "active link retains cleanup marker until PendingIssuerToken deletion succeeds"
    );
    cleanup_expired_pending(&rt_b).await;
    assert!(runner_b
        .credential(PeerCredentialSlot::PendingIssuerToken, &b_cred4)
        .is_none());
    let b_row4_cleaned = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_lid4)
        .unwrap()
        .unwrap();
    assert!(b_row4_cleaned.pending_attempt_id.is_none());
    assert!(b_row4_cleaned.pending_expires_at.is_none());

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// Blocker 6: Validate remote expiry against local bounded attempt window (reject expired replies,
// cap excessive remote expiry values).
#[tokio::test]
async fn start_pairing_rejects_expired_remote_reply_and_caps_excessive_remote_expiry() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(171);
    let pk_b = fixture_wg_pubkey(172);
    let clock = FakeClock::new(1_801_100_000);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);

    let remote_expires_slot: Arc<StdMutex<i64>> = Arc::new(StdMutex::new(0));
    let remote_att_counter = Arc::new(AtomicUsize::new(1));
    let exp_c = Arc::clone(&remote_expires_slot);
    let cnt_c = Arc::clone(&remote_att_counter);
    let pk_b_c = pk_b.clone();

    let transport = Arc::new(ControlledPublicTransport {
        responder: Arc::new(move |req| {
            let idx = cnt_c.fetch_add(1, Ordering::SeqCst);
            let resp = PublicPairingResponse {
                attempt_id: format!("remote-att-{idx}"),
                comparison_code: derive_comparison_code(&req.wg_pubkey, &pk_b_c),
                expires_at: *exp_c.lock().unwrap(),
                server_name: "remote-b".to_string(),
                version: "4.0.0-test".to_string(),
                peer_protocol: PEER_PROTOCOL_VERSION,
            };
            (StatusCode::OK, serde_json::to_vec(&resp).unwrap())
        }),
    });

    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        transport,
        &clock,
        false,
    );
    let pairing_string = PairingPayload {
        https_url: "https://remote-b.example.test".to_string(),
        wg_pubkey: pk_b.clone(),
        endpoint: "10.10.0.2".to_string(),
        wg_port: 51821,
        tunnel_ip: ip_b.to_string(),
        code: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
    }
    .encode()
    .unwrap();

    let now_ts = clock.epoch.load(Ordering::SeqCst);
    // 6A. Already-expired remote replies (both past and exact `now_ts`) are rejected & rolled back.
    for bad_exp in [now_ts - 30, now_ts] {
        *remote_expires_slot.lock().unwrap() = bad_exp;
        let (st, val) = call_admin(
            &rt_a,
            Method::POST,
            "/pair",
            Some(json!({
                "pairing_string": pairing_string,
                "name": "remote-b",
                "endpoint": "10.10.0.1"
            })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::GONE,
            "expected CODE_EXPIRED for {bad_exp}: {val}"
        );
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert!(!runner_a.has_peer(&pk_b));
        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
    }

    // 6B. Excessive remote expiry (30 days / i64::MAX) is capped to `now_ts + PAIRING_WINDOW_TTL_SECS`.
    *remote_expires_slot.lock().unwrap() = i64::MAX;
    let (st, val) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": pairing_string,
            "name": "remote-b",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "val={val}");
    let expected_cap = now_ts + PAIRING_WINDOW_TTL_SECS;
    assert_eq!(val["expires_at"].as_i64(), Some(expected_cap));
    let link_id = val["link_id"].as_str().unwrap();
    let stored = db_peers::get_peer_link(&db_a.lock().unwrap(), link_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.pending_expires_at, Some(expected_cap));
}

// Blocker 7: Unified revocation invalidation & retryable cleanup across admin, notice, and health
// `LINK_REVOKED`, plus malformed `/peer/v1/hello` denials checking source before body processing
// with safe route label and audit.
#[tokio::test]
async fn unified_revocation_cleanup_retry_health_link_revoked_and_malformed_hello_denials() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(181);
    let pk_b = fixture_wg_pubkey(182);
    let clock = FakeClock::new(1_801_200_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 71], 45500)),
        }),
        &clock,
        true,
    );

    // 7C first (while pending): malformed `/peer/v1/hello` checks source BEFORE body parsing and
    // audits with safe constant route label `"POST /peer/v1/hello"`.
    let (st, win) = call_admin(
        &rt_b,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.10.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair) = call_admin(
        &rt_a,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.10.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let a_link_id = pair["link_id"].as_str().unwrap().to_string();
    let attempt_id = pair["attempt_id"].as_str().unwrap().to_string();

    let a_listener = build_listener_router(Arc::clone(&rt_a));
    // Unknown source IP with malformed / oversized body -> 401 PEER_UNAUTHORIZED BEFORE body parsing!
    let mut unknown_malformed = Request::builder()
        .method(Method::POST)
        .uri("/peer/v1/hello")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(vec![
            b'x';
            TUNNEL_INTERNAL_BODY_LIMIT_BYTES + 100
        ]))
        .unwrap();
    unknown_malformed
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 9, 8, 7], 59000))));
    let resp_unk = a_listener.clone().oneshot(unknown_malformed).await.unwrap();
    assert_eq!(resp_unk.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp_unk.headers()[header::CACHE_CONTROL], "no-store");
    let body_unk: Value =
        serde_json::from_slice(&to_bytes(resp_unk.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body_unk["code"], "PEER_UNAUTHORIZED");

    // Known pending source IP with malformed JSON, wrong media type, and oversized body -> typed
    // no-store rejections (400, 415, 413) audited under safe route label `"POST /peer/v1/hello"`.
    for (ct, payload, expected_st, expected_code) in [
        (
            "application/json",
            b"{broken-hello-secret".to_vec(),
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
        ),
        (
            "text/plain",
            b"{}".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
        ),
        (
            "application/json",
            vec![b'y'; TUNNEL_INTERNAL_BODY_LIMIT_BYTES + 64],
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
        ),
    ] {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/peer/v1/hello")
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(payload))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip_b, 59001)));
        let resp = a_listener.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), expected_st);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let val: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(val["code"], expected_code);
        assert!(!val["message"]
            .as_str()
            .unwrap()
            .contains("broken-hello-secret"));
    }
    let a_audit_text = audit_entries_text(&db_a);
    assert!(a_audit_text.contains("POST /peer/v1/hello"));
    assert!(!a_audit_text.contains("broken-hello-secret"));

    // Finish pairing so both links are active.
    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    let b_port = rt_b
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_port);
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);
    let (st, conf) = call_admin(
        &rt_b,
        Method::POST,
        &format!("/pairing/{attempt_id}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let b_link_id = conf["link_id"].as_str().unwrap().to_string();
    let a_held_for_b = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();

    let (status, list) = call_admin(&rt_a, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    let active_view = &list["peers"][0];
    assert_eq!(active_view["id"], a_link_id);
    assert_eq!(active_view["state"], "active");
    assert!(active_view["pending_attempt_id"].is_null());
    assert!(active_view["pending_expires_at"].is_null());

    // 7A. Admin DELETE with transient runner RemovePeer failure: immediately disables incoming
    // authorization, publishes RevocationEvent, writes audit, propagates 503 PEER_BUSY while
    // retaining durable `revoking` row, and completes cleanup cleanly on sweep!
    let mut rev_rx_b = rt_b.subscribe_revocations();
    runner_b.set_next_remove_error(PeerNetworkError::Busy("wg busy".to_string()));
    // Shut down A's listener briefly so B doesn't also revoke A during this sub-test.
    rt_a.shutdown_all().await;
    let (del_err_st, del_err_val) =
        call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}"), None).await;
    assert_eq!(del_err_st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(del_err_val["code"], "PEER_BUSY");

    // Incoming auth on B is IMMEDIATELY disabled even while runner cleanup is still pending!
    let b_row_revoking = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .expect("revoking row stays durable for retry");
    assert_eq!(b_row_revoking.state, "revoking");
    assert!(b_row_revoking.inbound_token_hash.is_none());
    let (status, list) = call_admin(&rt_b, Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    let revoked_view = &list["peers"][0];
    assert_eq!(revoked_view["id"], b_link_id);
    assert_eq!(revoked_view["state"], "revoked");
    assert!(revoked_view["pending_attempt_id"].is_null());
    assert!(revoked_view["pending_expires_at"].is_null());
    assert_eq!(
        rev_rx_b.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: b_link_id.clone(),
            peer_name: "seedbox-1".to_string(),
        }
    );
    assert!(audit_entries_text(&db_b).contains("peer_link_revoked"));

    // Calling B's `/health` with A's previously valid token immediately gets 403 LINK_REVOKED!
    let (st_health_rev, body_health_rev, _) = rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(a_held_for_b.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(st_health_rev, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&body_health_rev).unwrap()["code"],
        "LINK_REVOKED"
    );

    // 7B. Health `LINK_REVOKED` on A runs unified revocation: disables inbound auth, publishes
    // RevocationEvent, records audit, emits notification, and cleans up WG peer + credentials
    // with retryable persisted cleanup when DeleteLinkCredentials fails transiently!
    let mut rev_rx_a = rt_a.subscribe_revocations();
    let a_removes = runner_a.remove_peer_call_count();
    runner_a.set_next_delete_link_creds_error(PeerNetworkError::Busy("cred busy".to_string()));
    run_health_tick(&rt_a).await;
    assert_eq!(runner_a.remove_peer_call_count(), a_removes);
    assert!(runner_a.has_peer(&pk_b));

    let a_after_health_rev = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_after_health_rev.state, "revoked");
    assert!(a_after_health_rev.inbound_token_hash.is_none());
    assert_eq!(
        a_after_health_rev.pending_expires_at,
        Some(0),
        "failed credential cleanup must retain durable retry marker on revoked link"
    );
    assert_eq!(
        rev_rx_a.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: a_link_id.clone(),
            peer_name: "media-2".to_string(),
        }
    );
    assert!(audit_entries_text(&db_a).contains("peer_link_revoked_by_remote"));
    assert!(
        runner_a
            .credential(PeerCredentialSlot::LinkToken, &a_link_id)
            .is_some(),
        "LinkToken still present prior to retry"
    );

    // Next health tick retries cleanup on A AND B: removes remaining credentials/WG peers and
    // finalizes both rows without duplicate revocation events!
    run_health_tick(&rt_a).await;
    cleanup_expired_pending(&rt_b).await;

    assert!(!runner_a.has_peer(&pk_b));
    assert!(runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .is_none());
    let a_final = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(a_final.state, "revoked_unowned");
    assert!(a_final.pending_expires_at.is_none());
    assert_eq!(runner_a.remove_peer_call_count(), a_removes + 1);

    runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.10.0.2:51821");
    let (status, _) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(runner_a.has_peer(&pk_b));
    assert_eq!(runner_a.remove_peer_call_count(), a_removes + 1);
    assert!(
        rev_rx_a.try_recv().is_err(),
        "cleanup retry must not publish duplicate RevocationEvent"
    );

    assert!(!runner_b.has_peer(&pk_a));
    assert!(runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .is_none());
    assert!(db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .is_none());

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

// Blocker 8: Fail closed on missing/unreadable/mismatched tunnel identity, enforce interface vs
// loopback fixture constraints, reuse keyed tunnel clients, and reject valid tokens presented
// from a wrong source IP (including another active peer's tunnel IP).
#[tokio::test]
async fn tunnel_binding_fails_closed_reuses_clients_and_rejects_valid_token_from_wrong_source() {
    let (ip_a, ip_b) = next_loopback_pair();
    let (ip_c, ip_wrong) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(191);
    let pk_b = fixture_wg_pubkey(192);
    let pk_c = fixture_wg_pubkey(193);
    let clock = FakeClock::new(1_801_300_000);

    // Count actual HTTP hits on ip_b to verify fail-closed checks NEVER transmit requests/tokens.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = Arc::clone(&hits);
    let probe_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_b, 0))
        .await
        .unwrap();
    let probe_port = probe_listener.local_addr().unwrap().port();
    let probe_task = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move || {
                let h = Arc::clone(&hits_c);
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, axum::Json(json!({ "status": "ok" })))
                }
            }),
        );
        let _ = axum::serve(probe_listener, app).await;
    });

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let (rt_a, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, probe_port);

    let secret = PeerCredentialSecret::new(
        "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
    );

    // 8A-1. Missing identity -> fails closed, zero hits.
    assert!(rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // 8A-2. Unreadable tunnel IP in DB -> fails closed, zero hits.
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: "not-a-valid-ip".to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    assert!(rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // 8A-3. Address-family mismatch (::1 local vs IPv4 dest) -> fails closed, zero hits.
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: "::1".to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    assert!(rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // 8A-4. Non-loopback identity or destination rejected in LoopbackFixture mode -> fails closed.
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: "10.231.0.1".to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    assert!(rt_a
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // 8A-5. Production WireGuardInterface mode refuses loopback addresses and nonexistent device!
    let (rt_prod_mode, db_prod_mode) = build_test_runtime_with_binding(
        "prod-mode",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::WireGuardInterface("afpeer-missing0".to_string()),
    );
    {
        let conn = db_prod_mode.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: ip_a.to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    assert!(rt_prod_mode
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // Inbound listener binding guards:
    assert!(
        spawn_tunnel_listener(
            Arc::clone(&rt_a),
            IpAddr::V4(Ipv4Addr::new(10, 231, 0, 1)),
            0,
            None
        )
        .await
        .is_err(),
        "unbound non-loopback listener must be rejected"
    );
    assert!(
        spawn_tunnel_listener(Arc::clone(&rt_prod_mode), ip_a, 0, Some("afpeer0"))
            .await
            .is_err(),
        "device-bound loopback listener must be rejected"
    );
    assert!(
        spawn_tunnel_listener(
            Arc::clone(&rt_prod_mode),
            IpAddr::V4(Ipv4Addr::new(10, 231, 0, 1)),
            0,
            Some("afpeer-missing0"),
        )
        .await
        .is_err(),
        "binding to a missing WireGuard interface must fail closed"
    );

    // 8A-6. Unreadable identity table (SQLite error) -> fails closed, zero hits.
    {
        let conn = db_prod_mode.lock().unwrap();
        conn.execute("DROP TABLE peer_identity", []).unwrap();
    }
    assert!(rt_prod_mode
        .send_tunnel_request(
            Method::GET,
            "10.231.0.2",
            "/health",
            Some(&secret),
            None,
            Duration::from_secs(2),
        )
        .await
        .is_err());

    // 8B. Valid local binding succeeds and reuses a single cached tunnel client across calls.
    {
        let conn = db_a.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: ip_a.to_string(),
                wg_port: 51821,
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
    }
    for _ in 0..3 {
        let (st, _, _) = rt_a
            .send_tunnel_request(
                Method::GET,
                &ip_b.to_string(),
                "/health",
                Some(&secret),
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(st, StatusCode::OK);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    assert_eq!(
        rt_a.tunnel_clients.lock().unwrap().len(),
        1,
        "valid tunnel binding must reuse a single cached reqwest client"
    );

    // 8C. Valid-token wrong-source checks (both unknown source IP and another active peer's IP).
    let tok_b = "6666666666666666666666666666666666666666666666666666666666666666";
    let tok_c = "7777777777777777777777777777777777777777777777777777777777777777";
    {
        let conn = db_a.lock().unwrap();
        for (id, name, pk, tip, tok) in [
            ("src-link-b", "peer-b", &pk_b, ip_b, tok_b),
            ("src-link-c", "peer-c", &pk_c, ip_c, tok_c),
        ] {
            db_peers::insert_peer_link(
                &conn,
                &PeerLink {
                    id: id.to_string(),
                    name: name.to_string(),
                    wg_pubkey: pk.clone(),
                    tunnel_ip: tip.to_string(),
                    endpoint: "10.10.0.2".to_string(),
                    wg_port: 51821,
                    state: "active".to_string(),
                    peer_version: Some("4.0.0".to_string()),
                    peer_protocol: Some(1),
                    capabilities: Some(r#"["links"]"#.to_string()),
                    rtt_ms: None,
                    last_ok_at: None,
                    last_error: None,
                    consecutive_failures: 0,
                    inbound_token_hash: Some(super::pairing::sha256_prefixed(tok)),
                    pending_attempt_id: None,
                    pending_expires_at: None,
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: Utc::now().to_rfc3339(),
                },
            )
            .unwrap();
        }
    }

    let listener = build_listener_router(Arc::clone(&rt_a));
    // Valid token for peer-b presented from BOTH an unknown IP (`ip_wrong`) AND another active
    // peer's IP (`ip_c`) must fail closed on every active tunnel route!
    for wrong_source in [ip_wrong, ip_c] {
        for (method, path) in [
            (Method::GET, "/health"),
            (Method::GET, "/peer/v1/link"),
            (Method::POST, "/peer/v1/revoke-notice"),
        ] {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header(super::HEADER_LINK_TOKEN, tok_b)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(wrong_source, 58000)));
            let resp = listener.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "valid token from wrong source {wrong_source} on {path} must fail with 401"
            );
            let body: Value =
                serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
            assert_eq!(body["code"], "PEER_UNAUTHORIZED");
        }
    }
    // Matching source + matching token still succeeds.
    let mut good_req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header(super::HEADER_LINK_TOKEN, tok_b)
        .body(Body::empty())
        .unwrap();
    good_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip_b, 58001)));
    let good_resp = listener.oneshot(good_req).await.unwrap();
    assert_eq!(good_resp.status(), StatusCode::OK);

    probe_task.abort();
}

// ─────────────────────────────────────────────────────────────────────────────
// NEW-02 & NEW-03 Regressions: Durable Affirmative WG Ownership & Start Rollback
// ─────────────────────────────────────────────────────────────────────────────

type BarrierTransportReply = Result<(StatusCode, Vec<u8>), String>;

struct BarrierPublicTransport {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    response: Arc<StdMutex<BarrierTransportReply>>,
}

impl PublicPairingTransport for BarrierPublicTransport {
    fn post_pairing_request<'a>(
        &'a self,
        url: Url,
        _body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        let response = Arc::clone(&self.response);
        Box::pin(async move {
            if url.scheme() != "https" {
                return Err("Public pairing requires https://".to_string());
            }
            entered.notify_one();
            release.notified().await;
            response.lock().unwrap().clone()
        })
    }
}

/// NEW-02(a): A fresh `PeerRuntime` over the same DB and runner (process restart) preserves
/// preexisting WireGuard peers across pending cancel, pending expiry sweep, and even full
/// activation -> health down/active -> remote & admin revocation, without leaking internal
/// ownership states in admin or tunnel JSON, while still cleaning up legitimately owned peers.
#[tokio::test]
async fn durable_wg_ownership_preserves_preexisting_peer_across_restart_and_full_lifecycle() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(201);
    let pk_b = fixture_wg_pubkey(202);
    let clock = FakeClock::new(1_802_000_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b1, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a1, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b1),
            client_ip: SocketAddr::from(([198, 51, 100, 81], 45600)),
        }),
        &clock,
        true,
    );

    // Pre-seed matching independently configured WG peers on BOTH A and B.
    runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.20.0.2:51821");
    runner_b.insert_preexisting_peer(&pk_a, &ip_a.to_string(), "10.20.0.1:51821");

    // 1. Initiator cancel after fresh PeerRuntime restart preserves preexisting WG peer.
    let (st, win1) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair1) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win1["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let a_link1 = pair1["link_id"].as_str().unwrap().to_string();
    let att1 = pair1["attempt_id"].as_str().unwrap().to_string();
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link1)
            .unwrap()
            .unwrap()
            .state,
        "pending",
        "reconciled preexisting WG peer must remain unowned ('pending')"
    );

    // Simulate process restart on A: brand-new PeerRuntime over the exact same DB and runner.
    let rt_a_restarted = build_test_runtime_with_db_and_timeout(
        "seedbox-1",
        Arc::clone(&db_a),
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    let (st, _) = call_admin(
        &rt_a_restarted,
        Method::DELETE,
        &format!("/pairing/{att1}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link1)
        .unwrap()
        .is_none());
    assert!(
        runner_a.has_peer(&pk_b),
        "fresh PeerRuntime cancel must preserve preexisting WG peer"
    );
    assert_eq!(runner_a.remove_peer_call_count(), 0);

    // 2. Initiator expiry sweep AND responder cancel/sweep after fresh PeerRuntime restart both
    // preserve preexisting WG peers.
    let (st, win2) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair2) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win2["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let a_link2 = pair2["link_id"].as_str().unwrap().to_string();
    let att2 = pair2["attempt_id"].as_str().unwrap().to_string();

    // Point B at closed port so confirm reserves b_link2, reconciles preexisting pk_a (stays
    // unowned `pending`), writes PendingIssuerToken, and stops at HANDSHAKE_TIMEOUT.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    rt_b1
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, closed_port);
    let (st, _) = call_admin(
        &rt_b1,
        Method::POST,
        &format!("/pairing/{att2}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);
    let b_link2 = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att2.as_str()))
        .unwrap()
        .id;
    assert_eq!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link2)
            .unwrap()
            .unwrap()
            .state,
        "pending"
    );

    // Restart BOTH runtimes, advance past expiry, and sweep!
    clock.advance(PAIRING_WINDOW_TTL_SECS + 5);
    let rt_a_sweep = build_test_runtime_with_db_and_timeout(
        "seedbox-1",
        Arc::clone(&db_a),
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    let rt_b_sweep = build_test_runtime_with_db_and_timeout(
        "media-2",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    cleanup_expired_pending(&rt_a_sweep).await;
    cleanup_expired_pending(&rt_b_sweep).await;

    assert!(db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link2)
        .unwrap()
        .is_none());
    assert!(db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link2)
        .unwrap()
        .is_none());
    assert!(runner_b
        .credential(
            PeerCredentialSlot::PendingIssuerToken,
            &pending_issuer_credential_id(&b_link2),
        )
        .is_none());
    assert!(
        runner_a.has_peer(&pk_b) && runner_b.has_peer(&pk_a),
        "fresh PeerRuntime expiry sweep must preserve preexisting WG peers on both sides"
    );
    assert_eq!(runner_a.remove_peer_call_count(), 0);
    assert_eq!(runner_b.remove_peer_call_count(), 0);

    // 3. Preexisting WG peer completes pairing -> active_unowned <-> down_unowned -> restart ->
    // admin DELETE on B + remote revoke-notice on A preserves preexisting WG peers on BOTH sides,
    // keeps revocation/auth semantics intact, and never exposes internal states via JSON!
    let (a_link3, b_link3, _att3) =
        pair_two_test_runtimes(&rt_a1, &rt_b1, ip_a, ip_b, "media-2").await;
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link3)
            .unwrap()
            .unwrap()
            .state,
        "active_unowned"
    );
    assert_eq!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link3)
            .unwrap()
            .unwrap()
            .state,
        "active_unowned"
    );

    // Admin JSON and tunnel /peer/v1/link must project public "active", never "active_unowned".
    let (st, list_a) = call_admin(&rt_a1, Method::GET, "/", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_a["peers"][0]["state"], "active");

    let a_held_tok = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link3)
        .unwrap();
    let (st_link, body_link, _) = rt_a1
        .send_tunnel_request(
            Method::GET,
            &ip_b.to_string(),
            "/peer/v1/link",
            Some(&PeerCredentialSecret::new(a_held_tok.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(st_link, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body_link).unwrap()["state"],
        "active"
    );

    // Health down -> active transitions preserve the unowned marker and project public states.
    runner_a.set_peer_live_state(&pk_b, false, None);
    run_health_tick(&rt_a1).await;
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link3)
            .unwrap()
            .unwrap()
            .state,
        "down_unowned"
    );
    let (_, list_a_down) = call_admin(&rt_a1, Method::GET, "/", None).await;
    assert_eq!(list_a_down["peers"][0]["state"], "down");

    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    run_health_tick(&rt_a1).await;
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link3)
            .unwrap()
            .unwrap()
            .state,
        "active_unowned"
    );

    // Restart B into a fresh PeerRuntime over same DB & runner, pointing at A's live listener,
    // and revoke via admin DELETE.
    let a_port = rt_a1
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    let rt_b2 = build_test_runtime_with_db_and_timeout(
        "media-2",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    rt_b2
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);
    let mut rev_rx_a = rt_a1.subscribe_revocations();
    let mut rev_rx_b = rt_b2.subscribe_revocations();

    let (del_st, del_val) = call_admin(&rt_b2, Method::DELETE, &format!("/{b_link3}"), None).await;
    assert_eq!(del_st, StatusCode::OK, "del_val={del_val}");
    assert_eq!(del_val["revoked"], true);
    assert_eq!(del_val["notice_delivered"], true);

    // Both sides invalidated auth, removed credentials, published RevocationEvent, normalized JSON,
    // and PRESERVED the preexisting WG peers (zero RemovePeer calls)!
    assert!(db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link3)
        .unwrap()
        .is_none());
    assert!(runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link3)
        .is_none());
    assert!(runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link3)
        .is_none());
    let a_rev = db_peers::get_peer_link(&db_a.lock().unwrap(), &a_link3)
        .unwrap()
        .unwrap();
    assert_eq!(a_rev.state, "revoked_unowned");
    assert!(a_rev.inbound_token_hash.is_none());
    assert!(a_rev.pending_expires_at.is_none());
    let (_, list_a_rev) = call_admin(&rt_a1, Method::GET, "/", None).await;
    assert_eq!(list_a_rev["peers"][0]["state"], "revoked");
    assert_eq!(
        rev_rx_a.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: a_link3.clone(),
            peer_name: "media-2".to_string(),
        }
    );
    assert_eq!(
        rev_rx_b.try_recv().unwrap(),
        RevocationEvent::LinkRevoked {
            link_id: b_link3.clone(),
            peer_name: "seedbox-1".to_string(),
        }
    );
    assert!(
        runner_a.has_peer(&pk_b) && runner_b.has_peer(&pk_a),
        "revoking an unowned link must preserve preexisting WG peers even after restart"
    );
    assert_eq!(runner_a.remove_peer_call_count(), 0);
    assert_eq!(runner_b.remove_peer_call_count(), 0);

    // 4. Legitimate OWNED cleanup across restart: remove preexisting peers so AddPeer definitively
    // creates owned peers (`pending_owned` -> `active`), then verify BOTH pending cancel/sweep and
    // active revocation on a restarted PeerRuntime DO remove the owned WG peers!
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_b.clone(),
        })
        .await;
    let _ = runner_b
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_a.clone(),
        })
        .await;

    let (st, win4) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair4) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win4["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let a_owned_pend = pair4["link_id"].as_str().unwrap().to_string();
    let att4 = pair4["attempt_id"].as_str().unwrap().to_string();
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_owned_pend)
            .unwrap()
            .unwrap()
            .state,
        "pending_owned"
    );
    // Admin JSON must hide `pending_owned` and project `"pending"`.
    let (_, list_owned_pend) = call_admin(&rt_a1, Method::GET, "/", None).await;
    assert_eq!(list_owned_pend["peers"][0]["state"], "pending");

    // Restart A and cancel owned pending link -> MUST remove owned WG peer!
    let rt_a_cancel_owned = build_test_runtime_with_db_and_timeout(
        "seedbox-1",
        Arc::clone(&db_a),
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    let (st, _) = call_admin(
        &rt_a_cancel_owned,
        Method::DELETE,
        &format!("/pairing/{att4}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !runner_a.has_peer(&pk_b),
        "restarted runtime MUST remove legitimately owned pending WG peer on cancel"
    );

    // Pair cleanly into owned `active` links, restart B, and DELETE -> removes owned WG peers!
    let (a_owned_act, b_owned_act, _) =
        pair_two_test_runtimes(&rt_a1, &rt_b1, ip_a, ip_b, "media-2").await;
    assert_eq!(
        db_peers::get_peer_link(&db_a.lock().unwrap(), &a_owned_act)
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    assert_eq!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_owned_act)
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    let rt_b_rev_owned = build_test_runtime_with_db_and_timeout(
        "media-2",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    rt_b_rev_owned
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);
    let (st, _) = call_admin(
        &rt_b_rev_owned,
        Method::DELETE,
        &format!("/{b_owned_act}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !runner_b.has_peer(&pk_a) && !runner_a.has_peer(&pk_b),
        "restarted revocation MUST remove legitimately owned WG peers on both sides"
    );

    rt_a1.shutdown_all().await;
    rt_b1.shutdown_all().await;
}

/// NEW-02(b): `AddPeer` conflict (`Conflict` / `TunnelIpConflict`) or ambiguous failure combined
/// with transient credential-delete contention (`Busy`) preserves the unrelated conflicting WG
/// peer on BOTH immediate in-process retry AND after a fresh `PeerRuntime` restart, while still
/// cleaning up the pending DB row and temporary credentials.
#[tokio::test]
async fn add_peer_conflict_with_transient_credential_delete_contention_preserves_peer_on_retry_and_restart(
) {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(211);
    let pk_b = fixture_wg_pubkey(212);
    let pk_other = fixture_wg_pubkey(213);
    let clock = FakeClock::new(1_802_100_000);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b1, db_b) = build_test_runtime(
        "media-2",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a1, db_a) = build_test_runtime(
        "seedbox-1",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b1),
            client_ip: SocketAddr::from(([198, 51, 100, 82], 45610)),
        }),
        &clock,
        true,
    );

    // 1. Responder confirm: AddPeer Conflict (unrelated WG peer using pk_a at 127.9.9.9) +
    // transient DeleteCredential(PendingIssuerToken) Busy -> immediate in-process retry preserves
    // the conflicting WG peer!
    runner_b.insert_preexisting_peer(&pk_a, "127.9.9.9", "10.9.9.9:51821");

    let (st, win1) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair1) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win1["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let att1 = pair1["attempt_id"].as_str().unwrap().to_string();

    runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("cred lock contended".to_string()));
    let (st, val) = call_admin(
        &rt_b1,
        Method::POST,
        &format!("/pairing/{att1}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "expected Conflict -> 409: {val}");
    assert_eq!(val["code"], "KEY_MISMATCH");

    let retained_b1 = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att1.as_str()))
        .expect("pending row stays durable after transient credential delete failure");
    assert_eq!(retained_b1.state, "pending");
    assert_eq!(retained_b1.pending_expires_at, Some(0));
    assert!(runner_b.has_peer(&pk_a));
    assert_eq!(runner_b.remove_peer_call_count(), 0);

    // Immediate in-process retry via sweep must delete pending row & PendingIssuerToken WITHOUT
    // removing the unrelated conflicting WG peer!
    cleanup_expired_pending(&rt_b1).await;
    assert!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &retained_b1.id)
            .unwrap()
            .is_none()
    );
    assert!(runner_b
        .credential(
            PeerCredentialSlot::PendingIssuerToken,
            &pending_issuer_credential_id(&retained_b1.id),
        )
        .is_none());
    assert!(
        runner_b.has_peer(&pk_a),
        "immediate retry after AddPeer Conflict + cred busy must preserve unrelated conflicting WG peer"
    );
    assert_eq!(runner_b.remove_peer_call_count(), 0);

    // Clean up A's pending attempt1.
    let (st, _) = call_admin(&rt_a1, Method::DELETE, &format!("/pairing/{att1}"), None).await;
    assert_eq!(st, StatusCode::OK);

    // 2. Same scenario (AddPeer TunnelIpConflict + transient DeleteCredential Busy) followed by a
    // fresh PeerRuntime RESTART over the same DB & runner!
    let _ = runner_b
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_a.clone(),
        })
        .await;
    let base_b_removes = runner_b.remove_peer_call_count();
    runner_b.insert_preexisting_peer(&pk_other, &ip_a.to_string(), "10.9.9.10:51821");

    let (st, win2) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair2) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win2["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let att2 = pair2["attempt_id"].as_str().unwrap().to_string();

    runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("cred busy restart".to_string()));
    let (st, val) = call_admin(
        &rt_b1,
        Method::POST,
        &format!("/pairing/{att2}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "expected TunnelIpConflict: {val}");
    assert_eq!(val["code"], "TUNNEL_IP_CONFLICT");

    let retained_b2 = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att2.as_str()))
        .expect("pending row stays durable for restart retry");
    assert_eq!(retained_b2.state, "pending");
    assert_eq!(retained_b2.pending_expires_at, Some(0));

    let rt_b_restarted = build_test_runtime_with_db_and_timeout(
        "media-2",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    cleanup_expired_pending(&rt_b_restarted).await;
    assert!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &retained_b2.id)
            .unwrap()
            .is_none()
    );
    assert!(runner_b
        .credential(
            PeerCredentialSlot::PendingIssuerToken,
            &pending_issuer_credential_id(&retained_b2.id),
        )
        .is_none());
    assert!(
        runner_b.has_peer(&pk_other),
        "restarted PeerRuntime retry must preserve unrelated conflicting WG peer"
    );
    assert_eq!(runner_b.remove_peer_call_count(), base_b_removes);

    let (st, _) = call_admin(&rt_a1, Method::DELETE, &format!("/pairing/{att2}"), None).await;
    assert_eq!(st, StatusCode::OK);

    // 3. Initiator `start_pairing` AddPeer Conflict + transient DeleteLinkCredentials Busy ->
    // preserves unrelated conflicting WG peer on BOTH immediate retry AND fresh PeerRuntime restart!
    runner_a.insert_preexisting_peer(&pk_b, "127.9.9.8", "10.9.9.8:51821");
    let base_a_removes = runner_a.remove_peer_call_count();

    for use_restart in [false, true] {
        let (st, win) = call_admin(
            &rt_b1,
            Method::POST,
            "/pairing-window",
            Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        runner_a
            .set_next_delete_link_creds_error(PeerNetworkError::Busy("link cred busy".to_string()));
        let (st, val) = call_admin(
            &rt_a1,
            Method::POST,
            "/pair",
            Some(json!({
                "pairing_string": win["pairing_string"].as_str().unwrap(),
                "name": "media-2",
                "endpoint": "10.20.0.1"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT, "val={val}");
        assert_eq!(val["code"], "KEY_MISMATCH");

        let retained = db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .into_iter()
            .next()
            .expect("pending link row stays durable on transient credential delete failure");
        assert_eq!(retained.state, "pending");
        assert_eq!(retained.pending_expires_at, Some(0));

        if use_restart {
            let rt_a_restarted = build_test_runtime_with_db_and_timeout(
                "seedbox-1",
                Arc::clone(&db_a),
                Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
                Arc::new(UnreachablePublicTransport),
                &clock,
                false,
                TunnelTransportBinding::LoopbackFixture,
                PEER_LOCK_WAIT_TIMEOUT,
            );
            cleanup_expired_pending(&rt_a_restarted).await;
        } else {
            cleanup_expired_pending(&rt_a1).await;
        }

        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
        assert!(
            runner_a.has_peer(&pk_b),
            "initiator retry (restart={use_restart}) must preserve conflicting WG peer"
        );
        assert_eq!(runner_a.remove_peer_call_count(), base_a_removes);
    }

    // 4. Confirm retry of a previously owned (`pending_owned`) attempt whose WireGuard peer was
    // externally replaced with a conflicting tunnel IP + transient DeleteCredential Busy:
    // confirm MUST durably demote `pending_owned` -> `pending` and preserve the conflicting WG
    // peer across both immediate retry and fresh PeerRuntime restart!
    let _ = runner_a
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_b.clone(),
        })
        .await;
    let _ = runner_b
        .dispatch(&PeerNetworkRequest::RemovePeer {
            pubkey: pk_other.clone(),
        })
        .await;
    let (st, win_demote) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, pair_demote) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_demote["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let att_demote = pair_demote["attempt_id"].as_str().unwrap().to_string();

    // First confirm succeeds AddPeer -> `pending_owned`, then times out on closed port.
    let closed_d = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_d_port = closed_d.local_addr().unwrap().port();
    drop(closed_d);
    rt_b1
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, closed_d_port);
    let (st, _) = call_admin(
        &rt_b1,
        Method::POST,
        &format!("/pairing/{att_demote}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);
    let b_demote_link = db_peers::list_peer_links(&db_b.lock().unwrap())
        .unwrap()
        .into_iter()
        .find(|l| l.pending_attempt_id.as_deref() == Some(att_demote.as_str()))
        .unwrap();
    assert_eq!(b_demote_link.state, "pending_owned");

    // Simulate an external operator replacing pk_a on afpeer0 with a conflicting tunnel IP!
    runner_b.insert_preexisting_peer(&pk_a, "127.9.9.11", "10.9.9.11:51821");
    let base_b_demote_removes = runner_b.remove_peer_call_count();
    runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("demote cred busy".to_string()));
    let (st, val) = call_admin(
        &rt_b1,
        Method::POST,
        &format!("/pairing/{att_demote}/confirm"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "val={val}");
    let retained_demote = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_demote_link.id)
        .unwrap()
        .expect("demoted row stays durable on transient credential delete failure");
    assert_eq!(
        retained_demote.state, "pending",
        "conflict on retry must durably demote pending_owned -> pending"
    );
    assert_eq!(retained_demote.pending_expires_at, Some(0));

    let rt_b_demote_restart = build_test_runtime_with_db_and_timeout(
        "media-2",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    cleanup_expired_pending(&rt_b_demote_restart).await;
    assert!(
        db_peers::get_peer_link(&db_b.lock().unwrap(), &b_demote_link.id)
            .unwrap()
            .is_none()
    );
    assert!(
        runner_b.has_peer(&pk_a),
        "restarted sweep after demotion must preserve externally replaced conflicting WG peer"
    );
    assert_eq!(runner_b.remove_peer_call_count(), base_b_demote_removes);

    let (st, _) = call_admin(
        &rt_a1,
        Method::DELETE,
        &format!("/pairing/{att_demote}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 5. Uncertain AddPeer outcome (ambiguous Runtime error) never promotes ownership and
    // preserves WG state even if the peer exists on afpeer0.
    runner_a.insert_preexisting_peer(&pk_b, "127.9.9.8", "10.9.9.8:51821");
    let base_a_uncertain_removes = runner_a.remove_peer_call_count();
    let (st, win_uncertain) = call_admin(
        &rt_b1,
        Method::POST,
        "/pairing-window",
        Some(json!({ "https_url": "https://media-2.example.test", "endpoint": "10.20.0.2" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    runner_a.set_next_add_error(PeerNetworkError::Runtime(
        "runner transport dropped after wg apply".to_string(),
    ));
    let (st, val) = call_admin(
        &rt_a1,
        Method::POST,
        "/pair",
        Some(json!({
            "pairing_string": win_uncertain["pairing_string"].as_str().unwrap(),
            "name": "media-2",
            "endpoint": "10.20.0.1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "val={val}");
    assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
        .unwrap()
        .is_empty());
    assert!(
        runner_a.has_peer(&pk_b),
        "uncertain AddPeer error must fail safe and preserve WG peer"
    );
    assert_eq!(runner_a.remove_peer_call_count(), base_a_uncertain_removes);

    rt_a1.shutdown_all().await;
    rt_b1.shutdown_all().await;
}

/// NEW-03: Bounded deterministic fixtures proving lock contention in `start_pairing_inner` at
/// BOTH Stage 1 (initial link lock taken before row reservation) and Stage 2 (attempt_lock and
/// link_lock contention after pending row insertion + successful AddPeer) never bypass rollback
/// or leave a 10-minute normal-TTL orphan.
#[tokio::test]
async fn start_pairing_lock_contention_after_both_stages_rolls_back_or_marks_zero_expiry() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(221);
    let pk_b = fixture_wg_pubkey(222);
    let clock = FakeClock::new(1_802_200_000);
    let short_timeout = Duration::from_millis(60);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let pairing_string = PairingPayload {
        https_url: "https://media-2.example.test".to_string(),
        wg_pubkey: pk_b.clone(),
        endpoint: "10.30.0.2".to_string(),
        wg_port: 51821,
        tunnel_ip: ip_b.to_string(),
        code: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
    }
    .encode()
    .unwrap();

    // ── Stage 1: Initial link_lock contention (taken BEFORE reserving pending row) ──────────
    let db_a = open_isolated_peer_db();
    let rt_stage1 = build_test_runtime_with_db_and_timeout(
        "seedbox-1",
        Arc::clone(&db_a),
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        short_timeout,
    );
    let fixed_link_id = "stage1-contended-link".to_string();
    let held_stage1 = rt_stage1
        .lock_link(&fixed_link_id, "test_stage1_contention")
        .await
        .unwrap();
    let err = start_pairing_with_link_id(
        &rt_stage1,
        &admin_user(),
        None,
        &axum::http::HeaderMap::new(),
        StartPairingReq {
            pairing_string: pairing_string.clone(),
            name: Some("media-2".to_string()),
            endpoint: Some("10.30.0.1".to_string()),
            local_name: None,
        },
        fixed_link_id.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.code(), "PEER_BUSY");
    assert!(
        db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty(),
        "Stage 1 lock contention before reservation must leave ZERO pending DB rows"
    );
    assert_eq!(
        runner_a.add_peer_call_count(),
        0,
        "Stage 1 lock contention must not invoke AddPeer"
    );
    assert!(!runner_a.has_peer(&pk_b));
    drop(held_stage1);

    // ── Stage 2A: Attempt-lock contention AFTER pending row insertion + AddPeer ─────────────
    let comparison_code = derive_comparison_code(&pk_a, &pk_b);
    let now_ts = clock.epoch.load(Ordering::SeqCst);
    let make_ok_reply = |attempt_id: &str| {
        let resp = PublicPairingResponse {
            attempt_id: attempt_id.to_string(),
            comparison_code: comparison_code.clone(),
            expires_at: now_ts + PAIRING_WINDOW_TTL_SECS,
            server_name: "media-2".to_string(),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
        };
        Ok((StatusCode::OK, serde_json::to_vec(&resp).unwrap()))
    };

    for preexisting in [false, true] {
        if preexisting {
            runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.30.0.2:51821");
        } else {
            let _ = runner_a
                .dispatch(&PeerNetworkRequest::RemovePeer {
                    pubkey: pk_b.clone(),
                })
                .await;
        }
        let removes_before = runner_a.remove_peer_call_count();

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let att_id = if preexisting {
            "stage2a-contended-preexisting"
        } else {
            "stage2a-contended-owned"
        };
        let transport = Arc::new(BarrierPublicTransport {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            response: Arc::new(StdMutex::new(make_ok_reply(att_id))),
        });
        let rt = build_test_runtime_with_db_and_timeout(
            "seedbox-1",
            Arc::clone(&db_a),
            Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
            transport,
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            short_timeout,
        );

        let held_att = rt
            .lock_attempt(att_id, "test_stage2a_attempt_contention")
            .await
            .unwrap();
        let rt_call = Arc::clone(&rt);
        let pstr_c = pairing_string.clone();
        let handle = tokio::spawn(async move {
            call_admin(
                &rt_call,
                Method::POST,
                "/pair",
                Some(json!({
                    "pairing_string": pstr_c,
                    "name": "media-2",
                    "endpoint": "10.30.0.1"
                })),
            )
            .await
        });

        // Wait until Stage 1 (DB reservation + AddPeer) has completed and outbound HTTPS began.
        entered.notified().await;
        let expected_state = if preexisting {
            "pending"
        } else {
            "pending_owned"
        };
        assert_eq!(
            db_peers::list_peer_links(&db_a.lock().unwrap()).unwrap()[0].state,
            expected_state
        );
        release.notify_one();

        let (st, val) = handle.await.unwrap();
        drop(held_att);

        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "val={val}");
        assert_eq!(val["code"], "PEER_BUSY");
        assert!(
            db_peers::list_peer_links(&db_a.lock().unwrap())
                .unwrap()
                .is_empty(),
            "Stage 2A attempt_lock contention must roll back pending DB row immediately"
        );
        if preexisting {
            assert!(
                runner_a.has_peer(&pk_b),
                "Stage 2A rollback must preserve preexisting WG peer"
            );
            assert_eq!(runner_a.remove_peer_call_count(), removes_before);
        } else {
            assert!(
                !runner_a.has_peer(&pk_b),
                "Stage 2A rollback must remove owned WG peer"
            );
            assert_eq!(runner_a.remove_peer_call_count(), removes_before + 1);
        }
    }

    // ── Stage 2B: Link-lock contention AFTER pending row insertion + AddPeer ────────────────
    // Verifies BOTH Stage 2 commit contention AND post-AddPeer transport failure under link_lock
    // contention immediately persist guarded zero-expiry cleanup (no 10-minute normal TTL orphan)
    // and clean up on bounded retry once the contender releases the lock.
    for (preexisting, transport_fails) in [(false, false), (true, false), (false, true)] {
        if preexisting {
            runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.30.0.2:51821");
        } else {
            let _ = runner_a
                .dispatch(&PeerNetworkRequest::RemovePeer {
                    pubkey: pk_b.clone(),
                })
                .await;
        }
        let removes_before = runner_a.remove_peer_call_count();

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let reply = if transport_fails {
            Err("simulated HTTPS failure under link lock contention".to_string())
        } else {
            make_ok_reply(if preexisting {
                "stage2b-link-contended-preexisting"
            } else {
                "stage2b-link-contended-owned"
            })
        };
        let transport = Arc::new(BarrierPublicTransport {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            response: Arc::new(StdMutex::new(reply)),
        });
        let rt = build_test_runtime_with_db_and_timeout(
            "seedbox-1",
            Arc::clone(&db_a),
            Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
            transport,
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            short_timeout,
        );

        let rt_call = Arc::clone(&rt);
        let pstr_c = pairing_string.clone();
        let handle = tokio::spawn(async move {
            call_admin(
                &rt_call,
                Method::POST,
                "/pair",
                Some(json!({
                    "pairing_string": pstr_c,
                    "name": "media-2",
                    "endpoint": "10.30.0.1"
                })),
            )
            .await
        });

        // After Stage 1 releases initial link_lock and starts HTTPS, contend on that exact link_id.
        entered.notified().await;
        let in_flight = db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .into_iter()
            .next()
            .expect("pending link reserved in Stage 1");
        let held_link = rt
            .lock_link(&in_flight.id, "test_stage2b_link_contention")
            .await
            .unwrap();
        release.notify_one();

        let (st, val) = handle.await.unwrap();
        if transport_fails {
            assert_eq!(st, StatusCode::BAD_GATEWAY, "val={val}");
            assert_eq!(val["code"], "ENDPOINT_UNREACHABLE");
        } else {
            assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "val={val}");
            assert_eq!(val["code"], "PEER_BUSY");
        }

        // While link_lock is still held, row MUST already have guarded zero-expiry (`Some(0)`),
        // NEVER the 10-minute normal TTL, preserving its durable ownership state!
        let deferred = db_peers::get_peer_link(&db_a.lock().unwrap(), &in_flight.id)
            .unwrap()
            .expect("deferred cleanup row must stay durable while link_lock is held");
        assert_eq!(
            deferred.pending_expires_at,
            Some(0),
            "contended rollback must immediately persist zero-expiry cleanup marker (no 10-min TTL orphan)"
        );
        assert_eq!(
            deferred.state,
            if preexisting {
                "pending"
            } else {
                "pending_owned"
            }
        );
        // Admin JSON must hide the internal retry marker and internal ownership state.
        let (list_st, list_val) = call_admin(&rt, Method::GET, "/", None).await;
        assert_eq!(list_st, StatusCode::OK);
        assert_eq!(list_val["peers"][0]["state"], "pending");
        assert!(list_val["peers"][0]["pending_attempt_id"].is_null());
        assert!(list_val["peers"][0]["pending_expires_at"].is_null());

        // Release contender lock and run sweep WITHOUT advancing the clock (also testing a fresh
        // restarted PeerRuntime for the preexisting case): zero-expiry row cleans up immediately!
        drop(held_link);
        if preexisting {
            let rt_restarted = build_test_runtime_with_db_and_timeout(
                "seedbox-1",
                Arc::clone(&db_a),
                Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
                Arc::new(UnreachablePublicTransport),
                &clock,
                false,
                TunnelTransportBinding::LoopbackFixture,
                short_timeout,
            );
            cleanup_expired_pending(&rt_restarted).await;
        } else {
            cleanup_expired_pending(&rt).await;
        }

        assert!(
            db_peers::list_peer_links(&db_a.lock().unwrap())
                .unwrap()
                .is_empty(),
            "zero-expiry deferred rollback must clear immediately on sweep without clock advance"
        );
        if preexisting {
            assert!(runner_a.has_peer(&pk_b));
            assert_eq!(runner_a.remove_peer_call_count(), removes_before);
        } else {
            assert!(!runner_a.has_peer(&pk_b));
            assert_eq!(runner_a.remove_peer_call_count(), removes_before + 1);
        }
    }
}

#[tokio::test]
async fn cleanup_finalization_failure_cannot_repeat_wireguard_removal() {
    for (initial_state, cleanup_state) in
        [("pending_owned", "pending"), ("active", "revoking_unowned")]
    {
        let (local_ip, peer_ip) = next_loopback_pair();
        let peer_key = fixture_wg_pubkey(212);
        let clock = FakeClock::new(1_802_900_000);
        let runner = FakePeerRunner::new(fixture_wg_pubkey(211), local_ip, 51821);
        let peer_ip = peer_ip.to_string();
        runner.insert_preexisting_peer(&peer_key, &peer_ip, "10.10.0.2:51821");
        let (runtime, db) = build_test_runtime(
            "local",
            Arc::clone(&runner) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            false,
        );
        let now = runtime.now();
        let link = PeerLink {
            id: "cleanup-fixture".to_string(),
            name: "peer".to_string(),
            wg_pubkey: peer_key.clone(),
            tunnel_ip: peer_ip.clone(),
            endpoint: "10.10.0.2".to_string(),
            wg_port: 51821,
            state: initial_state.to_string(),
            peer_version: None,
            peer_protocol: None,
            capabilities: None,
            rtt_ms: None,
            last_ok_at: None,
            last_error: None,
            consecutive_failures: 0,
            inbound_token_hash: None,
            pending_attempt_id: None,
            pending_expires_at: (initial_state == "pending_owned").then(|| now.timestamp() + 60),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };
        {
            let conn = db.lock().unwrap();
            db_peers::insert_peer_link(&conn, &link).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER block_cleanup_finalization BEFORE DELETE ON peer_links
                 BEGIN SELECT RAISE(ABORT, 'fixture: fail link finalization'); END;",
            )
            .unwrap();
        }

        let (status, _) = call_admin(&runtime, Method::DELETE, "/cleanup-fixture", None).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!runner.has_peer(&peer_key));
        assert_eq!(runner.remove_peer_call_count(), 1);
        {
            let conn = db.lock().unwrap();
            let retained = db_peers::get_peer_link(&conn, &link.id).unwrap().unwrap();
            assert_eq!(retained.state, cleanup_state);
            assert_eq!(retained.pending_expires_at, Some(0));
            conn.execute_batch("DROP TRIGGER block_cleanup_finalization")
                .unwrap();
        }

        runner.insert_preexisting_peer(&peer_key, &peer_ip, "10.10.0.2:51821");
        let restarted = build_test_runtime_with_db_and_timeout(
            "local",
            Arc::clone(&db),
            Arc::clone(&runner) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        cleanup_expired_pending(&restarted).await;
        assert!(db_peers::get_peer_link(&db.lock().unwrap(), &link.id)
            .unwrap()
            .is_none());
        assert!(runner.has_peer(&peer_key));
        assert_eq!(runner.remove_peer_call_count(), 1);
    }
}

/// Deterministic runner decorator for interleaving exact clock advances or concurrent DB markers
/// around awaited runner calls without wall-clock sleeps.
type RunnerHookFn = Box<dyn FnMut(&PeerNetworkRequest) + Send>;

struct HookedPeerRunner {
    inner: Arc<FakePeerRunner>,
    after_hook: StdMutex<Option<RunnerHookFn>>,
}

impl HookedPeerRunner {
    fn new(inner: Arc<FakePeerRunner>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            after_hook: StdMutex::new(None),
        })
    }

    fn set_after_hook(&self, hook: impl FnMut(&PeerNetworkRequest) + Send + 'static) {
        *self.after_hook.lock().unwrap() = Some(Box::new(hook));
    }

    fn clear_after_hook(&self) {
        *self.after_hook.lock().unwrap() = None;
    }
}

impl PeerRunner for HookedPeerRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerNetworkRequest,
    ) -> BoxFuture<'a, Result<PeerNetworkResponse, PeerNetworkError>> {
        Box::pin(async move {
            let res = self.inner.dispatch(req).await;
            if let Some(hook) = self.after_hook.lock().unwrap().as_mut() {
                hook(req);
            }
            res
        })
    }
}

/// P3-EXPIRY-01: Start pairing Stage 1 (post-AddPeer) and Stage 2 (post-HTTPS / post-lock-wait)
/// must revalidate current nonzero exclusive expiry and authoritative pending row state at actual
/// commit, never revive `pending_expires_at = 0`, and roll back cleanly without double removal.
#[tokio::test]
async fn start_pairing_stage2_revalidates_expiry_and_never_revives_zero_marker_after_external_work()
{
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(231);
    let pk_b = fixture_wg_pubkey(232);
    let clock = FakeClock::new(1_803_100_000);
    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let hooked_runner_a = HookedPeerRunner::new(Arc::clone(&base_runner_a));
    let db_a = open_isolated_peer_db();

    let pairing_string = PairingPayload {
        https_url: "https://media-exp.example.test".to_string(),
        wg_pubkey: pk_b.clone(),
        endpoint: "10.31.0.2".to_string(),
        wg_port: 51821,
        tunnel_ip: ip_b.to_string(),
        code: "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
    }
    .encode()
    .unwrap();
    let comparison_code = derive_comparison_code(&pk_a, &pk_b);

    // 1A: Clock reaches exact `now_ts == effective_expires_at` while Stage 2 waits on attempt_lock
    // after public HTTPS already returned an initially valid expiry.
    {
        let start_ts = clock.epoch.load(Ordering::SeqCst);
        let remote_exp = start_ts + 30;
        let att_id = "start-stage2-exact-exp";
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let resp = PublicPairingResponse {
            attempt_id: att_id.to_string(),
            comparison_code: comparison_code.clone(),
            expires_at: remote_exp,
            server_name: "media-exp".to_string(),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
        };
        let transport = Arc::new(BarrierPublicTransport {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            response: Arc::new(StdMutex::new(Ok((
                StatusCode::OK,
                serde_json::to_vec(&resp).unwrap(),
            )))),
        });
        let rt = build_test_runtime_with_db_and_timeout(
            "seedbox-1",
            Arc::clone(&db_a),
            Arc::clone(&hooked_runner_a) as Arc<dyn PeerRunner>,
            transport,
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        let held_att = rt.lock_attempt(att_id, "test_hold_att").await.unwrap();
        let removes_before = base_runner_a.remove_peer_call_count();
        let rt_call = Arc::clone(&rt);
        let pstr_c = pairing_string.clone();
        let handle = tokio::spawn(async move {
            call_admin(
                &rt_call,
                Method::POST,
                "/pair",
                Some(json!({
                    "pairing_string": pstr_c,
                    "name": "media-exp",
                    "endpoint": "10.31.0.1"
                })),
            )
            .await
        });

        entered.notified().await;
        // Release HTTPS response while `attempt_lock` is still held, then advance clock to exact
        // `remote_exp` before releasing `attempt_lock` so Stage 2 commits at `now == expires_at`.
        release.notify_one();
        tokio::task::yield_now().await;
        clock.advance(30);
        assert_eq!(clock.epoch.load(Ordering::SeqCst), remote_exp);
        drop(held_att);

        let (st, val) = handle.await.unwrap();
        assert_eq!(
            st,
            StatusCode::GONE,
            "expected exact-expiry rejection: {val}"
        );
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
        assert!(!base_runner_a.has_peer(&pk_b));
        assert_eq!(base_runner_a.remove_peer_call_count(), removes_before + 1);
    }

    // 1B & 1C: Concurrent cleanup marker (`pending_expires_at = 0`) set while outbound HTTPS is in
    // flight — both when row is still `pending_owned` (rolls back WG peer once) and when already
    // demoted to `pending` (rolls back DB row without issuing a second `RemovePeer`).
    for already_demoted in [false, true] {
        let start_ts = clock.epoch.load(Ordering::SeqCst);
        let att_id = if already_demoted {
            "start-stage2-zero-demoted"
        } else {
            "start-stage2-zero-owned"
        };
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let resp = PublicPairingResponse {
            attempt_id: att_id.to_string(),
            comparison_code: comparison_code.clone(),
            expires_at: start_ts + 300,
            server_name: "media-exp".to_string(),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
        };
        let transport = Arc::new(BarrierPublicTransport {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            response: Arc::new(StdMutex::new(Ok((
                StatusCode::OK,
                serde_json::to_vec(&resp).unwrap(),
            )))),
        });
        let rt = build_test_runtime_with_db_and_timeout(
            "seedbox-1",
            Arc::clone(&db_a),
            Arc::clone(&hooked_runner_a) as Arc<dyn PeerRunner>,
            transport,
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        let removes_before = base_runner_a.remove_peer_call_count();
        let rt_call = Arc::clone(&rt);
        let pstr_c = pairing_string.clone();
        let handle = tokio::spawn(async move {
            call_admin(
                &rt_call,
                Method::POST,
                "/pair",
                Some(json!({
                    "pairing_string": pstr_c,
                    "name": "media-exp",
                    "endpoint": "10.31.0.1"
                })),
            )
            .await
        });

        entered.notified().await;
        {
            let conn = db_a.lock().unwrap();
            let row = db_peers::list_peer_links(&conn).unwrap().pop().unwrap();
            assert_eq!(row.state, "pending_owned");
            if already_demoted {
                conn.execute(
                    "UPDATE peer_links SET state = 'pending', pending_expires_at = 0 WHERE id = ?1",
                    [&row.id],
                )
                .unwrap();
            } else {
                conn.execute(
                    "UPDATE peer_links SET pending_expires_at = 0 WHERE id = ?1",
                    [&row.id],
                )
                .unwrap();
            }
        }
        release.notify_one();

        let (st, val) = handle.await.unwrap();
        assert_eq!(
            st,
            StatusCode::CONFLICT,
            "must refuse reviving zero marker: {val}"
        );
        assert_eq!(val["code"], "PEER_CONFLICT");
        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
        if already_demoted {
            assert!(
                base_runner_a.has_peer(&pk_b),
                "demoted cleanup-marked row must not issue a second RemovePeer"
            );
            assert_eq!(base_runner_a.remove_peer_call_count(), removes_before);
            // Clean up simulated remaining WG peer for next subtest.
            let _ = base_runner_a
                .dispatch(&PeerNetworkRequest::RemovePeer {
                    pubkey: pk_b.clone(),
                })
                .await;
        } else {
            assert!(!base_runner_a.has_peer(&pk_b));
            assert_eq!(base_runner_a.remove_peer_call_count(), removes_before + 1);
        }
    }

    // 1D: Clock crosses exact `local_max_expires_at` DURING Stage 1 `AddPeer`:
    // `commit_pending_wg_ownership_locked` records cleanup-only ownership without restoring
    // validity, outbound HTTPS is skipped, and the newly added WG peer is removed exactly once.
    {
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let transport_calls_c = Arc::clone(&transport_calls);
        let transport = Arc::new(ControlledPublicTransport {
            responder: Arc::new(move |_| {
                transport_calls_c.fetch_add(1, Ordering::SeqCst);
                (StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
            }),
        });
        let clock_hook = Arc::clone(&clock);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::AddPeer { .. }) {
                clock_hook.advance(PAIRING_WINDOW_TTL_SECS);
            }
        });
        let rt = build_test_runtime_with_db_and_timeout(
            "seedbox-1",
            Arc::clone(&db_a),
            Arc::clone(&hooked_runner_a) as Arc<dyn PeerRunner>,
            transport,
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        let removes_before = base_runner_a.remove_peer_call_count();
        let (st, val) = call_admin(
            &rt,
            Method::POST,
            "/pair",
            Some(json!({
                "pairing_string": pairing_string,
                "name": "media-exp",
                "endpoint": "10.31.0.1"
            })),
        )
        .await;
        hooked_runner_a.clear_after_hook();

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert_eq!(
            transport_calls.load(Ordering::SeqCst),
            0,
            "Stage 1 expiry after AddPeer must abort before outbound HTTPS"
        );
        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
        assert!(!base_runner_a.has_peer(&pk_b));
        assert_eq!(base_runner_a.remove_peer_call_count(), removes_before + 1);
    }
}

/// P3-EXPIRY-01: Confirm responder phases 1, 2, and 4 enforce fresh row/attempt nonzero exclusive
/// expiry guards before runner I/O and at decisive SQL commits (issuer digest, held-token metadata,
/// final activation + completion), persist terminal attempt status promptly, and preserve retry
/// and cancel semantics.
#[tokio::test]
async fn confirm_pairing_phases_1_2_4_enforce_fresh_expiry_zero_marker_and_prompt_attempt_status() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(233);
    let pk_b = fixture_wg_pubkey(234);
    let clock = FakeClock::new(1_803_200_000);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let hooked_runner_b = HookedPeerRunner::new(Arc::clone(&base_runner_b));
    let db_b = open_isolated_peer_db();
    let rt_b = build_test_runtime_with_db_and_timeout(
        "media-b",
        Arc::clone(&db_b),
        Arc::clone(&hooked_runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    {
        let conn = db_b.lock().unwrap();
        db_peers::upsert_peer_identity(
            &conn,
            &PeerIdentity {
                wg_pubkey: pk_b.clone(),
                tunnel_ip: ip_b.to_string(),
                wg_port: 51821,
                created_at: rt_b.now().to_rfc3339(),
            },
        )
        .unwrap();
    }

    let seed_attempt = |att_id: &str, ttl_secs: i64| -> i64 {
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        let exp = now_ts + ttl_secs;
        let conn = db_b.lock().unwrap();
        db_peers::insert_pairing_attempt(
            &conn,
            &af_db::peers::PairingAttempt {
                id: att_id.to_string(),
                window_id: None,
                remote_name: Some("seedbox-a".to_string()),
                remote_pubkey: Some(pk_a.clone()),
                remote_tunnel_ip: Some(ip_a.to_string()),
                remote_endpoint: Some("10.32.0.1:51821".to_string()),
                source_ip: Some("198.51.100.32".to_string()),
                status: "pending".to_string(),
                error_code: None,
                expires_at: exp,
                created_at: rt_b.now().to_rfc3339(),
            },
        )
        .unwrap();
        exp
    };

    // Mock A tunnel listener with programmable hooks on Bootstrap and Acknowledge.
    type VoidHookSlot = Arc<StdMutex<Option<Box<dyn FnMut() + Send>>>>;
    let on_bootstrap_hook: VoidHookSlot = Arc::new(StdMutex::new(None));
    let on_ack_hook: VoidHookSlot = Arc::new(StdMutex::new(None));
    let ack_received = Arc::new(AtomicUsize::new(0));
    let boot_hook_c = Arc::clone(&on_bootstrap_hook);
    let ack_hook_c = Arc::clone(&on_ack_hook);
    let ack_recv_c = Arc::clone(&ack_received);
    let pk_a_c = pk_a.clone();
    let mock_a_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_a, 0))
        .await
        .unwrap();
    let mock_a_port = mock_a_listener.local_addr().unwrap().port();
    let mock_a_task = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/peer/v1/hello",
            axum::routing::post(move |axum::Json(req): axum::Json<HelloRequest>| {
                let bh = Arc::clone(&boot_hook_c);
                let ah = Arc::clone(&ack_hook_c);
                let ar = Arc::clone(&ack_recv_c);
                let pk = pk_a_c.clone();
                async move {
                    match req.phase {
                        HelloPhase::Bootstrap => {
                            if let Some(f) = bh.lock().unwrap().as_mut() {
                                f();
                            }
                            axum::Json(HelloResponse {
                                phase: HelloPhase::Bootstrap,
                                attempt_id: req.attempt_id,
                                acknowledged: false,
                                state: "pending".to_string(),
                                wg_pubkey: pk,
                                version: "4.0.0-test".to_string(),
                                peer_protocol: PEER_PROTOCOL_VERSION,
                                capabilities: vec!["links".to_string()],
                                link_token: Some(PeerCredentialSecret::new(
                                    "4444444444444444444444444444444444444444444444444444444444444444"
                                        .to_string(),
                                )),
                            })
                        }
                        HelloPhase::Acknowledge => {
                            ar.fetch_add(1, Ordering::SeqCst);
                            if let Some(f) = ah.lock().unwrap().as_mut() {
                                f();
                            }
                            axum::Json(HelloResponse {
                                phase: HelloPhase::Acknowledge,
                                attempt_id: req.attempt_id,
                                acknowledged: true,
                                state: "active".to_string(),
                                wg_pubkey: pk,
                                version: "4.0.0-test".to_string(),
                                peer_protocol: PEER_PROTOCOL_VERSION,
                                capabilities: vec!["links".to_string()],
                                link_token: None,
                            })
                        }
                    }
                }
            }),
        );
        let _ = axum::serve(mock_a_listener, app).await;
    });
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, mock_a_port);

    // 2A-1: Pre-existing cleanup-marked (`pending_expires_at = 0`) pending row refuses confirm
    // BEFORE any Phase 1 runner mutations (`WriteCredential` or `AddPeer`).
    {
        let att_id = "confirm-p1-zero-marker";
        let _exp = seed_attempt(att_id, 300);
        let now_rfc = rt_b.now().to_rfc3339();
        {
            let conn = db_b.lock().unwrap();
            db_peers::insert_peer_link(
                &conn,
                &PeerLink {
                    id: "zero-marked-link".to_string(),
                    name: "seedbox-a".to_string(),
                    wg_pubkey: pk_a.clone(),
                    tunnel_ip: ip_a.to_string(),
                    endpoint: "10.32.0.1".to_string(),
                    wg_port: 51821,
                    state: "pending".to_string(),
                    peer_version: None,
                    peer_protocol: None,
                    capabilities: None,
                    rtt_ms: None,
                    last_ok_at: None,
                    last_error: None,
                    consecutive_failures: 0,
                    inbound_token_hash: None,
                    pending_attempt_id: Some(att_id.to_string()),
                    pending_expires_at: Some(0),
                    created_at: now_rfc.clone(),
                    updated_at: now_rfc,
                },
            )
            .unwrap();
        }
        // Hold link_lock briefly during initial pre-sweep? No, confirm runs sweep first, so test
        // zero-marker rejection during Phase 1 via a hook right after `ReadCredential(LinkToken)`.
        // Reset pending_expires_at to valid initially so pre-sweep keeps it, then set 0 during
        // ReadCredential(LinkToken) before WriteCredential(PendingIssuerToken) and AddPeer!
        {
            let conn = db_b.lock().unwrap();
            conn.execute(
                "UPDATE peer_links SET pending_expires_at = ?1 WHERE id = 'zero-marked-link'",
                rusqlite::params![clock.epoch.load(Ordering::SeqCst) + 300],
            )
            .unwrap();
        }
        let db_hook = Arc::clone(&db_b);
        hooked_runner_b.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::ReadCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    ..
                }
            ) {
                db_hook
                    .lock()
                    .unwrap()
                    .execute(
                        "UPDATE peer_links SET pending_expires_at = 0 WHERE id = 'zero-marked-link'",
                        [],
                    )
                    .unwrap();
            }
        });
        let writes_before =
            base_runner_b.write_cred_call_count(PeerCredentialSlot::PendingIssuerToken);
        let adds_before = base_runner_b.add_peer_call_count();
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_b.clear_after_hook();

        assert_eq!(
            st,
            StatusCode::CONFLICT,
            "expected cleanup-marked conflict: {val}"
        );
        assert_eq!(val["code"], "PEER_CONFLICT");
        assert_eq!(
            base_runner_b.write_cred_call_count(PeerCredentialSlot::PendingIssuerToken),
            writes_before,
            "must refuse before WriteCredential(PendingIssuerToken)"
        );
        assert_eq!(
            base_runner_b.add_peer_call_count(),
            adds_before,
            "must refuse before AddPeer"
        );
        let retained = db_peers::get_peer_link(&db_b.lock().unwrap(), "zero-marked-link")
            .unwrap()
            .unwrap();
        assert_eq!(retained.pending_expires_at, Some(0));
        assert!(retained.inbound_token_hash.is_none());
        cleanup_expired_pending(&rt_b).await;
    }

    // 2A-1b: Exact expiry (`now_ts == expires_at`) during Pre-Phase 1 `EnsureIdentity` ->
    // reservation tx revalidates fresh clock, promptly persists `expired`, inserts no pending link,
    // and performs zero Phase 1 credential or WireGuard writes!
    {
        let att_id = "confirm-pre-p1-identity-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        hooked_runner_b.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::EnsureIdentity { .. }) {
                clock_hook.advance(60);
            }
        });
        let writes_before =
            base_runner_b.write_cred_call_count(PeerCredentialSlot::PendingIssuerToken);
        let adds_before = base_runner_b.add_peer_call_count();
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_b.clear_after_hook();

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert_eq!(
            base_runner_b.write_cred_call_count(PeerCredentialSlot::PendingIssuerToken),
            writes_before
        );
        assert_eq!(base_runner_b.add_peer_call_count(), adds_before);
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
        let att = db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
            .unwrap()
            .unwrap();
        assert_eq!(att.status, "expired");
        assert_eq!(att.error_code.as_deref(), Some("CODE_EXPIRED"));
    }

    // 2A-2: Exact expiry (`now_ts == expires_at`) during Phase 1 `WriteCredential(PendingIssuerToken)`
    // -> guarded issuer-digest SQL rejects, no `AddPeer`, attempt promptly persisted as `expired`.
    {
        let att_id = "confirm-p1-issuer-digest-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        hooked_runner_b.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::WriteCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    ..
                }
            ) {
                clock_hook.advance(60);
            }
        });
        let adds_before = base_runner_b.add_peer_call_count();
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_b.clear_after_hook();

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert_eq!(base_runner_b.add_peer_call_count(), adds_before);
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
        let att = db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
            .unwrap()
            .unwrap();
        assert_eq!(att.status, "expired");
        assert_eq!(att.error_code.as_deref(), Some("CODE_EXPIRED"));
    }

    // 2A-3: Exact expiry DURING Phase 1 `AddPeer` (`Ok(Mutation)`) + transient `DeleteCredential Busy`
    // -> cleanup-only ownership recording marks `pending_owned` without restoring validity,
    // confirming SQL rejects, attempt is PROMPTLY persisted as `expired`, and sweep removes the
    // newly added WG peer exactly once!
    {
        let att_id = "confirm-p1-addpeer-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        let runner_for_busy = Arc::clone(&base_runner_b);
        hooked_runner_b.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::AddPeer { .. }) {
                clock_hook.advance(60);
                runner_for_busy
                    .set_next_delete_cred_error(PeerNetworkError::Busy("cred busy".to_string()));
            }
        });
        let removes_before = base_runner_b.remove_peer_call_count();
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_b.clear_after_hook();

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        let att = db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            att.status, "expired",
            "attempt must be persisted as expired promptly even when runner cleanup fails transiently"
        );
        let retained = db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .into_iter()
            .find(|l| l.pending_attempt_id.as_deref() == Some(att_id))
            .expect("owned pending link stays durable for sweep");
        assert_eq!(retained.state, "pending_owned");
        assert_eq!(retained.pending_expires_at, Some(0));
        assert!(base_runner_b.has_peer(&pk_a));
        assert_eq!(base_runner_b.remove_peer_call_count(), removes_before);

        // Sweep cleans up the owned WG peer exactly once and deletes the pending link.
        cleanup_expired_pending(&rt_b).await;
        assert!(!base_runner_b.has_peer(&pk_a));
        assert_eq!(base_runner_b.remove_peer_call_count(), removes_before + 1);
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
    }

    // 2B-1: Exact expiry DURING Phase 2 Bootstrap HTTP -> refused BEFORE `WriteCredential(LinkToken)`!
    {
        let att_id = "confirm-p2-boot-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        *on_bootstrap_hook.lock().unwrap() = Some(Box::new(move || {
            clock_hook.advance(60);
        }));
        let link_cred_writes_before =
            base_runner_b.write_cred_call_count(PeerCredentialSlot::LinkToken);
        let ack_before = ack_received.load(Ordering::SeqCst);
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        *on_bootstrap_hook.lock().unwrap() = None;

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert_eq!(
            base_runner_b.write_cred_call_count(PeerCredentialSlot::LinkToken),
            link_cred_writes_before,
            "Phase 2 pre-I/O guard must refuse before writing LinkToken"
        );
        assert_eq!(ack_received.load(Ordering::SeqCst), ack_before);
        assert!(!base_runner_b.has_peer(&pk_a));
        assert_eq!(
            db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
                .unwrap()
                .unwrap()
                .status,
            "expired"
        );
    }

    // 2B-2: Exact expiry DURING Phase 2 `WriteCredential(LinkToken)` -> guarded held-token metadata
    // SQL rejects, cleans up `LinkToken` + WG peer, prompts `expired`, and never sends Acknowledge!
    {
        let att_id = "confirm-p2-metadata-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        hooked_runner_b.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::WriteCredential {
                    slot: PeerCredentialSlot::LinkToken,
                    ..
                }
            ) {
                clock_hook.advance(60);
            }
        });
        let ack_before = ack_received.load(Ordering::SeqCst);
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_b.clear_after_hook();

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert_eq!(
            ack_received.load(Ordering::SeqCst),
            ack_before,
            "Phase 2 guarded metadata SQL must stop before Phase 3 Acknowledge"
        );
        assert!(!base_runner_b.has_peer(&pk_a));
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
        assert_eq!(
            db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
                .unwrap()
                .unwrap()
                .status,
            "expired"
        );
    }

    // 2C-1: Exact expiry DURING Phase 3 Acknowledge HTTP -> Phase 4 guarded activation + completion
    // SQL rejects, rolls back, prompts `expired`, and cleans up without activating!
    {
        let att_id = "confirm-p4-ack-exp";
        let _exp = seed_attempt(att_id, 60);
        let clock_hook = Arc::clone(&clock);
        *on_ack_hook.lock().unwrap() = Some(Box::new(move || {
            clock_hook.advance(60);
        }));
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        *on_ack_hook.lock().unwrap() = None;

        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert!(!base_runner_b.has_peer(&pk_a));
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
        let att = db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
            .unwrap()
            .unwrap();
        assert_eq!(att.status, "expired");
    }

    // 2C-2: `pending_expires_at = 0` injected DURING Phase 3 Acknowledge HTTP -> Phase 4 guarded
    // activation + completion SQL refuses with `409 PEER_CONFLICT`, never activating or completing!
    {
        let att_id = "confirm-p4-ack-zero";
        let _exp = seed_attempt(att_id, 60);
        let db_hook = Arc::clone(&db_b);
        let att_hook = att_id.to_string();
        *on_ack_hook.lock().unwrap() = Some(Box::new(move || {
            db_hook
                .lock()
                .unwrap()
                .execute(
                    "UPDATE peer_links SET pending_expires_at = 0 WHERE pending_attempt_id = ?1",
                    [&att_hook],
                )
                .unwrap();
        }));
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        *on_ack_hook.lock().unwrap() = None;

        assert_eq!(st, StatusCode::CONFLICT, "val={val}");
        assert_eq!(val["code"], "PEER_CONFLICT");
        let link = db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .into_iter()
            .find(|l| l.pending_attempt_id.as_deref() == Some(att_id))
            .expect("cleanup-marked link must remain pending, not active");
        assert_eq!(link.state, "pending_owned");
        assert_eq!(link.pending_expires_at, Some(0));
        let att = db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
            .unwrap()
            .unwrap();
        assert_eq!(att.status, "confirming");
        cleanup_expired_pending(&rt_b).await;
        assert!(!base_runner_b.has_peer(&pk_a));
    }

    // 2D: Cancel hitting transient `DeleteCredential Busy` promptly persists `cancelled`, blocks a
    // subsequent `confirm_pairing` (`410 WINDOW_CLOSED`), and preserves `cancelled` across sweep!
    {
        let att_id = "confirm-cancel-prompt-status";
        let _exp = seed_attempt(att_id, 300);
        // Point at closed port so first confirm creates pending_owned link + PendingIssuerToken
        // and returns retryable HandshakeTimeout (leaving attempt `confirming`).
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        rt_b.tunnel_port_overrides
            .write()
            .unwrap()
            .insert(ip_a, closed_port);

        let (st, _) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
                .unwrap()
                .unwrap()
                .status,
            "confirming"
        );

        // Cancel hits transient DeleteCredential Busy: attempt MUST already be `cancelled`!
        base_runner_b.set_next_delete_cred_error(PeerNetworkError::Busy("cred busy".to_string()));
        let (st, val) =
            call_admin(&rt_b, Method::DELETE, &format!("/pairing/{att_id}"), None).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "val={val}");
        assert_eq!(
            db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
                .unwrap()
                .unwrap()
                .status,
            "cancelled",
            "cancel must promptly persist terminal cancelled status before runner cleanup"
        );

        // Restore live mock port and attempt to confirm the cancelled attempt -> MUST reject!
        rt_b.tunnel_port_overrides
            .write()
            .unwrap()
            .insert(ip_a, mock_a_port);
        let (st, val) = call_admin(
            &rt_b,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "WINDOW_CLOSED");

        // Sweep finishes deleting pending row while preserving `cancelled` (not overwriting to `expired`)!
        cleanup_expired_pending(&rt_b).await;
        assert!(db_peers::list_peer_links(&db_b.lock().unwrap())
            .unwrap()
            .is_empty());
        assert!(!base_runner_b.has_peer(&pk_a));
        assert_eq!(
            db_peers::get_pairing_attempt(&db_b.lock().unwrap(), att_id)
                .unwrap()
                .unwrap()
                .status,
            "cancelled"
        );
    }

    mock_a_task.abort();
}

/// P3-EXPIRY-01: Initiator `POST /peer/v1/hello` must recheck with a fresh clock AFTER awaited
/// credential work before responding (Bootstrap) or acknowledging (pending activation AND
/// `active`/`down` ack retries).
#[tokio::test]
async fn hello_initiator_rechecks_fresh_clock_after_credential_io_including_live_ack_retries() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(235);
    let pk_b = fixture_wg_pubkey(236);
    let clock = FakeClock::new(1_803_300_000);
    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let hooked_runner_a = HookedPeerRunner::new(Arc::clone(&base_runner_a));
    let db_a = open_isolated_peer_db();
    let rt_a = build_test_runtime_with_db_and_timeout(
        "seedbox-a",
        Arc::clone(&db_a),
        Arc::clone(&hooked_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let (rt_b, db_b) = build_test_runtime(
        "media-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
    );
    {
        let now_rfc = rt_a.now().to_rfc3339();
        db_peers::upsert_peer_identity(
            &db_a.lock().unwrap(),
            &PeerIdentity {
                wg_pubkey: pk_a.clone(),
                tunnel_ip: ip_a.to_string(),
                wg_port: 51821,
                created_at: now_rfc.clone(),
            },
        )
        .unwrap();
        db_peers::upsert_peer_identity(
            &db_b.lock().unwrap(),
            &PeerIdentity {
                wg_pubkey: pk_b.clone(),
                tunnel_ip: ip_b.to_string(),
                wg_port: 51821,
                created_at: now_rfc,
            },
        )
        .unwrap();
    }
    let a_addr = rt_a.ensure_listener_started().await.unwrap().unwrap();
    rt_b.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_addr.port());

    // 3A: Bootstrap expires (`now_ts == pending_expires_at`) DURING `WriteCredential(PendingIssuerToken)`
    // -> guarded SQL rejects with `410 CODE_EXPIRED`, never issues `link_token`, cleans up row/WG/creds!
    {
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        let now_rfc = rt_a.now().to_rfc3339();
        let link_id = "hello-boot-exp-link";
        let att_id = "hello-boot-exp-att";
        base_runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.33.0.2:51821");
        db_peers::insert_peer_link(
            &db_a.lock().unwrap(),
            &PeerLink {
                id: link_id.to_string(),
                name: "media-b".to_string(),
                wg_pubkey: pk_b.clone(),
                tunnel_ip: ip_b.to_string(),
                endpoint: "10.33.0.2".to_string(),
                wg_port: 51821,
                state: "pending_owned".to_string(),
                peer_version: None,
                peer_protocol: None,
                capabilities: None,
                rtt_ms: None,
                last_ok_at: None,
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: Some(att_id.to_string()),
                pending_expires_at: Some(now_ts + 45),
                created_at: now_rfc.clone(),
                updated_at: now_rfc,
            },
        )
        .unwrap();

        let clock_hook = Arc::clone(&clock);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::WriteCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    ..
                }
            ) {
                clock_hook.advance(45);
            }
        });
        let body = serde_json::to_vec(&HelloRequest {
            phase: HelloPhase::Bootstrap,
            attempt_id: att_id.to_string(),
            wg_pubkey: pk_b.clone(),
            tunnel_ip: Some(ip_b.to_string()),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
            capabilities: vec!["links".to_string()],
            link_token: Some(PeerCredentialSecret::new(
                "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            )),
        })
        .unwrap();
        let (st, bytes, _) = rt_b
            .send_tunnel_request(
                Method::POST,
                &ip_a.to_string(),
                "/peer/v1/hello",
                None,
                Some(body),
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        hooked_runner_a.clear_after_hook();

        let val: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert!(val.get("link_token").is_none());
        assert!(db_peers::get_peer_link(&db_a.lock().unwrap(), link_id)
            .unwrap()
            .is_none());
        assert!(!base_runner_a.has_peer(&pk_b));
        assert!(base_runner_a
            .credential(PeerCredentialSlot::LinkToken, link_id)
            .is_none());
        assert!(base_runner_a
            .credential(
                PeerCredentialSlot::PendingIssuerToken,
                &pending_issuer_credential_id(link_id),
            )
            .is_none());
    }

    // 3B: Pending Acknowledge expires (`now_ts == pending_expires_at`) DURING
    // `DeleteCredential(PendingIssuerToken)` -> rejects with `410 CODE_EXPIRED`, never activates!
    {
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        let now_rfc = rt_a.now().to_rfc3339();
        let link_id = "hello-ack-pend-exp";
        let att_id = "hello-ack-pend-att";
        let issued_tok = PeerCredentialSecret::new(
            "6666666666666666666666666666666666666666666666666666666666666666".to_string(),
        );
        let digest = super::pairing::sha256_prefixed(issued_tok.expose_secret());
        base_runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.33.0.2:51821");
        db_peers::insert_peer_link(
            &db_a.lock().unwrap(),
            &PeerLink {
                id: link_id.to_string(),
                name: "media-b".to_string(),
                wg_pubkey: pk_b.clone(),
                tunnel_ip: ip_b.to_string(),
                endpoint: "10.33.0.2".to_string(),
                wg_port: 51821,
                state: "pending_owned".to_string(),
                peer_version: None,
                peer_protocol: None,
                capabilities: None,
                rtt_ms: None,
                last_ok_at: None,
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: Some(digest),
                pending_attempt_id: Some(att_id.to_string()),
                pending_expires_at: Some(now_ts + 45),
                created_at: now_rfc.clone(),
                updated_at: now_rfc,
            },
        )
        .unwrap();

        let clock_hook = Arc::clone(&clock);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::DeleteCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    ..
                }
            ) {
                clock_hook.advance(45);
            }
        });
        let body = serde_json::to_vec(&HelloRequest {
            phase: HelloPhase::Acknowledge,
            attempt_id: att_id.to_string(),
            wg_pubkey: pk_b.clone(),
            tunnel_ip: Some(ip_b.to_string()),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
            capabilities: vec!["links".to_string()],
            link_token: None,
        })
        .unwrap();
        let (st, bytes, _) = rt_b
            .send_tunnel_request(
                Method::POST,
                &ip_a.to_string(),
                "/peer/v1/hello",
                Some(&issued_tok),
                Some(body),
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        hooked_runner_a.clear_after_hook();

        let val: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(st, StatusCode::GONE, "val={val}");
        assert_eq!(val["code"], "CODE_EXPIRED");
        assert!(db_peers::get_peer_link(&db_a.lock().unwrap(), link_id)
            .unwrap()
            .is_none());
        assert!(!base_runner_a.has_peer(&pk_b));
    }

    // 3C: Active AND Down ack retries expire (`now_ts == pending_expires_at`) DURING
    // `DeleteCredential(PendingIssuerToken)` -> BOTH reject with `410 CODE_EXPIRED` instead of
    // returning `acknowledged: true`, clearing retry markers only when credential delete succeeded!
    for (live_state, inject_delete_busy) in [("active", false), ("down", false), ("down", true)] {
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        let now_rfc = rt_a.now().to_rfc3339();
        let link_id = format!("hello-ack-{live_state}-{inject_delete_busy}");
        let att_id = format!("hello-ack-att-{live_state}-{inject_delete_busy}");
        let issued_tok = PeerCredentialSecret::new(
            "7777777777777777777777777777777777777777777777777777777777777777".to_string(),
        );
        let digest = super::pairing::sha256_prefixed(issued_tok.expose_secret());
        db_peers::insert_peer_link(
            &db_a.lock().unwrap(),
            &PeerLink {
                id: link_id.clone(),
                name: format!("media-{live_state}-{inject_delete_busy}"),
                wg_pubkey: pk_b.clone(),
                tunnel_ip: ip_b.to_string(),
                endpoint: "10.33.0.2".to_string(),
                wg_port: 51821,
                state: live_state.to_string(),
                peer_version: Some("4.0.0-test".to_string()),
                peer_protocol: Some(PEER_PROTOCOL_VERSION),
                capabilities: Some("[\"links\"]".to_string()),
                rtt_ms: Some(1.0),
                last_ok_at: Some(now_rfc.clone()),
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: Some(digest),
                pending_attempt_id: Some(att_id.clone()),
                pending_expires_at: Some(now_ts + 45),
                created_at: now_rfc.clone(),
                updated_at: now_rfc,
            },
        )
        .unwrap();

        if inject_delete_busy {
            base_runner_a.set_next_delete_cred_error(PeerNetworkError::Busy(
                "busy during live ack retry".to_string(),
            ));
        }
        let clock_hook = Arc::clone(&clock);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(
                req,
                PeerNetworkRequest::DeleteCredential {
                    slot: PeerCredentialSlot::PendingIssuerToken,
                    ..
                }
            ) {
                clock_hook.advance(45);
            }
        });
        let body = serde_json::to_vec(&HelloRequest {
            phase: HelloPhase::Acknowledge,
            attempt_id: att_id.clone(),
            wg_pubkey: pk_b.clone(),
            tunnel_ip: Some(ip_b.to_string()),
            version: "4.0.0-test".to_string(),
            peer_protocol: PEER_PROTOCOL_VERSION,
            capabilities: vec!["links".to_string()],
            link_token: None,
        })
        .unwrap();
        let (st, bytes, _) = rt_b
            .send_tunnel_request(
                Method::POST,
                &ip_a.to_string(),
                "/peer/v1/hello",
                Some(&issued_tok),
                Some(body),
                Duration::from_secs(3),
            )
            .await
            .unwrap();
        hooked_runner_a.clear_after_hook();

        let val: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            st,
            StatusCode::GONE,
            "live_state={live_state} busy={inject_delete_busy}: {val}"
        );
        assert_eq!(val["code"], "CODE_EXPIRED");
        let after = db_peers::get_peer_link(&db_a.lock().unwrap(), &link_id)
            .unwrap()
            .unwrap();
        assert_eq!(after.state, live_state);
        if inject_delete_busy {
            assert_eq!(
                after.pending_attempt_id.as_deref(),
                Some(att_id.as_str()),
                "failed cred delete must retain tracking columns for sweep retry"
            );
            assert_eq!(after.pending_expires_at, Some(now_ts + 45));
        } else {
            assert!(after.pending_attempt_id.is_none());
            assert!(after.pending_expires_at.is_none());
        }
        // Clean up row before next loop iteration (same pubkey/tunnel_ip).
        db_peers::delete_peer_link(&db_a.lock().unwrap(), &link_id).unwrap();
    }

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

/// P3-EXPIRY-01: Endpoint change refuses cleanup-marked (`0`) and exact-expired pending links
/// before `SetEndpoint` runner mutation, guards the later SQL write across `SetEndpoint` I/O,
/// and continues allowing live (`active`/`down`) links to update endpoints regardless of
/// `pending_expires_at`.
#[tokio::test]
async fn update_peer_endpoint_refuses_expired_or_cleanup_marked_pending_before_and_after_runner() {
    let (ip_local, ip_peer) = next_loopback_pair();
    let pk_local = fixture_wg_pubkey(237);
    let pk_peer = fixture_wg_pubkey(238);
    let clock = FakeClock::new(1_803_400_000);
    let base_runner = FakePeerRunner::new(pk_local, ip_local, 51821);
    let hooked_runner = HookedPeerRunner::new(Arc::clone(&base_runner));
    base_runner.insert_preexisting_peer(&pk_peer, &ip_peer.to_string(), "10.34.0.2:51821");
    let db = open_isolated_peer_db();
    let rt = build_test_runtime_with_db_and_timeout(
        "local",
        Arc::clone(&db),
        Arc::clone(&hooked_runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );

    let seed_link = |id: &str, state: &str, pending_expires_at: Option<i64>| {
        let now_rfc = rt.now().to_rfc3339();
        let conn = db.lock().unwrap();
        let _ = db_peers::delete_peer_link(&conn, id);
        db_peers::insert_peer_link(
            &conn,
            &PeerLink {
                id: id.to_string(),
                name: "peer-ep".to_string(),
                wg_pubkey: pk_peer.clone(),
                tunnel_ip: ip_peer.to_string(),
                endpoint: "10.34.0.2".to_string(),
                wg_port: 51821,
                state: state.to_string(),
                peer_version: None,
                peer_protocol: None,
                capabilities: None,
                rtt_ms: None,
                last_ok_at: None,
                last_error: None,
                consecutive_failures: 0,
                inbound_token_hash: None,
                pending_attempt_id: None,
                pending_expires_at,
                created_at: now_rfc.clone(),
                updated_at: now_rfc,
            },
        )
        .unwrap();
    };

    // 4A: Cleanup-marked (`pending_expires_at = 0`) pending link -> refused BEFORE SetEndpoint!
    seed_link("ep-link", "pending_owned", Some(0));
    let before = base_runner.set_endpoint_call_count();
    let (st, val) = call_admin(
        &rt,
        Method::PUT,
        "/ep-link/endpoint",
        Some(json!({ "endpoint": "10.34.0.99", "wg_port": 51999 })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "val={val}");
    assert_eq!(val["code"], "PEER_CONFLICT");
    assert_eq!(base_runner.set_endpoint_call_count(), before);
    let unchanged = db_peers::get_peer_link(&db.lock().unwrap(), "ep-link")
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.endpoint, "10.34.0.2");
    assert_eq!(unchanged.pending_expires_at, Some(0));

    // 4B: Exact-expired (`now_ts == pending_expires_at`) pending link -> refused BEFORE SetEndpoint!
    let now_ts = clock.epoch.load(Ordering::SeqCst);
    seed_link("ep-link", "pending_owned", Some(now_ts));
    let (st, val) = call_admin(
        &rt,
        Method::PUT,
        "/ep-link/endpoint",
        Some(json!({ "endpoint": "10.34.0.99", "wg_port": 51999 })),
    )
    .await;
    assert_eq!(st, StatusCode::GONE, "val={val}");
    assert_eq!(val["code"], "CODE_EXPIRED");
    assert_eq!(base_runner.set_endpoint_call_count(), before);

    // 4C-1: Pending link expires (`now_ts == pending_expires_at`) DURING `SetEndpoint` -> guarded
    // SQL write rejects with `410 CODE_EXPIRED` and leaves DB endpoint unchanged!
    let now_ts = clock.epoch.load(Ordering::SeqCst);
    seed_link("ep-link", "pending_owned", Some(now_ts + 30));
    let clock_hook = Arc::clone(&clock);
    hooked_runner.set_after_hook(move |req| {
        if matches!(req, PeerNetworkRequest::SetEndpoint { .. }) {
            clock_hook.advance(30);
        }
    });
    let (st, val) = call_admin(
        &rt,
        Method::PUT,
        "/ep-link/endpoint",
        Some(json!({ "endpoint": "10.34.0.88", "wg_port": 51888 })),
    )
    .await;
    hooked_runner.clear_after_hook();
    assert_eq!(st, StatusCode::GONE, "val={val}");
    assert_eq!(val["code"], "CODE_EXPIRED");
    let unchanged = db_peers::get_peer_link(&db.lock().unwrap(), "ep-link")
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.endpoint, "10.34.0.2");
    assert_eq!(unchanged.wg_port, 51821);

    // 4C-2: Pending link marked `pending_expires_at = 0` DURING `SetEndpoint` -> guarded SQL write
    // rejects with `409 PEER_CONFLICT` and leaves DB endpoint unchanged!
    let now_ts = clock.epoch.load(Ordering::SeqCst);
    seed_link("ep-link", "pending_owned", Some(now_ts + 30));
    let db_hook = Arc::clone(&db);
    hooked_runner.set_after_hook(move |req| {
        if matches!(req, PeerNetworkRequest::SetEndpoint { .. }) {
            db_hook
                .lock()
                .unwrap()
                .execute(
                    "UPDATE peer_links SET pending_expires_at = 0 WHERE id = 'ep-link'",
                    [],
                )
                .unwrap();
        }
    });
    let (st, val) = call_admin(
        &rt,
        Method::PUT,
        "/ep-link/endpoint",
        Some(json!({ "endpoint": "10.34.0.77", "wg_port": 51777 })),
    )
    .await;
    hooked_runner.clear_after_hook();
    assert_eq!(st, StatusCode::CONFLICT, "val={val}");
    assert_eq!(val["code"], "PEER_CONFLICT");
    let unchanged = db_peers::get_peer_link(&db.lock().unwrap(), "ep-link")
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.endpoint, "10.34.0.2");
    assert_eq!(unchanged.pending_expires_at, Some(0));

    // 4D: Live (`active` and `down`) links with `pending_expires_at = Some(0)` or expired expiry
    // MUST still succeed updating their endpoints!
    for (live_state, exp) in [("active", Some(0)), ("down", Some(now_ts - 10))] {
        seed_link("ep-link", live_state, exp);
        let (st, val) = call_admin(
            &rt,
            Method::PUT,
            "/ep-link/endpoint",
            Some(json!({ "endpoint": "10.34.0.55", "wg_port": 51555 })),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "live {live_state} update failed: {val}");
        assert_eq!(val["peer"]["endpoint"], "10.34.0.55");
        assert_eq!(val["peer"]["wg_port"], 51555);
    }
}

/// P3-EXPIRY-01: Inspect `commit_pending_wg_ownership_locked` fallback on ownership DB write
/// failure after `AddPeer` succeeds: never reissue `RemovePeer` after removal succeeds, and never
/// remove an unverified peer (row mutated to `active` or deleted).
#[tokio::test]
async fn commit_pending_wg_ownership_fallback_no_reissued_remove_and_no_unverified_peer_removal() {
    let (ip_a, ip_b) = next_loopback_pair();
    let pk_a = fixture_wg_pubkey(239);
    let pk_b = fixture_wg_pubkey(240);
    let clock = FakeClock::new(1_803_500_000);
    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let hooked_runner_a = HookedPeerRunner::new(Arc::clone(&base_runner_a));
    let db_a = open_isolated_peer_db();
    let rt_a = build_test_runtime_with_db_and_timeout(
        "seedbox-a",
        Arc::clone(&db_a),
        Arc::clone(&hooked_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        TunnelTransportBinding::LoopbackFixture,
        PEER_LOCK_WAIT_TIMEOUT,
    );
    let pairing_string = PairingPayload {
        https_url: "https://media-own.example.test".to_string(),
        wg_pubkey: pk_b.clone(),
        endpoint: "10.35.0.2".to_string(),
        wg_port: 51821,
        tunnel_ip: ip_b.to_string(),
        code: "8888888888888888888888888888888888888888888888888888888888888888".to_string(),
    }
    .encode()
    .unwrap();

    // 5A: `STATE_PENDING` + DB `BEFORE UPDATE` trigger aborts ownership persistence after `AddPeer`
    // succeeds -> fallback verifies exact pending row, issues ONE `RemovePeer`, leaves row unowned
    // (`pending`); later sweep after trigger removal MUST NOT reissue `RemovePeer`!
    {
        let db_hook = Arc::clone(&db_a);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::AddPeer { .. }) {
                db_hook
                    .lock()
                    .unwrap()
                    .execute_batch(
                        "CREATE TRIGGER block_ownership_update BEFORE UPDATE ON peer_links
                         BEGIN SELECT RAISE(ABORT, 'fixture: fail ownership update'); END;",
                    )
                    .unwrap();
            }
        });
        let removes_before = base_runner_a.remove_peer_call_count();
        let (st, val) = call_admin(
            &rt_a,
            Method::POST,
            "/pair",
            Some(json!({
                "pairing_string": pairing_string,
                "name": "media-own",
                "endpoint": "10.35.0.1"
            })),
        )
        .await;
        hooked_runner_a.clear_after_hook();

        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "val={val}");
        assert!(!base_runner_a.has_peer(&pk_b));
        assert_eq!(base_runner_a.remove_peer_call_count(), removes_before + 1);

        // Drop trigger, re-insert an unrelated WG peer with the same key, advance past expiry, and
        // run sweep on a restarted runtime -> MUST delete unowned DB row with ZERO extra RemovePeer!
        {
            let conn = db_a.lock().unwrap();
            conn.execute_batch("DROP TRIGGER block_ownership_update")
                .unwrap();
            let retained = db_peers::list_peer_links(&conn).unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].state, "pending");
        }
        base_runner_a.insert_preexisting_peer(&pk_b, &ip_b.to_string(), "10.35.0.2:51821");
        clock.advance(PAIRING_WINDOW_TTL_SECS + 5);
        let restarted = build_test_runtime_with_db_and_timeout(
            "seedbox-a",
            Arc::clone(&db_a),
            Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        cleanup_expired_pending(&restarted).await;
        assert!(db_peers::list_peer_links(&db_a.lock().unwrap())
            .unwrap()
            .is_empty());
        assert!(
            base_runner_a.has_peer(&pk_b),
            "subsequent sweep must never reissue RemovePeer on an unowned fallback row"
        );
        assert_eq!(base_runner_a.remove_peer_call_count(), removes_before + 1);
        let _ = base_runner_a
            .dispatch(&PeerNetworkRequest::RemovePeer {
                pubkey: pk_b.clone(),
            })
            .await;
    }

    // 5B: `STATE_PENDING_OWNED` + DB `BEFORE UPDATE` trigger aborts ownership re-commit on confirm
    // retry -> fallback MUST NOT issue uncheckpointed direct `RemovePeer`; once DB recovers, sweep
    // consumes `pending_owned -> pending` and removes the peer ONCE (never twice)!
    {
        let (ip_c, ip_d) = next_loopback_pair();
        let pk_c = fixture_wg_pubkey(241);
        let pk_d = fixture_wg_pubkey(242);
        let base_runner_d = FakePeerRunner::new(pk_d.clone(), ip_d, 51821);
        let hooked_runner_d = HookedPeerRunner::new(Arc::clone(&base_runner_d));
        let db_d = open_isolated_peer_db();
        let rt_d = build_test_runtime_with_db_and_timeout(
            "media-d",
            Arc::clone(&db_d),
            Arc::clone(&hooked_runner_d) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            false,
            TunnelTransportBinding::LoopbackFixture,
            PEER_LOCK_WAIT_TIMEOUT,
        );
        let now_ts = clock.epoch.load(Ordering::SeqCst);
        let now_rfc = rt_d.now().to_rfc3339();
        let att_id = "own-retry-trigger-att";
        {
            let conn = db_d.lock().unwrap();
            db_peers::upsert_peer_identity(
                &conn,
                &PeerIdentity {
                    wg_pubkey: pk_d.clone(),
                    tunnel_ip: ip_d.to_string(),
                    wg_port: 51821,
                    created_at: now_rfc.clone(),
                },
            )
            .unwrap();
            db_peers::insert_pairing_attempt(
                &conn,
                &af_db::peers::PairingAttempt {
                    id: att_id.to_string(),
                    window_id: None,
                    remote_name: Some("peer-c".to_string()),
                    remote_pubkey: Some(pk_c.clone()),
                    remote_tunnel_ip: Some(ip_c.to_string()),
                    remote_endpoint: Some("10.35.0.3:51821".to_string()),
                    source_ip: Some("198.51.100.35".to_string()),
                    status: "confirming".to_string(),
                    error_code: None,
                    expires_at: now_ts + 300,
                    created_at: now_rfc.clone(),
                },
            )
            .unwrap();
            db_peers::insert_peer_link(
                &conn,
                &PeerLink {
                    id: "owned-retry-link".to_string(),
                    name: "peer-c".to_string(),
                    wg_pubkey: pk_c.clone(),
                    tunnel_ip: ip_c.to_string(),
                    endpoint: "10.35.0.3".to_string(),
                    wg_port: 51821,
                    state: "pending_owned".to_string(),
                    peer_version: None,
                    peer_protocol: None,
                    capabilities: None,
                    rtt_ms: None,
                    last_ok_at: None,
                    last_error: None,
                    consecutive_failures: 0,
                    inbound_token_hash: None,
                    pending_attempt_id: Some(att_id.to_string()),
                    pending_expires_at: Some(now_ts + 300),
                    created_at: now_rfc.clone(),
                    updated_at: now_rfc,
                },
            )
            .unwrap();
        }
        // Fail UPDATE peer_links ONLY on state='pending_owned' ownership write and subsequent
        // cleanup UPDATEs while trigger is active.
        let db_hook = Arc::clone(&db_d);
        hooked_runner_d.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::AddPeer { .. }) {
                db_hook
                    .lock()
                    .unwrap()
                    .execute_batch(
                        "CREATE TRIGGER block_owned_update BEFORE UPDATE ON peer_links
                         BEGIN SELECT RAISE(ABORT, 'fixture: fail owned update'); END;",
                    )
                    .unwrap();
            }
        });
        let (st, val) = call_admin(
            &rt_d,
            Method::POST,
            &format!("/pairing/{att_id}/confirm"),
            None,
        )
        .await;
        hooked_runner_d.clear_after_hook();

        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "val={val}");
        assert_eq!(
            base_runner_d.remove_peer_call_count(),
            0,
            "already pending_owned row must not bypass checkpointed removal"
        );
        assert!(base_runner_d.has_peer(&pk_c));

        // Drop trigger, expire, sweep: checkpointed cleanup removes peer ONCE and deletes row!
        db_d.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER block_owned_update")
            .unwrap();
        clock.advance(305);
        cleanup_expired_pending(&rt_d).await;
        assert!(!base_runner_d.has_peer(&pk_c));
        assert_eq!(base_runner_d.remove_peer_call_count(), 1);
        assert!(db_peers::list_peer_links(&db_d.lock().unwrap())
            .unwrap()
            .is_empty());
    }

    // 5C: Unverified peer — row concurrently transitioned to `active` during `AddPeer` ->
    // ownership commit gets `changed == 0`, fallback verifies row is NOT pending and issues ZERO
    // `RemovePeer` calls!
    {
        let db_hook = Arc::clone(&db_a);
        hooked_runner_a.set_after_hook(move |req| {
            if matches!(req, PeerNetworkRequest::AddPeer { .. }) {
                db_hook
                    .lock()
                    .unwrap()
                    .execute(
                        "UPDATE peer_links SET state = 'active', pending_expires_at = NULL",
                        [],
                    )
                    .unwrap();
            }
        });
        let removes_before = base_runner_a.remove_peer_call_count();
        let (st, val) = call_admin(
            &rt_a,
            Method::POST,
            "/pair",
            Some(json!({
                "pairing_string": pairing_string,
                "name": "media-own",
                "endpoint": "10.35.0.1"
            })),
        )
        .await;
        hooked_runner_a.clear_after_hook();

        assert_eq!(st, StatusCode::CONFLICT, "val={val}");
        assert_eq!(val["code"], "PEER_CONFLICT");
        assert_eq!(
            base_runner_a.remove_peer_call_count(),
            removes_before,
            "must NEVER remove an unverified / non-pending peer on ownership commit conflict"
        );
        assert!(base_runner_a.has_peer(&pk_b));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. P5 Scoped Peer Grants, Concurrency, Offer, Isolation & Real-Router Dispatch
// ─────────────────────────────────────────────────────────────────────────────

async fn call_admin_raw_body(
    rt: &Arc<PeerRuntime>,
    method: Method,
    uri: &str,
    body: Vec<u8>,
    with_peer_principal: Option<crate::auth::PeerPrincipal>,
) -> (StatusCode, Value) {
    let app = admin_routes_with_runtime(Arc::clone(rt));
    let mut builder = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let mut req = builder.body(Body::from(body)).unwrap();
    req.extensions_mut().insert(admin_user());
    if let Some(principal) = with_peer_principal {
        req.extensions_mut().insert(principal);
    }
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 128 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, json)
}

#[tokio::test]
async fn p5_grant_lifecycle_directional_separation_rotation_idempotent_revoke_and_offer() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_800_500_000);
    let pk_a = fixture_wg_pubkey(111);
    let pk_b = fixture_wg_pubkey(112);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b, db_b) = build_test_runtime(
        "server-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "server-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 31], 45100)),
        }),
        &clock,
        true,
    );

    let (a_link_id, b_link_id, _att) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "server-b").await;
    let mut rev_rx_a = rt_a.subscribe_revocations();

    // 1. Initial GET /grant returns {inbound: null, outbound: null} matching GET /peers.
    let (st, grant_a0) = call_admin(&rt_a, Method::GET, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(grant_a0, json!({ "inbound": null, "outbound": null }));
    let (st, list_a0) = call_admin(&rt_a, Method::GET, "/", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_a0["peers"][0]["grants"], grant_a0);

    // Reject unknown fields and empty grants before issuing credentials.
    for invalid in [
        json!({ "unknown": true }),
        json!({ "access": { "service": "write" } }),
        json!({ "access": {} }),
        json!({ "access": af_db::peers::AccessMap::none() }),
    ] {
        let (st, bad_put) = call_admin(
            &rt_a,
            Method::PUT,
            &format!("/{a_link_id}/grant"),
            Some(invalid),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(bad_put["code"], "INVALID_REQUEST");
    }

    // 3. POST /grant-offer accepts empty body and {} and never changes grant state on either side.
    let b_notif_before = notification_row_count(&db_b);
    let (st, offer1) = call_admin_raw_body(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/grant-offer"),
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "offer1={offer1}");
    assert_eq!(offer1, json!({ "sent": true }));
    let (st, offer2) = call_admin(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/grant-offer"),
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "offer2={offer2}");
    assert_eq!(offer2, json!({ "sent": true }));
    assert_eq!(notification_row_count(&db_b), b_notif_before + 2);
    assert!(audit_entries_text(&db_a).contains("peer_grant_offer_sent"));
    assert!(audit_entries_text(&db_b).contains("peer_grant_offer_received"));
    let (_, ga_after_offer) =
        call_admin(&rt_a, Method::GET, &format!("/{a_link_id}/grant"), None).await;
    let (_, gb_after_offer) =
        call_admin(&rt_b, Method::GET, &format!("/{b_link_id}/grant"), None).await;
    assert_eq!(ga_after_offer, json!({ "inbound": null, "outbound": null }));
    assert_eq!(gb_after_offer, json!({ "inbound": null, "outbound": null }));

    // 4. PUT /grant on A grants B `services: read`, `files: write`.
    let mut partial = af_db::peers::AccessMap::none();
    partial.services = af_db::peers::AccessLevel::Read;
    partial.files = af_db::peers::AccessLevel::Write;
    let (st, saved_a) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": partial })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "saved_a={saved_a}");
    assert!(saved_a["inbound"].is_object());
    assert!(saved_a["outbound"].is_null());
    assert_eq!(saved_a["inbound"]["access"]["services"], "read");
    assert_eq!(saved_a["inbound"]["access"]["files"], "write");
    assert_eq!(saved_a["inbound"]["access"]["users"], "none");
    assert_eq!(saved_a["inbound"]["created_by"], "alice");
    let first_grant_id = saved_a["inbound"]["id"].as_str().unwrap().to_string();
    let run_as_uid = saved_a["inbound"]["run_as_user_id"].as_i64().unwrap();
    assert!(run_as_uid > 0);

    // B sees the exact grant under `outbound` while its own `inbound` stays null!
    let (st, view_b) = call_admin(&rt_b, Method::GET, &format!("/{b_link_id}/grant"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(view_b["inbound"].is_null());
    assert_eq!(view_b["outbound"], saved_a["inbound"]);
    let (st, list_b) = call_admin(&rt_b, Method::GET, "/", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_b["peers"][0]["grants"], view_b);

    // Independent token storage: raw 64-hex token on B (distinct from LinkToken); only sha256 digest on A.
    let b_link_tok = runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .expect("B must hold link token");
    let (_, b_grant_secret_1) =
        super::grants::read_committed_received_grant_token(&rt_b, &b_link_id)
            .await
            .unwrap()
            .expect("B must hold grant token");
    let b_grant_tok_1 = b_grant_secret_1.expose_secret().to_string();
    assert_ne!(b_grant_tok_1, b_link_tok);
    assert_eq!(b_grant_tok_1.len(), 64);

    let a_db_grant = db_peers::get_active_peer_grant_for_link(&db_a.lock().unwrap(), &a_link_id)
        .unwrap()
        .expect("active grant on A");
    let expected_digest_1 = super::pairing::sha256_prefixed(&b_grant_tok_1);
    assert_eq!(
        a_db_grant.token_hash.as_deref(),
        Some(expected_digest_1.as_str())
    );

    // Verify dedicated `peer-server-b` user on A has `account_type = 'peer'` and active quota status.
    {
        let conn = db_a.lock().unwrap();
        let (uname, role, acct, pw): (String, String, String, String) = conn
            .query_row(
                "SELECT username, role, account_type, password_hash FROM users WHERE id = ?1",
                rusqlite::params![run_as_uid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(uname, "peer-server-b");
        assert_eq!(role, "admin");
        assert_eq!(acct, "peer");
        assert!(pw.is_empty());
        let qstatus: String = conn
            .query_row(
                "SELECT status FROM user_quotas WHERE user_id = ?1",
                rusqlite::params![run_as_uid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(qstatus, "active");
    }

    // 5. Grant opposite direction on B for A (`read_write_all`): both directions stay separate.
    let (st, saved_b) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_write_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "saved_b={saved_b}");
    assert!(saved_b["inbound"].is_object());
    assert_eq!(saved_b["outbound"]["id"], first_grant_id);
    let (_, view_a_both) =
        call_admin(&rt_a, Method::GET, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(view_a_both["inbound"]["id"], first_grant_id);
    assert_eq!(view_a_both["outbound"]["id"], saved_b["inbound"]["id"]);

    // 6. Rotate A's inbound grant to read_only_all: emits GrantRevoked for old grant, rotates token.
    let (st, rotated_a) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "rotated_a={rotated_a}");
    let second_grant_id = rotated_a["inbound"]["id"].as_str().unwrap().to_string();
    assert_ne!(second_grant_id, first_grant_id);
    assert_eq!(
        rotated_a["inbound"]["run_as_user_id"].as_i64(),
        Some(run_as_uid)
    );
    let ev = rev_rx_a
        .try_recv()
        .expect("rotation must publish GrantRevoked");
    assert_eq!(
        ev,
        RevocationEvent::GrantRevoked {
            link_id: a_link_id.clone(),
            grant_id: first_grant_id.clone(),
            run_as_user_id: run_as_uid,
        }
    );
    let (b_grant_row_2, b_grant_secret_2) =
        super::grants::read_committed_received_grant_token(&rt_b, &b_link_id)
            .await
            .unwrap()
            .expect("rotated grant token on B");
    let b_grant_slot_2 =
        super::grants::committed_received_grant_credential_id(&b_grant_row_2).to_string();
    let b_grant_tok_2 = b_grant_secret_2.expose_secret().to_string();
    assert_ne!(b_grant_tok_2, b_grant_tok_1);

    // Old grant token is immediately rejected (401 PEER_UNAUTHORIZED) on A's tunnel listener!
    let (old_st, old_body, _) = rt_b
        .send_tunnel_request_with_headers(
            Method::GET,
            &ip_a.to_string(),
            "/api/v1/admin/services",
            Some(&PeerCredentialSecret::new(b_link_tok.clone())),
            &[(HEADER_GRANT_TOKEN.to_string(), b_grant_tok_1.clone())],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(old_st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_slice::<Value>(&old_body).unwrap()["code"],
        "PEER_UNAUTHORIZED"
    );

    // An empty save preserves the already-active grant.
    let (st, all_none_a) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::none() })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "all_none_a={all_none_a}");
    assert_eq!(all_none_a["code"], "INVALID_REQUEST");
    assert!(matches!(
        rev_rx_a.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        super::grants::read_committed_received_grant_token(&rt_b, &b_link_id)
            .await
            .unwrap()
            .map(|(_, secret)| secret.expose_secret().to_string()),
        Some(b_grant_tok_2.clone()),
    );
    let (_, after_empty_save) =
        call_admin(&rt_a, Method::GET, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(after_empty_save, rotated_a);

    // 8. DELETE /grant revokes inbound direction, suspends run-as user, emits GrantRevoked,
    //    clears B's outbound & GrantToken, and preserves link token, tunnel health, and opposite direction!
    let (st, del_a) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(st, StatusCode::OK, "del_a={del_a}");
    assert!(del_a["inbound"].is_null());
    assert_eq!(del_a["outbound"]["id"], saved_b["inbound"]["id"]);
    assert_eq!(
        rev_rx_a.try_recv().unwrap(),
        RevocationEvent::GrantRevoked {
            link_id: a_link_id.clone(),
            grant_id: second_grant_id,
            run_as_user_id: run_as_uid,
        }
    );
    assert!(
        super::grants::read_committed_received_grant_token(&rt_b, &b_link_id)
            .await
            .unwrap()
            .is_none()
            && runner_b
                .credential(PeerCredentialSlot::GrantToken, &b_grant_slot_2)
                .is_none()
            && runner_b
                .credential(PeerCredentialSlot::GrantToken, &b_link_id)
                .is_none(),
        "B must clear GrantToken on remote grant revoke"
    );
    let (_, view_b_after_del) =
        call_admin(&rt_b, Method::GET, &format!("/{b_link_id}/grant"), None).await;
    assert!(view_b_after_del["outbound"].is_null());
    assert!(
        view_b_after_del["inbound"].is_object(),
        "opposite direction grant on B must remain active"
    );

    let quota_status: String = db_a
        .lock()
        .unwrap()
        .query_row(
            "SELECT status FROM user_quotas WHERE user_id = ?1",
            [run_as_uid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(quota_status, "suspended");
    let (overview_status, overview_body, _) = rt_b
        .send_tunnel_request_with_headers(
            Method::GET,
            &ip_a.to_string(),
            "/api/v1/auth/ready",
            Some(&PeerCredentialSecret::new(b_link_tok.clone())),
            &[(HEADER_GRANT_TOKEN.to_string(), b_grant_tok_2.clone())],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(overview_status, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&overview_body).unwrap()["code"],
        "PEER_SCOPE_DENIED",
    );

    // Idempotent second DELETE succeeds cleanly.
    let (st, del_a2) =
        call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(del_a2, del_a);

    // Link token and tunnel health stay intact after grant revocation.
    let (hlth_st, _, _) = rt_b
        .send_tunnel_request(
            Method::GET,
            &ip_a.to_string(),
            "/health",
            Some(&PeerCredentialSecret::new(b_link_tok.clone())),
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(hlth_st, StatusCode::OK);

    // 9. Zero secrets or SHA-256 digests leaked in admin JSON or audit logs on either server.
    let all_serialized = format!(
        "{saved_a}{saved_b}{rotated_a}{all_none_a}{del_a}{view_b}{list_b}{}{}",
        audit_entries_text(&db_a),
        audit_entries_text(&db_b)
    );
    for secret in [
        &b_link_tok,
        &b_grant_tok_1,
        &b_grant_tok_2,
        &expected_digest_1,
    ] {
        assert!(
            !all_serialized.contains(secret.as_str()),
            "secret or digest leaked in response or audit log"
        );
    }

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn p5_grant_delivery_failure_concurrency_p3_interop_and_link_revocation_cleanup() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_800_600_000);
    let pk_a = fixture_wg_pubkey(121);
    let pk_b = fixture_wg_pubkey(122);

    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rt_b, db_b) = build_test_runtime(
        "peer-b-race",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
    );
    let (rt_a, db_a) = build_test_runtime(
        "peer-a-race",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 31], 45100)),
        }),
        &clock,
        true,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "peer-b-race").await;

    // 1. Delivery failure (peer B listener stopped) fails closed without activating any grant.
    rt_b.shutdown_all().await;
    let (st, fail_val) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY, "fail_val={fail_val}");
    assert_eq!(fail_val["code"], "LINK_DOWN");
    assert!(
        db_peers::get_active_peer_grant_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_none(),
        "failed grant delivery must NEVER activate local grant"
    );
    // Run-as user created during prepare must stay suspended!
    {
        let conn = db_a.lock().unwrap();
        let status: String = conn
            .query_row(
                "SELECT q.status FROM user_quotas q JOIN users u ON u.id = q.user_id \
                 WHERE u.account_type = 'peer' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "suspended");
    }

    // 2. Malformed ack & P3 link-only interop (stub server on ip_b).
    let stub_listener = tokio::net::TcpListener::bind(SocketAddr::new(ip_b, 0))
        .await
        .unwrap();
    let stub_port = stub_listener.local_addr().unwrap().port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, stub_port);
    let (stub_tx, mut stub_rx) = tokio::sync::watch::channel(false);
    let stub_app = axum::Router::new()
        .route(
            "/health",
            axum::routing::get(|| async {
                Json(json!({
                    "status": "ok",
                    "version": "4.0.0-p3",
                    "peer_protocol": 1,
                    "capabilities": ["links"]
                }))
            }),
        )
        .route(
            "/peer/v1/grant-token",
            axum::routing::post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "code": "PEER_ROUTE_UNCLASSIFIED",
                        "server": "p3-peer",
                        "step": "tunnel_dispatch",
                        "message": "Route is not an allowed peer internal endpoint",
                        "action": "Upgrade"
                    })),
                )
            }),
        )
        .route(
            "/peer/v1/grant-offer",
            axum::routing::post(|| async { (StatusCode::OK, Json(json!({ "accepted": false }))) }),
        );
    let stub_task = tokio::spawn(async move {
        let _ = axum::serve(stub_listener, stub_app)
            .with_graceful_shutdown(async move {
                while !*stub_rx.borrow() {
                    if stub_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
    });

    // P3 link-only server health check succeeds with compatibility=limited, missing=["grants"].
    runner_a.set_peer_live_state(&pk_b, true, Some(5));
    run_health_tick(&rt_a).await;
    let (_, list_p3) = call_admin(&rt_a, Method::GET, "/", None).await;
    assert_eq!(list_p3["peers"][0]["compatibility"], "limited");
    assert_eq!(
        list_p3["peers"][0]["missing_capabilities"],
        json!(["grants"])
    );

    // PUT /grant against P3 link-only server returns 422 VERSION_INCOMPATIBLE and does not activate.
    let (st, p3_err) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "p3_err={p3_err}");
    assert_eq!(p3_err["code"], "VERSION_INCOMPATIBLE");
    assert!(
        db_peers::get_active_peer_grant_for_link(&db_a.lock().unwrap(), &a_link_id)
            .unwrap()
            .is_none()
    );

    let (offer_status, offer_error) = call_admin(
        &rt_a,
        Method::POST,
        &format!("/{a_link_id}/grant-offer"),
        None,
    )
    .await;
    assert!(!offer_status.is_success());
    assert_eq!(offer_error["code"], "LINK_DOWN");
    assert!(!audit_entries_text(&db_a).contains("peer_grant_offer_sent"));

    let _ = stub_tx.send(true);
    let _ = stub_task.await;

    // 3. Restart B's real listener and execute mutual simultaneous two-way PUT /grant (deadlock test!).
    let b_addr = rt_b.ensure_listener_started().await.unwrap().unwrap();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, b_addr.port());

    let grant_path_a = format!("/{a_link_id}/grant");
    let grant_path_b = format!("/{b_link_id}/grant");
    let (res_a, res_b) = tokio::join!(
        call_admin(
            &rt_a,
            Method::PUT,
            &grant_path_a,
            Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
        ),
        call_admin(
            &rt_b,
            Method::PUT,
            &grant_path_b,
            Some(json!({ "access": af_db::peers::AccessMap::read_write_all() })),
        ),
    );
    assert_eq!(res_a.0, StatusCode::OK, "mutual A->B failed: {:?}", res_a.1);
    assert_eq!(res_b.0, StatusCode::OK, "mutual B->A failed: {:?}", res_b.1);
    let (_, ga) = call_admin(&rt_a, Method::GET, &format!("/{a_link_id}/grant"), None).await;
    let (_, gb) = call_admin(&rt_b, Method::GET, &format!("/{b_link_id}/grant"), None).await;
    assert!(ga["inbound"].is_object() && ga["outbound"].is_object());
    assert!(gb["inbound"].is_object() && gb["outbound"].is_object());

    // 4. Stale generation fencing on receiver (/peer/v1/grant-token & /peer/v1/grant-revoke).
    let a_link_tok = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();
    let (stale_tok_st, stale_tok_body, _) = rt_a
        .send_tunnel_request(
            Method::POST,
            &ip_b.to_string(),
            "/peer/v1/grant-token",
            Some(&PeerCredentialSecret::new(a_link_tok.clone())),
            Some(
                serde_json::to_vec(&json!({
                    "grant_id": "stale-grant-id",
                    "run_as_user_id": 999,
                    "access": af_db::peers::AccessMap::read_write_all(),
                    "created_by": "alice",
                    "created_at": "2026-11-23T00:00:00Z",
                    "generation": 1,
                    "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }))
                .unwrap(),
            ),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(stale_tok_st, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_slice::<Value>(&stale_tok_body).unwrap()["code"],
        "PEER_CONFLICT"
    );

    // 5. Link revocation disables grants and suspends run-as accounts on BOTH sides and emits GrantRevoked!
    let mut rev_rx_a = rt_a.subscribe_revocations();
    let mut rev_rx_b = rt_b.subscribe_revocations();
    let (del_st, del_link) =
        call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}"), None).await;
    assert_eq!(del_st, StatusCode::OK, "del_link={del_link}");
    assert_eq!(del_link["revoked"], true);

    let mut a_events = Vec::new();
    while let Ok(ev) = rev_rx_a.try_recv() {
        a_events.push(ev);
    }
    assert!(
        a_events
            .iter()
            .any(|e| matches!(e, RevocationEvent::GrantRevoked { .. })),
        "local link delete must emit GrantRevoked: {a_events:?}"
    );
    assert!(
        a_events
            .iter()
            .any(|e| matches!(e, RevocationEvent::LinkRevoked { .. })),
        "local link delete must emit LinkRevoked: {a_events:?}"
    );

    let mut b_events = Vec::new();
    while let Ok(ev) = rev_rx_b.try_recv() {
        b_events.push(ev);
    }
    assert!(
        b_events
            .iter()
            .any(|e| matches!(e, RevocationEvent::GrantRevoked { .. })),
        "remote revoke-notice must emit GrantRevoked: {b_events:?}"
    );
    assert!(
        db_peers::get_active_peer_grant_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .is_none(),
        "remote link revocation must revoke B's active inbound grant"
    );
    {
        let conn = db_b.lock().unwrap();
        let b_status: String = conn
            .query_row(
                "SELECT q.status FROM user_quotas q JOIN users u ON u.id = q.user_id \
                 WHERE u.account_type = 'peer' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b_status, "suspended");
    }

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test(flavor = "current_thread")]
async fn p5_scoped_tunnel_dispatch_real_router_headers_host_csrf_backup_and_peer_user_isolation() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-peer-p5-e2e-{}", uuid::Uuid::new_v4()));
    let backup_dir = root.join("backups");
    std::fs::create_dir_all(&backup_dir).unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        std::env::set_var(key, &root);
    }
    let db_path = root.join("p5.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, &db_path);
    }
    std::env::set_var("AETHERFLOW_BACKUP_DIR", &backup_dir);
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::set_var(
        "JWT_SECRET",
        "p5-test-jwt-secret-key-at-least-32-bytes-long",
    );
    std::env::remove_var("CSRF_DISABLED");
    af_db::init_db().unwrap();

    // Seed single human admin with real bcrypt password.
    let pw_hash = bcrypt::hash("SuperSecretAdmin123!", 4).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, email, role, account_type) \
             VALUES (1, 'human-admin', ?1, 'admin@example.test', 'admin', 'human')",
            rusqlite::params![pw_hash],
        )
        .unwrap();
    }

    // Create a genuine verified SQLite backup artifact for backup download testing.
    let created_backup = crate::storage::perform_system_backup().expect("create fixture backup");

    // Set up Server B backed by PeerDb::Production + REAL routes::build_router(), and Server A isolated.
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_800_700_000);
    let pk_a = fixture_wg_pubkey(131);
    let pk_b = fixture_wg_pubkey(132);
    let runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);

    let (rev_tx_b, _) = broadcast::channel(64);
    let rt_b = Arc::new(PeerRuntime {
        db: PeerDb::Production,
        runner: Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        public_transport: Arc::new(UnreachablePublicTransport),
        revocation_tx: rev_tx_b,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: Duration::from_secs(5),
        listen_port: 0,
        max_conn_per_link: 64,
        rtt_warn_ms: 25.0,
        server_name_override: Some("managed-b".to_string()),
        version_override: Some("4.0.0-p5".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: true,
        management_router_override: None,
    });
    let (rt_a, _db_a) = build_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 31], 45100)),
        }),
        &clock,
        true,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "managed-b").await;

    // B grants A read access to services, settings and files.
    let mut read_access = af_db::peers::AccessMap::none();
    read_access.services = af_db::peers::AccessLevel::Read;
    read_access.settings = af_db::peers::AccessLevel::Read;
    read_access.files = af_db::peers::AccessLevel::Read;
    let (st, grant_resp) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": read_access })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "grant_resp={grant_resp}");
    let peer_uid = grant_resp["inbound"]["run_as_user_id"].as_i64().unwrap();

    let a_link_tok = runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();
    let (_, a_grant_secret) = super::grants::read_committed_received_grant_token(&rt_a, &a_link_id)
        .await
        .unwrap()
        .unwrap();
    let a_grant_tok = a_grant_secret.expose_secret().to_string();

    // A. Verify normal browser auth, Host, CSRF, and peer run-as account isolation on REAL build_router().
    let app = crate::routes::build_router();
    let mut ua_hdrs = axum::http::HeaderMap::new();
    ua_hdrs.insert(header::USER_AGENT, "p5-browser-test".parse().unwrap());
    let (human_jwt, _) = crate::auth::create_standard_jwt(1, &ua_hdrs).unwrap();
    let (peer_jwt, _) = crate::auth::create_standard_jwt(peer_uid, &ua_hdrs).unwrap();

    // 1. Untrusted Host rejected for normal browser requests.
    let bad_host = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/services")
                .header(header::HOST, "evil.example")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::BAD_REQUEST);

    // 2. Cookie-auth PUT without CSRF rejected for normal browser requests.
    let bad_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/admin/settings")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::COOKIE, format!("aetherflow_session={human_jwt}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"language":"en"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_csrf.status(), StatusCode::FORBIDDEN);

    // 3. Peer run-as user is rejected by local_login and session JWT middleware!
    let peer_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/public/auth/login")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"peer-manager-a","password":"anypassword"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(peer_login.status(), StatusCode::UNAUTHORIZED);

    let peer_jwt_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/services")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {peer_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(peer_jwt_resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Peer run-as user is hidden from /admin/users and /admin/quotas, undeletable, un-demotable,
    //    and does NOT allow deleting the sole human admin!
    let users_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(users_resp.status(), StatusCode::OK);
    let users_json: Value =
        serde_json::from_slice(&to_bytes(users_resp.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(users_json.as_array().unwrap().len(), 1);
    assert_eq!(users_json[0]["username"], "human-admin");

    let quotas_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/quotas")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(quotas_resp.status(), StatusCode::OK);
    let quotas_json: Value =
        serde_json::from_slice(&to_bytes(quotas_resp.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(quotas_json["quotas"].as_array().unwrap().len(), 1);
    assert_eq!(quotas_json["quotas"][0]["username"], "human-admin");

    let del_peer_user = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/admin/users/{peer_uid}"))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_peer_user.status(), StatusCode::FORBIDDEN);

    let role_peer_user = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/v1/admin/users/{peer_uid}/role"))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"role":"user"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(role_peer_user.status(), StatusCode::FORBIDDEN);

    let del_sole_human = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/admin/users/1")
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        del_sole_human.status(),
        StatusCode::BAD_REQUEST,
        "peer run-as admin must NOT allow deleting the last human admin"
    );

    for (method, uri, body) in [
        (
            Method::GET,
            format!("/api/v1/auth/mcbrowser/policy/{peer_uid}"),
            Body::empty(),
        ),
        (
            Method::PUT,
            "/api/v1/admin/streaming/user-links".to_string(),
            Body::from(
                json!({
                    "afUserId": peer_uid,
                    "provider": "jellyfin",
                    "serverId": "fixture",
                    "providerUserId": "fixture-user",
                })
                .to_string(),
            ),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "p5-browser-test")
                    .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // 5. Defense-in-depth: PeerPrincipal injected directly on admin_routes is rejected!
    let (st, direct_peer_deny) = call_admin_raw_body(
        &rt_b,
        Method::GET,
        "/",
        Vec::new(),
        Some(crate::auth::PeerPrincipal {
            link_id: b_link_id.clone(),
            link_name: "manager-a".to_string(),
            local_server: "managed-b".to_string(),
            grant_id: "g".to_string(),
            run_as_user_id: peer_uid,
            run_as_username: "peer-manager-a".to_string(),
            access: af_db::peers::AccessMap::read_write_all(),
            origin_operator: Some("alice".to_string()),
            request_id: "req-direct".to_string(),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(direct_peer_deny["code"], "PEER_SCOPE_DENIED");

    // B. Scoped tunnel dispatch through REAL build_router() on B's tunnel listener.
    let link_secret = PeerCredentialSecret::new(a_link_tok.clone());

    // 1. Allowed read route + double-slash canonicalization + forged browser/forwarding headers stripped!
    let (st, body, _) = rt_a
        .send_tunnel_request_with_headers(
            Method::GET,
            &ip_b.to_string(),
            "//api//v1/admin/settings",
            Some(&link_secret),
            &[
                (HEADER_GRANT_TOKEN.to_string(), a_grant_tok.clone()),
                (HEADER_ORIGIN_OPERATOR.to_string(), "ops-alice".to_string()),
                ("x-request-id".to_string(), "req-p5-e2e-1".to_string()),
                (
                    "cookie".to_string(),
                    "aetherflow_session=forged".to_string(),
                ),
                ("authorization".to_string(), "Bearer forged".to_string()),
                ("x-forwarded-for".to_string(), "203.0.113.99".to_string()),
                ("x-forwarded-host".to_string(), "evil.example".to_string()),
            ],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        st,
        StatusCode::OK,
        "canonicalized settings read should succeed: {}",
        String::from_utf8_lossy(&body)
    );

    let mut settings: Value = serde_json::from_slice(&body).unwrap();
    settings["language"] = json!("fr");

    // 2. Read overview route succeeds with partial read access.
    let (st, _, _) = rt_a
        .send_tunnel_request_with_headers(
            Method::GET,
            &ip_b.to_string(),
            "/api/v1/auth/ready",
            Some(&link_secret),
            &[(HEADER_GRANT_TOKEN.to_string(), a_grant_tok.clone())],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(st, StatusCode::OK);

    let (head_status, _, _) = rt_a
        .send_tunnel_request_with_headers(
            Method::HEAD,
            &ip_b.to_string(),
            "/api/v1/admin/settings",
            Some(&link_secret),
            &[(HEADER_GRANT_TOKEN.to_string(), a_grant_tok.clone())],
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(head_status, StatusCode::OK);

    // Read-only receipt polling can project status, but must preserve the stored action.
    let queued_action = {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO pending_actions (source, action, status) VALUES ('fixture', 'Observe receipt', 'queued')",
            [],
        )
        .unwrap();
        conn.last_insert_rowid()
    };
    for (path, expected_status) in [
        (
            format!("/api/v1/admin/actions/{queued_action}"),
            "unavailable",
        ),
        (
            "/api/v1/admin/actions/pending?status=queued".into(),
            "queued",
        ),
    ] {
        let (status, body, _) = rt_a
            .send_tunnel_request_with_headers(
                Method::GET,
                &ip_b.to_string(),
                &path,
                Some(&link_secret),
                &[(HEADER_GRANT_TOKEN.to_string(), a_grant_tok.clone())],
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).unwrap();
        let receipt = if path.contains('?') {
            &body["actions"][0]
        } else {
            &body
        };
        assert_eq!(receipt["id"], queued_action);
        assert_eq!(receipt["status"], expected_status);
        assert_eq!(
            af_db::get_pending_action_by_id(queued_action)
                .unwrap()
                .unwrap()
                .status,
            "queued",
        );
    }

    // 3. Denied: write route on read-only area, uncovered area, mutating GETs, forbidden routes,
    //    non-versioned routes, traversal smuggling.
    for (method, path, expected_code) in [
        (Method::PUT, "/api/v1/admin/settings", "PEER_SCOPE_DENIED"),
        (Method::GET, "/api/v1/admin/users", "PEER_SCOPE_DENIED"),
        (
            Method::GET,
            "/api/v1/auth/mcbrowser/uploads",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::HEAD,
            "/api/v1/auth/mcbrowser/uploads/sample-id",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::GET,
            "/api/v1/auth/mcbrowser/policy/1",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::GET,
            &format!("/api/v1/admin/backup/download/{}", created_backup.filename),
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::POST,
            &format!("/api/v1/admin/backup/download/{}", created_backup.filename),
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::GET,
            "/api/v1/auth/mcbrowser/archive/tkt-1",
            "PEER_SCOPE_DENIED",
        ),
        (Method::GET, "/api/v1/admin/peers", "PEER_SCOPE_DENIED"),
        (
            Method::PUT,
            &format!("/api/v1/admin/peers/{b_link_id}/grant"),
            "PEER_SCOPE_DENIED",
        ),
        (Method::GET, "/api/v1/auth/session", "PEER_SCOPE_DENIED"),
        (
            Method::POST,
            "/api/v1/admin/oidc/clients",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::POST,
            "/api/v1/admin/plugins/demo/token",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::POST,
            "/api/v1/admin/apps/launch",
            "PEER_SCOPE_DENIED",
        ),
        (Method::GET, "/api/v1/auth/ws", "PEER_SCOPE_DENIED"),
        (
            Method::GET,
            "/api/admin/settings",
            "PEER_ROUTE_UNCLASSIFIED",
        ),
        // The HTTP client resolves the dot segment. The listener then denies the
        // resulting peer-admin route. The canonicalization unit test covers the raw path.
        (
            Method::GET,
            "/api/v1/admin/%2e%2e/admin/peers",
            "PEER_SCOPE_DENIED",
        ),
        (
            Method::GET,
            "/api/v1/admin/unknown-route-xyz",
            "PEER_ROUTE_UNCLASSIFIED",
        ),
    ] {
        let (st, resp_body, _) = rt_a
            .send_tunnel_request_with_headers(
                method.clone(),
                &ip_b.to_string(),
                path,
                Some(&link_secret),
                &[(HEADER_GRANT_TOKEN.to_string(), a_grant_tok.clone())],
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(st, StatusCode::FORBIDDEN, "for {method} {path}");
        if method != Method::HEAD {
            let parsed: Value = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(
                parsed["code"], expected_code,
                "for {method} {path}: {parsed}"
            );
        }
    }

    // 4. Upgrade grant to `settings: write`: mutating PUT (no CSRF) AND backup password-recheck
    //    GET/POST both succeed cleanly via PeerPrincipal, while browser without password still gets 403!
    let mut write_settings = af_db::peers::AccessMap::none();
    write_settings.settings = af_db::peers::AccessLevel::Write;
    let (st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": write_settings })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (_, a_grant_secret_write) =
        super::grants::read_committed_received_grant_token(&rt_a, &a_link_id)
            .await
            .unwrap()
            .unwrap();
    let a_grant_tok_write = a_grant_secret_write.expose_secret().to_string();

    let denied_settings_updates = [
        (
            "baseDomain",
            "fixture.example.test",
            "req-p5-deny-domain",
            "Network and Marketplace",
        ),
        ("updateChannel", "nightly", "req-p5-deny-channel", "Updates"),
    ];
    for (field, value, request_id, required_areas) in denied_settings_updates {
        let mut cross_area_update = settings.clone();
        cross_area_update[field] = json!(value);
        let (status, body, _) = rt_a
            .send_tunnel_request_with_headers(
                Method::PUT,
                &ip_b.to_string(),
                "/api/v1/admin/settings",
                Some(&link_secret),
                &[
                    (HEADER_GRANT_TOKEN.to_string(), a_grant_tok_write.clone()),
                    ("x-request-id".to_string(), request_id.to_string()),
                ],
                Some(serde_json::to_vec(&cross_area_update).unwrap()),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN, "{field}");
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["code"], "PEER_SCOPE_DENIED");
        assert_eq!(error["server"], "managed-b");
        assert!(error["message"].as_str().unwrap().contains(required_areas));
    }

    let (st, put_body, _) = rt_a
        .send_tunnel_request_with_headers(
            Method::PUT,
            &ip_b.to_string(),
            "/api/v1/admin/settings",
            Some(&link_secret),
            &[
                (HEADER_GRANT_TOKEN.to_string(), a_grant_tok_write.clone()),
                (HEADER_ORIGIN_OPERATOR.to_string(), "ops-alice".to_string()),
                ("x-request-id".to_string(), "req-p5-write-1".to_string()),
            ],
            Some(serde_json::to_vec(&settings).unwrap()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        st,
        StatusCode::OK,
        "settings write without CSRF must succeed with PeerPrincipal: {}",
        String::from_utf8_lossy(&put_body)
    );

    let stored_language: String = af_db::get_read_conn()
        .unwrap()
        .query_row("SELECT language FROM settings WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored_language, "fr");

    // Browser admin without password on backup download still gets 403!
    let browser_no_pw = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/backup/download/{}",
                    created_backup.filename
                ))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p5-browser-test")
                .header(header::AUTHORIZATION, format!("Bearer {human_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(browser_no_pw.status(), StatusCode::FORBIDDEN);

    // Peer with `settings: write` satisfies backup password re-check on both POST and GET!
    let (prep_st, prep_body, _) = rt_a
        .send_tunnel_request_with_headers(
            Method::POST,
            &ip_b.to_string(),
            &format!("/api/v1/admin/backup/download/{}", created_backup.filename),
            Some(&link_secret),
            &[(HEADER_GRANT_TOKEN.to_string(), a_grant_tok_write.clone())],
            Some(b"{}".to_vec()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        prep_st,
        StatusCode::OK,
        "backup prepare failed: {}",
        String::from_utf8_lossy(&prep_body)
    );

    // The management listener streams the download. The control-message helper
    // buffers and caps replies, so use the same bound HTTP client directly.
    let binding = rt_a.resolve_outbound_tunnel_binding(ip_b).await.unwrap();
    let client = rt_a.get_or_build_tunnel_client(&binding).unwrap();
    let download_url = rt_a
        .build_tunnel_url(
            &ip_b.to_string(),
            &format!("/api/v1/admin/backup/download/{}", created_backup.filename),
        )
        .unwrap();
    let download = client
        .get(download_url)
        .header(super::HEADER_LINK_TOKEN, link_secret.expose_secret())
        .header(HEADER_GRANT_TOKEN, &a_grant_tok_write)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    let dl_body = download.bytes().await.unwrap();
    assert!(
        dl_body.starts_with(b"SQLite format 3\0"),
        "expected valid SQLite backup stream"
    );

    // 5. Audit log on B records trusted peer identity, origin operator, and request IDs with zero secrets.
    let audit_rows: Vec<(i64, String, String, String)> = {
        let conn = af_db::get_read_conn().unwrap();
        let mut stmt = conn
            .prepare("SELECT user_id, username, action, detail FROM admin_audit_log")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    };
    assert!(
        audit_rows.iter().any(|(uid, uname, action, detail)| {
            *uid == peer_uid
                && uname == "peer-manager-a"
                && action == "peer_management_allowed"
                && detail.contains("via manager-a")
                && detail.contains("operator=ops-alice")
                && detail.contains("request_id=req-p5-e2e-1")
        }),
        "expected trusted peer audit row: {audit_rows:?}"
    );
    assert!(
        audit_rows
            .iter()
            .any(|(_, _, action, _)| action == "peer_management_denied"),
        "expected denied management audit row"
    );
    for (_, _, request_id, required_areas) in denied_settings_updates {
        let rows: Vec<_> = audit_rows
            .iter()
            .filter(|(_, _, _, detail)| detail.contains(&format!("request_id={request_id},")))
            .collect();
        assert_eq!(rows.len(), 1, "{request_id} audit rows: {rows:?}");
        let (user_id, username, action, detail) = rows[0];
        assert_eq!(*user_id, peer_uid);
        assert_eq!(username, "peer-manager-a");
        assert_eq!(action, "peer_management_denied");
        assert!(detail.contains("PUT /api/v1/admin/settings via manager-a"));
        assert!(detail.contains("server=managed-b"));
        assert!(detail.contains("code=PEER_SCOPE_DENIED, step=update_settings"));
        assert!(detail.contains(required_areas));
    }
    let audit_blob = format!("{audit_rows:?}");
    assert!(!audit_blob.contains(&a_link_tok));
    assert!(!audit_blob.contains(&a_grant_tok));
    assert!(!audit_blob.contains(&a_grant_tok_write));
    assert!(!audit_blob.contains("unknown-route-xyz"));

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    let _ = std::fs::remove_dir_all(&root);
}
