//! Peer clustering control plane, tunnel listener lifecycle, pairing, health, and link management.

pub mod errors;
pub mod grants;
pub mod health;
pub mod links;
pub mod listener;
pub mod pairing;
pub mod proxy;
pub mod scopes;

#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
mod tests;

use af_runner::{PeerCredentialSecret, PeerNetworkError, PeerNetworkRequest, PeerNetworkResponse};
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::{DateTime, Utc};
use errors::{redact_sensitive_text, PeerError};
use futures::future::BoxFuture;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use std::sync::RwLock;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch, Mutex as TokioMutex, OwnedMutexGuard, Semaphore};
use url::Url;

pub const PEER_PROTOCOL_VERSION: i64 = 1;
pub const MIN_PEER_PROTOCOL_VERSION: i64 = 1;
pub const DEFAULT_PEER_LISTEN_PORT: u16 = 9443;
pub const DEFAULT_PEER_MAX_CONN: usize = 64;
pub const DEFAULT_PEER_MAX_WS: usize = 16;
pub const DEFAULT_PEER_PROXY_HEADER_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_PEER_RTT_WARN_MS: f64 = 25.0;
pub const PUBLIC_PAIRING_BODY_LIMIT_BYTES: usize = 4096;
pub const HEADER_LINK_TOKEN: &str = "x-af-link-token";
pub const HEADER_GRANT_TOKEN: &str = "x-af-grant-token";
pub const HEADER_ORIGIN_OPERATOR: &str = "x-af-origin-operator";

/// Internal durable `peer_links.state` values encoding both lifecycle state and affirmative
/// WireGuard (`afpeer0`) peer ownership within the existing schema.
///
/// Ownership invariants:
/// - Newly reserved pending rows always start as [`STATE_PENDING`] (unowned).
/// - Only a definitive successful `PeerNetworkRequest::AddPeer` (`Ok(Mutation)`) may promote a
///   pending row to [`STATE_PENDING_OWNED`].
/// - `PeerAlreadyExists` (reconciled), `Conflict`, `TunnelIpConflict`, `Busy`, ambiguous runner
///   errors, and crashes before durable commit never establish ownership; uncertain outcomes
///   preserve the WireGuard peer for explicit reconciliation or re-pairing.
/// - Guarded SQL lifecycle transitions preserve ownership across the full lifecycle:
///   - Owned: `pending_owned` -> `active` <-> `down` -> `revoked` / `revoking`
///   - Unowned: `pending` -> `active_unowned` <-> `down_unowned` -> `revoked_unowned` / `revoking_unowned`
/// - Destructive `RemovePeer` cleanup is permitted only when [`is_wg_peer_owned`] is `true`
///   (explicit affirmative allowlist) and no other `peer_links` row shares the public key.
/// - [`public_link_state`] normalizes all internal states back to `"pending" | "active" | "down" |
///   "revoked"` before exposing them in admin or tunnel JSON responses.
pub(crate) const STATE_PENDING: &str = "pending";
pub(crate) const STATE_PENDING_OWNED: &str = "pending_owned";
pub(crate) const STATE_ACTIVE: &str = "active";
pub(crate) const STATE_ACTIVE_UNOWNED: &str = "active_unowned";
pub(crate) const STATE_DOWN: &str = "down";
pub(crate) const STATE_DOWN_UNOWNED: &str = "down_unowned";
pub(crate) const STATE_REVOKED: &str = "revoked";
pub(crate) const STATE_REVOKED_UNOWNED: &str = "revoked_unowned";
pub(crate) const STATE_REVOKING: &str = "revoking";
pub(crate) const STATE_REVOKING_UNOWNED: &str = "revoking_unowned";

/// Affirmative durable WireGuard peer ownership predicate (fail-closed allowlist).
pub(crate) fn is_wg_peer_owned(state: &str) -> bool {
    matches!(
        state,
        STATE_PENDING_OWNED | STATE_ACTIVE | STATE_DOWN | STATE_REVOKED | STATE_REVOKING
    )
}

pub(crate) fn is_pending_link_state(state: &str) -> bool {
    matches!(state, STATE_PENDING | STATE_PENDING_OWNED)
}

pub(crate) fn is_active_link_state(state: &str) -> bool {
    matches!(state, STATE_ACTIVE | STATE_ACTIVE_UNOWNED)
}

pub(crate) fn is_down_link_state(state: &str) -> bool {
    matches!(state, STATE_DOWN | STATE_DOWN_UNOWNED)
}

pub(crate) fn is_live_link_state(state: &str) -> bool {
    is_active_link_state(state) || is_down_link_state(state)
}

pub(crate) fn is_revoked_state(state: &str) -> bool {
    matches!(state, STATE_REVOKED | STATE_REVOKED_UNOWNED)
}

pub(crate) fn is_revoking_state(state: &str) -> bool {
    matches!(state, STATE_REVOKING | STATE_REVOKING_UNOWNED)
}

pub(crate) fn is_revoked_or_revoking_state(state: &str) -> bool {
    is_revoked_state(state) || is_revoking_state(state)
}

/// Projects internal durable `peer_links.state` values to public API/tunnel lifecycle states so
/// internal ownership or revocation-retry markers are never exposed externally.
pub(crate) fn public_link_state(state: &str) -> &str {
    match state {
        STATE_PENDING | STATE_PENDING_OWNED => "pending",
        STATE_ACTIVE | STATE_ACTIVE_UNOWNED => "active",
        STATE_DOWN | STATE_DOWN_UNOWNED => "down",
        STATE_REVOKED | STATE_REVOKED_UNOWNED | STATE_REVOKING | STATE_REVOKING_UNOWNED => {
            "revoked"
        }
        other => other,
    }
}

/// Capabilities advertised on `/health` and tunnel `/health`.
///
/// P5 advertises `["links", "grants"]` once scoped grant issuance, revocation, reciprocal grant
/// offers, and scoped tunnel management dispatch are enabled.
pub fn capabilities() -> Vec<&'static str> {
    vec!["links", "grants"]
}

/// Broadcast events published whenever a link or grant is revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationEvent {
    LinkRevoked {
        link_id: String,
        peer_name: String,
    },
    #[allow(dead_code)]
    GrantRevoked {
        link_id: String,
        grant_id: String,
        run_as_user_id: i64,
    },
}

/// Detected non-loopback local network address candidate for the WireGuard endpoint picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectedEndpoint {
    pub interface: String,
    pub address: String,
    pub family: &'static str,
    pub recommended: bool,
}

/// Privileged runner abstraction so production calls `af_runner::dispatch_peer_network`
/// while local tests inject deterministic fake runner replies without host privileges.
pub(crate) trait PeerRunner: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerNetworkRequest,
    ) -> BoxFuture<'a, Result<PeerNetworkResponse, PeerNetworkError>>;
}

struct ProductionPeerRunner;

impl PeerRunner for ProductionPeerRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerNetworkRequest,
    ) -> BoxFuture<'a, Result<PeerNetworkResponse, PeerNetworkError>> {
        Box::pin(af_runner::dispatch_peer_network(req))
    }
}

/// Outbound HTTPS public pairing transport.
///
/// Production always uses strict TLS certificate validation (`rustls-tls`, never
/// `danger_accept_invalid_certs`) with redirects disabled.
pub(crate) trait PublicPairingTransport: Send + Sync {
    fn post_pairing_request<'a>(
        &'a self,
        url: Url,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>>;
}

pub(crate) struct ProductionPublicPairingTransport {
    client: reqwest::Client,
}

impl ProductionPublicPairingTransport {
    pub(crate) fn new() -> Self {
        let client = build_strict_public_pairing_client();
        Self { client }
    }
}

pub(crate) fn build_strict_public_pairing_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
        .expect("strict public pairing reqwest client")
}

impl PublicPairingTransport for ProductionPublicPairingTransport {
    fn post_pairing_request<'a>(
        &'a self,
        url: Url,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Result<(StatusCode, Vec<u8>), String>> {
        Box::pin(async move {
            if url.scheme() != "https" {
                return Err("Public pairing endpoint must use https://".to_string());
            }
            let resp = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|err| redact_sensitive_text(&err.to_string()))?;
            let status = resp.status();
            if status.is_redirection() {
                return Err(format!(
                    "Target server attempted an HTTP redirect ({}) during public pairing; redirects are refused",
                    status.as_u16()
                ));
            }
            let bytes = read_bounded_reqwest_body(resp, 64 * 1024).await?;
            Ok((status, bytes))
        })
    }
}

/// Bounded body reader for peer HTTP responses.
async fn read_bounded_reqwest_body(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|err| redact_sensitive_text(&err.to_string()))?
    {
        if chunk.len() > max_bytes.saturating_sub(out.len()) {
            return Err("Peer response body exceeded maximum allowed size".to_string());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Database handle supporting both the global production SQLite pools and isolated test DBs.
#[derive(Clone)]
pub(crate) enum PeerDb {
    Production,
    #[cfg(test)]
    Isolated(Arc<StdMutex<rusqlite::Connection>>),
}

impl PeerDb {
    pub(crate) async fn read<F, R>(&self, server: &str, step: &str, f: F) -> Result<R, PeerError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<R, PeerError> + Send + 'static,
        R: Send + 'static,
    {
        let server_s = server.to_string();
        let step_s = step.to_string();
        match self {
            Self::Production => tokio::task::spawn_blocking(move || {
                let conn = af_db::get_read_conn().map_err(|err| {
                    PeerError::internal(
                        &server_s,
                        &step_s,
                        format!("Database read connection unavailable: {err}"),
                    )
                })?;
                f(&conn)
            })
            .await
            .map_err(|_| {
                PeerError::internal(server, step, "Database worker task terminated unexpectedly")
            })?,
            #[cfg(test)]
            Self::Isolated(conn_arc) => {
                let guard = conn_arc.lock().unwrap_or_else(|e| e.into_inner());
                let _ = af_db::peers::ensure_peer_grant_schema_invariants(&guard);
                f(&guard)
            }
        }
    }

    pub(crate) async fn write<F, R>(&self, server: &str, step: &str, f: F) -> Result<R, PeerError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<R, PeerError> + Send + 'static,
        R: Send + 'static,
    {
        let server_s = server.to_string();
        let step_s = step.to_string();
        match self {
            Self::Production => tokio::task::spawn_blocking(move || {
                let conn = af_db::get_conn().map_err(|err| {
                    PeerError::internal(
                        &server_s,
                        &step_s,
                        format!("Database write connection unavailable: {err}"),
                    )
                })?;
                f(&conn)
            })
            .await
            .map_err(|_| {
                PeerError::internal(server, step, "Database worker task terminated unexpectedly")
            })?,
            #[cfg(test)]
            Self::Isolated(conn_arc) => {
                let guard = conn_arc.lock().unwrap_or_else(|e| e.into_inner());
                let _ = af_db::peers::ensure_peer_grant_schema_invariants(&guard);
                f(&guard)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_audit(
        &self,
        user_id: i64,
        username: String,
        action: String,
        target_type: String,
        target_id: String,
        detail: String,
        ip_address: String,
        user_agent: String,
    ) {
        let safe_detail = redact_sensitive_text(&detail);
        match self {
            Self::Production => {
                let _ = tokio::task::spawn_blocking(move || {
                    af_db::record_audit(
                        user_id,
                        &username,
                        &action,
                        &target_type,
                        &target_id,
                        &safe_detail,
                        &ip_address,
                        &user_agent,
                    );
                })
                .await;
            }
            #[cfg(test)]
            Self::Isolated(conn_arc) => {
                let guard = conn_arc.lock().unwrap_or_else(|e| e.into_inner());
                let _ = guard.execute(
                    "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        user_id,
                        username,
                        action,
                        target_type,
                        target_id,
                        safe_detail,
                        ip_address,
                        user_agent,
                    ],
                );
            }
        }
    }

    pub(crate) async fn emit_notification(&self, level: &str, title: String, message: String) {
        let level = level.to_string();
        let safe_title = redact_sensitive_text(&title);
        let safe_message = redact_sensitive_text(&message);
        match self {
            Self::Production => {
                let _ = tokio::task::spawn_blocking(move || {
                    if let Ok(conn) = af_db::get_conn() {
                        let _ = conn.execute(
                            "INSERT INTO notifications (user_id, level, title, message, read) VALUES (NULL, ?1, ?2, ?3, 0)",
                            rusqlite::params![level, safe_title, safe_message],
                        );
                    }
                })
                .await;
            }
            #[cfg(test)]
            Self::Isolated(conn_arc) => {
                let guard = conn_arc.lock().unwrap_or_else(|e| e.into_inner());
                let _ = guard.execute(
                    "INSERT INTO notifications (user_id, level, title, message, read) VALUES (NULL, ?1, ?2, ?3, 0)",
                    rusqlite::params![level, safe_title, safe_message],
                );
            }
        }
    }
}

pub(crate) const PEER_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RETAINED_LOCK_WEAKS: usize = 128;
const MAX_CACHED_TUNNEL_CLIENTS: usize = 8;

/// Bounded per-key async lock pool backed by weak references so idle keys do not accumulate.
#[derive(Default)]
pub(crate) struct KeyedAsyncLockPool {
    entries: StdMutex<HashMap<String, Weak<TokioMutex<()>>>>,
}

pub(crate) struct KeyedLockGuard {
    _permit: OwnedMutexGuard<()>,
    _arc: Arc<TokioMutex<()>>,
}

impl KeyedAsyncLockPool {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn acquire(
        &self,
        key: &str,
        timeout: Duration,
        server: &str,
        step: &str,
    ) -> Result<KeyedLockGuard, PeerError> {
        let lock_arc = {
            let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if map.len() > MAX_RETAINED_LOCK_WEAKS {
                map.retain(|_, weak| weak.strong_count() > 0);
            }
            if let Some(existing) = map.get(key).and_then(Weak::upgrade) {
                existing
            } else {
                let fresh = Arc::new(TokioMutex::new(()));
                map.insert(key.to_string(), Arc::downgrade(&fresh));
                fresh
            }
        };

        let permit = tokio::time::timeout(timeout, Arc::clone(&lock_arc).lock_owned())
            .await
            .map_err(|_| {
                PeerError::busy(
                    server,
                    step,
                    "Another operation is already in progress for this peer or pairing attempt",
                )
            })?;
        Ok(KeyedLockGuard {
            _permit: permit,
            _arc: lock_arc,
        })
    }

    pub(crate) fn try_acquire(
        &self,
        key: &str,
        server: &str,
        step: &str,
    ) -> Result<KeyedLockGuard, PeerError> {
        let lock_arc = {
            let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if map.len() > MAX_RETAINED_LOCK_WEAKS {
                map.retain(|_, weak| weak.strong_count() > 0);
            }
            if let Some(existing) = map.get(key).and_then(Weak::upgrade) {
                existing
            } else {
                let fresh = Arc::new(TokioMutex::new(()));
                map.insert(key.to_string(), Arc::downgrade(&fresh));
                fresh
            }
        };

        let permit = Arc::clone(&lock_arc).try_lock_owned().map_err(|_| {
            PeerError::busy(
                server,
                step,
                "Another operation is already in progress for this peer or pairing attempt",
            )
        })?;
        Ok(KeyedLockGuard {
            _permit: permit,
            _arc: lock_arc,
        })
    }
}

/// Transport binding mode for inbound TCP peer listener and outbound HTTP tunnel requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TunnelTransportBinding {
    /// Production mode: bind strictly to the dedicated WireGuard interface (`afpeer0`) via
    /// `SO_BINDTODEVICE` AND the stored local non-loopback tunnel IP.
    WireGuardInterface(String),
    /// Local test-only mode: bind strictly to the stored local loopback tunnel IP (`127.0.0.0/8`
    /// or `::1`), refusing non-loopback sources or targets without modifying host networking.
    #[cfg(test)]
    LoopbackFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TunnelClientBindingKey {
    pub(crate) local_ip: IpAddr,
    pub(crate) interface: Option<String>,
}

pub(crate) struct ListenerHandle {
    pub(crate) tunnel_ip: IpAddr,
    pub(crate) interface: Option<String>,
    pub(crate) bound_addr: SocketAddr,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

/// Errors produced when executing an outbound HTTP request over the WireGuard tunnel.
#[derive(Debug, Clone)]
pub(crate) enum TunnelHttpError {
    Timeout(String),
    Unreachable(String),
    InvalidTarget(String),
}

impl TunnelHttpError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Timeout(m) | Self::Unreachable(m) | Self::InvalidTarget(m) => m,
        }
    }
}

type ClockFn = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;
type MonotonicClockFn = Arc<dyn Fn() -> Duration + Send + Sync>;

/// Extension attached by the peer tunnel listener so downstream handlers (such as WebSocket
/// ticket issuance and live revocation subscriptions) bind strictly to the originating
/// `PeerRuntime` in both production and isolated multi-server test fixtures.
#[derive(Clone)]
pub struct PeerListenerRuntime(pub(crate) Arc<PeerRuntime>);

/// Extension carrying a per-link WebSocket semaphore permit from the peer tunnel listener into an
/// upgraded WebSocket task so the permit stays held for the full socket lifetime and releases
/// immediately on rejection, disconnect, or revocation.
#[derive(Clone)]
pub struct PeerWsPermit(pub(crate) Arc<StdMutex<Option<tokio::sync::OwnedSemaphorePermit>>>);

impl PeerWsPermit {
    pub(crate) fn new(permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self(Arc::new(StdMutex::new(Some(permit))))
    }

    pub(crate) fn take(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Shared runtime state for peer clustering.
pub struct PeerRuntime {
    pub(crate) db: PeerDb,
    pub(crate) runner: Arc<dyn PeerRunner>,
    pub(crate) public_transport: Arc<dyn PublicPairingTransport>,
    pub(crate) revocation_tx: broadcast::Sender<RevocationEvent>,
    pub(crate) pairing_rate_limiter: pairing::PairingRateLimiter,
    /// Canonical per-attempt pairing lock (always acquired BEFORE `link_locks` when both are needed,
    /// and never held across outbound HTTP).
    pub(crate) attempt_locks: KeyedAsyncLockPool,
    /// Canonical per-link lock serializing endpoint updates, link revocations/cleanups, pending
    /// sweeps, AND grant receiver writes/revokes/credential cleanups so revalidated live link
    /// ownership surrounds all credential I/O. Never held across outbound tunnel HTTP.
    pub(crate) link_locks: KeyedAsyncLockPool,
    pub(crate) link_semaphores: StdMutex<HashMap<String, Weak<Semaphore>>>,
    pub(crate) link_ws_semaphores: StdMutex<HashMap<String, Weak<Semaphore>>>,
    pub(crate) tunnel_clients: StdMutex<HashMap<TunnelClientBindingKey, reqwest::Client>>,
    pub(crate) proxy_tunnel_clients: StdMutex<HashMap<TunnelClientBindingKey, reqwest::Client>>,
    pub(crate) listener_state: TokioMutex<Option<ListenerHandle>>,
    pub(crate) health_shutdown: TokioMutex<Option<watch::Sender<bool>>>,
    pub(crate) clock: ClockFn,
    pub(crate) monotonic_clock: MonotonicClockFn,
    pub(crate) lock_wait_timeout: Duration,
    pub(crate) listen_port: u16,
    pub(crate) max_conn_per_link: usize,
    pub(crate) max_ws_per_link: usize,
    pub(crate) proxy_header_timeout: Duration,
    pub(crate) rtt_warn_ms: f64,
    pub(crate) server_name_override: Option<String>,
    pub(crate) version_override: Option<String>,
    pub(crate) tunnel_binding: TunnelTransportBinding,
    pub(crate) tunnel_request_timeout: Duration,
    #[cfg(test)]
    pub(crate) tunnel_port_overrides: RwLock<HashMap<IpAddr, u16>>,
    #[cfg(test)]
    pub(crate) bind_listener_in_handlers: bool,
    #[cfg(test)]
    pub(crate) management_router_override: Option<Router>,
}

static GLOBAL_RUNTIME: Lazy<Arc<PeerRuntime>> = Lazy::new(|| Arc::new(PeerRuntime::production()));

impl PeerRuntime {
    pub fn global() -> Arc<Self> {
        Arc::clone(&GLOBAL_RUNTIME)
    }

    pub fn production() -> Self {
        let (revocation_tx, _) = broadcast::channel(128);
        let monotonic_origin = Instant::now();
        Self {
            db: PeerDb::Production,
            runner: Arc::new(ProductionPeerRunner),
            public_transport: Arc::new(ProductionPublicPairingTransport::new()),
            revocation_tx,
            pairing_rate_limiter: pairing::PairingRateLimiter::new(
                pairing::PAIRING_RATE_LIMIT_PER_MIN,
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
            clock: Arc::new(Utc::now),
            monotonic_clock: Arc::new(move || monotonic_origin.elapsed()),
            lock_wait_timeout: PEER_LOCK_WAIT_TIMEOUT,
            listen_port: configured_peer_listen_port(),
            max_conn_per_link: configured_peer_max_conn(),
            max_ws_per_link: configured_peer_max_ws(),
            proxy_header_timeout: Duration::from_secs(DEFAULT_PEER_PROXY_HEADER_TIMEOUT_SECS),
            rtt_warn_ms: configured_peer_rtt_warn_ms(),
            server_name_override: None,
            version_override: None,
            tunnel_binding: TunnelTransportBinding::WireGuardInterface(
                af_runner::peer_network::PEER_WG_INTERFACE.to_string(),
            ),
            tunnel_request_timeout: Duration::from_secs(10),
            #[cfg(test)]
            tunnel_port_overrides: RwLock::new(HashMap::new()),
            #[cfg(test)]
            bind_listener_in_handlers: true,
            #[cfg(test)]
            management_router_override: None,
        }
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    pub(crate) fn monotonic_now(&self) -> Duration {
        (self.monotonic_clock)()
    }

    pub(crate) async fn lock_attempt(
        &self,
        attempt_id: &str,
        step: &str,
    ) -> Result<KeyedLockGuard, PeerError> {
        self.attempt_locks
            .acquire(
                attempt_id,
                self.lock_wait_timeout,
                &self.local_server_name(),
                step,
            )
            .await
    }

    pub(crate) async fn lock_link(
        &self,
        link_id: &str,
        step: &str,
    ) -> Result<KeyedLockGuard, PeerError> {
        self.link_locks
            .acquire(
                link_id,
                self.lock_wait_timeout,
                &self.local_server_name(),
                step,
            )
            .await
    }

    pub(crate) fn try_lock_link(
        &self,
        link_id: &str,
        step: &str,
    ) -> Result<KeyedLockGuard, PeerError> {
        self.link_locks
            .try_acquire(link_id, &self.local_server_name(), step)
    }

    pub(crate) fn local_server_name(&self) -> String {
        if let Some(ref name) = self.server_name_override {
            return name.clone();
        }
        resolve_local_server_name()
    }

    pub(crate) fn local_version(&self) -> String {
        if let Some(ref ver) = self.version_override {
            return ver.clone();
        }
        af_runner::af_release::runtime::runtime_identity()
            .version
            .clone()
    }

    pub fn subscribe_revocations(&self) -> broadcast::Receiver<RevocationEvent> {
        self.revocation_tx.subscribe()
    }

    pub(crate) fn publish_revocation(&self, event: RevocationEvent) {
        let _ = self.revocation_tx.send(event);
    }

    pub(crate) fn acquire_link_permit(
        &self,
        link_key: &str,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = {
            let mut map = self
                .link_semaphores
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if map.len() > MAX_RETAINED_LOCK_WEAKS {
                map.retain(|_, weak| weak.strong_count() > 0);
            }
            if let Some(existing) = map.get(link_key).and_then(Weak::upgrade) {
                existing
            } else {
                let fresh = Arc::new(Semaphore::new(self.max_conn_per_link));
                map.insert(link_key.to_string(), Arc::downgrade(&fresh));
                fresh
            }
        };
        sem.try_acquire_owned().ok()
    }

    pub(crate) fn acquire_link_ws_permit(
        &self,
        link_key: &str,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let sem = {
            let mut map = self
                .link_ws_semaphores
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if map.len() > MAX_RETAINED_LOCK_WEAKS {
                map.retain(|_, weak| weak.strong_count() > 0);
            }
            if let Some(existing) = map.get(link_key).and_then(Weak::upgrade) {
                existing
            } else {
                let fresh = Arc::new(Semaphore::new(self.max_ws_per_link));
                map.insert(link_key.to_string(), Arc::downgrade(&fresh));
                fresh
            }
        };
        sem.try_acquire_owned().ok()
    }

    #[cfg(test)]
    pub(crate) fn available_link_http_permits(&self, link_key: &str) -> usize {
        self.link_semaphores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(link_key)
            .and_then(Weak::upgrade)
            .map_or(self.max_conn_per_link, |s| s.available_permits())
    }

    #[cfg(test)]
    pub(crate) fn available_link_ws_permits(&self, link_key: &str) -> usize {
        self.link_ws_semaphores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(link_key)
            .and_then(Weak::upgrade)
            .map_or(self.max_ws_per_link, |s| s.available_permits())
    }

    /// Builds an outbound tunnel HTTP URL strictly from a stored peer tunnel IP address.
    pub(crate) fn build_tunnel_url(
        &self,
        peer_tunnel_ip: &str,
        path: &str,
    ) -> Result<Url, TunnelHttpError> {
        let trimmed = peer_tunnel_ip.trim();
        let ip: IpAddr = trimmed
            .parse::<IpAddr>()
            .map_err(|_| {
                TunnelHttpError::InvalidTarget(format!(
                    "Stored peer tunnel IP '{trimmed}' is not a valid IP address"
                ))
            })?
            .to_canonical();
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(TunnelHttpError::InvalidTarget(
                "Stored peer tunnel IP must be a unicast host address".to_string(),
            ));
        }
        let port = self.resolve_tunnel_port_for(ip);
        let normalized_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let raw = match ip {
            IpAddr::V4(v4) => format!("http://{v4}:{port}{normalized_path}"),
            IpAddr::V6(v6) => format!("http://[{v6}]:{port}{normalized_path}"),
        };
        Url::parse(&raw).map_err(|err| {
            TunnelHttpError::InvalidTarget(format!("Invalid tunnel destination URL: {err}"))
        })
    }

    fn resolve_tunnel_port_for(&self, ip: IpAddr) -> u16 {
        #[cfg(test)]
        {
            if let Ok(map) = self.tunnel_port_overrides.read() {
                if let Some(&port) = map.get(&ip) {
                    return port;
                }
            }
        }
        let _ = ip;
        self.listen_port
    }

    fn validate_tunnel_binding_for(
        &self,
        local_ip: IpAddr,
        dest_ip: Option<IpAddr>,
    ) -> Result<TunnelClientBindingKey, TunnelHttpError> {
        let local_ip = local_ip.to_canonical();
        if local_ip.is_unspecified() || local_ip.is_multicast() {
            return Err(TunnelHttpError::InvalidTarget(
                "Configured local peer tunnel IP must be a unicast host address".to_string(),
            ));
        }
        match &self.tunnel_binding {
            TunnelTransportBinding::WireGuardInterface(iface) => {
                if iface.is_empty()
                    || iface.len() > 15
                    || !iface
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                {
                    return Err(TunnelHttpError::InvalidTarget(
                        "Configured tunnel interface name is invalid".to_string(),
                    ));
                }
                if local_ip.is_loopback() {
                    return Err(TunnelHttpError::InvalidTarget(
                        "Production WireGuard tunnel identity cannot use a loopback address"
                            .to_string(),
                    ));
                }
                if let Some(raw_dest) = dest_ip {
                    let dest = raw_dest.to_canonical();
                    if dest.is_loopback() {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Production WireGuard tunnel target cannot be a loopback address"
                                .to_string(),
                        ));
                    }
                    if local_ip.is_ipv4() != dest.is_ipv4() {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Peer tunnel IP address family does not match configured local tunnel IP"
                                .to_string(),
                        ));
                    }
                    if local_ip == dest {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Peer destination tunnel IP matches local tunnel IP".to_string(),
                        ));
                    }
                }
                Ok(TunnelClientBindingKey {
                    local_ip,
                    interface: Some(iface.clone()),
                })
            }
            #[cfg(test)]
            TunnelTransportBinding::LoopbackFixture => {
                if !local_ip.is_loopback() {
                    return Err(TunnelHttpError::InvalidTarget(
                        "Loopback fixture mode requires a loopback local tunnel IP".to_string(),
                    ));
                }
                if let Some(raw_dest) = dest_ip {
                    let dest = raw_dest.to_canonical();
                    if !dest.is_loopback() {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Loopback fixture mode refuses non-loopback tunnel targets".to_string(),
                        ));
                    }
                    if local_ip.is_ipv4() != dest.is_ipv4() {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Peer tunnel IP address family does not match configured local tunnel IP"
                                .to_string(),
                        ));
                    }
                    if local_ip == dest {
                        return Err(TunnelHttpError::InvalidTarget(
                            "Peer destination tunnel IP matches local tunnel IP".to_string(),
                        ));
                    }
                }
                Ok(TunnelClientBindingKey {
                    local_ip,
                    interface: None,
                })
            }
        }
    }

    pub(crate) async fn resolve_outbound_tunnel_binding(
        &self,
        dest_ip: IpAddr,
    ) -> Result<TunnelClientBindingKey, TunnelHttpError> {
        let identity = self
            .db
            .read(&self.local_server_name(), "tunnel_http", |conn| {
                af_db::peers::get_peer_identity(conn).map_err(|err| {
                    PeerError::internal("local", "tunnel_http", err.to_string())
                })
            })
            .await
            .map_err(|err| {
                TunnelHttpError::Unreachable(format!(
                    "Failed reading configured local peer tunnel identity; refusing unbound request: {}",
                    err.detail().message
                ))
            })?
            .ok_or_else(|| {
                TunnelHttpError::InvalidTarget(
                    "Local peer tunnel identity is missing; refusing unbound tunnel request"
                        .to_string(),
                )
            })?;

        let local_ip: IpAddr = identity
            .tunnel_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| {
                TunnelHttpError::InvalidTarget(
                    "Configured local peer tunnel IP is unreadable; refusing unbound request"
                        .to_string(),
                )
            })?
            .to_canonical();

        let binding = self.validate_tunnel_binding_for(local_ip, Some(dest_ip))?;

        let listener_guard = self.listener_state.lock().await;
        if let Some(active_listener) = listener_guard.as_ref() {
            if !active_listener.task.is_finished()
                && (active_listener.tunnel_ip != binding.local_ip
                    || active_listener.interface != binding.interface)
            {
                return Err(TunnelHttpError::InvalidTarget(
                    "Configured local tunnel identity does not match active tunnel listener binding"
                        .to_string(),
                ));
            }
        }
        drop(listener_guard);

        Ok(binding)
    }

    fn get_or_build_tunnel_client(
        &self,
        binding: &TunnelClientBindingKey,
    ) -> Result<reqwest::Client, TunnelHttpError> {
        let mut map = self
            .tunnel_clients
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(binding) {
            return Ok(existing.clone());
        }

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .local_address(binding.local_ip);

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref iface) = binding.interface {
            builder = builder.interface(iface);
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if binding.interface.is_some() {
            return Err(TunnelHttpError::InvalidTarget(
                "Tunnel interface binding requires Linux SO_BINDTODEVICE".to_string(),
            ));
        }

        let client = builder.build().map_err(|err| {
            TunnelHttpError::Unreachable(format!(
                "Failed building bound tunnel HTTP client: {}",
                redact_sensitive_text(&err.to_string())
            ))
        })?;

        if map.len() >= MAX_CACHED_TUNNEL_CLIENTS {
            map.clear();
        }
        map.insert(binding.clone(), client.clone());
        Ok(client)
    }

    /// Returns a bound streaming proxy HTTP client using `proxy_header_timeout` strictly for TCP
    /// connect (never imposing a whole-stream timeout on multi-minute uploads or downloads).
    pub(crate) fn get_or_build_proxy_tunnel_client(
        &self,
        binding: &TunnelClientBindingKey,
    ) -> Result<reqwest::Client, TunnelHttpError> {
        let mut map = self
            .proxy_tunnel_clients
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(binding) {
            return Ok(existing.clone());
        }

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(self.proxy_header_timeout)
            .local_address(binding.local_ip);

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref iface) = binding.interface {
            builder = builder.interface(iface);
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if binding.interface.is_some() {
            return Err(TunnelHttpError::InvalidTarget(
                "Tunnel interface binding requires Linux SO_BINDTODEVICE".to_string(),
            ));
        }

        let client = builder.build().map_err(|err| {
            TunnelHttpError::Unreachable(format!(
                "Failed building bound tunnel proxy HTTP client: {}",
                redact_sensitive_text(&err.to_string())
            ))
        })?;

        if map.len() >= MAX_CACHED_TUNNEL_CLIENTS {
            map.clear();
        }
        map.insert(binding.clone(), client.clone());
        Ok(client)
    }

    /// Executes an HTTP request strictly against a stored peer tunnel IP bound to the configured
    /// local tunnel identity and interface (`afpeer0` in production), with proxies and redirects
    /// disabled and a per-request timeout applied to the reused client.
    pub(crate) async fn send_tunnel_request(
        &self,
        method: Method,
        peer_tunnel_ip: &str,
        path: &str,
        link_token: Option<&PeerCredentialSecret>,
        json_body: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<(StatusCode, Vec<u8>, f64), TunnelHttpError> {
        self.send_tunnel_request_with_headers(
            method,
            peer_tunnel_ip,
            path,
            link_token,
            &[],
            json_body,
            timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_tunnel_request_with_headers(
        &self,
        method: Method,
        peer_tunnel_ip: &str,
        path: &str,
        link_token: Option<&PeerCredentialSecret>,
        extra_headers: &[(String, String)],
        json_body: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<(StatusCode, Vec<u8>, f64), TunnelHttpError> {
        let url = self.build_tunnel_url(peer_tunnel_ip, path)?;
        let dest_ip: IpAddr = peer_tunnel_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| TunnelHttpError::InvalidTarget("Invalid peer tunnel IP".to_string()))?
            .to_canonical();

        let binding = self.resolve_outbound_tunnel_binding(dest_ip).await?;
        let client = self.get_or_build_tunnel_client(&binding)?;

        let mut req_builder = client.request(method, url).timeout(timeout);
        if let Some(secret) = link_token {
            let mut hv = HeaderValue::from_str(secret.expose_secret()).map_err(|_| {
                TunnelHttpError::InvalidTarget(
                    "Stored link credential contains invalid HTTP header bytes".to_string(),
                )
            })?;
            hv.set_sensitive(true);
            req_builder = req_builder.header(HeaderName::from_static(HEADER_LINK_TOKEN), hv);
        }
        for (name, value) in extra_headers {
            let hn = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                TunnelHttpError::InvalidTarget("Invalid tunnel header name".to_string())
            })?;
            let mut hv = HeaderValue::from_str(value).map_err(|_| {
                TunnelHttpError::InvalidTarget("Invalid tunnel header value".to_string())
            })?;
            if name.eq_ignore_ascii_case(HEADER_GRANT_TOKEN)
                || name.eq_ignore_ascii_case(HEADER_LINK_TOKEN)
            {
                hv.set_sensitive(true);
            }
            req_builder = req_builder.header(hn, hv);
        }
        if let Some(body) = json_body {
            req_builder = req_builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }

        let started = Instant::now();
        let resp = req_builder.send().await.map_err(|err| {
            let msg = redact_sensitive_text(&err.to_string());
            if err.is_timeout() {
                TunnelHttpError::Timeout(msg)
            } else {
                TunnelHttpError::Unreachable(msg)
            }
        })?;
        let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status();
        if status.is_redirection() {
            return Err(TunnelHttpError::Unreachable(format!(
                "Peer tunnel listener returned disallowed HTTP redirect ({})",
                status.as_u16()
            )));
        }
        let bytes = read_bounded_reqwest_body(resp, 128 * 1024)
            .await
            .map_err(TunnelHttpError::Unreachable)?;
        Ok((status, bytes, rtt_ms))
    }

    /// Starts the link-only tunnel listener on `<identity.tunnel_ip>:<listen_port>` (bound to
    /// `afpeer0` in production) if an identity is configured and the listener is not already
    /// running for that exact binding.
    pub(crate) async fn ensure_listener_started(
        self: &Arc<Self>,
    ) -> Result<Option<SocketAddr>, PeerError> {
        #[cfg(test)]
        if !self.bind_listener_in_handlers {
            return Ok(None);
        }

        let server = self.local_server_name();
        let identity = self
            .db
            .read(&server, "peer_listener_start", |conn| {
                af_db::peers::get_peer_identity(conn).map_err(|err| {
                    PeerError::internal(
                        "local",
                        "peer_listener_start",
                        format!("Failed reading peer identity: {err}"),
                    )
                })
            })
            .await?;

        let Some(identity) = identity else {
            return Ok(None);
        };

        let tunnel_ip: IpAddr = identity
            .tunnel_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| {
                PeerError::internal(
                    &server,
                    "peer_listener_start",
                    "Configured peer identity has an invalid tunnel IP address",
                )
            })?
            .to_canonical();

        let binding = self
            .validate_tunnel_binding_for(tunnel_ip, None)
            .map_err(|err| PeerError::internal(&server, "peer_listener_start", err.message()))?;

        let mut guard = self.listener_state.lock().await;
        if let Some(existing) = guard.as_ref() {
            if existing.tunnel_ip == binding.local_ip
                && existing.interface == binding.interface
                && !existing.task.is_finished()
            {
                return Ok(Some(existing.bound_addr));
            }
        }
        if let Some(stale) = guard.take() {
            let _ = stale.shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), stale.task).await;
        }

        let handle = listener::spawn_tunnel_listener(
            Arc::clone(self),
            binding.local_ip,
            self.listen_port,
            binding.interface.as_deref(),
        )
        .await
        .map_err(|err| {
            PeerError::internal(
                &server,
                "peer_listener_start",
                format!(
                    "Failed binding peer tunnel listener on {}:{}: {err}",
                    binding.local_ip, self.listen_port
                ),
            )
        })?;
        let bound_addr = handle.bound_addr;
        *guard = Some(handle);
        Ok(Some(bound_addr))
    }

    pub(crate) async fn shutdown_all(&self) {
        if let Some(tx) = self.health_shutdown.lock().await.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.listener_state.lock().await.take() {
            let _ = handle.shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), handle.task).await;
        }
    }
}

async fn reject_peer_principal_middleware(req: Request, next: Next) -> Response {
    if req
        .extensions()
        .get::<crate::auth::PeerPrincipal>()
        .is_some()
    {
        return PeerError::peer_scope_denied(
            "local",
            "peer_admin_local_only",
            "Peer administration endpoints are local-only and cannot be called through a peer grant",
        )
        .into_response();
    }
    next.run(req).await
}

/// Admin router mounted strictly under `/api/v1/admin/peers`.
#[allow(dead_code)]
pub fn admin_routes() -> Router {
    admin_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_admin_routes() -> crate::routes::TrackedRouter {
    tracked_admin_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_admin_routes_with_runtime(
    runtime: Arc<PeerRuntime>,
) -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{delete, get, post, put, TrackedRouter};
    TrackedRouter::new()
        .route("/", get(links::list_peers))
        .route(
            "/pairing-window",
            post(pairing::open_pairing_window).delete(pairing::close_all_pairing_windows),
        )
        .route("/pairing-window/:id", delete(pairing::close_pairing_window))
        .route("/pair", post(pairing::start_pairing))
        .route("/pairing/:attempt/confirm", post(pairing::confirm_pairing))
        .route("/pairing/:attempt", delete(pairing::cancel_pairing))
        .route("/:id", delete(links::delete_peer))
        .route("/:id/endpoint", put(links::update_peer_endpoint))
        .route(
            "/:id/grant",
            get(grants::get_peer_grant)
                .put(grants::put_peer_grant)
                .delete(grants::delete_peer_grant),
        )
        .route("/:id/grant-offer", post(grants::send_grant_offer))
        .layer(middleware::from_fn(reject_peer_principal_middleware))
        .with_state(runtime)
}

#[allow(dead_code)]
pub(crate) fn admin_routes_with_runtime(runtime: Arc<PeerRuntime>) -> Router {
    tracked_admin_routes_with_runtime(runtime).into_router()
}

/// Public pairing bootstrap router mounted strictly under `/api/v1` outside session auth,
/// enforcing a strict 4 KiB body limit.
#[allow(dead_code)]
pub fn public_routes() -> Router {
    public_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_public_routes() -> crate::routes::TrackedRouter {
    tracked_public_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_public_routes_with_runtime(
    runtime: Arc<PeerRuntime>,
) -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{post, TrackedRouter};
    TrackedRouter::new()
        .route(
            "/peer-pairing/request",
            post(pairing::public_pairing_request),
        )
        .layer(axum::extract::DefaultBodyLimit::max(
            PUBLIC_PAIRING_BODY_LIMIT_BYTES,
        ))
        .with_state(runtime)
}

#[allow(dead_code)]
pub(crate) fn public_routes_with_runtime(runtime: Arc<PeerRuntime>) -> Router {
    tracked_public_routes_with_runtime(runtime).into_router()
}

/// Admin-only versioned peer management proxy router mounted strictly under `/api/v1/peers`.
#[allow(dead_code)]
pub fn proxy_routes() -> Router {
    proxy_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_proxy_routes() -> crate::routes::TrackedRouter {
    tracked_proxy_routes_with_runtime(PeerRuntime::global())
}

pub(crate) fn tracked_proxy_routes_with_runtime(
    runtime: Arc<PeerRuntime>,
) -> crate::routes::TrackedRouter {
    use crate::routes::inventory::{get, TrackedRouter};
    TrackedRouter::new()
        .route(
            "/:id/*rest",
            get(proxy::handle_peer_proxy)
                .head(proxy::handle_peer_proxy)
                .post(proxy::handle_peer_proxy)
                .put(proxy::handle_peer_proxy)
                .patch(proxy::handle_peer_proxy)
                .delete(proxy::handle_peer_proxy),
        )
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(middleware::from_fn(reject_peer_principal_middleware))
        .layer(middleware::from_fn(crate::auth::admin_only_middleware))
        .layer(middleware::from_fn(crate::auth::csrf_middleware))
        .layer(middleware::from_fn(crate::auth::auth_middleware))
        .with_state(runtime)
}

#[allow(dead_code)]
pub(crate) fn proxy_routes_with_runtime(runtime: Arc<PeerRuntime>) -> Router {
    tracked_proxy_routes_with_runtime(runtime).into_router()
}

/// Subscribes to peer link and grant revocation broadcasts.
#[allow(dead_code)]
pub fn subscribe_revocations() -> broadcast::Receiver<RevocationEvent> {
    PeerRuntime::global().subscribe_revocations()
}

/// Starts peer background subsystems:
/// - If a local `peer_identity` exists, starts the isolated tunnel-IP link listener.
/// - Starts the 15-second peer health & pending-expiry loop (dormant when no identity/links exist).
pub async fn start() {
    start_with_runtime(PeerRuntime::global()).await;
}

pub(crate) async fn start_with_runtime(runtime: Arc<PeerRuntime>) {
    match runtime.ensure_listener_started().await {
        Ok(Some(addr)) => {
            tracing::info!(addr = %addr, "Peer link listener started on configured tunnel IP");
        }
        Ok(None) => {
            tracing::debug!("Peer identity not configured; peer link listener remains dormant");
        }
        Err(error) => {
            tracing::warn!(%error, "Initial peer link listener bind deferred; health loop will retry once tunnel is ready");
        }
    }

    // Recover any durable pending revoked-grant credential deletions left behind across restarts
    // (dormant no-op with zero runner calls when no cleanup markers exist).
    grants::cleanup_pending_received_grant_credentials(&runtime).await;

    let mut health_guard = runtime.health_shutdown.lock().await;
    if health_guard.is_none() {
        let (tx, rx) = watch::channel(false);
        health::spawn_health_loop(Arc::clone(&runtime), rx);
        *health_guard = Some(tx);
    }
}

/// Gracefully shuts down the peer tunnel listener and health loop.
pub async fn shutdown() {
    PeerRuntime::global().shutdown_all().await;
}

pub(crate) fn configured_peer_listen_port() -> u16 {
    env::var("AF_PEER_LISTEN_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(DEFAULT_PEER_LISTEN_PORT)
}

pub(crate) fn configured_peer_max_conn() -> usize {
    env::var("AF_PEER_MAX_CONN")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PEER_MAX_CONN)
}

pub(crate) fn configured_peer_max_ws() -> usize {
    env::var("AF_PEER_MAX_WS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PEER_MAX_WS)
}

pub(crate) fn configured_peer_rtt_warn_ms() -> f64 {
    env::var("AF_PEER_RTT_WARN_MS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|&v| v.is_finite() && v > 0.0)
        .unwrap_or(DEFAULT_PEER_RTT_WARN_MS)
}

pub(crate) fn resolve_local_server_name() -> String {
    for key in ["AF_SERVER_NAME", "HOSTNAME"] {
        if let Ok(raw) = env::var(key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && pairing::is_valid_peer_name(trimmed) {
                return trimmed.to_string();
            }
        }
    }
    if let Ok(raw) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && pairing::is_valid_peer_name(trimmed) {
            return trimmed.to_string();
        }
    }
    "aetherflow".to_string()
}

/// Enumerates non-loopback local interface addresses for the WireGuard endpoint picker,
/// flagging RFC 1918 / RFC 4193 private (VLAN) addresses as recommended.
pub(crate) fn detect_local_endpoints() -> Vec<DetectedEndpoint> {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        use std::net::{Ipv4Addr, Ipv6Addr};

        let mut results: Vec<DetectedEndpoint> = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `getifaddrs` writes an allocated linked list pointer into `ifap`, which we
        // unconditionally release with `freeifaddrs` before returning.
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
            return results;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            // SAFETY: `cur` walks the valid null-terminated list returned by `getifaddrs`.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;

            if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: `ifa_name` is a non-null C string provided by `getifaddrs`.
            let iface = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if iface == "lo" || iface == af_runner::peer_network::PEER_WG_INTERFACE {
                continue;
            }
            // SAFETY: `ifa_addr` is non-null; inspect `sa_family` before casting.
            let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            let parsed_ip = match family {
                libc::AF_INET => {
                    // SAFETY: `sa_family == AF_INET` guarantees `sockaddr_in` layout.
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if ip.is_loopback()
                        || ip.is_link_local()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                    {
                        None
                    } else {
                        let recommended = ip.is_private();
                        Some((IpAddr::V4(ip), "ipv4", recommended))
                    }
                }
                libc::AF_INET6 => {
                    // SAFETY: `sa_family == AF_INET6` guarantees `sockaddr_in6` layout.
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let seg0 = ip.segments()[0];
                    let is_link_local = (seg0 & 0xffc0) == 0xfe80;
                    let is_ula = (seg0 & 0xfe00) == 0xfc00;
                    if ip.is_loopback() || is_link_local || ip.is_unspecified() || ip.is_multicast()
                    {
                        None
                    } else {
                        Some((IpAddr::V6(ip), "ipv6", is_ula))
                    }
                }
                _ => None,
            };

            if let Some((ip, fam, recommended)) = parsed_ip {
                let addr_str = ip.to_string();
                if !results.iter().any(|e| e.address == addr_str) {
                    results.push(DetectedEndpoint {
                        interface: iface,
                        address: addr_str,
                        family: fam,
                        recommended,
                    });
                }
            }
        }
        // SAFETY: `ifap` was returned by `getifaddrs` above.
        unsafe {
            libc::freeifaddrs(ifap);
        }

        results.sort_by(|a, b| {
            b.recommended
                .cmp(&a.recommended)
                .then_with(|| a.family.cmp(b.family))
                .then_with(|| a.interface.cmp(&b.interface))
                .then_with(|| a.address.cmp(&b.address))
        });
        results
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}
