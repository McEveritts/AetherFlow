//! Isolated tunnel-IP peer listener (P3 link-only slice).
//!
//! Binds strictly to `<own tunnel IP>:AF_PEER_LISTEN_PORT` once peer identity exists.
//! Serves only:
//! - `POST /peer/v1/hello` (attempt-bound pre-activation bootstrap and authenticated acknowledge)
//! - `GET /health` (link-authenticated health & capability exchange)
//! - `GET /peer/v1/link` (link-authenticated link status view)
//! - `POST /peer/v1/revoke-notice` (link-authenticated peer revocation notice)
//!
//! All other routes—including management `/api/v1/*` and unknown internal routes—fail closed
//! and are audited.

use super::errors::PeerError;
use super::pairing::sha256_prefixed;
use super::{
    capabilities, is_live_link_state, is_revoked_or_revoking_state, links, pairing, ListenerHandle,
    PeerRuntime, HEADER_LINK_TOKEN, PEER_PROTOCOL_VERSION,
};
use af_db::peers::{self as db_peers, PeerLink};
use af_models::constant_time_eq;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::watch;

pub(crate) const TUNNEL_INTERNAL_BODY_LIMIT_BYTES: usize = 8192;

/// Verified identity of an active peer link calling the tunnel listener.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedPeerLink {
    pub(crate) link: PeerLink,
    pub(crate) source_ip: IpAddr,
}

/// Verifies that the tunnel caller's TCP source IP (`ConnectInfo`) matches an active/down link
/// and that `X-AF-Link-Token` matches `peer_links.inbound_token_hash` in constant time.
pub(crate) async fn authenticate_active_link(
    runtime: &PeerRuntime,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    route_label: &str,
) -> Result<(AuthenticatedPeerLink, tokio::sync::OwnedSemaphorePermit), PeerError> {
    let local_server = runtime.local_server_name();
    let step = "tunnel_link_auth";

    let Some(ConnectInfo(remote_addr)) = connect_info else {
        audit_listener_denial(runtime, route_label, "unknown", "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Tunnel peer source address is unavailable",
        ));
    };
    let source_ip = remote_addr.ip().to_canonical();
    let source_ip_str = source_ip.to_string();

    let ip_lookup = source_ip_str.clone();
    let link = runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_peer_link_by_tunnel_ip(conn, &ip_lookup)
                .map_err(|err| PeerError::internal("local", "tunnel_link_auth", err.to_string()))
        })
        .await?;

    let Some(link) = link else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Tunnel source IP does not match any registered peer link",
        ));
    };

    if is_revoked_or_revoking_state(&link.state) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "LINK_REVOKED").await;
        return Err(PeerError::link_revoked(
            &local_server,
            step,
            format!("Link with '{}' has been revoked", link.name),
        ));
    }

    if !is_live_link_state(&link.state) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Peer link is not active; complete pairing before calling link routes",
        ));
    }

    let Some(presented) = headers
        .get(HEADER_LINK_TOKEN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Missing X-AF-Link-Token header",
        ));
    };

    let Some(expected_hash) = link.inbound_token_hash.as_deref() else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Peer link has no active incoming credential",
        ));
    };

    let presented_hash = sha256_prefixed(presented);
    if !constant_time_eq(presented_hash.as_bytes(), expected_hash.as_bytes()) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Invalid X-AF-Link-Token credential",
        ));
    }

    let Some(permit) = runtime.acquire_link_permit(&link.id) else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_BUSY").await;
        return Err(PeerError::busy(
            &local_server,
            step,
            "Per-link concurrency limit exceeded on tunnel listener",
        ));
    };

    Ok((AuthenticatedPeerLink { link, source_ip }, permit))
}

pub(crate) async fn audit_listener_denial(
    runtime: &PeerRuntime,
    route_label: &str,
    source_ip: &str,
    error_code: &str,
) {
    runtime
        .db
        .record_audit(
            0,
            "peer-listener".to_string(),
            "peer_listener_denied".to_string(),
            "peer_listener".to_string(),
            route_label.to_string(),
            format!("Denied tunnel request to {route_label} ({error_code})"),
            source_ip.to_string(),
            String::new(),
        )
        .await;
}

/// Link-authenticated `GET /health` over the WireGuard tunnel.
async fn tunnel_health(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let (_auth, _permit) =
        match authenticate_active_link(&runtime, connect_info, &headers, "GET /health").await {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "status": "ok",
            "version": runtime.local_version(),
            "peer_protocol": PEER_PROTOCOL_VERSION,
            "capabilities": capabilities(),
        })),
    )
        .into_response()
}

/// Fail-closed fallback rejecting every route outside the P3 internal link routes
/// (including `/api/v1/*` management routes, unknown `/peer/v1/*` routes, and disallowed methods).
async fn tunnel_fail_closed_fallback(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request,
) -> Response {
    let route_label = "unclassified tunnel request";
    let local_server = runtime.local_server_name();

    let auth_res =
        authenticate_active_link(&runtime, connect_info, req.headers(), route_label).await;
    let (_auth, _permit) = match auth_res {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    let source_ip = connect_info
        .map(|ConnectInfo(addr)| addr.ip().to_canonical().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let trimmed_path = req.uri().path().trim_start_matches('/');
    let err = if trimmed_path == "api" || trimmed_path.starts_with("api/") {
        PeerError::peer_scope_denied(
            &local_server,
            "tunnel_dispatch",
            "Management routes are not enabled on this link-only peer listener",
        )
    } else {
        PeerError::peer_route_unclassified(
            &local_server,
            "tunnel_dispatch",
            "Route is not an allowed peer internal endpoint",
        )
    };
    audit_listener_denial(&runtime, route_label, &source_ip, err.code()).await;
    err.into_response()
}

/// Builds the isolated link-only Axum router for the peer listener.
pub(crate) fn build_listener_router(runtime: Arc<PeerRuntime>) -> Router {
    Router::new()
        .route("/peer/v1/hello", post(pairing::handle_tunnel_hello))
        .route("/health", get(tunnel_health))
        .route("/peer/v1/link", get(links::handle_tunnel_link_view))
        .route(
            "/peer/v1/revoke-notice",
            post(links::handle_tunnel_revoke_notice),
        )
        .fallback(tunnel_fail_closed_fallback)
        .method_not_allowed_fallback(tunnel_fail_closed_fallback)
        .layer(axum::extract::DefaultBodyLimit::max(
            TUNNEL_INTERNAL_BODY_LIMIT_BYTES,
        ))
        .with_state(runtime)
}

/// Binds and spawns the peer listener strictly on `<tunnel_ip>:<port>`, constraining production
/// sockets to `afpeer0` via `SO_BINDTODEVICE` (`bind_device = Some("afpeer0")`) and allowing
/// unbound loopback sockets strictly for isolated loopback test fixtures (`bind_device = None`).
pub(crate) async fn spawn_tunnel_listener(
    runtime: Arc<PeerRuntime>,
    tunnel_ip: IpAddr,
    port: u16,
    bind_device: Option<&str>,
) -> std::io::Result<ListenerHandle> {
    let tunnel_ip = tunnel_ip.to_canonical();
    if tunnel_ip.is_unspecified() || tunnel_ip.is_multicast() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Peer tunnel listener refuses to bind unspecified or multicast address",
        ));
    }
    if bind_device.is_some() && tunnel_ip.is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "WireGuard-bound peer tunnel listener refuses loopback address",
        ));
    }
    if bind_device.is_none() && !tunnel_ip.is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Peer tunnel listener without device binding is restricted to loopback fixtures",
        ));
    }

    let bind_addr = SocketAddr::new(tunnel_ip, port);
    let socket = match tunnel_ip {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(iface) = bind_device {
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if bind_device.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Tunnel device binding requires Linux SO_BINDTODEVICE",
        ));
    }

    socket.bind(bind_addr)?;
    let tcp_listener = socket.listen(1024)?;
    let bound_addr = tcp_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let app = build_listener_router(runtime);

    let task = tokio::spawn(async move {
        let serve_res = axum::serve(
            tcp_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        if let Err(error) = serve_res {
            tracing::warn!(%error, "Peer tunnel listener exited with error");
        }
    });

    Ok(ListenerHandle {
        tunnel_ip,
        interface: bind_device.map(str::to_string),
        bound_addr,
        shutdown_tx,
        task,
    })
}
