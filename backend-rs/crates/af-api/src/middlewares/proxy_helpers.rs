use super::host_resolution::strip_host_port_and_dot;
use crate::auth::{api_error, decode_session_claims, resolve_raw_token};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use once_cell::sync::Lazy;
use rusqlite::OptionalExtension;
use std::any::Any;
use std::collections::HashSet;
use std::env;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::watch;
use url::Url;

pub(super) static PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        // Bound connection setup without limiting long-lived media response bodies.
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub(super) static PROXY_LOOPBACK_TLS_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub(super) static PROXY_LOOPBACK_TLS_WS_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub(crate) fn upstream_uses_tls(app_name: &str, port: u16) -> bool {
    let clean = app_name.trim().to_ascii_lowercase();
    if clean.is_empty() || port == 0 {
        return false;
    }
    if matches!(clean.as_str(), "kasmvnc" | "af-kasmvnc") {
        return true;
    }
    if let Ok(raw) = env::var("AETHERFLOW_TLS_UPSTREAM_APPS") {
        for entry in raw.split(',') {
            let token = entry.trim().to_ascii_lowercase();
            if token.is_empty() {
                continue;
            }
            if let Some((name, entry_port)) = token.split_once(':') {
                if name.trim() == clean && entry_port.trim().parse::<u16>().ok() == Some(port) {
                    return true;
                }
            } else if token == clean {
                return true;
            }
        }
    }
    false
}

pub(super) fn is_strict_loopback_https_url(target_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(target_url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    matches!(parsed.host_str(), Some("127.0.0.1" | "::1" | "[::1]"))
}

pub(super) fn is_trusted_proxy_ip(ip: IpAddr) -> bool {
    crate::ws::is_trusted_proxy_peer(ip)
}

pub(super) fn is_forwarded_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-server"
            | "x-real-ip"
    )
}

pub(super) fn canonical_forwarded_headers(
    incoming_headers: &axum::http::HeaderMap,
    raw_host: &str,
    peer_ip: Option<IpAddr>,
    trust_forwarded: bool,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut out = Vec::new();
    if !strip_host_port_and_dot(raw_host).is_empty() {
        if let Ok(value) = HeaderValue::from_str(raw_host) {
            out.push((HeaderName::from_static("x-forwarded-host"), value));
        }
    }

    let xf_proto = if trust_forwarded {
        incoming_headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .and_then(|p| {
                if p.eq_ignore_ascii_case("https") {
                    Some("https")
                } else if p.eq_ignore_ascii_case("http") {
                    Some("http")
                } else {
                    None
                }
            })
            .unwrap_or("http")
    } else {
        "http"
    };
    out.push((
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(xf_proto),
    ));

    if let Some(peer) = peer_ip {
        let client_ip = crate::ws::extract_client_ip_for_peer(incoming_headers, Some(peer));
        if let Ok(value) = HeaderValue::from_str(&client_ip) {
            out.push((HeaderName::from_static("x-forwarded-for"), value.clone()));
            out.push((HeaderName::from_static("x-real-ip"), value));
        }
    }
    out
}

pub(super) fn is_spoofable_identity_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("x-aetherflow-")
        || matches!(
            lower.as_str(),
            "remote-user"
                | "x-remote-user"
                | "x-forwarded-user"
                | "x-forwarded-email"
                | "x-forwarded-groups"
        )
}

#[cfg(test)]
pub(super) fn forward_proxy_http_headers(
    mut upstream_req: reqwest::RequestBuilder,
    incoming_headers: &axum::http::HeaderMap,
    raw_host: &str,
    peer_ip: Option<IpAddr>,
    trust_forwarded: bool,
) -> reqwest::RequestBuilder {
    for (k, v) in incoming_headers.iter() {
        let name_str = k.as_str();
        // Host is set once below; reqwest's header() appends values.
        if is_hop_by_hop_header(name_str)
            || is_forwarded_header_name(name_str)
            || is_spoofable_identity_header(name_str)
            || name_str.eq_ignore_ascii_case("host")
        {
            continue;
        }
        if let (Ok(rk), Ok(rv)) = (
            reqwest::header::HeaderName::from_bytes(name_str.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            upstream_req = upstream_req.header(rk, rv);
        }
    }

    if !raw_host.is_empty() {
        upstream_req = upstream_req.header("Host", raw_host);
    }
    for (hn, hv) in
        canonical_forwarded_headers(incoming_headers, raw_host, peer_ip, trust_forwarded)
    {
        if let (Ok(rk), Ok(rv)) = (
            reqwest::header::HeaderName::from_bytes(hn.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(hv.as_bytes()),
        ) {
            upstream_req = upstream_req.header(rk, rv);
        }
    }
    upstream_req
}

fn parse_strict_ip_or_socket(raw_ip: &str) -> Option<IpAddr> {
    let trimmed = raw_ip.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    let clean = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    clean.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

pub(super) fn is_private_or_loopback_ip(raw_ip: &str) -> bool {
    let Some(addr) = parse_strict_ip_or_socket(raw_ip) else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub(super) fn resolve_optional_authenticated_user(
    headers: &axum::http::HeaderMap,
    peer: Option<IpAddr>,
) -> Option<crate::auth::ActiveSubject> {
    let token = resolve_raw_token(headers).or_else(|| {
        let (scheme, _) = headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        crate::ws::extract_cookie(headers, "aetherflow_session")
    })?;
    let claims = decode_session_claims(&token, false).ok()?;
    if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
        return None;
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let ip = if peer.is_some() {
        crate::ws::extract_client_ip_for_peer(headers, peer)
    } else {
        "127.0.0.1".to_string()
    };
    let fingerprint = crate::auth::legacy_client_fingerprint(&ip, user_agent);
    if crate::auth::is_session_token_revoked_beyond_grace_for_fp(
        &claims.jti,
        claims.user_id,
        Some(&fingerprint),
    ) || !crate::auth::matches_client_fingerprint(&claims.cfp, &ip, user_agent)
    {
        return None;
    }
    let conn = af_db::get_read_conn().ok()?;
    let subject = crate::auth::load_active_human_subject(&conn, claims.user_id).ok()?;
    (claims.ver >= subject.sessions_revoked_after && !subject.username.is_empty())
        .then_some(subject)
}

pub(super) fn verify_proxy_basic_credentials(headers: &axum::http::HeaderMap) -> Option<String> {
    use base64::Engine;
    let (scheme, encoded) = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.len() > 4096 {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let (username, password) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
    if username.is_empty() || password.is_empty() {
        return None;
    }
    let conn = af_db::get_read_conn().ok()?;
    let user: Option<(i64, String, i64)> = conn
        .query_row(
            "SELECT id, COALESCE(password_hash, ''), COALESCE(totp_enabled, 0) FROM users WHERE username = ?1",
            [username],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .ok()?;
    if user
        .as_ref()
        .is_some_and(|(_, _, totp_enabled)| *totp_enabled != 0)
    {
        return None;
    }
    let admin = user.and_then(|(user_id, hash, _)| {
        let subject = crate::auth::load_active_human_subject(&conn, user_id).ok()?;
        (subject.role == "admin").then_some((subject.username, hash))
    });
    drop(conn);

    let (master_user, master_password, _) = af_services::mutators::load_master_credentials();
    if username == master_user
        && !master_password.is_empty()
        && af_models::constant_time_eq(password.as_bytes(), master_password.as_bytes())
    {
        return Some(master_user);
    }
    let (username, hash) = admin?;
    crate::auth::verify_password(password, &hash).then_some(username)
}

pub(super) fn librespeed_tls_client() -> Result<Option<reqwest::Client>, String> {
    let override_path =
        env::var_os("AETHERFLOW_LIBRESPEED_SETTINGS_PATH").filter(|path| !path.is_empty());
    let path = if let Some(path) = override_path {
        PathBuf::from(path)
    } else {
        let mut selected = None;
        for candidate in [
            "/etc/aetherflow/librespeed/upstream-tls.toml",
            "/etc/aetherflow/librespeed/settings.toml",
            "/opt/librespeed/settings.toml",
        ] {
            match std::fs::symlink_metadata(candidate) {
                Ok(_) => {
                    selected = Some(PathBuf::from(candidate));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Cannot inspect LibreSpeed TLS settings at {candidate}: {error}. Grant the API service read access to the settings and search access to its parent directories.")),
            }
        }
        let Some(path) = selected else {
            return Ok(None);
        };
        path
    };
    for ancestor in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!("Cannot inspect LibreSpeed TLS settings path {}: {error}. Check that the settings exist and that the API service can access the path.", ancestor.display())
        })?;
        if metadata.file_type().is_symlink() || (ancestor == path && !metadata.is_file()) {
            return Err(format!("LibreSpeed TLS settings must be a regular file reached without symlinks. Check {}.", ancestor.display()));
        }
    }
    let settings = af_runner::package_executor::try_librespeed_runner_settings_tls_config(&path, None)
        .ok_or_else(|| format!("Cannot read LibreSpeed TLS settings at {}. Grant the API service read access to the settings and search access to its parent directories.", path.display()))?;
    if !settings.enabled {
        return Ok(None);
    }
    let cert_path = settings.ca_cert_file.ok_or_else(|| {
        format!(
            "Missing or invalid LibreSpeed upstream certificate. Check tls_cert_file in {}.",
            path.display()
        )
    })?;
    let pem = std::fs::read(&cert_path)
        .map_err(|error| format!("Cannot read LibreSpeed upstream certificate at {cert_path}: {error}. Grant the API service read access."))?;
    // In the Rustls backend, a PEM file with no certificate blocks can
    // otherwise construct a client with an empty trust store.
    if reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|error| error.to_string())?
        .is_empty()
    {
        return Err("LibreSpeed upstream PEM contains no certificates".into());
    }
    let cert = reqwest::Certificate::from_pem(&pem).map_err(|error| error.to_string())?;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .no_proxy()
        .http1_only()
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .build()
        .map(Some)
        .map_err(|error| error.to_string())
}

pub(super) fn local_domain_client_allowed(
    headers: &axum::http::HeaderMap,
    peer: Option<IpAddr>,
) -> bool {
    peer.is_none_or(|peer| {
        is_private_or_loopback_ip(&peer.to_string())
            && is_private_or_loopback_ip(&crate::ws::extract_client_ip_for_peer(
                headers,
                Some(peer),
            ))
    })
}

pub(super) fn internal_domain_forbidden() -> Response {
    api_error(
        StatusCode::FORBIDDEN,
        "INTERNAL_DOMAIN",
        "Internal .aether.local domains are restricted to local network clients",
    )
}

pub(crate) fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "http2-settings"
    )
}

/// Collects lowercased header names nominated as hop-by-hop by any `Connection` header (RFC 9110 §7.6.1).
pub(crate) fn connection_header_tokens(headers: &HeaderMap) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(raw) = val.to_str() {
            for part in raw.split(',') {
                let token = part.trim();
                if !token.is_empty() {
                    tokens.insert(token.to_ascii_lowercase());
                }
            }
        }
    }
    tokens
}

pub(crate) fn is_websocket_upgrade_request(headers: &HeaderMap, method: &Method) -> bool {
    if *method != Method::GET {
        return false;
    }
    let upgrade_ws = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("websocket"));
    let conn_upgrade = headers.get_all(header::CONNECTION).iter().any(|val| {
        val.to_str().ok().is_some_and(|raw| {
            raw.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
    });
    upgrade_ws && conn_upgrade
}

/// Upgrade protocol policy for [`super::subdomain_proxy::stream_proxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamProxyUpgradePolicy {
    Disabled,
    /// Subdomain proxy: preserves existing upgrade detection for WebSockets and generic HTTP upgrades.
    AnyUpgrade,
    /// Peer proxy: permits only `GET` + `Connection: Upgrade` + `Upgrade: websocket`.
    WebSocketOnly,
}

/// Optional local source IP and Linux `SO_BINDTODEVICE` interface binding for plain TCP upstream
/// connections (used by peer management proxy WebSocket upgrades).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamProxySocketBind {
    pub(crate) local_ip: IpAddr,
    pub(crate) interface: Option<String>,
}

/// Transport error category emitted by [`super::subdomain_proxy::stream_proxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamProxyErrorKind {
    BadGateway,
    GatewayTimeout,
    Cancelled,
}

pub(crate) type StreamProxyErrorFn =
    Box<dyn FnOnce(StreamProxyErrorKind, String) -> Response + Send>;

pub(crate) type StreamProxyResponseTransform = Box<dyn FnOnce(&mut Response, bool) + Send>;

/// Configuration options for [`super::subdomain_proxy::stream_proxy`].
pub(crate) struct StreamProxyOptions {
    /// Pre-filtered request headers to forward upstream (hop-by-hop headers are stripped
    /// automatically; WebSocket handshake headers are preserved for accepted upgrades).
    pub(crate) upstream_headers: HeaderMap,
    /// Explicit `Host` header to send upstream (subdomain proxy sends the browser host; peer proxy
    /// sends the derived tunnel `<ip>:<port>` authority).
    pub(crate) upstream_host: Option<String>,
    /// Optional local IP + interface binding for plain TCP WebSocket upstream connections.
    pub(crate) tcp_bind: Option<StreamProxySocketBind>,
    /// Optional dedicated `reqwest::Client` for TLS WebSocket upgrades (subdomain proxy only).
    pub(crate) tls_ws_client: Option<reqwest::Client>,
    /// Connect + response header timeout budget; does NOT limit multi-minute streaming bodies or
    /// established WebSocket tunnels.
    pub(crate) header_timeout: Duration,
    /// Optional time without upload progress, independent of total request duration.
    pub(crate) upload_idle_timeout: Option<Duration>,
    /// Connect timeout for plain TCP WebSocket upstream sockets (bounded by `header_timeout`).
    pub(crate) ws_connect_timeout: Duration,
    /// Upgrade protocol policy.
    pub(crate) upgrade_policy: StreamProxyUpgradePolicy,
    /// Resource/permit guard held for the entire streaming response body or upgraded WebSocket
    /// tunnel lifetime, automatically released on completion, stream error, cancellation, or drop.
    pub(crate) guard: Option<Box<dyn Any + Send + Sync>>,
    /// Optional cancellation signal that tears down an active HTTP stream (request upload, header
    /// wait, or response body) or upgraded WebSocket tunnel and releases `guard` immediately.
    pub(crate) stream_cancel: Option<watch::Receiver<bool>>,
    /// Optional response transform hook called with `(&mut response, is_switching_protocols)`.
    pub(crate) response_transform: Option<StreamProxyResponseTransform>,
    /// Optional custom error response mapper.
    pub(crate) on_error: Option<StreamProxyErrorFn>,
    /// Structured log context (never contains raw credentials).
    pub(crate) log_context: String,
    /// When `true`, discards the incoming request body instead of streaming it upstream (used for
    /// remote backup step-up POST so local admin passwords are never forwarded over the tunnel).
    pub(crate) discard_request_body: bool,
}

/// Resolves once `rx` observes `true` (cancelled) or its sender closes.
pub(super) async fn wait_for_cancel_watch(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

pub(super) struct CancelWaiter {
    fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl CancelWaiter {
    pub(super) fn new(mut rx: watch::Receiver<bool>) -> Self {
        Self {
            fut: Box::pin(async move {
                wait_for_cancel_watch(&mut rx).await;
            }),
        }
    }

    pub(super) fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> bool {
        self.fut.as_mut().poll(cx).is_ready()
    }
}

/// Zero-copy `Body` wrapper that holds an arbitrary resource/permit guard and optional
/// cancellation signal until the stream reaches EOF, yields an error, is cancelled, or is
/// dropped (client disconnect / revocation).
pub(crate) struct GuardedBody<G = Box<dyn Any + Send + Sync>> {
    inner: Body,
    guard: Option<G>,
    cancel: Option<CancelWaiter>,
    cancelled: bool,
}

impl<G: Send + Sync + Unpin + 'static> GuardedBody<G> {
    #[allow(dead_code)]
    pub(crate) fn wrap(inner: Body, guard: Option<G>) -> Body {
        Self::wrap_with_cancel(inner, guard, None)
    }

    pub(crate) fn wrap_with_cancel(
        inner: Body,
        guard: Option<G>,
        cancel: Option<watch::Receiver<bool>>,
    ) -> Body {
        if guard.is_none() && cancel.is_none() {
            return inner;
        }
        Body::new(Self {
            inner,
            guard,
            cancel: cancel.map(CancelWaiter::new),
            cancelled: false,
        })
    }
}

impl<G: Unpin> HttpBody for GuardedBody<G> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.cancelled {
            return Poll::Ready(None);
        }
        if let Some(cancel) = self.cancel.as_mut() {
            if cancel.poll_cancelled(cx) {
                self.cancelled = true;
                self.cancel = None;
                self.inner = Body::empty();
                self.guard.take();
                return Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Stream cancelled due to peer revocation",
                )))));
            }
        }
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(poll, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.guard.take();
            self.cancel = None;
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.cancelled || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.cancelled {
            SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
}

/// Connects an upstream TCP socket for plain-HTTP WebSocket upgrades, enforcing optional local
/// tunnel IP + Linux `SO_BINDTODEVICE` interface binding.
pub(super) async fn connect_upstream_tcp(
    target: &Url,
    bind: Option<&StreamProxySocketBind>,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, StreamProxyErrorKind> {
    let port = target
        .port_or_known_default()
        .ok_or(StreamProxyErrorKind::BadGateway)?;

    if let Some(bind_cfg) = bind {
        let host_str = target
            .host_str()
            .ok_or(StreamProxyErrorKind::BadGateway)?
            .trim_matches(['[', ']']);
        let dest_ip = host_str
            .parse::<IpAddr>()
            .map_err(|_| StreamProxyErrorKind::BadGateway)?
            .to_canonical();
        let local_ip = bind_cfg.local_ip.to_canonical();
        if dest_ip.is_ipv4() != local_ip.is_ipv4() {
            return Err(StreamProxyErrorKind::BadGateway);
        }

        let socket = match local_ip {
            IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }
        .map_err(|_| StreamProxyErrorKind::BadGateway)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(ref iface) = bind_cfg.interface {
            socket
                .bind_device(Some(iface.as_bytes()))
                .map_err(|_| StreamProxyErrorKind::BadGateway)?;
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        if bind_cfg.interface.is_some() {
            return Err(StreamProxyErrorKind::BadGateway);
        }

        socket
            .bind(SocketAddr::new(local_ip, 0))
            .map_err(|_| StreamProxyErrorKind::BadGateway)?;

        let dest_addr = SocketAddr::new(dest_ip, port);
        match tokio::time::timeout(timeout, socket.connect(dest_addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => Err(StreamProxyErrorKind::BadGateway),
            Err(_) => Err(StreamProxyErrorKind::GatewayTimeout),
        }
    } else {
        let host = target
            .host_str()
            .ok_or(StreamProxyErrorKind::BadGateway)?
            .trim_matches(['[', ']'])
            .to_string();
        match tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => Err(StreamProxyErrorKind::BadGateway),
            Err(_) => Err(StreamProxyErrorKind::GatewayTimeout),
        }
    }
}

pub(super) fn managed_app_route_unavailable() -> Response {
    api_error(
        StatusCode::MISDIRECTED_REQUEST,
        "APP_ROUTE_UNAVAILABLE",
        "This host does not have the configured external application route",
    )
}

pub(super) fn strip_gateway_session_cookies(headers: &mut axum::http::HeaderMap, protected: bool) {
    if !protected
        && crate::ws::extract_cookie(headers, crate::app_launch::APP_SESSION_COOKIE).is_none()
    {
        return;
    }
    let cookies: Vec<_> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| {
            let value = value.to_str().ok()?;
            let cookies = value
                .split(';')
                .map(str::trim)
                .filter(|cookie| {
                    !cookie.is_empty()
                        && !cookie.split_once('=').is_some_and(|(name, _)| {
                            let name = name.trim();
                            name == crate::app_launch::APP_SESSION_COOKIE
                                || (protected && name == "aetherflow_session")
                        })
                })
                .collect::<Vec<_>>()
                .join("; ");
            if cookies.is_empty() {
                return None;
            }
            HeaderValue::from_str(&cookies).ok()
        })
        .collect();
    headers.remove(header::COOKIE);
    for cookie in cookies {
        headers.append(header::COOKIE, cookie);
    }
}
