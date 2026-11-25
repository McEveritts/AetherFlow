use super::host_resolution::{
    explicit_control_plane_host, local_control_plane_host, resolve_app_host_disposition,
    resolve_proxy_work, strip_host_port_and_dot, AppHostResolution, PROXY_AUTH_BLOCKING_LIMIT,
    PROXY_RESOLVE_TIMEOUT,
};
use super::proxy_helpers::{
    canonical_forwarded_headers, connect_upstream_tcp, connection_header_tokens,
    internal_domain_forbidden, is_forwarded_header_name, is_hop_by_hop_header,
    is_spoofable_identity_header, is_strict_loopback_https_url, is_trusted_proxy_ip,
    is_websocket_upgrade_request, librespeed_tls_client, local_domain_client_allowed,
    managed_app_route_unavailable, resolve_optional_authenticated_user,
    strip_gateway_session_cookies, upstream_uses_tls, verify_proxy_basic_credentials,
    wait_for_cancel_watch, CancelWaiter, GuardedBody, StreamProxyErrorKind, StreamProxyOptions,
    StreamProxyUpgradePolicy, PROXY_HTTP_CLIENT, PROXY_LOOPBACK_TLS_CLIENT,
    PROXY_LOOPBACK_TLS_WS_CLIENT,
};
use super::rate_limit::{rate_limited_response, PROXY_BASIC_AUTH_LIMITER};
use crate::auth::api_error;
use af_runner::package_executor::{
    requires_external_app_auth as external_proxy_requires_auth, GATEWAY_APP_HEADER,
};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;
use url::Url;

const WS_HANDSHAKE_HEADERS: [&str; 4] = [
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

struct SignalingStream<S> {
    inner: S,
    progress: Option<watch::Sender<Option<Instant>>>,
    track_progress: bool,
    cancel: Option<CancelWaiter>,
    cancelled: bool,
}

impl<S> SignalingStream<S> {
    fn finish(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.send_replace(None);
        }
    }
}

impl<S> Drop for SignalingStream<S> {
    fn drop(&mut self) {
        self.finish();
    }
}

impl<S, T, E> futures::Stream for SignalingStream<S>
where
    S: futures::Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Item = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.cancelled {
            return Poll::Ready(None);
        }
        if let Some(cancel) = self.cancel.as_mut() {
            if cancel.poll_cancelled(cx) {
                self.cancelled = true;
                self.cancel = None;
                self.finish();
                return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Request stream cancelled due to peer revocation",
                )))));
            }
        }
        let poll = Pin::new(&mut self.inner).poll_next(cx);
        match poll {
            Poll::Ready(None) => {
                self.finish();
                self.cancel = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.finish();
                self.cancel = None;
                Poll::Ready(Some(Err(err.into())))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                if self.track_progress && !chunk.as_ref().is_empty() {
                    if let Some(progress) = &self.progress {
                        progress.send_replace(Some(Instant::now()));
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn wait_optional_cancel(cancel: &mut Option<watch::Receiver<bool>>) {
    match cancel.as_mut() {
        Some(rx) => wait_for_cancel_watch(rx).await,
        None => std::future::pending().await,
    }
}

async fn wait_for_http_proxy_timeout(
    mut progress: watch::Receiver<Option<Instant>>,
    upload_idle_timeout: Option<Duration>,
    header_timeout: Duration,
) -> &'static str {
    if let Some(idle) = upload_idle_timeout {
        // Wait independently of the body poller so downstream backpressure also counts as idle.
        loop {
            let Some(last_progress) = *progress.borrow_and_update() else {
                break;
            };
            tokio::select! {
                biased;
                changed = progress.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(last_progress + idle) => return "request body",
            }
        }
    } else {
        let _ = progress.wait_for(Option::is_none).await;
    }
    tokio::time::sleep(header_timeout).await;
    "response headers"
}

fn build_stream_proxy_error(
    on_error: Option<super::proxy_helpers::StreamProxyErrorFn>,
    kind: StreamProxyErrorKind,
    detail: String,
) -> Response {
    if let Some(mapper) = on_error {
        return mapper(kind, detail);
    }
    match kind {
        StreamProxyErrorKind::BadGateway => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "bad_gateway",
                "message": detail,
            })),
        )
            .into_response(),
        StreamProxyErrorKind::GatewayTimeout => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({
                "error": "gateway_timeout",
                "message": detail,
            })),
        )
            .into_response(),
        StreamProxyErrorKind::Cancelled => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": detail,
            })),
        )
            .into_response(),
    }
}

fn is_upgrade_request_for_policy(
    req: &Request,
    policy: StreamProxyUpgradePolicy,
) -> Option<String> {
    match policy {
        StreamProxyUpgradePolicy::Disabled => None,
        StreamProxyUpgradePolicy::WebSocketOnly => {
            if is_websocket_upgrade_request(req.headers(), req.method()) {
                Some("websocket".to_string())
            } else {
                None
            }
        }
        StreamProxyUpgradePolicy::AnyUpgrade => {
            let upgrade_header = req
                .headers()
                .get(header::UPGRADE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let is_upgrade = !upgrade_header.is_empty()
                && (upgrade_header.eq_ignore_ascii_case("websocket")
                    || req
                        .headers()
                        .get(header::CONNECTION)
                        .and_then(|v| v.to_str().ok())
                        .map(|c| c.to_ascii_lowercase().contains("upgrade"))
                        .unwrap_or(false));
            is_upgrade.then_some(upgrade_header)
        }
    }
}

fn copy_filtered_response_headers(
    out_headers: &mut HeaderMap,
    upstream_headers: &HeaderMap,
    preserve_upgrade_headers: bool,
) {
    let conn_tokens = if preserve_upgrade_headers {
        HashSet::new()
    } else {
        connection_header_tokens(upstream_headers)
    };
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if !preserve_upgrade_headers
            && (is_hop_by_hop_header(name) || conn_tokens.contains(&name.to_ascii_lowercase()))
        {
            continue;
        }
        out_headers.append(k.clone(), v.clone());
    }
}

fn copy_filtered_reqwest_response_headers(
    out_headers: &mut HeaderMap,
    upstream_headers: &reqwest::header::HeaderMap,
    preserve_upgrade_headers: bool,
) {
    let mut conn_tokens = HashSet::new();
    if !preserve_upgrade_headers {
        for val in upstream_headers.get_all(reqwest::header::CONNECTION) {
            if let Ok(raw) = val.to_str() {
                for part in raw.split(',') {
                    let token = part.trim();
                    if !token.is_empty() {
                        conn_tokens.insert(token.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if !preserve_upgrade_headers
            && (is_hop_by_hop_header(name) || conn_tokens.contains(&name.to_ascii_lowercase()))
        {
            continue;
        }
        if let (Ok(hk), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out_headers.append(hk, hv);
        }
    }
}

fn apply_upgrade_request_headers(
    dst: &mut HeaderMap,
    upstream_headers: &HeaderMap,
    incoming_headers: &HeaderMap,
    upstream_host: Option<&str>,
    upgrade_header: &str,
) {
    let conn_tokens = connection_header_tokens(upstream_headers);
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop_header(name)
            || conn_tokens.contains(&name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        dst.append(k.clone(), v.clone());
    }
    if let Some(host) = upstream_host.filter(|h| !h.is_empty()) {
        if let Ok(hv) = HeaderValue::from_str(host) {
            dst.insert(header::HOST, hv);
        }
    }
    if let Ok(up_hv) = HeaderValue::from_str(upgrade_header) {
        dst.insert(header::UPGRADE, up_hv);
    }
    dst.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    for ws_hdr in WS_HANDSHAKE_HEADERS {
        if let Some(val) = incoming_headers.get(ws_hdr) {
            if let Ok(hn) = HeaderName::from_bytes(ws_hdr.as_bytes()) {
                dst.insert(hn, val.clone());
            }
        }
    }
}

fn apply_reqwest_headers(
    mut builder: reqwest::RequestBuilder,
    upstream_headers: &HeaderMap,
    upstream_host: Option<&str>,
    include_ws_headers_from: Option<(&HeaderMap, &str)>,
) -> reqwest::RequestBuilder {
    let conn_tokens = connection_header_tokens(upstream_headers);
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop_header(name)
            || conn_tokens.contains(&name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("host")
        {
            continue;
        }
        if let (Ok(rk), Ok(mut rv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            if v.is_sensitive() {
                rv.set_sensitive(true);
            }
            builder = builder.header(rk, rv);
        }
    }
    if let Some(host) = upstream_host.filter(|h| !h.is_empty()) {
        if let Ok(hv) = reqwest::header::HeaderValue::from_str(host) {
            builder = builder.header(reqwest::header::HOST, hv);
        }
    }
    if let Some((incoming_headers, upgrade_header)) = include_ws_headers_from {
        if let Ok(up_hv) = reqwest::header::HeaderValue::from_str(upgrade_header) {
            builder = builder.header(reqwest::header::UPGRADE, up_hv);
        }
        builder = builder.header(reqwest::header::CONNECTION, "Upgrade");
        for ws_hdr in WS_HANDSHAKE_HEADERS {
            if let Some(val) = incoming_headers.get(ws_hdr) {
                if let (Ok(rk), Ok(rv)) = (
                    reqwest::header::HeaderName::from_bytes(ws_hdr.as_bytes()),
                    reqwest::header::HeaderValue::from_bytes(val.as_bytes()),
                ) {
                    builder = builder.header(rk, rv);
                }
            }
        }
    }
    builder
}

fn spawn_bidirectional_tunnel<C, U, FutC, FutU, E1, E2>(
    client_upgrade: FutC,
    upstream_upgrade: FutU,
    upgrade_timeout: Duration,
    guard: Option<Box<dyn std::any::Any + Send + Sync>>,
    stream_cancel: Option<watch::Receiver<bool>>,
    log_context: String,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    FutC: std::future::Future<Output = Result<C, E1>> + Send + 'static,
    FutU: std::future::Future<Output = Result<U, E2>> + Send + 'static,
    E1: std::fmt::Display + Send + 'static,
    E2: std::fmt::Display + Send + 'static,
{
    tokio::spawn(async move {
        let _guard = guard;
        let mut cancel_rx = stream_cancel;

        let upgraded = async {
            let join = async move {
                tokio::try_join!(
                    async move { client_upgrade.await.map_err(|e| e.to_string()) },
                    async move { upstream_upgrade.await.map_err(|e| e.to_string()) },
                )
            };
            if let Some(rx) = cancel_rx.as_mut() {
                tokio::select! {
                    biased;
                    _ = wait_for_cancel_watch(rx) => Err("cancelled".to_string()),
                    res = tokio::time::timeout(upgrade_timeout, join) => match res {
                        Ok(pair) => pair,
                        Err(_) => Err("upgrade handshake timed out".to_string()),
                    }
                }
            } else {
                match tokio::time::timeout(upgrade_timeout, join).await {
                    Ok(pair) => pair,
                    Err(_) => Err("upgrade handshake timed out".to_string()),
                }
            }
        }
        .await;

        let (client_io, upstream_io) = match upgraded {
            Ok(pair) => pair,
            Err(err) => {
                tracing::debug!(context = %log_context, error = %err, "proxy websocket upgrade tunnel closed before copy");
                return;
            }
        };

        // Pump both directions independently and bound half-open drain after either peer closes so
        // an abrupt disconnect or remote revocation never leaks a per-link WebSocket permit on a
        // stalled client socket while still allowing any final Close frame to flush cleanly.
        use tokio::io::AsyncWriteExt as _;
        let (mut client_read, mut client_write) = tokio::io::split(client_io);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_io);
        let mut c2u = Box::pin(async move {
            let res = tokio::io::copy(&mut client_read, &mut upstream_write).await;
            let _ = upstream_write.shutdown().await;
            res
        });
        let mut u2c = Box::pin(async move {
            let res = tokio::io::copy(&mut upstream_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
            res
        });
        let half_close_drain = Duration::from_millis(250);

        if let Some(mut rx) = cancel_rx {
            tokio::select! {
                biased;
                _ = wait_for_cancel_watch(&mut rx) => {
                    tracing::debug!(context = %log_context, "proxy websocket tunnel torn down by cancellation");
                }
                res = &mut u2c => {
                    if let Err(err) = res {
                        tracing::debug!(context = %log_context, error = %err, "proxy websocket upstream stream ended");
                    }
                    let _ = tokio::time::timeout(half_close_drain, &mut c2u).await;
                }
                res = &mut c2u => {
                    if let Err(err) = res {
                        tracing::debug!(context = %log_context, error = %err, "proxy websocket client stream ended");
                    }
                    let _ = tokio::time::timeout(half_close_drain, &mut u2c).await;
                }
            }
        } else {
            tokio::select! {
                res = &mut u2c => {
                    if let Err(err) = res {
                        tracing::debug!(context = %log_context, error = %err, "proxy websocket upstream stream ended");
                    }
                    let _ = tokio::time::timeout(half_close_drain, &mut c2u).await;
                }
                res = &mut c2u => {
                    if let Err(err) = res {
                        tracing::debug!(context = %log_context, error = %err, "proxy websocket client stream ended");
                    }
                    let _ = tokio::time::timeout(half_close_drain, &mut u2c).await;
                }
            }
        }
    });
}

/// Shared streaming HTTP and WebSocket upgrade proxy transport used by both
/// [`app_subdomain_proxy_middleware`] and the P6 peer management proxy.
pub(crate) async fn stream_proxy(
    req: Request,
    target: Url,
    client: &reqwest::Client,
    mut opts: StreamProxyOptions,
) -> Response {
    if opts.stream_cancel.as_ref().is_some_and(|rx| *rx.borrow()) {
        return build_stream_proxy_error(
            opts.on_error.take(),
            StreamProxyErrorKind::Cancelled,
            format!("Upstream {} access revoked.", opts.log_context),
        );
    }

    let upgrade_header_opt = is_upgrade_request_for_policy(&req, opts.upgrade_policy);
    let use_tls = target.scheme().eq_ignore_ascii_case("https");
    let method = req.method().clone();
    let incoming_headers = req.headers().clone();

    if let Some(upgrade_header) = upgrade_header_opt {
        if use_tls {
            let ws_client = opts.tls_ws_client.as_ref().unwrap_or(client);
            let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
                .unwrap_or(reqwest::Method::GET);
            let mut ws_req = ws_client.request(reqwest_method, target.as_str());
            ws_req = apply_reqwest_headers(
                ws_req,
                &opts.upstream_headers,
                opts.upstream_host.as_deref(),
                Some((&incoming_headers, &upgrade_header)),
            );

            let ws_send = tokio::select! {
                biased;
                _ = wait_optional_cancel(&mut opts.stream_cancel) => None,
                res = tokio::time::timeout(opts.header_timeout, ws_req.send()) => Some(res),
            };
            let upstream_resp = match ws_send {
                None => {
                    return build_stream_proxy_error(
                        opts.on_error.take(),
                        StreamProxyErrorKind::Cancelled,
                        format!("Upstream {} access revoked.", opts.log_context),
                    );
                }
                Some(Ok(Ok(resp))) => resp,
                Some(Ok(Err(err))) => {
                    tracing::warn!(context = %opts.log_context, error = %err, "TLS websocket upstream error");
                    let kind = if err.is_timeout() {
                        StreamProxyErrorKind::GatewayTimeout
                    } else {
                        StreamProxyErrorKind::BadGateway
                    };
                    return build_stream_proxy_error(
                        opts.on_error.take(),
                        kind,
                        format!("Upstream {} is unavailable.", opts.log_context),
                    );
                }
                Some(Err(_)) => {
                    return build_stream_proxy_error(
                        opts.on_error.take(),
                        StreamProxyErrorKind::GatewayTimeout,
                        format!("Upstream {} upgrade timed out.", opts.log_context),
                    );
                }
            };

            if upstream_resp.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS {
                let resp_headers_clone = upstream_resp.headers().clone();
                let client_upgrade = hyper::upgrade::on(req);
                let upstream_upgrade = upstream_resp.upgrade();
                spawn_bidirectional_tunnel(
                    async move {
                        client_upgrade
                            .await
                            .map(hyper_util::rt::TokioIo::new)
                            .map_err(|e| e.to_string())
                    },
                    async move { upstream_upgrade.await.map_err(|e| e.to_string()) },
                    opts.header_timeout,
                    opts.guard.take(),
                    opts.stream_cancel.take(),
                    opts.log_context.clone(),
                );

                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                copy_filtered_reqwest_response_headers(
                    response.headers_mut(),
                    &resp_headers_clone,
                    true,
                );
                if let Some(transform) = opts.response_transform.take() {
                    transform(&mut response, true);
                }
                if !response.headers().contains_key(header::UPGRADE) {
                    if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                        response.headers_mut().insert(header::UPGRADE, up_hv);
                    }
                }
                if !response.headers().contains_key(header::CONNECTION) {
                    response
                        .headers_mut()
                        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
                }
                return response;
            } else {
                let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                let resp_headers_clone = upstream_resp.headers().clone();
                let stream = upstream_resp.bytes_stream();
                let mut response = Response::new(GuardedBody::wrap_with_cancel(
                    Body::from_stream(stream),
                    opts.guard.take(),
                    opts.stream_cancel.take(),
                ));
                *response.status_mut() = status;
                copy_filtered_reqwest_response_headers(
                    response.headers_mut(),
                    &resp_headers_clone,
                    false,
                );
                if let Some(transform) = opts.response_transform.take() {
                    transform(&mut response, false);
                }
                return response;
            }
        }

        // Plain HTTP WebSocket upgrade over raw TCP + hyper HTTP/1.1 with strict deadline budget.
        let deadline = tokio::time::Instant::now() + opts.header_timeout;
        let connect_budget = opts
            .ws_connect_timeout
            .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        let tcp_res = tokio::select! {
            biased;
            _ = wait_optional_cancel(&mut opts.stream_cancel) => None,
            res = connect_upstream_tcp(&target, opts.tcp_bind.as_ref(), connect_budget) => Some(res),
        };
        let tcp_stream = match tcp_res {
            None => {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::Cancelled,
                    format!("Upstream {} access revoked.", opts.log_context),
                );
            }
            Some(Ok(stream)) => stream,
            Some(Err(kind)) => {
                tracing::warn!(context = %opts.log_context, ?kind, "websocket upstream connect error");
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    kind,
                    match kind {
                        StreamProxyErrorKind::BadGateway => {
                            format!("Upstream {} is unavailable.", opts.log_context)
                        }
                        StreamProxyErrorKind::GatewayTimeout => {
                            format!("Upstream {} timed out connecting.", opts.log_context)
                        }
                        StreamProxyErrorKind::Cancelled => {
                            format!("Upstream {} access revoked.", opts.log_context)
                        }
                    },
                );
            }
        };

        let io = hyper_util::rt::TokioIo::new(tcp_stream);
        let handshake_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        let hs_res = tokio::select! {
            biased;
            _ = wait_optional_cancel(&mut opts.stream_cancel) => None,
            res = tokio::time::timeout(handshake_budget, hyper::client::conn::http1::handshake(io)) => Some(res),
        };
        let (mut sender, conn) = match hs_res {
            None => {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::Cancelled,
                    format!("Upstream {} access revoked.", opts.log_context),
                );
            }
            Some(Ok(Ok(pair))) => pair,
            Some(Ok(Err(err))) => {
                tracing::warn!(context = %opts.log_context, error = %err, "websocket upstream HTTP/1 handshake error");
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::BadGateway,
                    format!("Upstream {} is unavailable.", opts.log_context),
                );
            }
            Some(Err(_)) => {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::GatewayTimeout,
                    format!("Upstream {} handshake timed out.", opts.log_context),
                );
            }
        };

        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!(error = %err, "upstream websocket connection ended");
            }
        });

        let target_pq = match target.query() {
            Some(q) => format!("{}?{}", target.path(), q),
            None => target.path().to_string(),
        };
        let mut req_builder = hyper::Request::builder().method(method).uri(&target_pq);
        if let Some(hdrs) = req_builder.headers_mut() {
            apply_upgrade_request_headers(
                hdrs,
                &opts.upstream_headers,
                &incoming_headers,
                opts.upstream_host.as_deref(),
                &upgrade_header,
            );
        }

        let Ok(upstream_ws_req) =
            req_builder.body(http_body_util::Empty::<axum::body::Bytes>::new())
        else {
            return build_stream_proxy_error(
                opts.on_error.take(),
                StreamProxyErrorKind::BadGateway,
                format!("Upstream {} is unavailable.", opts.log_context),
            );
        };

        let send_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        let ws_resp_res = tokio::select! {
            biased;
            _ = wait_optional_cancel(&mut opts.stream_cancel) => None,
            res = tokio::time::timeout(send_budget, sender.send_request(upstream_ws_req)) => Some(res),
        };
        let mut upstream_resp = match ws_resp_res {
            None => {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::Cancelled,
                    format!("Upstream {} access revoked.", opts.log_context),
                );
            }
            Some(Ok(Ok(resp))) => resp,
            Some(Ok(Err(err))) => {
                tracing::warn!(context = %opts.log_context, error = %err, "websocket upstream response error");
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::BadGateway,
                    format!("Upstream {} is unavailable.", opts.log_context),
                );
            }
            Some(Err(_)) => {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::GatewayTimeout,
                    format!("Upstream {} upgrade timed out.", opts.log_context),
                );
            }
        };

        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let resp_headers_clone = upstream_resp.headers().clone();
            let client_upgrade = hyper::upgrade::on(req);
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
            spawn_bidirectional_tunnel(
                async move {
                    client_upgrade
                        .await
                        .map(hyper_util::rt::TokioIo::new)
                        .map_err(|e| e.to_string())
                },
                async move {
                    upstream_upgrade
                        .await
                        .map(hyper_util::rt::TokioIo::new)
                        .map_err(|e| e.to_string())
                },
                opts.header_timeout,
                opts.guard.take(),
                opts.stream_cancel.take(),
                opts.log_context.clone(),
            );

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            copy_filtered_response_headers(response.headers_mut(), &resp_headers_clone, true);
            if let Some(transform) = opts.response_transform.take() {
                transform(&mut response, true);
            }
            if !response.headers().contains_key(header::UPGRADE) {
                if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                    response.headers_mut().insert(header::UPGRADE, up_hv);
                }
            }
            if !response.headers().contains_key(header::CONNECTION) {
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            }
            return response;
        } else {
            let (upstream, body) = upstream_resp.into_parts();
            let mut response = Response::new(GuardedBody::wrap_with_cancel(
                Body::new(body),
                opts.guard.take(),
                opts.stream_cancel.take(),
            ));
            *response.status_mut() = upstream.status;
            copy_filtered_response_headers(response.headers_mut(), &upstream.headers, false);
            if let Some(transform) = opts.response_transform.take() {
                transform(&mut response, false);
            }
            return response;
        }
    }

    // Streaming HTTP request & response (no buffering; header timeout does not cap multi-minute bodies).
    let has_body = if opts.discard_request_body {
        false
    } else {
        !hyper::body::Body::is_end_stream(req.body())
            || incoming_headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .is_some_and(|len| len > 0)
            || incoming_headers.contains_key(header::TRANSFER_ENCODING)
    };

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream_req = client.request(reqwest_method, target.as_str());
    upstream_req = apply_reqwest_headers(
        upstream_req,
        &opts.upstream_headers,
        opts.upstream_host.as_deref(),
        None,
    );

    enum SendOutcome {
        Response(Result<reqwest::Response, reqwest::Error>),
        Timeout(&'static str),
        Cancelled,
    }

    let send_res = if has_body {
        let (progress_tx, progress_rx) = watch::channel(Some(Instant::now()));
        let req_body_cancel = opts.stream_cancel.clone().map(CancelWaiter::new);
        let stream = SignalingStream {
            inner: req.into_body().into_data_stream(),
            progress: Some(progress_tx),
            track_progress: opts.upload_idle_timeout.is_some(),
            cancel: req_body_cancel,
            cancelled: false,
        };
        upstream_req = upstream_req.body(reqwest::Body::wrap_stream(stream));
        tokio::select! {
            biased;
            _ = wait_optional_cancel(&mut opts.stream_cancel) => SendOutcome::Cancelled,
            res = upstream_req.send() => SendOutcome::Response(res),
            stage = wait_for_http_proxy_timeout(progress_rx, opts.upload_idle_timeout, opts.header_timeout) => SendOutcome::Timeout(stage),
        }
    } else {
        tokio::select! {
            biased;
            _ = wait_optional_cancel(&mut opts.stream_cancel) => SendOutcome::Cancelled,
            res = tokio::time::timeout(opts.header_timeout, upstream_req.send()) => match res {
                Ok(resp_res) => SendOutcome::Response(resp_res),
                Err(_) => SendOutcome::Timeout("response headers"),
            },
        }
    };

    match send_res {
        SendOutcome::Response(Ok(upstream_resp)) => {
            if opts.stream_cancel.as_ref().is_some_and(|rx| *rx.borrow()) {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::Cancelled,
                    format!("Upstream {} access revoked.", opts.log_context),
                );
            }
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let upstream_headers = upstream_resp.headers().clone();
            let stream = upstream_resp.bytes_stream();
            let mut response = Response::new(GuardedBody::wrap_with_cancel(
                Body::from_stream(stream),
                opts.guard.take(),
                opts.stream_cancel.take(),
            ));
            *response.status_mut() = status;
            copy_filtered_reqwest_response_headers(
                response.headers_mut(),
                &upstream_headers,
                false,
            );
            if let Some(transform) = opts.response_transform.take() {
                transform(&mut response, false);
            }
            response
        }
        SendOutcome::Response(Err(err)) => {
            if opts.stream_cancel.as_ref().is_some_and(|rx| *rx.borrow()) {
                return build_stream_proxy_error(
                    opts.on_error.take(),
                    StreamProxyErrorKind::Cancelled,
                    format!("Upstream {} access revoked.", opts.log_context),
                );
            }
            tracing::warn!(context = %opts.log_context, error = %err, "stream proxy upstream error");
            let kind = if err.is_timeout() {
                StreamProxyErrorKind::GatewayTimeout
            } else {
                StreamProxyErrorKind::BadGateway
            };
            build_stream_proxy_error(
                opts.on_error.take(),
                kind,
                format!("Upstream {} is unavailable.", opts.log_context),
            )
        }
        SendOutcome::Timeout(stage) => {
            tracing::warn!(context = %opts.log_context, stage, "stream proxy timeout");
            build_stream_proxy_error(
                opts.on_error.take(),
                StreamProxyErrorKind::GatewayTimeout,
                format!("Upstream {} timed out.", opts.log_context),
            )
        }
        SendOutcome::Cancelled => {
            tracing::debug!(context = %opts.log_context, "stream proxy request aborted by cancellation");
            build_stream_proxy_error(
                opts.on_error.take(),
                StreamProxyErrorKind::Cancelled,
                format!("Upstream {} access revoked.", opts.log_context),
            )
        }
    }
}

pub async fn app_subdomain_proxy_middleware(req: Request, next: Next) -> Response {
    // Apache uses this header to require an application route. It cannot grant
    // access or select an upstream. The incoming Host still drives resolution.
    let managed_app = req.headers().get(GATEWAY_APP_HEADER);
    if req.uri().path().starts_with("/.well-known/acme-challenge/") {
        if managed_app.is_some() {
            return managed_app_route_unavailable();
        }
        return next.run(req).await;
    }

    let peer_ip_opt = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    if managed_app.is_some() && !peer_ip_opt.is_some_and(|peer| peer.to_canonical().is_loopback()) {
        return managed_app_route_unavailable();
    }
    let trust_forwarded = peer_ip_opt.is_some_and(is_trusted_proxy_ip);

    let raw_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let clean_host = strip_host_port_and_dot(&raw_host);

    let is_internal_aether_local = clean_host.ends_with(".aether.local");
    // Known control-plane authorities need no DB or auth work.
    if local_control_plane_host(&clean_host)
        || (managed_app.is_none() && explicit_control_plane_host(&raw_host, &clean_host))
        || af_db::maybe_cached_control_plane_host(&clean_host)
    {
        if managed_app.is_some() {
            return managed_app_route_unavailable();
        }
        return next.run(req).await;
    }
    if is_internal_aether_local && !local_domain_client_allowed(req.headers(), peer_ip_opt) {
        return internal_domain_forbidden();
    }

    let lookup_host = raw_host.clone();
    let Some(disposition) =
        resolve_proxy_work(move || resolve_app_host_disposition(&lookup_host)).await
    else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PROXY_RESOLUTION_UNAVAILABLE",
            "Proxy resolution unavailable",
        );
    };
    let (app_name, target_port) = match disposition {
        AppHostResolution::Proxy(app, port) => (app, port),
        AppHostResolution::DisabledExternalApp(_) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "EXTERNAL_ACCESS_DISABLED",
                "External access is not enabled for this application subdomain",
            );
        }
        AppHostResolution::ControlPlane if managed_app.is_some() => {
            return managed_app_route_unavailable();
        }
        AppHostResolution::ControlPlane => return next.run(req).await,
    };
    let requires_auth = !is_internal_aether_local && external_proxy_requires_auth(&app_name);
    if managed_app.is_some_and(|expected| {
        !requires_auth
            || expected.as_bytes() != app_name.as_bytes()
            || !(1..=65535).contains(&target_port)
    }) {
        return managed_app_route_unavailable();
    }
    if !(1..=65535).contains(&target_port) {
        return next.run(req).await;
    }

    let app_origin =
        crate::app_launch::managed_origin(req.headers(), &raw_host, managed_app.is_some());
    if req.uri().path() == af_models::APP_LAUNCH_EXCHANGE_PATH {
        return crate::app_launch::redeem(req, app_name, app_origin).await;
    }

    let headers = req.headers().clone();
    let auth_app = app_name.clone();
    let authenticated_user = resolve_proxy_work(move || {
        app_origin
            .and_then(|origin| crate::app_launch::authenticated_admin(&headers, &auth_app, &origin))
            .or_else(|| {
                resolve_optional_authenticated_user(&headers, peer_ip_opt)
                    .filter(|user| !requires_auth || user.role == "admin")
                    .map(|user| user.username)
            })
    })
    .await
    .flatten();
    let authenticated_user = if requires_auth
        && authenticated_user.is_none()
        && req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
    {
        let ip = peer_ip_opt.map_or_else(
            || "127.0.0.1".to_string(),
            |peer| crate::ws::extract_client_ip_for_peer(req.headers(), Some(peer)),
        );
        let Some(attempt) = PROXY_BASIC_AUTH_LIMITER.reserve(&ip) else {
            return rate_limited_response();
        };
        let headers = req.headers().clone();
        tokio::time::timeout(PROXY_RESOLVE_TIMEOUT, async move {
            let permit = PROXY_AUTH_BLOCKING_LIMIT.acquire().await.ok()?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let user = verify_proxy_basic_credentials(&headers);
                if user.is_some() {
                    PROXY_BASIC_AUTH_LIMITER.refund(&ip, attempt);
                }
                user
            })
            .await
            .ok()
            .flatten()
        })
        .await
        .ok()
        .flatten()
    } else {
        authenticated_user
    };
    if requires_auth && authenticated_user.is_none() {
        let mut response = api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Administrator authentication required",
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"AetherFlow\""),
        );
        return response;
    }

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let pinned_client = if app_name == "librespeed" {
        match resolve_proxy_work(librespeed_tls_client).await {
            Some(Ok(client)) => client,
            result => {
                tracing::warn!(?result, "LibreSpeed upstream TLS configuration unavailable");
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "LibreSpeed upstream TLS configuration unavailable",
                );
            }
        }
    } else {
        None
    };
    let use_tls = pinned_client.is_some()
        || (app_name != "librespeed" && upstream_uses_tls(&app_name, target_port as u16));
    let scheme = if use_tls { "https" } else { "http" };
    let target_url_str = format!("{scheme}://127.0.0.1:{target_port}{path_and_query}");

    if use_tls && !is_strict_loopback_https_url(&target_url_str) {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "bad_gateway",
                "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
            })),
        )
            .into_response();
    }

    let Ok(target_url) = Url::parse(&target_url_str) else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "bad_gateway",
                "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
            })),
        )
            .into_response();
    };

    let mut incoming_headers = req.headers().clone();
    if requires_auth {
        incoming_headers.remove(header::AUTHORIZATION);
    }
    strip_gateway_session_cookies(&mut incoming_headers, requires_auth);

    let mut upstream_headers = HeaderMap::new();
    for (k, v) in incoming_headers.iter() {
        let name_str = k.as_str();
        if is_hop_by_hop_header(name_str)
            || is_forwarded_header_name(name_str)
            || is_spoofable_identity_header(name_str)
            || name_str.eq_ignore_ascii_case("host")
        {
            continue;
        }
        upstream_headers.append(k.clone(), v.clone());
    }
    for (hn, hv) in
        canonical_forwarded_headers(&incoming_headers, &raw_host, peer_ip_opt, trust_forwarded)
    {
        upstream_headers.insert(hn, hv);
    }
    if let Some(ref user) = authenticated_user {
        if let Ok(user_hv) = HeaderValue::from_str(user) {
            upstream_headers.insert(HeaderName::from_static("x-aetherflow-user"), user_hv);
        }
    }

    let client = if use_tls {
        pinned_client.as_ref().unwrap_or(&PROXY_LOOPBACK_TLS_CLIENT)
    } else {
        &*PROXY_HTTP_CLIENT
    };
    let tls_ws_client = if use_tls {
        Some(
            pinned_client
                .clone()
                .unwrap_or_else(|| PROXY_LOOPBACK_TLS_WS_CLIENT.clone()),
        )
    } else {
        None
    };

    let is_upgrade =
        is_upgrade_request_for_policy(&req, StreamProxyUpgradePolicy::AnyUpgrade).is_some();
    let app_err_name = app_name.clone();
    let err_port = target_port;
    let opts = StreamProxyOptions {
        upstream_headers,
        upstream_host: (!raw_host.is_empty()).then_some(raw_host.clone()),
        tcp_bind: None,
        tls_ws_client,
        header_timeout: if is_upgrade {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(30)
        },
        upload_idle_timeout: None,
        ws_connect_timeout: Duration::from_secs(10),
        upgrade_policy: StreamProxyUpgradePolicy::AnyUpgrade,
        guard: None,
        stream_cancel: None,
        response_transform: None,
        on_error: Some(Box::new(move |kind, _| {
            match kind {
            StreamProxyErrorKind::BadGateway => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_err_name, err_port),
                })),
            )
                .into_response(),
            StreamProxyErrorKind::GatewayTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "gateway_timeout",
                    "message": format!("Upstream service {} on port {} timed out.", app_err_name, err_port),
                })),
            )
                .into_response(),
            StreamProxyErrorKind::Cancelled => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "message": format!("Upstream service {} on port {} request was cancelled.", app_err_name, err_port),
                })),
            )
                .into_response(),
        }
        })),
        log_context: format!("subdomain:{app_name}:{target_port}"),
        discard_request_body: false,
    };

    stream_proxy(req, target_url, client, opts).await
}

#[cfg(test)]
mod upload_progress_tests {
    use super::*;
    use axum::body::Bytes;
    use futures::StreamExt as _;

    #[tokio::test]
    async fn upload_activity_counts_only_when_bytes_are_forwarded() {
        let (progress_tx, mut progress_rx) = watch::channel(Some(Instant::now()));
        let chunks = futures::stream::iter([
            Ok::<_, std::io::Error>(Bytes::new()),
            Ok(Bytes::from_static(b"upload data")),
        ]);
        let mut stream = SignalingStream {
            inner: chunks,
            progress: Some(progress_tx),
            track_progress: true,
            cancel: None,
            cancelled: false,
        };

        assert!(stream.next().await.unwrap().unwrap().is_empty());
        assert!(!progress_rx.has_changed().unwrap());
        assert!(!stream.next().await.unwrap().unwrap().is_empty());
        assert!(progress_rx.has_changed().unwrap());
        assert!(progress_rx.borrow_and_update().is_some());
        assert!(stream.next().await.is_none());
        assert!(progress_rx.borrow().is_none());
    }
}
