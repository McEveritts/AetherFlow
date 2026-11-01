use crate::auth::{api_error, decode_session_claims, resolve_raw_token, AuthUser};
use crate::ws::extract_client_ip;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────────────
// 1. Subdomain & Host Resolution (`backend/services/blueprint_lifecycle.go`)
// ──────────────────────────────────────────────────────────────────────────────

fn strip_host_port_and_dot(raw_host: &str) -> String {
    let mut host = raw_host.trim().to_lowercase();
    if let Some(colon_idx) = host.rfind(':') {
        if !host[colon_idx..].contains(']') {
            host = host[..colon_idx].to_string();
        }
    }
    host = host.trim_matches(['[', ']']).trim_end_matches('.').to_string();
    host
}

fn query_settings_base_domain() -> String {
    let db_domain = af_db::get_base_domain();
    if !db_domain.is_empty() {
        return db_domain;
    }
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(dom) = conn.query_row(
            "SELECT COALESCE(domain, '') FROM settings WHERE id = 1",
            [],
            |r| r.get::<_, String>(0),
        ) {
            let norm = af_db::normalize_base_domain(&dom);
            if !norm.is_empty() {
                return norm;
            }
        }
    }
    af_services::resolve_base_domain()
}

pub fn resolve_app_target_for_host(raw_host: &str) -> Option<(String, i32)> {
    let clean_host = strip_host_port_and_dot(raw_host);
    if clean_host.is_empty()
        || clean_host == "localhost"
        || clean_host == "127.0.0.1"
        || clean_host == "::1"
        || clean_host == "aether.local"
        || clean_host == "aetherflow.aether.local"
    {
        return None;
    }
    if clean_host.parse::<IpAddr>().is_ok() {
        return None;
    }

    let base_domain = query_settings_base_domain();
    if !base_domain.is_empty()
        && (clean_host == base_domain
            || clean_host == format!("www.{}", base_domain)
            || clean_host == format!("direct.{}", base_domain)
            || clean_host == format!("aetherflow.{}", base_domain))
    {
        return None;
    }

    let configs = af_db::get_all_app_ingress_configs().unwrap_or_default();

    // 1. Exact match on configured `public_domain` (where `external_access_enabled` is true and `listen_port > 0`)
    //    or `<app>.aether.local` from `app_ingress_configs`
    for cfg in &configs {
        if cfg.listen_port <= 0 {
            continue;
        }
        let pub_dom = strip_host_port_and_dot(&cfg.public_domain);
        if cfg.external_access_enabled && !pub_dom.is_empty() && clean_host == pub_dom {
            return Some((cfg.app_name.clone(), cfg.listen_port));
        }
        let app_lower = cfg.app_name.trim().to_lowercase();
        if !app_lower.is_empty() && clean_host == format!("{}.aether.local", app_lower) {
            return Some((cfg.app_name.clone(), cfg.listen_port));
        }
    }

    // 2. Fallback: match `<app>.aether.local` or `<app>.<base_domain>` against catalog blueprints
    let mut candidate_app = None;
    let mut is_internal = false;

    if let Some(app_prefix) = clean_host.strip_suffix(".aether.local") {
        candidate_app = Some(app_prefix);
        is_internal = true;
    } else if !base_domain.is_empty() {
        let suffix = format!(".{}", base_domain);
        if let Some(app_prefix) = clean_host.strip_suffix(&suffix) {
            candidate_app = Some(app_prefix);
        }
    }

    if let Some(app) = candidate_app {
        if !app.is_empty() && !app.contains('.') {
            if let Some(bp) = af_services::get_blueprint(app) {
                if bp.default_port > 0 {
                    let mut port = bp.default_port;
                    if let Some(ing) = configs
                        .iter()
                        .find(|c| c.app_name.eq_ignore_ascii_case(&bp.app_name))
                    {
                        if !is_internal {
                            if !ing.external_access_enabled {
                                return None;
                            }
                            let pub_dom = strip_host_port_and_dot(&ing.public_domain);
                            if !pub_dom.is_empty() && pub_dom != clean_host {
                                return None;
                            }
                        }
                        if ing.listen_port > 0 {
                            port = ing.listen_port;
                        }
                    }
                    if port > 0 {
                        return Some((bp.app_name, port));
                    }
                }
            }
        }
    }

    None
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. Application Subdomain Reverse Proxy (`backend/api/ingress_handlers.go`)
// ──────────────────────────────────────────────────────────────────────────────

static PRIVATE_IP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1$|\[::1\]|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe80:)",
    )
    .unwrap()
});

static PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

fn forward_proxy_http_headers(
    mut upstream_req: reqwest::RequestBuilder,
    incoming_headers: &axum::http::HeaderMap,
    raw_host: &str,
) -> reqwest::RequestBuilder {
    for (k, v) in incoming_headers.iter() {
        let name_str = k.as_str();
        // Host is set once below; reqwest's header() appends values.
        if is_hop_by_hop_header(name_str)
            || name_str.eq_ignore_ascii_case("host")
            || name_str.eq_ignore_ascii_case("x-aetherflow-user")
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
        if !incoming_headers.contains_key("X-Forwarded-Host") {
            upstream_req = upstream_req.header("X-Forwarded-Host", raw_host);
        }
    }
    if !incoming_headers.contains_key("X-Forwarded-Proto") {
        upstream_req = upstream_req.header("X-Forwarded-Proto", "http");
    }
    upstream_req
}

fn is_private_or_loopback_ip(raw_ip: &str) -> bool {
    let mut ip_str = raw_ip.trim().to_lowercase();
    if let Some(colon_idx) = ip_str.rfind(':') {
        if !ip_str[colon_idx..].contains(']') && ip_str.matches(':').count() == 1 {
            ip_str = ip_str[..colon_idx].to_string();
        }
    }
    let clean = ip_str.trim_matches(['[', ']']);
    if clean.is_empty() || clean == "localhost" {
        return true;
    }
    if PRIVATE_IP_RE.is_match(clean) {
        return true;
    }
    if let Ok(addr) = clean.parse::<IpAddr>() {
        return match addr {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
    }
    false
}

fn resolve_authenticated_username(headers: &axum::http::HeaderMap) -> Option<String> {
    let token = resolve_raw_token(headers)?;
    let claims = decode_session_claims(&token, false).ok()?;
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if af_db::is_token_revoked(&claims.jti)
        || !crate::auth::matches_client_fingerprint(
            &claims.cfp,
            &extract_client_ip(headers),
            user_agent,
        )
    {
        return None;
    }
    let conn = af_db::get_conn().ok()?;
    conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![claims.user_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .filter(|u| !u.is_empty())
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
    )
}

pub async fn app_subdomain_proxy_middleware(req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/.well-known/acme-challenge/") {
        return next.run(req).await;
    }

    let raw_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let clean_host = strip_host_port_and_dot(&raw_host);

    if clean_host == "aether.local" || clean_host.ends_with(".aether.local") {
        let mut allowed = true;

        if let Some(ConnectInfo(peer_addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            if !is_private_or_loopback_ip(&peer_addr.ip().to_string()) {
                allowed = false;
            }
        }

        if let Some(real_ip) = req
            .headers()
            .get("X-Real-IP")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            if !is_private_or_loopback_ip(real_ip) {
                allowed = false;
            }
        }

        if let Some(xff) = req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            for hop in xff.split(',') {
                let hop_ip = hop.trim().trim_matches(['[', ']']);
                if hop_ip.is_empty() || !is_private_or_loopback_ip(hop_ip) {
                    allowed = false;
                    break;
                }
            }
        }

        if !allowed {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Internal .aether.local domains are restricted to local network clients"
                })),
            )
                .into_response();
        }
    }

    let Some((app_name, target_port)) = resolve_app_target_for_host(&raw_host) else {
        return next.run(req).await;
    };
    if target_port <= 0 {
        return next.run(req).await;
    }

    let upgrade_header = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let is_ws_upgrade = !upgrade_header.is_empty()
        && (upgrade_header.eq_ignore_ascii_case("websocket")
            || req
                .headers()
                .get(header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|c| c.to_ascii_lowercase().contains("upgrade"))
                .unwrap_or(false));

    let method_str = req.method().as_str().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let target_url = format!("http://127.0.0.1:{}{}", target_port, path_and_query);

    let authenticated_user = resolve_authenticated_username(req.headers());
    let incoming_headers = req.headers().clone();

    if is_ws_upgrade {
        let tcp_stream = match tokio::net::TcpStream::connect(("127.0.0.1", target_port as u16)).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket upstream connect error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        let io = hyper_util::rt::TokioIo::new(tcp_stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket handshake error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                tracing::debug!(error = %err, "upstream websocket connection ended");
            }
        });

        let mut req_builder = hyper::Request::builder()
            .method(req.method().clone())
            .uri(&path_and_query);

        if let Some(hdrs) = req_builder.headers_mut() {
            for (k, v) in incoming_headers.iter() {
                let name_str = k.as_str();
                if is_hop_by_hop_header(name_str) || name_str.eq_ignore_ascii_case("x-aetherflow-user") {
                    continue;
                }
                hdrs.append(k.clone(), v.clone());
            }
            if !raw_host.is_empty() {
                if let Ok(hv) = HeaderValue::from_str(&raw_host) {
                    hdrs.insert(header::HOST, hv.clone());
                    if !incoming_headers.contains_key("X-Forwarded-Host") {
                        hdrs.insert(HeaderName::from_static("x-forwarded-host"), hv);
                    }
                }
            }
            if !incoming_headers.contains_key("X-Forwarded-Proto") {
                hdrs.insert(
                    HeaderName::from_static("x-forwarded-proto"),
                    HeaderValue::from_static("http"),
                );
            }
            if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                hdrs.insert(header::UPGRADE, up_hv);
            }
            hdrs.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));

            for ws_hdr in [
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-protocol",
                "sec-websocket-extensions",
            ] {
                if let Some(val) = incoming_headers.get(ws_hdr) {
                    if let Ok(hn) = HeaderName::from_bytes(ws_hdr.as_bytes()) {
                        hdrs.insert(hn, val.clone());
                    }
                }
            }

            hdrs.remove("x-aetherflow-user");
            if let Some(ref user) = authenticated_user {
                if let Ok(user_hv) = HeaderValue::from_str(user) {
                    hdrs.insert(HeaderName::from_static("x-aetherflow-user"), user_hv);
                }
            }
        }

        let Ok(upstream_ws_req) = req_builder.body(http_body_util::Empty::<axum::body::Bytes>::new()) else {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response();
        };

        let mut upstream_resp = match sender.send_request(upstream_ws_req).await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    error = %err,
                    "subdomain reverse proxy websocket upstream response error"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let resp_headers_clone = upstream_resp.headers().clone();
            let client_upgrade = hyper::upgrade::on(req);
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);

            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok((client_upgraded, upstream_upgraded)) => {
                        let mut client_io = hyper_util::rt::TokioIo::new(client_upgraded);
                        let mut upstream_io = hyper_util::rt::TokioIo::new(upstream_upgraded);
                        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "subdomain websocket upgrade tunnel closed");
                    }
                }
            });

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            let out_headers = response.headers_mut();
            for (k, v) in resp_headers_clone.iter() {
                out_headers.append(k.clone(), v.clone());
            }
            if !out_headers.contains_key(header::UPGRADE) {
                if let Ok(up_hv) = HeaderValue::from_str(&upgrade_header) {
                    out_headers.insert(header::UPGRADE, up_hv);
                }
            }
            if !out_headers.contains_key(header::CONNECTION) {
                out_headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            }
            return response;
        } else {
            let status = upstream_resp.status();
            let resp_headers_clone = upstream_resp.headers().clone();
            let body_bytes = http_body_util::BodyExt::collect(upstream_resp.into_body())
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let mut response = Response::new(Body::from(body_bytes));
            *response.status_mut() = status;
            let out_headers = response.headers_mut();
            for (k, v) in resp_headers_clone.iter() {
                if !is_hop_by_hop_header(k.as_str()) {
                    out_headers.append(k.clone(), v.clone());
                }
            }
            return response;
        }
    }

    let Ok(body_bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "bad_gateway",
                "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
            })),
        )
            .into_response();
    };

    let reqwest_method = reqwest::Method::from_bytes(method_str.as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut upstream_req = PROXY_HTTP_CLIENT.request(reqwest_method, &target_url);

    upstream_req = forward_proxy_http_headers(upstream_req, &incoming_headers, &raw_host);
    if let Some(user) = authenticated_user {
        upstream_req = upstream_req.header("X-Aetherflow-User", user);
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    match upstream_req.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let upstream_headers = upstream_resp.headers().clone();
            let stream = upstream_resp.bytes_stream();
            let mut response = Response::new(Body::from_stream(stream));
            *response.status_mut() = status;

            let resp_headers = response.headers_mut();
            for (k, v) in upstream_headers.iter() {
                if is_hop_by_hop_header(k.as_str()) {
                    continue;
                }
                if let (Ok(hk), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    resp_headers.append(hk, hv);
                }
            }
            response
        }
        Err(err) => {
            tracing::warn!(
                app = %app_name,
                host = %raw_host,
                port = target_port,
                error = %err,
                "subdomain reverse proxy upstream error"
            );
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response()
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Host Header Validation Middleware (`backend/api/auth.go`)
// ──────────────────────────────────────────────────────────────────────────────

fn is_host_trusted(candidate_raw: &str, allowed_set: &HashSet<String>) -> bool {
    let trimmed = candidate_raw.trim().to_lowercase();
    if trimmed.is_empty() {
        return true;
    }
    let clean = strip_host_port_and_dot(&trimmed);

    if allowed_set.contains(&trimmed) || allowed_set.contains(&clean) {
        return true;
    }

    if clean == "aether.local" || clean.ends_with(".aether.local") {
        return true;
    }

    if let Ok(configs) = af_db::get_all_app_ingress_configs() {
        for cfg in configs {
            let pub_dom = strip_host_port_and_dot(&cfg.public_domain);
            if !pub_dom.is_empty() && clean == pub_dom {
                return true;
            }
        }
    }

    let base_domain = query_settings_base_domain();
    if !base_domain.is_empty()
        && (clean == base_domain || clean.ends_with(&format!(".{}", base_domain)))
    {
        return true;
    }

    false
}

pub async fn host_validation_middleware(req: Request, next: Next) -> Response {
    let raw_allowed = env::var("ALLOWED_HOSTS").unwrap_or_default();
    let allowed_set: HashSet<String> = raw_allowed
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    if allowed_set.is_empty() {
        return next.run(req).await;
    }

    if let Some(host_val) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !is_host_trusted(host_val, &allowed_set) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_HOST",
                "Untrusted Host header",
            );
        }
    }

    if let Some(xfh_val) = req
        .headers()
        .get("X-Forwarded-Host")
        .and_then(|v| v.to_str().ok())
    {
        for hop in xfh_val.split(',') {
            let h = hop.trim();
            if !h.is_empty() && !is_host_trusted(h, &allowed_set) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_HOST",
                    "Untrusted Host header",
                );
            }
        }
    }

    next.run(req).await
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. Per-IP Sliding-Window Rate Limiter Middlewares (`backend/api/ratelimit.go`)
// ──────────────────────────────────────────────────────────────────────────────

struct SlidingWindowLimiter {
    visitors: Mutex<HashMap<String, Vec<Instant>>>,
    limit: usize,
    window: Duration,
}

impl SlidingWindowLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            visitors: Mutex::new(HashMap::new()),
            limit,
            window,
        }
    }

    fn allow(&self, ip: &str) -> bool {
        let mut guard = match self.visitors.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let window = self.window;

        if guard.len() > 2048 {
            guard.retain(|_, timestamps| {
                timestamps.retain(|&t| now.duration_since(t) < window);
                !timestamps.is_empty()
            });
        }

        let entry = guard.entry(ip.to_string()).or_default();
        entry.retain(|&t| now.duration_since(t) < window);

        if entry.len() >= self.limit {
            return false;
        }
        entry.push(now);
        true
    }
}

static AUTH_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(10, Duration::from_secs(60)));
static OIDC_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));
static WEBHOOK_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(30, Duration::from_secs(60)));
static AI_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));

fn rate_limit_disabled() -> bool {
    env::var("AF_DISABLE_RATELIMIT")
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false)
}

fn rate_limited_response() -> Response {
    let mut resp = api_error(
        StatusCode::TOO_MANY_REQUESTS,
        "RATE_LIMITED",
        "Too many requests, please try again later",
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    resp
}

fn extract_request_ip(req: &Request) -> String {
    if let Some(ConnectInfo(peer_addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let trust_proxy = peer_addr.ip().is_loopback()
            || env::var("TRUST_PROXY_HEADERS")
                .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
                .unwrap_or(false);
        if trust_proxy
            && (req.headers().contains_key("X-Forwarded-For")
                || req.headers().contains_key("X-Real-IP"))
        {
            return extract_client_ip(req.headers());
        }
        return peer_addr.ip().to_string();
    }
    extract_client_ip(req.headers())
}

pub async fn auth_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !AUTH_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

pub async fn oidc_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !OIDC_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

pub async fn webhook_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !WEBHOOK_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

pub async fn ai_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !AI_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. Storage Quota Upload Guard Middleware (`backend/api/quota_handlers.go`)
// ──────────────────────────────────────────────────────────────────────────────

pub async fn quota_upload_guard_middleware(req: Request, next: Next) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let user_id = auth_user.user_id;

    let content_length: i64 = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);

    if let Ok(conn) = af_db::get_conn() {
        if let Ok((quota_bytes, used_bytes)) = conn.query_row(
            "SELECT COALESCE(quota_bytes, 0), COALESCE(used_bytes, 0) FROM user_quotas WHERE user_id = ?1",
            params![user_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        ) {
            if quota_bytes > 0
                && (used_bytes >= quota_bytes
                    || used_bytes.saturating_add(content_length) > quota_bytes)
            {
                return api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "QUOTA_EXCEEDED",
                    "Storage quota exceeded. Free up space or contact an administrator.",
                );
            }
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod proxy_header_tests {
    use super::*;

    #[test]
    fn forwards_public_host_once_and_filters_untrusted_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("jellyfin.example.com"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("x-aetherflow-user", HeaderValue::from_static("spoofed"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("authorization", HeaderValue::from_static("Bearer test-token"));
        let request = forward_proxy_http_headers(
            reqwest::Client::new().get("http://127.0.0.1:8096/health"),
            &headers,
            "jellyfin.example.com",
        )
        .build()
        .unwrap();

        assert_eq!(request.headers().get_all(header::HOST).iter().count(), 1);
        assert_eq!(request.headers()[header::HOST], "jellyfin.example.com");
        assert_eq!(request.headers()["x-forwarded-host"], "jellyfin.example.com");
        assert_eq!(request.headers()["x-forwarded-proto"], "https");
        assert_eq!(request.headers()["authorization"], "Bearer test-token");
        assert!(!request.headers().contains_key(header::CONNECTION));
        assert!(!request.headers().contains_key("x-aetherflow-user"));
    }
}
