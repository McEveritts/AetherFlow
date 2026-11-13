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

#[cfg(test)]
#[path = "middlewares_security_regressions.rs"]
mod security_regressions;

// ──────────────────────────────────────────────────────────────────────────────
// 1. Subdomain & Host Resolution (`backend/services/blueprint_lifecycle.go`)
// ──────────────────────────────────────────────────────────────────────────────

fn strip_host_port_and_dot(raw_host: &str) -> String {
    // Parse an authority, never discard arbitrary suffixes as if they were ports.
    if raw_host.is_empty() || raw_host.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return String::new();
    }
    if let Ok(ip) = raw_host.parse::<IpAddr>() {
        return ip.to_string();
    }
    let valid_port = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|b| b.is_ascii_digit())
            && value.parse::<u16>().is_ok()
    };
    if let Some(rest) = raw_host.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return String::new();
        };
        if !suffix.is_empty() && !suffix.strip_prefix(':').is_some_and(valid_port) {
            return String::new();
        }
        return host
            .parse::<std::net::Ipv6Addr>()
            .map(|ip| ip.to_string())
            .unwrap_or_default();
    }
    let (host, port) = raw_host
        .split_once(':')
        .map_or((raw_host, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| !valid_port(port)) {
        return String::new();
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return String::new();
    }
    host.to_ascii_lowercase()
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

    let configs = af_db::get_all_app_ingress_configs().ok()?;
    let jobs = af_services::package_job_snapshot().ok()?;
    let packages = af_services::get_packages_with_jobs(&jobs).ok()?;
    let authorized = |app: &str, active_ingress: bool| {
        if jobs
            .active
            .keys()
            .any(|name| name.eq_ignore_ascii_case(app))
            || jobs.outcomes.values().any(|job| {
                job.package_id.eq_ignore_ascii_case(app)
                    && (job.status == "interrupted"
                        || (job.status != "completed"
                            && matches!(job.action.as_str(), "install" | "reinstall" | "remove")))
            })
        {
            return false;
        }
        active_ingress
            || (packages.iter().any(|package| {
                package.name.eq_ignore_ascii_case(app) && package.status == "installed"
            }) && matches!(af_db::get_retained_app_ingress_config(app), Ok(None)))
    };

    // 1. Exact match on configured `public_domain` (where `external_access_enabled` is true and `listen_port > 0`)
    //    or `<app>.aether.local` from `app_ingress_configs`
    for cfg in &configs {
        if !(1..=65535).contains(&cfg.listen_port) || !authorized(&cfg.app_name, true) {
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
                let ingress = configs
                    .iter()
                    .find(|config| config.app_name.eq_ignore_ascii_case(&bp.app_name));
                if !authorized(&bp.app_name, ingress.is_some()) {
                    return None;
                }
                if bp.default_port > 0 || ingress.is_some() {
                    let mut port = bp.default_port;
                    if let Some(ing) = ingress {
                        if !(1..=65535).contains(&ing.listen_port) {
                            return None;
                        }
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
                    if (1..=65535).contains(&port) {
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
        // Bound connection setup without limiting long-lived media response bodies.
        .connect_timeout(Duration::from_secs(10))
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
    let conn = af_db::get_read_conn().ok()?;
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

    let lookup_host = raw_host.clone();
    let lookup_headers = req.headers().clone();
    let lookup = crate::auth::blocking_auth_work(move || {
        let target = resolve_app_target_for_host(&lookup_host);
        let username = target
            .as_ref()
            .and_then(|_| resolve_authenticated_username(&lookup_headers));
        (target, username)
    })
    .await;
    let (target, authenticated_user) = match lookup {
        Ok(result) => result,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Proxy authentication unavailable",
            )
                .into_response()
        }
    };
    let Some((app_name, target_port)) = target else {
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

    let incoming_headers = req.headers().clone();

    if is_ws_upgrade {
        let tcp_stream = match tokio::net::TcpStream::connect(("127.0.0.1", target_port as u16))
            .await
        {
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
                if is_hop_by_hop_header(name_str)
                    || name_str.eq_ignore_ascii_case("host")
                    || name_str.eq_ignore_ascii_case("x-aetherflow-user")
                {
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

        let Ok(upstream_ws_req) =
            req_builder.body(http_body_util::Empty::<axum::body::Bytes>::new())
        else {
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
                        let _ =
                            tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await;
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

    let reqwest_method =
        reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
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
    let clean = strip_host_port_and_dot(candidate_raw);
    if clean.is_empty() {
        return false;
    }

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

    if let Some(host_val) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
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
    match tokio::task::spawn_blocking(move || {
        crate::mcbrowser::check_user_quota_pre_mutation(user_id, 0)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return error.into_response(),
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Storage authorization worker failed",
            )
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod proxy_header_tests {
    use super::*;

    #[test]
    fn authority_validation_rejects_userinfo_and_non_numeric_ports() {
        let allowed = HashSet::from(["localhost".to_string()]);
        for invalid in [
            "localhost:@example.test",
            "localhost:word",
            "localhost:65536",
            "localhost:80:90",
            "localhost\\example.test",
            " localhost",
            "localhost/evil",
            "[::1]:bad",
        ] {
            assert!(strip_host_port_and_dot(invalid).is_empty(), "{invalid}");
            assert!(!is_host_trusted(invalid, &allowed), "{invalid}");
        }
        for (input, expected) in [
            ("LOCALHOST.:8080", "localhost"),
            ("example.test:443", "example.test"),
            ("[::1]:8080", "::1"),
            ("::1", "::1"),
            ("[2001:db8::1]", "2001:db8::1"),
        ] {
            assert_eq!(strip_host_port_and_dot(input), expected);
        }
    }

    #[test]
    fn forwards_public_host_once_and_filters_untrusted_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("jellyfin.example.com"),
        );
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("x-aetherflow-user", HeaderValue::from_static("spoofed"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-token"),
        );
        let request = forward_proxy_http_headers(
            reqwest::Client::new().get("http://127.0.0.1:8096/health"),
            &headers,
            "jellyfin.example.com",
        )
        .build()
        .unwrap();

        assert_eq!(request.headers().get_all(header::HOST).iter().count(), 1);
        assert_eq!(request.headers()[header::HOST], "jellyfin.example.com");
        assert_eq!(
            request.headers()["x-forwarded-host"],
            "jellyfin.example.com"
        );
        assert_eq!(request.headers()["x-forwarded-proto"], "https");
        assert_eq!(request.headers()["authorization"], "Bearer test-token");
        assert!(!request.headers().contains_key(header::CONNECTION));
        assert!(!request.headers().contains_key("x-aetherflow-user"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::any;
    use axum::Router;
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawns a strict raw HTTP/1.1 mock upstream that behaves like Jellyfin/Kestrel:
    /// - Rejects any request with `!= 1` `Host:` header lines with `400 Bad Request`
    /// - Supports WebSocket upgrade (`Upgrade: websocket`) and echoes a frame over the upgraded stream
    /// - For normal HTTP requests, returns 200 OK with JSON detailing the observed request line,
    ///   host header count, headers, and body.
    async fn spawn_strict_kestrel_mock_upstream() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut temp = [0u8; 4096];
                    let header_end_pos = loop {
                        match socket.read(&mut temp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&temp[..n]);
                                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    break pos;
                                }
                            }
                        }
                    };

                    let header_bytes = &buf[..header_end_pos];
                    let header_text = String::from_utf8_lossy(header_bytes).to_string();
                    let mut lines = header_text.split("\r\n");
                    let request_line = lines.next().unwrap_or("").to_string();

                    let mut host_headers = Vec::new();
                    let mut content_length: usize = 0;
                    let mut is_ws = false;
                    let mut all_headers: HashMap<String, Vec<String>> = HashMap::new();

                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            let key_trim = k.trim();
                            let val_trim = v.trim().to_string();
                            if key_trim.eq_ignore_ascii_case("host") {
                                host_headers.push(val_trim.clone());
                            }
                            if key_trim.eq_ignore_ascii_case("content-length") {
                                content_length = val_trim.parse::<usize>().unwrap_or(0);
                            }
                            if key_trim.eq_ignore_ascii_case("upgrade")
                                && val_trim.eq_ignore_ascii_case("websocket")
                            {
                                is_ws = true;
                            }
                            all_headers
                                .entry(key_trim.to_ascii_lowercase())
                                .or_default()
                                .push(val_trim);
                        }
                    }

                    // Strict Kestrel check: must have exactly 1 Host header
                    if host_headers.len() != 1 {
                        let resp = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nDuplicate or missing Host header: count={}",
                            format!("Duplicate or missing Host header: count={}", host_headers.len()).len(),
                            host_headers.len()
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }

                    let body_start = header_end_pos + 4;
                    while buf.len() < body_start + content_length {
                        match socket.read(&mut temp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&temp[..n]),
                        }
                    }
                    let body_slice = if buf.len() >= body_start + content_length {
                        &buf[body_start..body_start + content_length]
                    } else {
                        &buf[body_start..]
                    };
                    let body_str = String::from_utf8_lossy(body_slice).to_string();

                    if is_ws {
                        let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Upstream-Host-Count: 1\r\n\r\n";
                        if socket.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        // Read ping payload over upgraded tunnel and reply
                        let mut ws_buf = [0u8; 64];
                        if let Ok(n) = socket.read(&mut ws_buf).await {
                            if n > 0 {
                                let reply = format!(
                                    "ws-ack:{}:{}",
                                    host_headers[0],
                                    String::from_utf8_lossy(&ws_buf[..n])
                                );
                                let _ = socket.write_all(reply.as_bytes()).await;
                            }
                        }
                        return;
                    }

                    let payload = serde_json::json!({
                        "requestLine": request_line,
                        "hostCount": host_headers.len(),
                        "host": host_headers[0],
                        "headers": all_headers,
                        "body": body_str,
                    });
                    let body_json = serde_json::to_string(&payload).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Upstream-App: jellyfin\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_json.len(),
                        body_json
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        port
    }

    #[tokio::test]
    async fn test_subdomain_proxy_sends_single_host_header_and_preserves_http_and_ws() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "af-proxy-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db_file = tmp_dir.join("proxy_test.sqlite");
        std::env::set_var("DB_PATH", &db_file);
        af_db::init_db().unwrap();

        let upstream_port = spawn_strict_kestrel_mock_upstream().await;
        let now = Utc::now();
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "jellyfin".to_string(),
            public_domain: "jellyfin.example.test".to_string(),
            external_access_enabled: true,
            listen_port: upstream_port as i32,
            tls_enabled: true,
            created_at: now,
            updated_at: now,
        })
        .unwrap();
        af_db::invalidate_ingress_cache();

        let app = Router::new()
            .route("/*path", any(|| async { StatusCode::NOT_FOUND }))
            .route("/", any(|| async { StatusCode::NOT_FOUND }))
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));

        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_port = gw_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(
                gw_listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        let client = reqwest::Client::new();

        // 1. GET request with query params, cookies, Range, and spoofed X-Aetherflow-User
        let get_resp = client
            .get(format!(
                "http://127.0.0.1:{}/System/Info/Public?format=json",
                gw_port
            ))
            .header("Host", "jellyfin.example.test")
            .header("Cookie", "jellyfin_credentials=abc123")
            .header("Range", "bytes=0-1023")
            .header("X-Aetherflow-User", "spoofed-attacker")
            .send()
            .await
            .unwrap();

        assert_eq!(
            get_resp.status(),
            reqwest::StatusCode::OK,
            "strict upstream must return 200 OK (not 400 Bad Request from duplicate Host)"
        );
        assert_eq!(
            get_resp
                .headers()
                .get("x-upstream-app")
                .and_then(|v| v.to_str().ok()),
            Some("jellyfin")
        );
        let get_json: serde_json::Value = get_resp.json().await.unwrap();
        assert_eq!(get_json["hostCount"], 1);
        assert_eq!(get_json["host"], "jellyfin.example.test");
        assert_eq!(
            get_json["requestLine"],
            "GET /System/Info/Public?format=json HTTP/1.1"
        );
        assert_eq!(
            get_json["headers"]["cookie"][0],
            "jellyfin_credentials=abc123"
        );
        assert_eq!(get_json["headers"]["range"][0], "bytes=0-1023");
        assert!(
            get_json["headers"].get("x-aetherflow-user").is_none(),
            "spoofed X-Aetherflow-User header must be stripped on unauthenticated request"
        );
        assert_eq!(
            get_json["headers"]["x-forwarded-host"][0],
            "jellyfin.example.test"
        );

        // 2. POST request with JSON body via internal .aether.local domain from loopback
        let post_resp = client
            .post(format!(
                "http://127.0.0.1:{}/Users/AuthenticateByName",
                gw_port
            ))
            .header("Host", "jellyfin.aether.local")
            .header("Content-Type", "application/json")
            .body(r#"{"Username":"alice","Pw":"secret"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(post_resp.status(), reqwest::StatusCode::OK);
        let post_json: serde_json::Value = post_resp.json().await.unwrap();
        assert_eq!(post_json["hostCount"], 1);
        assert_eq!(post_json["host"], "jellyfin.aether.local");
        assert_eq!(post_json["body"], r#"{"Username":"alice","Pw":"secret"}"#);

        // 3. WebSocket upgrade tunneling against strict single-Host upstream
        let mut ws_sock = tokio::net::TcpStream::connect(("127.0.0.1", gw_port))
            .await
            .unwrap();
        let ws_handshake = concat!(
            "GET /socket?api_key=test HTTP/1.1\r\n",
            "Host: jellyfin.example.test\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );
        ws_sock.write_all(ws_handshake.as_bytes()).await.unwrap();

        let mut resp_buf = [0u8; 1024];
        let n = ws_sock.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]).to_string();
        assert!(
            resp_str.starts_with("HTTP/1.1 101 Switching Protocols"),
            "expected 101 Switching Protocols, got: {}",
            resp_str
        );

        ws_sock.write_all(b"ping-jellyfin").await.unwrap();
        let n2 = ws_sock.read(&mut resp_buf).await.unwrap();
        let tunnel_reply = String::from_utf8_lossy(&resp_buf[..n2]).to_string();
        assert_eq!(tunnel_reply, "ws-ack:jellyfin.example.test:ping-jellyfin");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
