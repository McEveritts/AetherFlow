use crate::auth::{api_error, decode_session_claims, resolve_raw_token, AuthUser};
use af_runner::package_executor::{
    requires_external_app_auth as external_proxy_requires_auth, GATEWAY_APP_HEADER,
};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use rusqlite::OptionalExtension;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "middlewares_security_regressions.rs"]
mod security_regressions;

// ──────────────────────────────────────────────────────────────────────────────
// 1. Subdomain & Host Resolution
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

const PROXY_RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
static PROXY_AUTH_BLOCKING_LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
static PROXY_RESOLVE_LIMIT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);

async fn resolve_proxy_work<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    tokio::time::timeout(PROXY_RESOLVE_TIMEOUT, async {
        let permit = PROXY_RESOLVE_LIMIT.acquire().await.ok()?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .ok()
    })
    .await
    .ok()
    .flatten()
}

fn local_control_plane_host(host: &str) -> bool {
    matches!(
        host,
        "" | "localhost" | "aether.local" | "aetherflow.aether.local"
    ) || host.parse::<IpAddr>().is_ok()
}

fn explicit_control_plane_host(raw: &str, clean: &str) -> bool {
    let base = configured_base_domain();
    is_control_plane_base_host(clean, &base)
        || (matches_allowed_hosts_control_plane(raw, clean)
            && !clean.ends_with(".aether.local")
            && (base.is_empty() || !clean.ends_with(&format!(".{base}")))
            && !af_db::matches_cached_ingress_subdomain(clean))
}

fn configured_base_domain() -> String {
    env::var("AETHERFLOW_BASE_DOMAIN")
        .or_else(|_| env::var("AETHERFLOW_DOMAIN"))
        .map(|domain| af_db::normalize_base_domain(&domain))
        .unwrap_or_default()
}

fn query_settings_base_domain() -> String {
    let db_domain = af_db::get_base_domain();
    if !db_domain.is_empty() {
        return db_domain;
    }
    if let Ok(conn) = af_db::get_read_conn() {
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
    configured_base_domain()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppHostResolution {
    Proxy(String, i32),
    DisabledExternalApp(String),
    ControlPlane,
}

fn is_control_plane_base_host(clean_host: &str, base_domain: &str) -> bool {
    !base_domain.is_empty()
        && (clean_host == base_domain
            || clean_host == format!("www.{base_domain}")
            || clean_host == format!("direct.{base_domain}")
            || clean_host == format!("aetherflow.{base_domain}"))
}

fn matches_allowed_hosts_control_plane(raw_host: &str, clean_host: &str) -> bool {
    let Ok(raw_allowed) = env::var("ALLOWED_HOSTS") else {
        return false;
    };
    let trimmed_raw = raw_host.trim().to_ascii_lowercase();
    raw_allowed
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .any(|entry| {
            entry == trimmed_raw
                || entry == clean_host
                || strip_host_port_and_dot(&entry) == clean_host
        })
}

fn outcome_allows_recovered_admission(job: &af_services::PackageJobOutcome) -> bool {
    job.status == "failed"
        && matches!(job.action.as_str(), "install" | "reinstall" | "update")
        && job.recovery_state.as_deref()
            == Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED)
}

fn resolve_app_host_disposition(raw_host: &str) -> AppHostResolution {
    let clean_host = strip_host_port_and_dot(raw_host);
    if local_control_plane_host(&clean_host) {
        return AppHostResolution::ControlPlane;
    }

    let base_domain = query_settings_base_domain();
    if is_control_plane_base_host(&clean_host, &base_domain) {
        return AppHostResolution::ControlPlane;
    }

    if clean_host
        .strip_suffix(".aether.local")
        .is_some_and(|label| label.contains('.'))
    {
        return AppHostResolution::ControlPlane;
    }

    let Ok(configs) = af_db::get_all_app_ingress_configs() else {
        return AppHostResolution::ControlPlane;
    };

    // Determine whether `clean_host` is even a candidate application domain BEFORE scanning
    // package job locks and installation markers on disk.
    let matched_public_cfg = configs.iter().find(|cfg| {
        let pub_dom = strip_host_port_and_dot(&cfg.public_domain);
        !pub_dom.is_empty() && pub_dom == clean_host
    });
    // A nested public hostname must be configured explicitly. Only a
    // single-label subdomain of the base domain participates in inference.
    if matched_public_cfg.is_none()
        && !base_domain.is_empty()
        && clean_host
            .strip_suffix(&format!(".{base_domain}"))
            .is_some_and(|label| label.contains('.'))
    {
        return AppHostResolution::ControlPlane;
    }
    if let Some(cfg) = matched_public_cfg {
        if !cfg.external_access_enabled {
            return AppHostResolution::DisabledExternalApp(cfg.app_name.clone());
        }
    }

    let matched_internal_cfg = configs.iter().find(|cfg| {
        let app_lower = cfg.app_name.trim().to_lowercase();
        !app_lower.is_empty() && clean_host == format!("{app_lower}.aether.local")
    });

    let mut candidate_app: Option<&str> = None;
    let mut is_internal = false;
    if let Some(app_prefix) = clean_host.strip_suffix(".aether.local") {
        candidate_app = Some(app_prefix);
        is_internal = true;
    } else if !base_domain.is_empty() {
        let suffix = format!(".{base_domain}");
        if let Some(app_prefix) = clean_host.strip_suffix(&suffix) {
            candidate_app = Some(app_prefix);
        }
    }

    let blueprint_opt = candidate_app
        .filter(|app| !app.is_empty() && !app.contains('.'))
        .and_then(af_services::get_blueprint);

    if matched_public_cfg.is_none() && matched_internal_cfg.is_none() && blueprint_opt.is_none() {
        // Also guard configured non-blueprint app names under `<app>.<base_domain>`
        if !is_internal {
            if let Some(app) = candidate_app.filter(|a| !a.is_empty() && !a.contains('.')) {
                if let Some(cfg) = configs
                    .iter()
                    .find(|c| c.app_name.eq_ignore_ascii_case(app))
                {
                    if !cfg.external_access_enabled {
                        return AppHostResolution::DisabledExternalApp(cfg.app_name.clone());
                    }
                }
            }
        }
        return AppHostResolution::ControlPlane;
    }

    let Ok(jobs) = af_services::package_job_snapshot() else {
        return match matched_public_cfg {
            Some(cfg) => AppHostResolution::DisabledExternalApp(cfg.app_name.clone()),
            None if !is_internal && blueprint_opt.is_some() => {
                AppHostResolution::DisabledExternalApp(blueprint_opt.unwrap().app_name)
            }
            _ => AppHostResolution::ControlPlane,
        };
    };
    let Ok(packages) = af_services::get_package_catalog() else {
        return match matched_public_cfg {
            Some(cfg) => AppHostResolution::DisabledExternalApp(cfg.app_name.clone()),
            None if !is_internal && blueprint_opt.is_some() => {
                AppHostResolution::DisabledExternalApp(blueprint_opt.unwrap().app_name)
            }
            _ => AppHostResolution::ControlPlane,
        };
    };

    let authorized = |app: &str, active_ingress: bool| {
        if jobs
            .active
            .keys()
            .any(|name| name.eq_ignore_ascii_case(app))
        {
            return false;
        }
        let mut recovered_from_failure = false;
        for job in jobs
            .outcomes
            .values()
            .filter(|job| job.package_id.eq_ignore_ascii_case(app))
        {
            if job.status == "completed" {
                continue;
            }
            if outcome_allows_recovered_admission(job) {
                recovered_from_failure = true;
            } else {
                return false;
            }
        }
        let lock_file = packages
            .iter()
            .find(|package| package.name.eq_ignore_ascii_case(app))
            .map(|package| package.lock_file.as_str())
            .filter(|path| !path.is_empty());
        let installed = if let Some(lock_file) = lock_file {
            let path = env::var("AETHERFLOW_FS_ROOT")
                .ok()
                .filter(|root| !root.trim().is_empty())
                .map_or_else(
                    || PathBuf::from(lock_file),
                    |root| Path::new(root.trim()).join(lock_file.trim_start_matches('/')),
                );
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                _ => return false,
            }
        } else {
            false
        };
        if recovered_from_failure {
            installed
                && (active_ingress
                    || matches!(af_db::has_retained_app_ingress_config(app), Ok(false)))
        } else {
            active_ingress
                || (installed && matches!(af_db::has_retained_app_ingress_config(app), Ok(false)))
        }
    };

    if let Some(cfg) = matched_public_cfg {
        if (1..=65535).contains(&cfg.listen_port) && authorized(&cfg.app_name, true) {
            return AppHostResolution::Proxy(cfg.app_name.clone(), cfg.listen_port);
        }
        return AppHostResolution::DisabledExternalApp(cfg.app_name.clone());
    }

    if let Some(cfg) = matched_internal_cfg {
        if (1..=65535).contains(&cfg.listen_port) && authorized(&cfg.app_name, true) {
            return AppHostResolution::Proxy(cfg.app_name.clone(), cfg.listen_port);
        }
    }

    if let Some(bp) = blueprint_opt {
        let ingress = configs
            .iter()
            .find(|config| config.app_name.eq_ignore_ascii_case(&bp.app_name));
        if !authorized(&bp.app_name, ingress.is_some()) {
            return if is_internal {
                AppHostResolution::ControlPlane
            } else {
                AppHostResolution::DisabledExternalApp(bp.app_name)
            };
        }
        if bp.default_port > 0 || ingress.is_some() {
            let mut port = bp.default_port;
            if let Some(ing) = ingress {
                if !(1..=65535).contains(&ing.listen_port) {
                    return if is_internal {
                        AppHostResolution::ControlPlane
                    } else {
                        AppHostResolution::DisabledExternalApp(bp.app_name)
                    };
                }
                if !is_internal {
                    if !ing.external_access_enabled {
                        return AppHostResolution::DisabledExternalApp(bp.app_name);
                    }
                    let pub_dom = strip_host_port_and_dot(&ing.public_domain);
                    if !pub_dom.is_empty() && pub_dom != clean_host {
                        return AppHostResolution::DisabledExternalApp(bp.app_name);
                    }
                }
                if ing.listen_port > 0 {
                    port = ing.listen_port;
                }
            } else if !is_internal {
                return AppHostResolution::DisabledExternalApp(bp.app_name);
            }
            if (1..=65535).contains(&port) {
                return AppHostResolution::Proxy(bp.app_name, port);
            }
        }
        if !is_internal {
            return AppHostResolution::DisabledExternalApp(bp.app_name);
        }
    }

    AppHostResolution::ControlPlane
}

pub fn resolve_app_target_for_host(raw_host: &str) -> Option<(String, i32)> {
    match resolve_app_host_disposition(raw_host) {
        AppHostResolution::Proxy(app, port) => Some((app, port)),
        AppHostResolution::DisabledExternalApp(_) | AppHostResolution::ControlPlane => None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. Application Subdomain Reverse Proxy
// ──────────────────────────────────────────────────────────────────────────────

static PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        // Bound connection setup without limiting long-lived media response bodies.
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

static PROXY_LOOPBACK_TLS_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

static PROXY_LOOPBACK_TLS_WS_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
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

fn is_strict_loopback_https_url(target_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(target_url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    matches!(parsed.host_str(), Some("127.0.0.1" | "::1" | "[::1]"))
}

fn is_trusted_proxy_ip(ip: IpAddr) -> bool {
    crate::ws::is_trusted_proxy_peer(ip)
}

fn is_forwarded_header_name(name: &str) -> bool {
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

fn canonical_forwarded_headers(
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

fn is_spoofable_identity_header(name: &str) -> bool {
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

fn forward_proxy_http_headers(
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

fn is_private_or_loopback_ip(raw_ip: &str) -> bool {
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

fn resolve_optional_authenticated_user(
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

fn verify_proxy_basic_credentials(headers: &axum::http::HeaderMap) -> Option<String> {
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

fn librespeed_tls_client() -> Result<Option<reqwest::Client>, String> {
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

fn local_domain_client_allowed(headers: &axum::http::HeaderMap, peer: Option<IpAddr>) -> bool {
    peer.is_none_or(|peer| {
        is_private_or_loopback_ip(&peer.to_string())
            && is_private_or_loopback_ip(&crate::ws::extract_client_ip_for_peer(
                headers,
                Some(peer),
            ))
    })
}

fn internal_domain_forbidden() -> Response {
    api_error(
        StatusCode::FORBIDDEN,
        "INTERNAL_DOMAIN",
        "Internal .aether.local domains are restricted to local network clients",
    )
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

fn managed_app_route_unavailable() -> Response {
    api_error(
        StatusCode::MISDIRECTED_REQUEST,
        "APP_ROUTE_UNAVAILABLE",
        "This host does not have the configured external application route",
    )
}

fn strip_gateway_session_cookies(headers: &mut axum::http::HeaderMap, protected: bool) {
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
    let target_url = format!("{scheme}://127.0.0.1:{target_port}{path_and_query}");

    let mut incoming_headers = req.headers().clone();
    if requires_auth {
        incoming_headers.remove(header::AUTHORIZATION);
    }
    strip_gateway_session_cookies(&mut incoming_headers, requires_auth);

    if is_ws_upgrade {
        if use_tls {
            if !is_strict_loopback_https_url(&target_url) {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "bad_gateway",
                        "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                    })),
                )
                    .into_response();
            }

            let reqwest_method =
                reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
            let mut ws_req = pinned_client
                .as_ref()
                .unwrap_or(&PROXY_LOOPBACK_TLS_WS_CLIENT)
                .request(reqwest_method, &target_url);
            ws_req = forward_proxy_http_headers(
                ws_req,
                &incoming_headers,
                &raw_host,
                peer_ip_opt,
                trust_forwarded,
            );
            ws_req = ws_req.header(reqwest::header::CONNECTION, "Upgrade");
            if let Some(ref user) = authenticated_user {
                ws_req = ws_req.header("X-Aetherflow-User", user);
            }

            let upstream_resp = match tokio::time::timeout(Duration::from_secs(15), ws_req.send())
                .await
            {
                Ok(Ok(resp)) => resp,
                Ok(Err(err)) => {
                    tracing::warn!(
                        app = %app_name,
                        host = %raw_host,
                        port = target_port,
                        error = %err,
                        "subdomain reverse proxy TLS websocket upstream error"
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
                Err(_) => {
                    return (
                        StatusCode::GATEWAY_TIMEOUT,
                        Json(serde_json::json!({
                            "error": "gateway_timeout",
                            "message": format!("Upstream service {} on port {} upgrade timed out.", app_name, target_port),
                        })),
                    )
                        .into_response();
                }
            };

            if upstream_resp.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS {
                let resp_headers_clone = upstream_resp.headers().clone();
                let client_upgrade = hyper::upgrade::on(req);
                let upstream_upgrade = upstream_resp.upgrade();

                tokio::spawn(async move {
                    match tokio::try_join!(
                        async move { client_upgrade.await.map_err(std::io::Error::other) },
                        async move { upstream_upgrade.await.map_err(std::io::Error::other) }
                    ) {
                        Ok((client_upgraded, mut upstream_upgraded)) => {
                            let mut client_io = hyper_util::rt::TokioIo::new(client_upgraded);
                            let _ = tokio::io::copy_bidirectional(
                                &mut client_io,
                                &mut upstream_upgraded,
                            )
                            .await;
                        }
                        Err(err) => {
                            tracing::debug!(error = %err, "subdomain TLS websocket upgrade tunnel closed");
                        }
                    }
                });

                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                let out_headers = response.headers_mut();
                for (k, v) in resp_headers_clone.iter() {
                    if let (Ok(hk), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_str().as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        out_headers.append(hk, hv);
                    }
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
                let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                let resp_headers_clone = upstream_resp.headers().clone();
                let stream = upstream_resp.bytes_stream();
                let mut response = Response::new(Body::from_stream(stream));
                *response.status_mut() = status;
                let out_headers = response.headers_mut();
                for (k, v) in resp_headers_clone.iter() {
                    if is_hop_by_hop_header(k.as_str()) {
                        continue;
                    }
                    if let (Ok(hk), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_str().as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        out_headers.append(hk, hv);
                    }
                }
                return response;
            }
        }

        let tcp_stream = match tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(("127.0.0.1", target_port as u16)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
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
            Err(_) => {
                tracing::warn!(
                    app = %app_name,
                    host = %raw_host,
                    port = target_port,
                    "subdomain reverse proxy websocket upstream connect timeout"
                );
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} timed out connecting.", app_name, target_port),
                    })),
                )
                    .into_response();
            }
        };

        let io = hyper_util::rt::TokioIo::new(tcp_stream);
        let (mut sender, conn) = match tokio::time::timeout(
            Duration::from_secs(10),
            hyper::client::conn::http1::handshake(io),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
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
            Err(_) => {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} handshake timed out.", app_name, target_port),
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
                    || is_forwarded_header_name(name_str)
                    || is_spoofable_identity_header(name_str)
                    || name_str.eq_ignore_ascii_case("host")
                {
                    continue;
                }
                hdrs.append(k.clone(), v.clone());
            }
            if !raw_host.is_empty() {
                if let Ok(hv) = HeaderValue::from_str(&raw_host) {
                    hdrs.insert(header::HOST, hv);
                }
            }
            for (hn, hv) in canonical_forwarded_headers(
                &incoming_headers,
                &raw_host,
                peer_ip_opt,
                trust_forwarded,
            ) {
                hdrs.insert(hn, hv);
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

        let mut upstream_resp = match tokio::time::timeout(
            Duration::from_secs(15),
            sender.send_request(upstream_ws_req),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
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
            Err(_) => {
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(serde_json::json!({
                        "error": "gateway_timeout",
                        "message": format!("Upstream service {} on port {} upgrade timed out.", app_name, target_port),
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
            let (upstream, body) = upstream_resp.into_parts();
            let mut response = Response::new(Body::new(body));
            *response.status_mut() = upstream.status;
            let out_headers = response.headers_mut();
            for (k, v) in &upstream.headers {
                if !is_hop_by_hop_header(k.as_str()) {
                    out_headers.append(k.clone(), v.clone());
                }
            }
            return response;
        }
    }

    let client = if use_tls {
        if !is_strict_loopback_https_url(&target_url) {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "bad_gateway",
                    "message": format!("Upstream service {} on port {} is unavailable.", app_name, target_port),
                })),
            )
                .into_response();
        }
        pinned_client.as_ref().unwrap_or(&PROXY_LOOPBACK_TLS_CLIENT)
    } else {
        &*PROXY_HTTP_CLIENT
    };

    let has_body = !hyper::body::Body::is_end_stream(req.body())
        || incoming_headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .is_some_and(|len| len > 0)
        || incoming_headers.contains_key(header::TRANSFER_ENCODING);

    let reqwest_method =
        reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream_req = client.request(reqwest_method, &target_url);

    upstream_req = forward_proxy_http_headers(
        upstream_req,
        &incoming_headers,
        &raw_host,
        peer_ip_opt,
        trust_forwarded,
    );
    if let Some(user) = authenticated_user {
        upstream_req = upstream_req.header("X-Aetherflow-User", user);
    }

    if has_body {
        upstream_req = upstream_req.body(reqwest::Body::wrap_stream(
            req.into_body().into_data_stream(),
        ));
    }

    let send_res = if has_body {
        Ok(upstream_req.send().await)
    } else {
        tokio::time::timeout(Duration::from_secs(30), upstream_req.send()).await
    };

    match send_res {
        Ok(Ok(upstream_resp)) => {
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
        Ok(Err(err)) => {
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
        Err(_) => {
            tracing::warn!(
                app = %app_name,
                host = %raw_host,
                port = target_port,
                "subdomain reverse proxy upstream timeout"
            );
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({
                    "error": "gateway_timeout",
                    "message": format!("Upstream service {} on port {} timed out.", app_name, target_port),
                })),
            )
                .into_response()
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Host Header Validation Middleware
// ──────────────────────────────────────────────────────────────────────────────

fn matches_configured_env_host(clean_host: &str) -> bool {
    for key in ["PUBLIC_URL", "OIDC_ISSUER", "ALLOWED_CORS_ORIGIN"] {
        if let Ok(raw) = env::var(key) {
            for item in raw.split(',') {
                let entry = item.trim();
                if entry.is_empty() {
                    continue;
                }
                if let Ok(parsed) = url::Url::parse(entry) {
                    if let Some(h) = parsed.host_str() {
                        let norm = strip_host_port_and_dot(h);
                        if !norm.is_empty() && clean_host == norm {
                            return true;
                        }
                    }
                } else {
                    let norm = strip_host_port_and_dot(entry);
                    if !norm.is_empty() && clean_host == norm {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn is_host_trusted(candidate_raw: &str, allowed_set: &HashSet<String>) -> bool {
    let clean = strip_host_port_and_dot(candidate_raw);
    if clean.is_empty() {
        return false;
    }
    let trimmed = candidate_raw.trim().to_ascii_lowercase();

    if local_control_plane_host(&clean) {
        return true;
    }

    let base_domain = query_settings_base_domain();
    if is_control_plane_base_host(&clean, &base_domain) {
        return true;
    }
    let configs = af_db::get_all_app_ingress_configs().unwrap_or_default();
    if let Some(subdomain) = clean.strip_suffix(".aether.local") {
        return !subdomain.contains('.')
            && (configs.iter().any(|cfg| cfg.app_name == subdomain)
                || af_services::get_blueprint(subdomain).is_some());
    }
    if !base_domain.is_empty() {
        if let Some(label) = clean.strip_suffix(&format!(".{base_domain}")) {
            if label.contains('.') {
                return false;
            }
            return configs.iter().any(|cfg| {
                cfg.external_access_enabled
                    && (strip_host_port_and_dot(&cfg.public_domain) == clean
                        || (cfg.public_domain.is_empty()
                            && cfg.app_name.eq_ignore_ascii_case(label)))
            });
        }
    }
    if let Some(config) = configs
        .iter()
        .find(|cfg| strip_host_port_and_dot(&cfg.public_domain) == clean)
    {
        return config.external_access_enabled;
    }
    allowed_set.contains(&trimmed)
        || allowed_set.contains(&clean)
        || matches_configured_env_host(&clean)
}

pub(crate) fn is_trusted_request_host(candidate_raw: &str) -> bool {
    let raw_allowed = env::var("ALLOWED_HOSTS").unwrap_or_default();
    let allowed_set: HashSet<String> = raw_allowed
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    is_host_trusted(candidate_raw, &allowed_set)
}

pub async fn host_validation_middleware(req: Request, next: Next) -> Response {
    let raw_allowed = env::var("ALLOWED_HOSTS").unwrap_or_default();
    let allowed_set: HashSet<String> = raw_allowed
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let host = req
        .headers()
        .get(header::HOST)
        .map(|value| value.to_str().unwrap_or("").to_string());
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    if host.as_deref().is_some_and(|raw| {
        let host = strip_host_port_and_dot(raw);
        host == "aether.local" || host.ends_with(".aether.local")
    }) && !local_domain_client_allowed(req.headers(), peer)
    {
        return internal_domain_forbidden();
    }
    let forwarded = peer
        .is_some_and(is_trusted_proxy_ip)
        .then(|| {
            req.headers()
                .get("X-Forwarded-Host")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|host| !host.is_empty())
                .map(str::to_owned)
        })
        .flatten();
    let hosts: Vec<_> = host
        .into_iter()
        .chain(forwarded)
        .filter(|raw| {
            let host = strip_host_port_and_dot(raw);
            host.is_empty()
                || !(local_control_plane_host(&host)
                    || explicit_control_plane_host(raw, &host)
                    || (af_db::maybe_cached_control_plane_host(&host)
                        && af_db::cached_base_domain()
                            .is_some_and(|base| is_control_plane_base_host(&host, &base))))
        })
        .collect();
    if !hosts.is_empty() {
        match resolve_proxy_work(move || {
            hosts.iter().all(|host| is_host_trusted(host, &allowed_set))
        })
        .await
        {
            Some(true) => {}
            Some(false) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_HOST",
                    "Untrusted Host header",
                )
            }
            None => {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "HOST_VALIDATION_UNAVAILABLE",
                    "Host validation unavailable",
                )
            }
        }
    }

    next.run(req).await
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. Per-IP Sliding-Window Rate Limiter Middlewares
// ──────────────────────────────────────────────────────────────────────────────

const RATE_LIMIT_KEY_CAPACITY: usize = 16_384;

#[derive(Default)]
struct RateLimitVisitors {
    timestamps: HashMap<String, Vec<Instant>>,
    oldest_first: BTreeSet<(Instant, String)>,
}

struct SlidingWindowLimiter {
    visitors: Mutex<RateLimitVisitors>,
    limit: usize,
    window: Duration,
}

impl SlidingWindowLimiter {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            visitors: Mutex::new(RateLimitVisitors::default()),
            limit,
            window,
        }
    }

    fn allow(&self, ip: &str) -> bool {
        self.reserve(ip).is_some()
    }

    fn reserve(&self, ip: &str) -> Option<Instant> {
        let mut guard = self
            .visitors
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let RateLimitVisitors {
            timestamps,
            oldest_first,
        } = &mut *guard;
        let now = Instant::now();
        while let Some((last_seen, _)) = oldest_first.first() {
            if now.duration_since(*last_seen) < self.window {
                break;
            }
            let (_, expired) = oldest_first.pop_first().expect("first entry exists");
            timestamps.remove(&expired);
        }
        if timestamps.len() >= RATE_LIMIT_KEY_CAPACITY && !timestamps.contains_key(ip) {
            if let Some((_, oldest)) = oldest_first.pop_first() {
                timestamps.remove(&oldest);
            }
        }
        let entry = timestamps.entry(ip.to_string()).or_default();
        let previous = entry.last().copied();
        entry.retain(|&t| now.duration_since(t) < self.window);
        if entry.len() >= self.limit {
            return None;
        }
        if let Some(previous) = previous {
            oldest_first.remove(&(previous, ip.to_string()));
        }
        entry.push(now);
        oldest_first.insert((now, ip.to_string()));
        Some(now)
    }

    fn refund(&self, ip: &str, attempt: Instant) {
        let mut guard = self
            .visitors
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let RateLimitVisitors {
            timestamps,
            oldest_first,
        } = &mut *guard;
        let Some(entry) = timestamps.get_mut(ip) else {
            return;
        };
        let Ok(index) = entry.binary_search(&attempt) else {
            return;
        };
        let previous = *entry.last().expect("matched reservation exists");
        entry.remove(index);
        oldest_first.remove(&(previous, ip.to_owned()));
        if let Some(&newest) = entry.last() {
            oldest_first.insert((newest, ip.to_owned()));
        } else {
            timestamps.remove(ip);
        }
    }
}

static PROXY_BASIC_AUTH_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));
static AUTH_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(10, Duration::from_secs(60)));
static OIDC_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));
static AI_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));

#[test]
fn proxy_rate_limit_refunds_verified_credentials_without_refunding_failures() {
    let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60));
    assert!(limiter.allow("fixture-client"));
    for _ in 0..30 {
        let verified = limiter.reserve("fixture-client").unwrap();
        assert!(!limiter.allow("fixture-client"));
        limiter.refund("fixture-client", verified);
    }
    assert!(limiter.allow("fixture-client"));
    assert!(!limiter.allow("fixture-client"));
}

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
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer_addr)| peer_addr.ip());
    crate::ws::extract_client_ip_for_peer(req.headers(), peer_ip)
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
// 5. Storage Quota Upload Guard Middleware
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
            Some("127.0.0.1".parse().unwrap()),
            true,
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

    #[test]
    fn external_auth_covers_newly_protected_apps() {
        for app in ["unmanic", "netdata", "autoscan"] {
            assert!(external_proxy_requires_auth(app));
        }
    }

    #[tokio::test]
    async fn external_proxy_limits_invalid_basic_auth_attempts_per_ip() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        env::set_var("AETHERFLOW_BASE_DOMAIN", "proxy-auth.test");
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "netdata".into(),
            public_domain: "netdata.proxy-auth.test".into(),
            external_access_enabled: true,
            listen_port: 19999,
            ..Default::default()
        })
        .unwrap();
        let app = Router::new()
            .fallback(any(|| async { StatusCode::NOT_FOUND }))
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
        for (ip, attempts) in [("198.51.100.1:1010", 21), ("198.51.100.2:1010", 1)] {
            for attempt in 0..attempts {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri("/")
                            .header(header::HOST, "netdata.proxy-auth.test")
                            .header(header::AUTHORIZATION, "Basic aW52YWxpZDpjcmVkZW50aWFscw==")
                            .extension(ConnectInfo(ip.parse::<SocketAddr>().unwrap()))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if attempt == 20 {
                    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                    let body = axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap();
                    assert!(std::str::from_utf8(&body).unwrap().contains("RATE_LIMITED"));
                } else {
                    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                }
            }
        }
    }

    #[tokio::test]
    async fn managed_apache_proxy_routes_http_and_websocket_after_admin_authentication() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use base64::Engine;
        use tower::ServiceExt;

        if run_plugin_test_in_subprocess() {
            return;
        }
        let root = ensure_shared_test_db().parent().unwrap();
        env::set_var("AETHERFLOW_CONFIG_ROOT", root);
        env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("no-master-file"));
        env::set_var("AETHERFLOW_BASE_DOMAIN", "proxy-auth.test");
        let host = "metrics.apps.proxy-auth.test";
        let upstream_port = spawn_strict_kestrel_mock_upstream().await;
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "prometheus".into(),
            public_domain: host.into(),
            external_access_enabled: true,
            listen_port: upstream_port.into(),
            ..Default::default()
        })
        .unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (username, role, password_hash) VALUES ('managed-admin', 'admin', ?1)",
            [bcrypt::hash("fixture-password", 4).unwrap()],
        )
        .unwrap();
        drop(conn);
        let basic =
            base64::engine::general_purpose::STANDARD.encode("managed-admin:fixture-password");
        let app = Router::new()
            .fallback(any(|| async { "dashboard fixture" }))
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));

        for (authority, marker, peer, expected) in [
            (
                "localhost",
                "prometheus",
                "127.0.0.1:3000",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                host,
                "mcvnc",
                "127.0.0.1:3000",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                host,
                "prometheus",
                "192.0.2.1:3000",
                StatusCode::MISDIRECTED_REQUEST,
            ),
            (
                host,
                "prometheus",
                "127.0.0.1:3000",
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, authority)
                        .header(GATEWAY_APP_HEADER, marker)
                        .header(header::UPGRADE, "websocket")
                        .header(header::CONNECTION, "Upgrade")
                        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{authority} {marker} {peer}");
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{gateway}/metrics?format=raw"))
            .header(header::HOST, host)
            .header(GATEWAY_APP_HEADER, "prometheus")
            .header(header::AUTHORIZATION, format!("Basic {basic}"))
            .header(
                header::COOKIE,
                "aetherflow_session=fixture; app_cookie=keep",
            )
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "192.0.2.7")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let observed: serde_json::Value = response.json().await.unwrap();
        assert_eq!(observed["requestLine"], "GET /metrics?format=raw HTTP/1.1");
        assert_eq!(observed["host"], host);
        let headers = &observed["headers"];
        assert_eq!(headers["x-forwarded-proto"][0], "https");
        assert_eq!(headers["x-forwarded-for"][0], "192.0.2.7");
        assert_eq!(headers["x-aetherflow-user"][0], "managed-admin");
        assert_eq!(headers["cookie"][0], "app_cookie=keep");
        assert!(headers.get("authorization").is_none());
        assert!(headers.get(GATEWAY_APP_HEADER).is_none());

        let mut socket = tokio::net::TcpStream::connect(gateway).await.unwrap();
        let handshake = format!(
            "GET /socket HTTP/1.1\r\nHost: {host}\r\n{GATEWAY_APP_HEADER}: prometheus\r\nAuthorization: Basic {basic}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        socket.write_all(handshake.as_bytes()).await.unwrap();
        let mut response = [0; 1024];
        let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response[..read].starts_with(b"HTTP/1.1 101 Switching Protocols"));
    }

    #[tokio::test]
    async fn proxy_basic_rejects_totp_admin_but_mfa_session_is_accepted() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use base64::Engine;
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        let fixture_root = ensure_shared_test_db().parent().unwrap();
        env::set_var("AETHERFLOW_CONFIG_ROOT", fixture_root);
        env::set_var(
            "AETHERFLOW_MASTER_CREDS_FILE",
            fixture_root.join("missing-master-file"),
        );
        let password = "test-proxy-admin-password";
        let secret = "JBSWY3DPEHPK3PXP";
        let writer = af_db::get_conn().unwrap();
        writer
            .execute(
                "INSERT INTO users (id, username, role, password_hash, totp_enabled, totp_secret)
            VALUES (93, 'proxy-mfa', 'admin', ?1, 1, ?2)",
                rusqlite::params![bcrypt::hash(password, 4).unwrap(), secret],
            )
            .unwrap();

        let master = af_db::encrypt_key(
            &serde_json::json!({
                "username": "proxy-mfa",
                "password": password,
            })
            .to_string(),
        )
        .unwrap();
        writer
            .execute(
                "INSERT INTO system_config (key, value) VALUES ('master_credentials', ?1)",
                [&master],
            )
            .unwrap();
        drop(writer);
        assert_eq!(
            af_services::mutators::load_master_credentials().0,
            "proxy-mfa"
        );

        let mut basic = axum::http::HeaderMap::new();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("proxy-mfa:{password}"));
        basic.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        assert_eq!(verify_proxy_basic_credentials(&basic), None);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("app-launch-browser"),
        );
        let login = crate::auth::local_login(
            headers.clone(),
            Json(crate::auth::CredentialsRequest {
                username: "proxy-mfa".into(),
                password: password.into(),
                setup_token: None,
            }),
        )
        .await;
        let body = axum::body::to_bytes(login.into_body(), 4096).await.unwrap();
        let challenge: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(challenge["requires_mfa"], true);
        let secret = data_encoding::BASE32_NOPAD
            .decode(secret.as_bytes())
            .unwrap();
        let code = totp_lite::totp_custom::<totp_lite::Sha1>(
            30,
            6,
            &secret,
            Utc::now().timestamp() as u64,
        );
        let mfa = crate::auth::mfa_login_verify(
            headers,
            Json(crate::auth::MfaVerifyRequest {
                mfa_token: challenge["mfa_token"].as_str().unwrap().into(),
                code,
            }),
        )
        .await;
        assert_eq!(mfa.status(), StatusCode::OK);
        let cookie = mfa.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        basic.insert(header::COOKIE, cookie.parse().unwrap());
        basic.insert(
            header::USER_AGENT,
            HeaderValue::from_static("app-launch-browser"),
        );
        let principal = resolve_optional_authenticated_user(&basic, None).unwrap();
        assert_eq!(principal.role, "admin");
        assert_eq!(principal.username, "proxy-mfa");

        let upstream_port = spawn_strict_kestrel_mock_upstream().await;
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "netdata".into(),
            public_domain: "metrics.proxy-mfa.test".into(),
            external_access_enabled: true,
            tls_enabled: true,
            listen_port: upstream_port.into(),
            ..Default::default()
        })
        .unwrap();
        let app = crate::routes::build_router()
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
        for (session, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(cookie), StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .uri("/")
                .header(header::USER_AGENT, "app-launch-browser")
                .header(header::HOST, "metrics.proxy-mfa.test")
                .header(GATEWAY_APP_HEADER, "netdata")
                .header(header::AUTHORIZATION, &basic[header::AUTHORIZATION])
                .extension(ConnectInfo(
                    "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
                ));
            if let Some(session) = session {
                request = request.header(header::COOKIE, session);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }

        let host = "metrics.proxy-mfa.test";
        let origin = "http://localhost";
        let destination = format!("https://{host}/graph?view=all");
        let launch_request = |destination: &str, csrf: bool| {
            let mut req = Request::builder()
                .method("POST")
                .uri("/api/v1/admin/apps/launch")
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, origin)
                .header(header::USER_AGENT, "app-launch-browser")
                .header(header::COOKIE, format!("{cookie}; csrf_token=launch-csrf"))
                .header(header::CONTENT_TYPE, "application/json");
            if csrf {
                req = req.header("x-csrf-token", "launch-csrf");
            }
            req.body(Body::from(
                serde_json::json!({ "app": "netdata", "destination": destination }).to_string(),
            ))
            .unwrap()
        };
        let read_json = |response: Response| async move {
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };

        let dir = fixture_root.join("etc/apache2/sites-enabled");
        std::fs::create_dir_all(&dir).unwrap();
        let vhost = dir.join("aetherflow-ext-netdata.conf");
        std::fs::write(
            &vhost,
            format!(
                "<VirtualHost *:443>
ServerName {host}
</VirtualHost>
"
            ),
        )
        .unwrap();
        let legacy = app
            .clone()
            .oneshot(launch_request(&destination, true))
            .await
            .unwrap();
        assert_eq!(read_json(legacy).await, serde_json::json!({}));
        std::fs::write(
            &vhost,
            format!(
                "<VirtualHost *:443>
ServerName {host}
RequestHeader set {GATEWAY_APP_HEADER} netdata
</VirtualHost>
"
            ),
        )
        .unwrap();

        let no_csrf = app
            .clone()
            .oneshot(launch_request(&destination, false))
            .await
            .unwrap();
        assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
        let wrong_destination = app
            .clone()
            .oneshot(launch_request("https://other.proxy-mfa.test/", true))
            .await
            .unwrap();
        assert_eq!(read_json(wrong_destination).await, serde_json::json!({}));

        let issue = || async {
            let response = app
                .clone()
                .oneshot(launch_request(&destination, true))
                .await
                .unwrap();
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            read_json(response).await["ticket"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let exchange = |ticket: &str, dashboard: &str, managed: bool| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(af_models::APP_LAUNCH_EXCHANGE_PATH)
                .header(header::HOST, host)
                .header("x-forwarded-proto", "https")
                .header(header::ORIGIN, dashboard)
                .header(header::USER_AGENT, "app-launch-browser")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .extension(ConnectInfo(
                    "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
                ));
            if managed {
                builder = builder.header(GATEWAY_APP_HEADER, "netdata");
            }
            builder
                .body(Body::from(format!("ticket={ticket}")))
                .unwrap()
        };

        let ticket = issue().await;
        for (dashboard, managed, expected) in [
            ("https://unexpected.test", true, StatusCode::UNAUTHORIZED),
            (origin, false, StatusCode::NOT_FOUND),
        ] {
            let response = app
                .clone()
                .oneshot(exchange(&ticket, dashboard, managed))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let (first, second) = tokio::join!(
            app.clone().oneshot(exchange(&ticket, origin, true)),
            app.clone().oneshot(exchange(&ticket, origin, true)),
        );
        let (mut first, mut second) = (first.unwrap(), second.unwrap());
        if second.status() == StatusCode::SEE_OTHER {
            std::mem::swap(&mut first, &mut second);
        }
        assert_eq!(first.status(), StatusCode::SEE_OTHER);
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(first.headers()[header::LOCATION], destination);
        assert_eq!(first.headers()[header::CACHE_CONTROL], "private, no-store");
        let set_cookie = first.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.starts_with("__Host-aetherflow_app="));
        assert!(set_cookie.contains("; Secure; HttpOnly"));
        assert!(!set_cookie.contains("Domain="));
        assert!(!set_cookie.contains(cookie));
        let app_cookie = set_cookie.split(';').next().unwrap();
        let request_app = || {
            Request::builder()
                .uri("/graph?view=all")
                .header(header::HOST, host)
                .header(header::USER_AGENT, "app-launch-browser")
                .header(header::COOKIE, format!("{app_cookie}; native=keep"))
                .header(GATEWAY_APP_HEADER, "netdata")
                .header("x-forwarded-proto", "https")
                .extension(ConnectInfo(
                    "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap()
        };
        let proxied = app.clone().oneshot(request_app()).await.unwrap();
        let observed = read_json(proxied).await;
        assert_eq!(observed["headers"]["cookie"][0], "native=keep");
        assert_eq!(observed["headers"]["x-aetherflow-user"][0], "proxy-mfa");
        assert_eq!(observed["requestLine"], "GET /graph?view=all HTTP/1.1");

        let pending = issue().await;
        let db = af_db::get_conn().unwrap();
        db.execute("UPDATE users SET role = 'user' WHERE id = 93", [])
            .unwrap();
        let denied = app.clone().oneshot(request_app()).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let denied = app
            .clone()
            .oneshot(launch_request(&destination, true))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let denied = app
            .clone()
            .oneshot(exchange(&pending, origin, true))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        db.execute("UPDATE users SET role = 'admin' WHERE id = 93", [])
            .unwrap();
        let pending = issue().await;
        db.execute("DELETE FROM active_sessions WHERE user_id = 93", [])
            .unwrap();
        let denied = app
            .clone()
            .oneshot(exchange(&pending, origin, true))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let denied = app.oneshot(request_app()).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    }

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
                    if request_line.starts_with("POST /Upload ") {
                        let mut received = buf.len().saturating_sub(body_start);
                        while received < content_length {
                            match socket.read(&mut temp).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => received += n,
                            }
                        }
                        let payload = serde_json::json!({
                            "receivedBytes": received,
                        });
                        let body_json = serde_json::to_string(&payload).unwrap();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_json.len(),
                            body_json
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }

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

        let mut ws_buf = [0u8; 1024];
        ws_sock.write_all(b"ping-jellyfin").await.unwrap();
        let n2 = ws_sock.read(&mut ws_buf).await.unwrap();
        let tunnel_reply = String::from_utf8_lossy(&ws_buf[..n2]).to_string();
        assert_eq!(tunnel_reply, "ws-ack:jellyfin.example.test:ping-jellyfin");

        // 4. Untrusted non-loopback peer cannot spoof X-Forwarded-* or X-Real-IP on HTTP or WS,
        // and >64 MiB request bodies stream cleanly without 413 buffering limits.
        let untrusted_peer: SocketAddr = "198.51.100.77:54321".parse().unwrap();
        let untrusted_req = axum::http::Request::builder()
            .method("GET")
            .uri("/System/Info")
            .header("Host", "jellyfin.example.test")
            .header("X-Forwarded-For", "10.0.0.5")
            .header("X-Forwarded-Host", "evil.attacker.example")
            .header("X-Forwarded-Proto", "https")
            .header("X-Real-IP", "10.0.0.5")
            .extension(ConnectInfo(untrusted_peer))
            .body(Body::empty())
            .unwrap();
        let untrusted_app = Router::new()
            .route("/*path", any(|| async { StatusCode::NOT_FOUND }))
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
        let untrusted_resp = tower::ServiceExt::oneshot(untrusted_app.clone(), untrusted_req)
            .await
            .unwrap();
        assert_eq!(untrusted_resp.status(), StatusCode::OK);
        let untrusted_body = axum::body::to_bytes(untrusted_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let untrusted_json: serde_json::Value = serde_json::from_slice(&untrusted_body).unwrap();
        assert_eq!(
            untrusted_json["headers"]["x-forwarded-for"][0],
            "198.51.100.77"
        );
        assert_eq!(untrusted_json["headers"]["x-real-ip"][0], "198.51.100.77");
        assert_eq!(
            untrusted_json["headers"]["x-forwarded-host"][0],
            "jellyfin.example.test"
        );
        assert_eq!(untrusted_json["headers"]["x-forwarded-proto"][0], "http");

        let upload_bytes: usize = 65 * 1024 * 1024;
        let streaming_body =
            futures::stream::iter((0..65).map(|_| {
                Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'a'; 1024 * 1024]))
            }));
        let streaming_req = axum::http::Request::builder()
            .method("POST")
            .uri("/Upload")
            .header("Host", "jellyfin.example.test")
            .header("Content-Length", upload_bytes.to_string())
            .body(Body::from_stream(streaming_body))
            .unwrap();
        let streaming_resp = tower::ServiceExt::oneshot(untrusted_app, streaming_req)
            .await
            .unwrap();
        assert_eq!(streaming_resp.status(), StatusCode::OK);
        let streaming_resp_bytes = axum::body::to_bytes(streaming_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let streaming_json: serde_json::Value =
            serde_json::from_slice(&streaming_resp_bytes).unwrap();
        assert_eq!(streaming_json["receivedBytes"], upload_bytes);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn upstream_uses_tls_identifies_kasmvnc_and_loopback_urls() {
        assert!(upstream_uses_tls("kasmvnc", 6081));
        assert!(upstream_uses_tls("af-kasmvnc", 6081));
        assert!(upstream_uses_tls(" KasmVNC ", 6081));
        assert!(!upstream_uses_tls("jellyfin", 8096));
        assert!(!upstream_uses_tls("kasmvnc", 0));

        assert!(is_strict_loopback_https_url(
            "https://127.0.0.1:6081/vnc.html"
        ));
        assert!(is_strict_loopback_https_url("https://[::1]:6081/"));
        assert!(!is_strict_loopback_https_url("http://127.0.0.1:6081/"));
        assert!(!is_strict_loopback_https_url("https://192.168.1.50:6081/"));
        assert!(!is_strict_loopback_https_url("https://evil.example.com/"));
    }

    #[test]
    fn external_subdomain_fails_closed_without_explicit_enabled_ingress() {
        const CHILD_ENV: &str = "AF_EXTERNAL_FAIL_CLOSED_TEST_CHILD";
        if env::var(CHILD_ENV).as_deref() != Ok("1") {
            let status = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "middlewares::tests::external_subdomain_fails_closed_without_explicit_enabled_ingress",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let root = env::temp_dir().join(format!("af-ext-fail-closed-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("install")).unwrap();
        env::set_var("AETHERFLOW_FS_ROOT", &root);
        env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        let db = root.join("gateway.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db);
        }
        let catalog = root.join("packages.json");
        std::fs::write(
            &catalog,
            serde_json::to_vec(&serde_json::json!([{
                "name": "syncthing",
                "label": "Syncthing",
                "description": "fixture",
                "lock_file": "/install/.syncthing.lock",
                "category": "test",
                "service_type": "systemd",
                "service_name": "syncthing",
                "default_port": 8384
            }]))
            .unwrap(),
        )
        .unwrap();
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        let automation = root.join("automation.json");
        std::fs::write(&automation, "{}").unwrap();
        env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
        af_db::init_db().unwrap();
        af_services::initialize_package_jobs(rusqlite::Connection::open(&db).unwrap()).unwrap();
        af_db::set_base_domain("example.test").unwrap();
        std::fs::write(root.join("install/.syncthing.lock"), "installed").unwrap();

        // 1. No AppIngressConfig: internal .aether.local resolves, external <app>.<base_domain> fails closed
        assert_eq!(
            resolve_app_target_for_host("syncthing.aether.local"),
            Some(("syncthing".into(), 8384))
        );
        assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

        // 2. Explicit AppIngressConfig with external_access_enabled: false -> external fails closed
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "syncthing".into(),
            public_domain: "syncthing.example.test".into(),
            external_access_enabled: false,
            listen_port: 18384,
            ..Default::default()
        })
        .unwrap();
        af_db::invalidate_ingress_cache();
        assert_eq!(
            resolve_app_target_for_host("syncthing.aether.local"),
            Some(("syncthing".into(), 18384))
        );
        assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

        // 3. Stored AppIngressConfig with out-of-range listen_port: 0 -> both internal and external fail closed
        af_db::get_conn()
            .unwrap()
            .execute(
                "UPDATE app_ingress_configs SET external_access_enabled = 1, listen_port = 0 WHERE app_name = 'syncthing'",
                [],
            )
            .unwrap();
        af_db::invalidate_ingress_cache();
        assert_eq!(resolve_app_target_for_host("syncthing.aether.local"), None);
        assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

        // 4. Explicit AppIngressConfig with external_access_enabled: true and valid port -> external allowed
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "syncthing".into(),
            public_domain: "syncthing.example.test".into(),
            external_access_enabled: true,
            listen_port: 18384,
            ..Default::default()
        })
        .unwrap();
        af_db::invalidate_ingress_cache();
        assert_eq!(
            resolve_app_target_for_host("syncthing.example.test"),
            Some(("syncthing".into(), 18384))
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
