use super::host_resolution::{
    explicit_control_plane_host, is_control_plane_base_host, local_control_plane_host,
    query_settings_base_domain, resolve_proxy_work, strip_host_port_and_dot,
};
use super::proxy_helpers::{
    internal_domain_forbidden, is_trusted_proxy_ip, local_domain_client_allowed,
};
use crate::auth::api_error;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashSet;
use std::env;
use std::net::SocketAddr;

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

pub(super) fn is_host_trusted(candidate_raw: &str, allowed_set: &HashSet<String>) -> bool {
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
