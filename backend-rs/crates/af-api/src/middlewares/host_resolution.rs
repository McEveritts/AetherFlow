use std::env;
use std::net::IpAddr;
use std::time::Duration;

pub(super) fn strip_host_port_and_dot(raw_host: &str) -> String {
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

pub(super) const PROXY_RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) static PROXY_AUTH_BLOCKING_LIMIT: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(4);
pub(super) static PROXY_RESOLVE_LIMIT: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(16);

pub(super) async fn resolve_proxy_work<T: Send + 'static>(
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

pub(super) fn local_control_plane_host(host: &str) -> bool {
    matches!(
        host,
        "" | "localhost" | "aether.local" | "aetherflow.aether.local"
    ) || host
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

pub(super) fn explicit_control_plane_host(raw: &str, clean: &str) -> bool {
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

pub(super) fn query_settings_base_domain() -> String {
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
pub(super) enum AppHostResolution {
    Proxy(String, i32),
    DisabledExternalApp(String),
    ControlPlane,
}

pub(super) fn is_control_plane_base_host(clean_host: &str, base_domain: &str) -> bool {
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

pub(super) fn resolve_app_host_disposition(raw_host: &str) -> AppHostResolution {
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
        let mut requires_install_receipt = false;
        for job in jobs
            .outcomes
            .values()
            .filter(|job| job.package_id.eq_ignore_ascii_case(app))
        {
            if job.status == "completed" {
                continue;
            }
            let legacy_failed_update =
                job.action == "update" && job.status == "failed" && job.recovery_state.is_none();
            if outcome_allows_recovered_admission(job) || legacy_failed_update {
                requires_install_receipt = true;
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
            match af_models::inspect_canonical_package_receipt(app, Some(lock_file), None) {
                Ok(present) => present,
                Err(_) => return false,
            }
        } else {
            false
        };
        if requires_install_receipt {
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
