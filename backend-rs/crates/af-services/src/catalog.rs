use super::*;

// Shared with health recovery and API controls. Cross-process exclusion lives
// in the runner's maintenance lock, since an API mutex cannot survive restart.
pub static PACKAGE_LIFECYCLE_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

/// Maps a Services card name, catalog id, primary unit, or companion unit to
/// the catalog package that owns it.
pub fn resolve_owning_package_id(target: &str) -> Option<String> {
    let clean = target
        .trim()
        .trim_end_matches(".service")
        .to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }
    let catalog = get_package_catalog().ok()?;
    let unit_matches = |unit: &str| {
        let unit = unit.trim().trim_end_matches(".service");
        !unit.is_empty() && unit.eq_ignore_ascii_case(&clean)
    };
    if let Some(pkg) = catalog.iter().find(|p| {
        p.name.eq_ignore_ascii_case(&clean)
            || p.label.eq_ignore_ascii_case(target.trim())
            || (p.service_name != "apache2" && unit_matches(&p.service_name))
            || p.sandbox_service_ids.iter().any(|unit| unit_matches(unit))
    }) {
        return Some(pkg.name.clone());
    }
    let canonical = resolve_canonical_service_id(&clean);
    catalog
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(&canonical))
        .map(|p| p.name.clone())
}

pub const CORE_SERVICE_IDS: [&str; 4] = [
    "aetherflow-api",
    "aetherflow-runner",
    "aetherflow-frontend",
    "apache2",
];

pub(crate) const INVENTORY_CORE_UNITS: [(&str, &str); 3] = [
    ("aetherflow-api", "AetherFlow API"),
    ("aetherflow-runner", "AetherFlow Runner"),
    ("apache2", "Apache2 Web Server"),
];

/// Validates a Services control request and returns the exact control target.
///
/// A card may only control its own logical service, primary unit, or catalog
/// companion units. This prevents the administrative control endpoint from
/// being used as a generic root `systemctl` proxy for unrelated host units.
pub fn authorize_service_control_target(
    card: &str,
    process: &str,
    managed_by: &str,
) -> Result<String, String> {
    let card_clean = card.trim();
    let process_clean = process.trim();
    let target = if process_clean.is_empty() {
        card_clean
    } else {
        process_clean
    };
    let norm = |value: &str| {
        value
            .trim()
            .trim_end_matches(".service")
            .to_ascii_lowercase()
    };
    let card_canonical = resolve_canonical_service_id(card_clean);
    if CORE_SERVICE_IDS.contains(&card_canonical.as_str()) {
        if managed_by == "pm2" {
            return Err("Core services require systemd controls".into());
        }
        if norm(target) == card_canonical || resolve_canonical_service_id(target) == card_canonical
        {
            return Ok(card_canonical);
        }
        return Err(format!("{} is not a component of {}", target, card_clean));
    }
    let Some(owner) = resolve_owning_package_id(card_clean) else {
        return Err(format!(
            "{} is not a managed AetherFlow service",
            card_clean
        ));
    };
    let pkg = get_package_catalog()
        .ok()
        .and_then(|catalog| catalog.into_iter().find(|p| p.name == owner))
        .ok_or_else(|| format!("{} is not a managed AetherFlow service", card_clean))?;
    if (managed_by == "pm2" && pkg.service_type != "pm2")
        || (pkg.service_type == "pm2" && !matches!(managed_by, "" | "pm2"))
    {
        return Err(format!(
            "Service manager does not match the catalog for {}",
            card_clean
        ));
    }
    let mut allowed: Vec<String> = vec![norm(&pkg.name)];
    if !pkg.service_name.trim().is_empty() {
        allowed.push(norm(&pkg.service_name));
    }
    if managed_by.trim().eq_ignore_ascii_case("pm2") {
        if allowed.contains(&norm(target)) {
            return Ok(target.to_string());
        }
        return Err(format!("{} is not a component of {}", target, card_clean));
    }
    allowed.extend(resolve_service_units(&pkg.name).iter().map(|u| norm(u)));
    allowed.extend(pkg.sandbox_service_ids.iter().map(|u| norm(u)));
    // Shared-vhost packages are hosted by Apache; only the Apache card may
    // control the shared daemon.
    allowed.retain(|unit| unit != "apache2");
    if allowed.contains(&norm(target)) {
        Ok(target.to_string())
    } else {
        Err(format!("{} is not a component of {}", target, card_clean))
    }
}

pub(crate) fn read_catalog_file(path: &Path) -> anyhow::Result<String> {
    af_runner::open_and_read_regular_config(path)
        .map_err(|error| anyhow::anyhow!("cannot read catalog {}: {error}", path.display()))
}

pub(crate) fn config_search_candidates(filename: &str) -> Vec<PathBuf> {
    af_runner::canonical_config_candidates(filename)
}

pub(crate) fn load_config_file_or_embedded(
    env_var: &str,
    filename: &str,
    embedded: &str,
) -> anyhow::Result<String> {
    if let Ok(explicit) = env::var(env_var) {
        if !explicit.trim().is_empty() {
            return read_catalog_file(Path::new(explicit.trim()));
        }
    }
    for c in config_search_candidates(filename) {
        match af_runner::open_and_read_regular_config(&c) {
            Ok(contents) => return Ok(contents),
            Err(error) if af_runner::is_missing_config_candidate(&error) => continue,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "cannot read catalog {}: {error}",
                    c.display()
                ))
            }
        }
    }
    Ok(embedded.to_string())
}

#[cfg(test)]
pub(crate) static CATALOG_READ_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn get_package_catalog() -> anyhow::Result<Vec<Package>> {
    #[cfg(test)]
    CATALOG_READ_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let raw_pkgs = load_config_file_or_embedded(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
    )?;
    let raw_auto = load_config_file_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
    )?;

    let mut pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs)?;
    let auto_map: HashMap<String, PackageAutomation> = serde_json::from_str(&raw_auto)?;

    let mut names = std::collections::HashSet::new();
    for p in &mut pkgs {
        anyhow::ensure!(
            !p.name.trim().is_empty() && names.insert(p.name.to_ascii_lowercase()),
            "catalog contains an empty or duplicate package id: {}",
            p.name
        );
        if let Some(auto) = auto_map.get(&p.name) {
            af_models::merge_package_automation(p, auto);
        }
    }
    Ok(pkgs)
}

pub fn get_packages() -> anyhow::Result<Vec<Package>> {
    get_packages_with_jobs(&package_job_snapshot()?)
}

pub fn get_packages_with_jobs(jobs: &PackageJobSnapshot) -> anyhow::Result<Vec<Package>> {
    lifecycle_cache::observe(jobs);
    let mut pkgs = get_package_catalog()?;
    populate_package_statuses(&mut pkgs, jobs)?;
    Ok(pkgs)
}

pub(crate) fn package_lock_installed(package: &Package) -> anyhow::Result<bool> {
    af_models::inspect_canonical_package_receipt(&package.name, Some(&package.lock_file), None)
        .map_err(anyhow::Error::msg)
}

pub(crate) fn public_app_vhost_enabled(app: &str, domain: &str, tls: bool) -> bool {
    ["", "-le-ssl"].into_iter().any(|suffix| {
        let path = mutators::resolve_config_path(&format!(
            "/etc/apache2/sites-enabled/aetherflow-ext-{app}{suffix}.conf"
        ));
        let Ok(config) = fs::read_to_string(path) else {
            return false;
        };
        // The runner renders an HTTP 503 vhost while the certificate is pending.
        // A certificate file alone also says nothing about what Apache loaded.
        config.split("</VirtualHost>").any(|vhost| {
            let has_directive = |directive: &str, value: &str| {
                vhost.lines().any(|line| {
                    let mut words = line.split_whitespace();
                    words
                        .next()
                        .is_some_and(|word| word.eq_ignore_ascii_case(directive))
                        && words
                            .next()
                            .is_some_and(|word| word.eq_ignore_ascii_case(value))
                })
            };
            has_directive("ServerName", domain)
                && has_directive("SSLEngine", "on") == tls
                && !vhost.contains("TLS certificate provisioning pending")
                && !vhost.contains("RewriteRule ^ https://")
        })
    })
}

pub(crate) fn launch_target(
    app: &str,
    port: i32,
    web_path: &str,
    ingress: Option<&af_models::AppIngressConfig>,
    host: &str,
) -> (Option<String>, Option<String>) {
    let unavailable = || (None, Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE.into()));
    let internal = resolve_app_internal_domain(app);
    if !(1..=65535).contains(&port) || !af_models::valid_ingress_hostname(&internal) {
        return unavailable();
    }
    let path = af_models::app_metadata::validate_app_web_path(web_path).unwrap_or_default();
    let enabled_vhost = mutators::resolve_config_path(&format!(
        "/etc/apache2/sites-enabled/aetherflow-app-{app}.conf"
    ));
    if let Some(ingress) = ingress.filter(|ing| {
        ing.external_access_enabled
            && af_models::valid_ingress_hostname(&ing.public_domain)
            && (1..=65535).contains(&ing.listen_port)
            && public_app_vhost_enabled(app, &ing.public_domain, ing.tls_enabled)
    }) {
        let domain = &ingress.public_domain;
        let scheme = if ingress.tls_enabled { "https" } else { "http" };
        return (
            Some(format!("{scheme}://{domain}{path}")),
            Some("public".to_string()),
        );
    }
    if enabled_vhost.is_file() {
        return (
            Some(format!("http://{internal}{path}")),
            Some("internal".to_string()),
        );
    }
    let scheme = service_web_scheme_for_id(app, port);
    if scheme.is_empty() {
        return unavailable();
    }
    let bind = (app == "qbittorrent")
        .then(mutators::qbittorrent_web_bind_address)
        .flatten();
    let scope = if app == "qbittorrent" {
        qbittorrent_bind_scope(bind.as_deref())
    } else {
        service_bind_scope_for_id(app)
    };
    if scope == "loopback" {
        return unavailable();
    }
    let ip = bind
        .as_deref()
        .and_then(|address| address.parse::<std::net::IpAddr>().ok())
        .filter(|address| !address.is_unspecified())
        .or_else(|| host.parse().ok());
    let Some(ip) = ip else {
        return unavailable();
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return unavailable();
    };
    let address = std::net::SocketAddr::new(ip, port as u16);
    (
        Some(format!("{scheme}://{address}{path}")),
        Some("network".to_string()),
    )
}

pub(crate) fn populate_package_core_statuses(
    pkgs: &mut [Package],
    jobs: &PackageJobSnapshot,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let update_map = workers::get_package_update_map();
    let mut installed_packages = std::collections::HashSet::new();

    for p in pkgs {
        let installed = package_lock_installed(p)?;
        if let Some(job) = jobs.active.get(&p.name) {
            p.status = job.status.clone();
        } else if installed {
            p.status = "installed".to_string();
        } else if p.status.eq_ignore_ascii_case("retired") {
            p.status = "retired".to_string();
        } else {
            p.status = "uninstalled".to_string();
        }

        if installed {
            installed_packages.insert(p.name.clone());
            if let Some(update) = update_map.get(&p.name) {
                p.installed_version = update.installed_version.clone();
                p.latest_version = update.latest_version.clone();
                p.update_available = update.update_available;
                p.update_checked_at = update.checked_at.clone();
                p.update_url = update.release_url.clone();
                p.update_error = workers::public_update_error(&update.error);
            }
        } else {
            p.launch_url = None;
            p.launch_scope = Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE.into());
        }
    }

    Ok(installed_packages)
}

pub(crate) fn populate_package_statuses(
    pkgs: &mut [Package],
    jobs: &PackageJobSnapshot,
) -> anyhow::Result<()> {
    let installed_packages = populate_package_core_statuses(pkgs, jobs)?;
    let ingress: HashMap<_, _> = af_db::get_all_app_ingress_configs()?
        .into_iter()
        .map(|config| (config.app_name.clone(), config))
        .collect();
    let host = mutators::detect_lan_ip();
    let native_url_base_apps: Vec<String> = pkgs
        .iter()
        .filter(|p| {
            installed_packages.contains(&p.name)
                && af_models::app_metadata::supports_native_url_base(&p.name)
        })
        .map(|p| p.name.clone())
        .collect();
    let native_meta = mutators::collect_native_url_base_meta(&native_url_base_apps);

    for p in pkgs {
        if installed_packages.contains(&p.name) {
            let meta = native_meta.get(&mutators::normalize_app_key_name(&p.name));
            let url_base = meta.map(|m| m.url_base.as_str()).unwrap_or("");
            p.web_path = af_models::app_metadata::effective_app_web_path(url_base, &p.web_path);
            let config = ingress.get(&p.name);
            let port = config
                .map(|ing| ing.listen_port)
                .filter(|port| *port > 0)
                .or_else(|| meta.map(|m| m.configured_port).filter(|port| *port > 0))
                .unwrap_or(p.default_port);
            (p.launch_url, p.launch_scope) =
                launch_target(&p.name, port, &p.web_path, config, &host);
        }
    }

    Ok(())
}
