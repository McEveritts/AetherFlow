use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// App Blueprints & Port / Domain Resolution
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBlueprint {
    pub app_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub service_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub category: String,
    pub default_port: i32,
    #[serde(default = "default_true_bool")]
    pub supports_dynamic_port: bool,
    #[serde(default = "default_port_range")]
    pub fallback_port_range: [i32; 2],
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub port_env_var: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub port_config_key: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub health_check_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub mutator_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub config_file_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub internal_domain: String,
    #[serde(default)]
    pub is_network_app: bool,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

pub(crate) fn default_true_bool() -> bool {
    true
}

pub(crate) fn default_port_range() -> [i32; 2] {
    af_models::MARKETPLACE_FALLBACK_PORT_RANGE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintStatusView {
    #[serde(flatten)]
    pub blueprint: AppBlueprint,
    pub active_port: i32,
    pub port_reassigned: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_domain: String,
    pub external_access_enabled: bool,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintSetupResult {
    pub app_name: String,
    pub service_name: String,
    pub allocated_port: i32,
    pub default_port: i32,
    pub port_reassigned: bool,
    pub internal_domain: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_domain: String,
    pub external_access_enabled: bool,
    pub config_applied: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mutated_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprivileged_skips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub ingress_synced: bool,
    pub hosts_synced: bool,
    pub network_dns_synced: bool,
}

pub(crate) fn default_blueprint_mutator_meta(
    app_name: &str,
) -> (&'static str, String, &'static str) {
    let clean = app_name.trim().to_lowercase();
    match clean.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
            ("xml", format!("/var/lib/{}/config.xml", clean), "Port")
        }
        "listenarr" => (
            "systemd",
            "/etc/systemd/system/listenarr.service".to_string(),
            "ASPNETCORE_URLS",
        ),
        "bazarr" => (
            "yaml",
            "/var/lib/bazarr/config/config.yaml".to_string(),
            "general.port",
        ),
        "dispatcharr" => (
            "ini",
            "/etc/dispatcharr/dispatcharr.env".to_string(),
            "DISPATCHARR_PORT",
        ),
        "jellyfin" => (
            "xml",
            "/etc/jellyfin/network.xml".to_string(),
            "InternalHttpPort",
        ),
        "emby" => (
            "xml",
            "/var/lib/emby/config/system.xml".to_string(),
            "HttpServerPortNumber",
        ),
        "qbittorrent" => (
            "ini",
            "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf".to_string(),
            r"WebUI\Port",
        ),
        "sabnzbd" => ("ini", "/var/lib/sabnzbd/sabnzbd.ini".to_string(), "port"),
        "tautulli" => (
            "ini",
            "/var/lib/tautulli/config.ini".to_string(),
            "http_port",
        ),
        "gitea" => ("ini", "/etc/gitea/app.ini".to_string(), "HTTP_PORT"),
        "transmission" => (
            "json",
            "/etc/transmission-daemon/settings.json".to_string(),
            "rpc-port",
        ),
        "overseerr" | "jellyseerr" => (
            "systemd",
            format!("/etc/systemd/system/{}.service", clean),
            "PORT",
        ),
        "jackett" => (
            "json",
            "/var/lib/jackett/Jackett/ServerConfig.json".to_string(),
            "Port",
        ),
        "pihole" => ("pihole", "/etc/pihole/pihole.toml".to_string(), "port"),
        _ => ("", String::new(), "port"),
    }
}

pub fn get_blueprint(app_name: &str) -> Option<AppBlueprint> {
    let pkgs = get_package_catalog().ok()?;
    let p = pkgs.into_iter().find(|x| x.name == app_name)?;
    let (mutator_type, config_file_path, port_config_key) = default_blueprint_mutator_meta(&p.name);
    let supports_dynamic_port = p.default_port > 0 && !mutator_type.is_empty();
    Some(AppBlueprint {
        app_name: p.name.clone(),
        service_name: if p.service_name.is_empty() {
            p.name.clone()
        } else {
            p.service_name
        },
        category: p.category,
        default_port: p.default_port,
        supports_dynamic_port,
        fallback_port_range: if supports_dynamic_port {
            default_port_range()
        } else {
            [0, 0]
        },
        port_env_var: if p.name == "maintainerr" {
            "UI_PORT".to_string()
        } else {
            "AF_APP_PORT".to_string()
        },
        port_config_key: port_config_key.to_string(),
        web_path: p.web_path,
        health_check_path: if p.name == "palate" {
            "/login".to_string()
        } else if p.name == "maintainerr" {
            "/api/health/ready".to_string()
        } else {
            "/".to_string()
        },
        mutator_type: mutator_type.to_string(),
        config_file_path,
        internal_domain: resolve_app_internal_domain(&p.name),
        is_network_app: matches!(
            p.name.as_str(),
            "pihole" | "adguardhome" | "wireguard" | "tailscale"
        ),
        dependencies: if p.name == "palate" {
            vec!["jellyfin".to_string()]
        } else {
            Vec::new()
        },
    })
}

pub fn get_all_blueprints() -> anyhow::Result<Vec<BlueprintStatusView>> {
    let pkgs = get_package_catalog()?;
    let ingress_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()?
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();
    let base_domain = resolve_base_domain();

    Ok(pkgs
        .into_iter()
        .filter_map(|p| get_blueprint(&p.name))
        .map(|bp| {
            let mut active_port = bp.default_port;
            let mut public_domain = String::new();
            let mut external_access = false;
            let mut tls_enabled = false;
            if let Some(ing) = ingress_map.get(&bp.app_name) {
                if ing.listen_port > 0 {
                    active_port = ing.listen_port;
                }
                public_domain = ing.public_domain.clone();
                external_access = ing.external_access_enabled;
                tls_enabled = ing.tls_enabled;
            } else {
                let runtime_meta = mutators::get_app_runtime_meta(&bp.app_name);
                if runtime_meta.configured_port > 0 {
                    active_port = runtime_meta.configured_port;
                }
            }
            if public_domain.is_empty() && !base_domain.is_empty() && active_port > 0 {
                public_domain = format_app_public_domain(&bp.app_name, &base_domain);
            }
            BlueprintStatusView {
                port_reassigned: active_port != bp.default_port && active_port > 0,
                blueprint: bp,
                active_port,
                public_domain,
                external_access_enabled: external_access,
                tls_enabled,
            }
        })
        .collect())
}

pub fn resolve_base_domain() -> String {
    let db_domain = af_db::get_base_domain();
    if !db_domain.is_empty() {
        return db_domain;
    }
    env::var("AETHERFLOW_BASE_DOMAIN")
        .or_else(|_| env::var("AETHERFLOW_DOMAIN"))
        .map(|d| af_db::normalize_base_domain(&d))
        .unwrap_or_default()
}

pub fn format_app_public_domain(app_name: &str, base_domain: &str) -> String {
    let norm = af_db::normalize_base_domain(base_domain);
    if norm.is_empty() {
        return String::new();
    }
    let clean_app: String = app_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{}.{}", clean_app.trim_matches('-'), norm)
}

pub fn resolve_app_internal_domain(app_name: &str) -> String {
    format!("{}.aether.local", app_name.trim().to_lowercase())
}

pub(crate) fn find_catalog_package(app: &str) -> Option<Package> {
    let clean = resolve_canonical_service_id(app);
    let lock_alias = af_models::resolve_package_lock_name(app);
    get_package_catalog().ok().and_then(|pkgs| {
        pkgs.into_iter().find(|p| {
            p.name.eq_ignore_ascii_case(&clean)
                || p.name.eq_ignore_ascii_case(lock_alias)
                || p.name.eq_ignore_ascii_case(app.trim())
        })
    })
}

pub(crate) fn package_is_physically_installed(app: &str) -> bool {
    find_catalog_package(app)
        .and_then(|p| package_lock_installed(&p).ok())
        .unwrap_or(false)
}

pub fn is_package_installed(app: &str) -> bool {
    package_is_physically_installed(app)
}

/// Returns `Ok(true)` iff the package lacks a canonical receipt and has a safe
/// regular legacy `/etc/Swizzin` upgrade-input receipt. Rejects unsafe lock types.
pub fn package_has_legacy_upgrade_receipt(app: &str) -> anyhow::Result<bool> {
    let Some(pkg) = find_catalog_package(app) else {
        return Ok(false);
    };
    let status = af_models::inspect_package_receipts(&pkg.name, Some(&pkg.lock_file), None)
        .map_err(anyhow::Error::msg)?;
    Ok(status.has_legacy_upgrade_receipt())
}

/// Reads an optional port hint from the package's canonical receipt or legacy
/// `/etc/Swizzin` upgrade receipt, rejecting unsafe lock types.
pub fn package_receipt_port(app: &str) -> anyhow::Result<Option<i32>> {
    let Some(pkg) = find_catalog_package(app) else {
        return Ok(None);
    };
    af_models::read_package_receipt_port(&pkg.name, Some(&pkg.lock_file), None)
        .map_err(anyhow::Error::msg)
}
