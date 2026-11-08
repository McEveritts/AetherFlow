pub mod cluster_daemon;
pub mod lifecycle_cache;
pub mod mutators;
pub mod plugins;
pub mod workers;
mod service_observations;

#[cfg(all(test, unix))]
mod inventory_regressions;
#[cfg(all(test, unix))]
mod http_lifecycle_regressions;
#[cfg(all(test, unix))]
mod readiness_regressions;
#[cfg(all(test, unix))]
mod native_metadata_regressions;

use af_models::{Package, PackageAutomation};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
// Package Catalog, Automation & Marketplace Orchestration (`package_service.go`)
// ─────────────────────────────────────────────────────────────────────────────

const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str = include_str!("../../../../config/package_automation.json");

mod package_jobs;
pub use package_jobs::*;

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

pub const CORE_SERVICE_IDS: [&str; 3] = ["aetherflow-api", "aetherflow-frontend", "apache2"];

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

fn read_catalog_file(path: &Path) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)?;
    anyhow::ensure!(
        metadata.is_file(),
        "catalog is not a regular file: {}",
        path.display()
    );
    fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("cannot read catalog {}: {error}", path.display()))
}

fn load_config_file_or_embedded(
    env_var: &str,
    filename: &str,
    embedded: &str,
) -> anyhow::Result<String> {
    if let Ok(explicit) = env::var(env_var) {
        if !explicit.trim().is_empty() {
            return read_catalog_file(Path::new(explicit.trim()));
        }
    }
    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/config").join(filename),
        PathBuf::from("/opt/AetherFlow/current/backend/config").join(filename),
        PathBuf::from("config").join(filename),
        PathBuf::from("../config").join(filename),
        PathBuf::from("/opt/AetherFlow/current/config").join(filename),
        PathBuf::from("/opt/AetherFlow/config").join(filename),
        PathBuf::from("backend/config").join(filename),
        PathBuf::from("../backend/config").join(filename),
        PathBuf::from("/opt/AetherFlow/backend/config").join(filename),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.insert(2, exe_dir.join("config").join(filename));
        }
    }
    for c in candidates {
        match fs::symlink_metadata(&c) {
            Ok(_) => return read_catalog_file(&c),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(embedded.to_string())
}

#[cfg(test)]
static CATALOG_READ_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
            p.update_source = auto.update_source.clone();
            p.update_repo = auto.update_repo.clone();
            p.update_repo_url = auto.update_repo_url.clone();
            p.update_package = auto.update_package.clone();
            p.version_command = auto.version_command.clone();
            p.version_regex = auto.version_regex.clone();
            p.sandbox_profile = auto.sandbox_profile.clone();
            p.sandbox_read_write = auto.sandbox_read_write.clone();
            p.sandbox_service_ids = auto.sandbox_service_ids.clone();
        }
    }
    Ok(pkgs)
}

fn resolve_filesystem_path(path_str: &str) -> PathBuf {
    if let Ok(root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = root.trim();
        if !trimmed.is_empty() {
            let rel = path_str.trim_start_matches('/');
            return Path::new(trimmed).join(rel);
        }
    }
    PathBuf::from(path_str)
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

fn package_lock_installed(package: &Package) -> anyhow::Result<bool> {
    if package.lock_file.is_empty() {
        return Ok(false);
    }
    let path = resolve_filesystem_path(&package.lock_file);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => anyhow::bail!(
            "installation lock is not a regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::anyhow!(
            "cannot inspect installation lock {}: {error}",
            path.display()
        )),
    }
}

fn populate_package_statuses(
    pkgs: &mut [Package],
    jobs: &PackageJobSnapshot,
) -> anyhow::Result<()> {
    let update_map = get_package_update_map();

    for p in pkgs {
        let installed = package_lock_installed(p)?;
        if let Some(job) = jobs.active.get(&p.name) {
            p.status = job.status.clone();
        } else if installed {
            p.status = "installed".to_string();
        } else {
            p.status = "uninstalled".to_string();
        }

        if let Some(u) = update_map.get(&p.name) {
            p.installed_version = u.installed_version.clone();
            p.latest_version = u.latest_version.clone();
            p.update_available = u.update_available;
            p.update_checked_at = u.checked_at.clone();
            p.update_url = u.update_url.clone();
            p.update_error = u.last_error.clone();
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct AppUpdateRecord {
    pub package_name: String,
    pub installed_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub update_url: String,
    pub checked_at: String,
    pub last_error: String,
}

pub fn get_package_update_map() -> HashMap<String, AppUpdateRecord> {
    let mut map = HashMap::new();
    let Ok(conn) = af_db::get_conn() else {
        return map;
    };
    let Ok(mut stmt) = conn.prepare(
        "SELECT package_name, installed_version, latest_version, update_available, update_url, COALESCE(CAST(checked_at AS TEXT), ''), last_error FROM app_updates",
    ) else {
        return map;
    };
    if let Ok(rows) = stmt.query_map([], |r| {
        Ok(AppUpdateRecord {
            package_name: r.get(0)?,
            installed_version: r.get(1)?,
            latest_version: r.get(2)?,
            update_available: r.get(3)?,
            update_url: r.get(4)?,
            checked_at: r.get(5)?,
            last_error: r.get(6)?,
        })
    }) {
        for r in rows.flatten() {
            map.insert(r.package_name.clone(), r);
        }
    }
    map
}

// ─────────────────────────────────────────────────────────────────────────────
// App Blueprints & Port / Domain Resolution (`app_catalog.go` & `blueprint_lifecycle.go`)
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

fn default_true_bool() -> bool {
    true
}

fn default_port_range() -> [i32; 2] {
    [17000, 19999]
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
    pub ingress_synced: bool,
    pub hosts_synced: bool,
    pub network_dns_synced: bool,
}

fn default_blueprint_mutator_meta(app_name: &str) -> (&'static str, String, &'static str) {
    let clean = app_name.trim().to_lowercase();
    match clean.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            ("xml", format!("/var/lib/{}/config.xml", clean), "Port")
        }
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
            "json",
            format!("/var/lib/{}/config/settings.json", clean),
            "main.port",
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
    let supports_dynamic_port = p.default_port > 0
        && !matches!(p.name.as_str(), "plex" | "calibreweb" | "calibre-web");
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
            [17000, 19999]
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
        internal_domain: format!("{}.aether.local", p.name),
        is_network_app: matches!(p.name.as_str(), "pihole" | "wireguard" | "tailscale"),
        dependencies: if p.name == "palate" {
            vec!["jellyfin".to_string()]
        } else {
            Vec::new()
        },
    })
}

pub fn get_all_blueprints() -> Vec<BlueprintStatusView> {
    let pkgs = get_package_catalog().unwrap_or_default();
    let ingress_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();
    let base_domain = resolve_base_domain();

    pkgs.into_iter()
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
        .collect()
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

pub(crate) fn resolve_app_internal_domain(app_name: &str) -> String {
    get_blueprint(app_name)
        .map(|blueprint| blueprint.internal_domain.trim().to_lowercase())
        .filter(|domain| !domain.is_empty())
        .unwrap_or_else(|| format!("{}.aether.local", app_name.trim().to_lowercase()))
}

fn package_is_physically_installed(app: &str) -> bool {
    let clean = resolve_canonical_service_id(app);
    get_package_catalog()
        .ok()
        .and_then(|pkgs| pkgs.into_iter().find(|p| p.name == clean || p.name == app))
        .is_some_and(|p| !p.lock_file.is_empty() && resolve_filesystem_path(&p.lock_file).is_file())
}

pub fn is_package_installed(app: &str) -> bool {
    package_is_physically_installed(app)
}

pub fn resolve_app_target_for_host(host_header: &str) -> Option<(String, i32)> {
    let host = host_header
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if host.is_empty() || host == "localhost" || host == "127.0.0.1" {
        return None;
    }

    // 1. Check `<app>.aether.local`
    if let Some(app_prefix) = host.strip_suffix(".aether.local") {
        if let Some(bp) = get_blueprint(app_prefix) {
            let active_config = af_db::get_app_ingress_config(app_prefix).ok().flatten();
            if active_config.is_none() && !package_is_physically_installed(app_prefix) {
                return None;
            }
            let port = af_db::get_app_ingress_config(app_prefix)
                .ok()
                .flatten()
                .map(|c| c.listen_port)
                .filter(|&p| p > 0)
                .unwrap_or_else(|| {
                    let meta = mutators::get_app_runtime_meta(app_prefix);
                    if meta.configured_port > 0 {
                        meta.configured_port
                    } else {
                        bp.default_port
                    }
                });
            if port > 0 {
                return Some((app_prefix.to_string(), port));
            }
        }
    }

    // 2. Check configured `public_domain` or `<app>.<baseDomain>`
    if let Ok(configs) = af_db::get_all_app_ingress_configs() {
        for cfg in configs {
            if cfg.external_access_enabled
                && cfg.public_domain.eq_ignore_ascii_case(&host)
                && cfg.listen_port > 0
            {
                return Some((cfg.app_name, cfg.listen_port));
            }
        }
    }

    let base = resolve_base_domain();
    if !base.is_empty() {
        let suffix = format!(".{}", base);
        if let Some(app_prefix) = host.strip_suffix(&suffix) {
            if let Some(bp) = get_blueprint(app_prefix) {
                let active_config = af_db::get_app_ingress_config(app_prefix).ok().flatten();
                if active_config.is_none() && !package_is_physically_installed(app_prefix) {
                    return None;
                }
                let port = af_db::get_app_ingress_config(app_prefix)
                    .ok()
                    .flatten()
                    .map(|c| c.listen_port)
                    .filter(|&p| p > 0)
                    .unwrap_or(bp.default_port);
                if port > 0 {
                    return Some((app_prefix.to_string(), port));
                }
            }
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Manager (`service_manager.go` & `systemctl.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceStatusItem {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub id: String,
    pub status: String,
    pub uptime: String,
    pub version: String,
    pub managed_by: String,
    pub process: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub default_port: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub active_port: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub api_key: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub internal_domain: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_domain: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub external_access_enabled: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_scheme: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub bind_scope: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub control_scope: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub components: Vec<ServiceComponentStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub units: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub installed_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub latest_version: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub update_available: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_error: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub job_status: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub job_id: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub progress: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub log_line: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub started_at: String,
    /// Terminal result of the most recent lifecycle job (authenticated view).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_job: Option<PackageJobOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServiceComponentStatus {
    pub unit: String,
    pub role: String,
    pub status: String,
    pub configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceComponentPolicy {
    pub unit: String,
    pub role: &'static str,
    pub configured: bool,
}

type ServiceInfoCacheEntry = ((String, String, String), Instant);
type Pm2ServicesCacheState = (Option<HashMap<String, (String, String)>>, Option<Instant>);

static SERVICE_INFO_CACHE: Lazy<RwLock<HashMap<String, ServiceInfoCacheEntry>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

static PM2_SERVICES_CACHE: Lazy<RwLock<Pm2ServicesCacheState>> =
    Lazy::new(|| RwLock::new((None, None)));

static SERVICE_STATUS_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn clear_service_status_cache() {
    SERVICE_STATUS_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    service_observations::invalidate();
    if let Ok(mut g) = SERVICE_INFO_CACHE.write() {
        g.clear();
    }
    if let Ok(mut g) = PM2_SERVICES_CACHE.write() {
        g.0 = None;
        g.1 = None;
    }
}

pub fn should_pre_stop_on_update(target: &str) -> bool {
    let clean = resolve_canonical_service_id(target);
    if resolve_service_control_scope(&clean) == "shared-vhost" {
        return false;
    }
    !matches!(clean.as_str(), "maintainerr" | "af-maintainerr")
}

pub fn resolve_canonical_service_id(target: &str) -> String {
    resolve_canonical_service_id_with_catalog(target, &get_package_catalog().unwrap_or_default())
}

fn resolve_canonical_service_id_with_catalog(target: &str, catalog: &[Package]) -> String {
    let clean = target
        .trim()
        .trim_end_matches(".service")
        .to_ascii_lowercase();
    match clean.as_str() {
        "af-maintainerr" => "maintainerr".to_string(),
        "af-palate" => "palate".to_string(),
        "af-kasmvnc" => "kasmvnc".to_string(),
        "af-mcvnc" => "mcvnc".to_string(),
        "deluged" | "deluge-web" => "deluge".to_string(),
        "paperless" | "paperless-webserver" | "paperless-worker" | "paperless-scheduler" => {
            "paperless-ngx".to_string()
        }
        "dispatcharr-celery" | "dispatcharr-celerybeat" => "dispatcharr".to_string(),
        "novnc-xvnc" => "novnc".to_string(),
        "xrdp-sesman" => "xrdp".to_string(),
        "node_exporter" => "prometheus".to_string(),
        "rclone-vfs" => "rclone".to_string(),
        "scrutiny-collector" | "scrutiny-collector.timer" => "scrutiny".to_string(),
        "recyclarr.timer" => "recyclarr".to_string(),
        "apache2 web server" => "apache2".to_string(),
        "aetherflow api" => "aetherflow-api".to_string(),
        "aetherflow frontend" => "aetherflow-frontend".to_string(),
        _ => {
            if let Some(pkg) = catalog.iter().find(|p| {
                p.name.eq_ignore_ascii_case(&clean)
                    || p.label.eq_ignore_ascii_case(target.trim())
                    || (!p.service_name.is_empty()
                        && p.service_name != "apache2"
                        && p.service_name
                            .trim_end_matches(".service")
                            .eq_ignore_ascii_case(&clean))
            }) {
                return pkg.name.to_ascii_lowercase();
            }
            clean
        }
    }
}

pub fn resolve_service_web_scheme(target: &str, default_port: i32) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    service_web_scheme_for_id(&clean, default_port)
}

fn service_web_scheme_for_id(clean: &str, default_port: i32) -> &'static str {
    if default_port > 0
        || matches!(
            clean,
            "nextcloud" | "rutorrent" | "organizr" | "maintainerr" | "palate" | "kasmvnc" | "mcvnc"
        )
    {
        "http"
    } else {
        ""
    }
}

pub fn resolve_service_bind_scope(target: &str) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    service_bind_scope_for_id(&clean)
}

fn service_bind_scope_for_id(clean: &str) -> &'static str {
    if matches!(clean, "maintainerr" | "palate" | "kasmvnc" | "mcvnc") {
        "loopback"
    } else {
        "network"
    }
}

pub fn resolve_service_control_scope(target: &str) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    service_control_scope_for_id(&clean)
}

fn service_control_scope_for_id(clean: &str) -> &'static str {
    if matches!(clean, "nextcloud" | "rutorrent" | "organizr") {
        "shared-vhost"
    } else {
        "service"
    }
}

pub fn is_rclone_vfs_configured() -> bool {
    let conf_path = mutators::resolve_config_path("/etc/rclone/rclone.conf");
    let Ok(content) = fs::read_to_string(conf_path) else {
        return false;
    };
    content
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[remote]"))
}

pub fn resolve_service_component_policies(target: &str) -> Vec<ServiceComponentPolicy> {
    resolve_service_component_policies_with(target, is_rclone_vfs_configured())
}

pub fn resolve_service_component_policies_with(
    target: &str,
    rclone_vfs_configured: bool,
) -> Vec<ServiceComponentPolicy> {
    service_component_policies_with_catalog(
        target,
        rclone_vfs_configured,
        &get_package_catalog().unwrap_or_default(),
    )
}

fn service_component_policies_with_catalog(
    target: &str,
    rclone_vfs_configured: bool,
    catalog: &[Package],
) -> Vec<ServiceComponentPolicy> {
    let clean = resolve_canonical_service_id_with_catalog(target, catalog);
    policies_for_units(
        resolve_service_units_with_catalog(&clean, catalog),
        rclone_vfs_configured,
    )
}

fn policies_for_units(
    units: Vec<String>,
    rclone_vfs_configured: bool,
) -> Vec<ServiceComponentPolicy> {
    units
        .into_iter()
        .map(|unit| {
            let unit_lower = unit.to_ascii_lowercase();
            let (role, configured) = if unit_lower.ends_with(".timer") {
                ("timer", true)
            } else if matches!(unit_lower.as_str(), "recyclarr" | "scrutiny-collector") {
                ("oneshot", true)
            } else if unit_lower == "rclone-vfs" {
                ("optional", rclone_vfs_configured)
            } else {
                ("required", true)
            };
            ServiceComponentPolicy {
                unit,
                role,
                configured,
            }
        })
        .collect()
}

pub fn resolve_controllable_service_units(target: &str, action: &str) -> Vec<String> {
    resolve_controllable_service_units_with(target, action, is_rclone_vfs_configured())
}

pub fn resolve_controllable_service_units_with(
    target: &str,
    action: &str,
    rclone_vfs_configured: bool,
) -> Vec<String> {
    let policies = resolve_service_component_policies_with(target, rclone_vfs_configured);
    let mut units: Vec<String> = policies
        .into_iter()
        .filter(|p| match p.role {
            "required" | "timer" => true,
            "optional" => p.configured || action == "stop",
            "oneshot" => action == "stop",
            _ => true,
        })
        .map(|p| p.unit)
        .collect();
    if action == "stop" {
        units.sort_by_key(|u| !u.ends_with(".timer"));
    }
    units
}

pub fn aggregate_component_statuses(
    components: &[ServiceComponentStatus],
    primary_fallback: &str,
) -> (String, String) {
    let primary_unit = components
        .iter()
        .find(|c| c.role == "required")
        .or_else(|| components.iter().find(|c| c.role == "timer"))
        .or_else(|| components.first())
        .map(|c| c.unit.clone())
        .unwrap_or_else(|| primary_fallback.to_string());

    if components.is_empty() {
        return ("stopped".to_string(), primary_unit);
    }
    if components.iter().any(|component| {
        component.status == "unknown" && (component.role != "optional" || component.configured)
    }) {
        return ("unknown".to_string(), primary_unit);
    }

    let mut required_or_timer_count = 0usize;
    let mut active_required_or_timer = 0usize;
    let mut restarting_required_or_timer = 0usize;
    let mut inactive_required_or_timer = 0usize;
    let mut configured_optional_failed = false;
    let mut oneshot_failed = false;

    for comp in components {
        match comp.role.as_str() {
            "required" | "timer" => {
                required_or_timer_count += 1;
                match comp.status.as_str() {
                    "running" => active_required_or_timer += 1,
                    "restarting" => restarting_required_or_timer += 1,
                    _ => inactive_required_or_timer += 1,
                }
            }
            "optional" => {
                if comp.configured && comp.status != "running" {
                    configured_optional_failed = true;
                }
            }
            "oneshot" => {
                if comp.status == "failed" {
                    oneshot_failed = true;
                }
            }
            _ => {}
        }
    }

    if required_or_timer_count == 0 {
        let any_run = components.iter().any(|c| c.status == "running");
        let status = if any_run { "running" } else { "stopped" };
        return (status.to_string(), primary_unit);
    }

    let status = if active_required_or_timer == required_or_timer_count {
        if configured_optional_failed || oneshot_failed {
            "degraded"
        } else {
            "running"
        }
    } else if active_required_or_timer > 0 {
        if restarting_required_or_timer > 0 && inactive_required_or_timer == 0 {
            "restarting"
        } else {
            "degraded"
        }
    } else if restarting_required_or_timer > 0 {
        "restarting"
    } else {
        "stopped"
    };

    (status.to_string(), primary_unit)
}

/// Resolves a logical package or service name into its concrete systemd unit names (`systemctl.go`).
pub fn resolve_service_units(target: &str) -> Vec<String> {
    resolve_service_units_with_catalog(target, &get_package_catalog().unwrap_or_default())
}

fn resolve_service_units_with_catalog(target: &str, catalog: &[Package]) -> Vec<String> {
    let clean = target.trim().trim_end_matches(".service").to_string();
    if clean.is_empty() {
        return Vec::new();
    }
    let lower = clean.to_lowercase();
    if let Some(pkg) = catalog.iter().find(|p| {
        p.name.eq_ignore_ascii_case(&lower)
            || p.service_name
                .trim_end_matches(".service")
                .eq_ignore_ascii_case(&lower)
            || p.sandbox_service_ids
                .iter()
                .any(|u| u.trim_end_matches(".service").eq_ignore_ascii_case(&lower))
    }) {
        let mut units = vec![if pkg.service_name.is_empty() {
            pkg.name.clone()
        } else {
            pkg.service_name.clone()
        }];
        units.extend(pkg.sandbox_service_ids.iter().cloned());
        let mut seen = std::collections::HashSet::new();
        return units
            .into_iter()
            .map(|u| u.trim_end_matches(".service").to_string())
            .filter(|u| !u.is_empty() && seen.insert(u.clone()))
            .collect();
    }
    match lower.as_str() {
        "deluge" | "deluged" => vec!["deluged".to_string(), "deluge-web".to_string()],
        "mcvnc" => vec!["af-mcvnc".to_string()],
        "kasmvnc" => vec!["af-kasmvnc".to_string()],
        "plex" | "plexmediaserver" => vec!["plexmediaserver".to_string()],
        "emby" | "emby-server" => vec!["emby-server".to_string()],
        "pihole" | "pihole-ftl" => vec!["pihole-FTL".to_string()],
        "transmission" | "transmission-daemon" => vec!["transmission-daemon".to_string()],
        "qbittorrent" | "qbittorrent-nox" => {
            // Check if a templated unit like qbittorrent-nox@<user>.service exists on disk
            for dir in [
                "/etc/systemd/system/multi-user.target.wants",
                "/etc/systemd/system",
            ] {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if fname.starts_with("qbittorrent-nox@") && fname.ends_with(".service") {
                            return vec![fname.trim_end_matches(".service").to_string()];
                        }
                    }
                }
            }
            vec!["qbittorrent".to_string()]
        }
        "paperless" | "paperless-ngx" | "paperless-webserver" => vec![
            "paperless-webserver".to_string(),
            "paperless-worker".to_string(),
            "paperless-scheduler".to_string(),
        ],
        "dispatcharr" => vec![
            "dispatcharr".to_string(),
            "dispatcharr-celery".to_string(),
            "dispatcharr-celerybeat".to_string(),
        ],
        "novnc" => vec!["novnc".to_string(), "novnc-xvnc".to_string()],
        "xrdp" => vec!["xrdp".to_string(), "xrdp-sesman".to_string()],
        "prometheus" => vec!["prometheus".to_string(), "node_exporter".to_string()],
        "rclone" => vec!["rclone".to_string(), "rclone-vfs".to_string()],
        "scrutiny" => vec![
            "scrutiny".to_string(),
            "scrutiny-collector.timer".to_string(),
            "scrutiny-collector".to_string(),
        ],
        "recyclarr" => vec!["recyclarr.timer".to_string(), "recyclarr".to_string()],
        "piped" => vec![
            "af-piped".to_string(),
            "af-piped-api".to_string(),
            "af-piped-proxy".to_string(),
        ],
        "invidious" => vec![
            "af-invidious".to_string(),
            "af-invidious-companion".to_string(),
        ],
        "maintainerr" => vec!["af-maintainerr".to_string()],
        "palate" => vec!["af-palate".to_string()],
        "wireguard" => vec!["wg-quick@wg0".to_string()],
        "tailscale" => vec!["tailscaled".to_string()],
        "mysql" | "mariadb" => vec!["mariadb".to_string()],
        "nfs" | "nfs-server" | "nfs-kernel-server" => vec!["nfs-kernel-server".to_string()],
        "samba" | "smbd" => vec!["smbd".to_string()],
        _ => vec![clean],
    }
}

pub fn format_uptime_duration(dur: chrono::Duration) -> String {
    let total_secs = dur.num_seconds();
    if total_secs < 0 {
        return "Active".to_string();
    }
    let days = total_secs / 86_400;
    let hours = (total_secs % 86_400) / 3_600;
    let mins = (total_secs % 3_600) / 60;
    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else if mins > 0 {
        format!("{}m", mins)
    } else {
        "Just started".to_string()
    }
}

/// Formats systemd's `ActiveEnterTimestamp` string into a concise human-readable uptime (`service_manager.go`).
pub fn format_uptime(enter_timestamp: &str) -> String {
    let raw = enter_timestamp.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("n/a") {
        return "Active".to_string();
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return format_uptime_duration(Utc::now().signed_duration_since(dt.with_timezone(&Utc)));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(raw) {
        return format_uptime_duration(Utc::now().signed_duration_since(dt.with_timezone(&Utc)));
    }

    // systemd format: "Mon 2026-03-30 12:34:56 UTC" or "2026-03-30 12:34:56 UTC"
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let date_time_pair = if tokens.len() >= 3 && tokens[0].chars().all(|c| c.is_ascii_alphabetic()) {
        Some(format!("{} {}", tokens[1], tokens[2]))
    } else if tokens.len() >= 2 {
        Some(format!("{} {}", tokens[0], tokens[1]))
    } else {
        None
    };

    if let Some(pair) = date_time_pair {
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%.f"] {
            if let Ok(naive) = NaiveDateTime::parse_from_str(&pair, fmt) {
                let dt_utc = Utc.from_utc_datetime(&naive);
                return format_uptime_duration(Utc::now().signed_duration_since(dt_utc));
            }
        }
    }

    "Active".to_string()
}

/// Queries `systemctl show <unit> --property=ActiveState,SubState,ActiveEnterTimestamp`
/// with a short in-memory cache and graceful fallback on non-systemd platforms (`service_manager.go`).
pub fn get_service_info(service_name: &str) -> (String, String, String) {
    let (status, uptime, primary_unit, _components) = get_service_info_detailed(service_name);
    (status, uptime, primary_unit)
}

/// Query a concrete unit without expanding it into all companion units.
pub fn get_systemd_unit_info(unit: &str) -> (String, String, String) {
    get_systemd_units_info(vec![unit.to_string()], unit)
}

pub fn get_service_info_detailed(
    service_name: &str,
) -> (String, String, String, Vec<ServiceComponentStatus>) {
    let policies = resolve_service_component_policies(service_name);
    get_service_info_for_policies(service_name, policies)
}

fn get_service_info_for_policies(
    service_name: &str,
    policies: Vec<ServiceComponentPolicy>,
) -> (String, String, String, Vec<ServiceComponentStatus>) {
    service_info_from_observations(service_name, policies, |policy| {
        query_single_systemd_unit_status(&policy.unit, policy.role, policy.configured)
    })
}

fn service_info_from_observations(
    service_name: &str,
    policies: Vec<ServiceComponentPolicy>,
    mut observe: impl FnMut(&ServiceComponentPolicy) -> (String, String),
) -> (String, String, String, Vec<ServiceComponentStatus>) {
    if policies.is_empty() {
        return (
            "stopped".to_string(),
            "-".to_string(),
            service_name.to_string(),
            Vec::new(),
        );
    }

    let mut components = Vec::with_capacity(policies.len());
    let mut best_uptime = "-".to_string();

    for policy in &policies {
        let (unit_status, unit_uptime) = observe(policy);
        if matches!(policy.role, "required" | "timer")
            && unit_status == "running"
            && best_uptime == "-"
            && unit_uptime != "-"
        {
            best_uptime = unit_uptime;
        }
        components.push(ServiceComponentStatus {
            unit: policy.unit.clone(),
            role: policy.role.to_string(),
            status: unit_status,
            configured: policy.configured,
        });
    }

    let (agg_status, primary_unit) = aggregate_component_statuses(&components, service_name);
    let agg_uptime = match agg_status.as_str() {
        "running" | "degraded" => {
            if best_uptime == "-" {
                "Active".to_string()
            } else {
                best_uptime
            }
        }
        "restarting" => "Transitioning".to_string(),
        _ => "-".to_string(),
    };

    (agg_status, agg_uptime, primary_unit, components)
}

pub fn classify_systemd_unit_show_output(stdout: &str, role: &str) -> (String, String) {
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut enter_ts = String::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "ActiveState" => active_state = v.trim().to_lowercase(),
                "SubState" => sub_state = v.trim().to_lowercase(),
                "ActiveEnterTimestamp" => enter_ts = v.trim().to_string(),
                _ => {}
            }
        }
    }
    if active_state.is_empty() && sub_state.is_empty() {
        ("unknown".to_string(), "-".to_string())
    } else if active_state == "active"
        || matches!(
            sub_state.as_str(),
            "running" | "exited" | "listening" | "waiting" | "elapsed"
        )
    {
        ("running".to_string(), format_uptime(&enter_ts))
    } else if matches!(
        active_state.as_str(),
        "activating" | "deactivating" | "reloading"
    ) {
        ("restarting".to_string(), "Transitioning".to_string())
    } else if active_state == "failed" || sub_state == "failed" {
        ("failed".to_string(), "-".to_string())
    } else if role == "oneshot" && (active_state == "inactive" || sub_state == "dead") {
        ("idle".to_string(), "-".to_string())
    } else {
        ("stopped".to_string(), "-".to_string())
    }
}

fn query_single_systemd_unit_status(unit: &str, role: &str, configured: bool) -> (String, String) {
    query_systemd_unit_with_timeout(unit, role, configured, Duration::from_secs(2))
}

fn query_systemd_unit_with_timeout(
    unit: &str,
    role: &str,
    configured: bool,
    timeout: Duration,
) -> (String, String) {
    let epoch = SERVICE_STATUS_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    let cache_key = format!("unit:{}:{}:{}", unit, role, configured);
    let now = Instant::now();
    if let Ok(guard) = SERVICE_INFO_CACHE.read() {
        if let Some(((st, up, _), expires_at)) = guard.get(&cache_key) {
            if now < *expires_at {
                return (st.clone(), up.clone());
            }
        }
    }

    #[cfg(target_os = "linux")]
    let resolved = match status_command_output(
        "systemctl",
        &[
            "show",
            unit,
            "--property=ActiveState,SubState,ActiveEnterTimestamp",
        ],
        timeout,
    ) {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            classify_systemd_unit_show_output(&stdout, role)
        }
        _ => ("unknown".to_string(), "-".to_string()),
    };

    #[cfg(not(target_os = "linux"))]
    let resolved = if role == "oneshot" {
        ("idle".to_string(), "-".to_string())
    } else if role == "optional" && !configured {
        ("stopped".to_string(), "-".to_string())
    } else {
        ("running".to_string(), "Active".to_string())
    };

    if let Ok(mut guard) = SERVICE_INFO_CACHE.write() {
        if SERVICE_STATUS_EPOCH.load(std::sync::atomic::Ordering::Acquire) == epoch {
            guard.insert(
                cache_key,
                (
                    (resolved.0.clone(), resolved.1.clone(), unit.to_string()),
                    Instant::now() + Duration::from_secs(3),
                ),
            );
        }
    }
    resolved
}

fn status_command_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let program = program.to_string();
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        runtime.block_on(async_status_command_output(&program, &args, timeout))
    })
    .join()
    .map_err(|_| std::io::Error::other("service status command worker panicked"))?
}

async fn async_status_command_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(program);
    command.args(args);
    af_runner::bounded_command::output(command, timeout, 1024 * 1024).await
}

fn get_systemd_units_info(units: Vec<String>, service_name: &str) -> (String, String, String) {
    let primary_unit = units
        .first()
        .cloned()
        .unwrap_or_else(|| service_name.to_string());
    if units.is_empty() {
        return ("stopped".to_string(), "-".to_string(), primary_unit);
    }

    let mut any_running = false;
    let mut any_restarting = false;
    let mut best_uptime = "-".to_string();

    for unit in &units {
        let (status, uptime) = query_single_systemd_unit_status(unit, "required", true);
        if status == "unknown" {
            return (status, "-".to_string(), primary_unit);
        }
        if status == "running" {
            any_running = true;
            if best_uptime == "-" {
                best_uptime = uptime;
            }
        } else if status == "restarting" {
            any_restarting = true;
        }
    }

    if any_running {
        ("running".to_string(), best_uptime, primary_unit)
    } else if any_restarting {
        (
            "restarting".to_string(),
            "Transitioning".to_string(),
            primary_unit,
        )
    } else {
        ("stopped".to_string(), "-".to_string(), primary_unit)
    }
}

pub fn get_pm2_services() -> anyhow::Result<HashMap<String, (String, String)>> {
    get_pm2_services_with_timeout(Duration::from_secs(2))
}

fn get_pm2_services_with_timeout(
    timeout: Duration,
) -> anyhow::Result<HashMap<String, (String, String)>> {
    let epoch = SERVICE_STATUS_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    let now = Instant::now();
    if let Ok(cache) = PM2_SERVICES_CACHE.read() {
        if cache.1.is_some_and(|expires| now < expires) {
            return cache
                .0
                .clone()
                .ok_or_else(|| anyhow::anyhow!("PM2 inventory unavailable"));
        }
    }
    let result = (|| -> anyhow::Result<HashMap<String, (String, String)>> {
        let mut map = HashMap::new();
        #[cfg(target_os = "linux")]
        {
            let out = status_command_output("pm2", &["jlist"], timeout)?;
            anyhow::ensure!(out.status.success(), "PM2 inventory command failed");
            let entries: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)?;
            for item in entries {
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("PM2 process name missing"))?;
                let pm2_env = item.get("pm2_env");
                let raw_status = pm2_env
                    .and_then(|e| e.get("status"))
                    .and_then(|v| v.as_str());
                let status = match raw_status {
                    Some("online") => "running",
                    Some("launching" | "stopping" | "waiting restart") => "restarting",
                    Some("stopped" | "errored") => "stopped",
                    _ => "unknown",
                };
                let uptime = if status == "running" {
                    pm2_env
                        .and_then(|e| e.get("pm_uptime"))
                        .and_then(|v| v.as_i64())
                        .filter(|&ms| ms > 0 && Utc::now().timestamp_millis() >= ms)
                        .map(|ms| {
                            format_uptime_duration(chrono::Duration::milliseconds(
                                Utc::now().timestamp_millis() - ms,
                            ))
                        })
                        .unwrap_or_else(|| "Active".into())
                } else {
                    "-".into()
                };
                anyhow::ensure!(
                    map.insert(name.to_string(), (status.to_string(), uptime))
                        .is_none(),
                    "duplicate PM2 process name"
                );
            }
        }
        Ok(map)
    })();
    if let Ok(mut cache) = PM2_SERVICES_CACHE.write() {
        if SERVICE_STATUS_EPOCH.load(std::sync::atomic::Ordering::Acquire) == epoch {
            *cache = (
                result.as_ref().ok().cloned(),
                Some(Instant::now() + Duration::from_secs(3)),
            );
        }
    }
    result
}

pub fn get_pm2_service_info(service_name: &str) -> (String, String) {
    let map = match get_pm2_services() {
        Ok(map) => map,
        Err(_) => return ("unknown".into(), "-".into()),
    };
    pm2_service_info_from_observations(&map, service_name)
}

fn pm2_service_info_from_observations(
    map: &HashMap<String, (String, String)>,
    service_name: &str,
) -> (String, String) {
    if let Some(info) = map.get(service_name) {
        return info.clone();
    }
    for (k, v) in map {
        if k.eq_ignore_ascii_case(service_name) {
            return v.clone();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        return ("running".to_string(), "Active".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        ("stopped".to_string(), "-".to_string())
    }
}

/// Unknown lifecycle state is an error, never an empty inventory.
pub fn get_active_services() -> anyhow::Result<HashMap<String, ServiceStatusItem>> {
    get_active_services_with_jobs(&package_job_snapshot()?)
}

pub fn get_active_services_with_jobs(
    jobs: &PackageJobSnapshot,
) -> anyhow::Result<HashMap<String, ServiceStatusItem>> {
    let deadline = Instant::now() + service_observations::OBSERVATION_BUDGET;
    lifecycle_cache::observe(jobs);
    let mut pkgs = get_package_catalog()?;
    populate_package_statuses(&mut pkgs, jobs)?;
    let rclone_vfs_configured = is_rclone_vfs_configured();
    let included = |package: &Package| {
        package.status == "installed"
            || jobs.active.contains_key(&package.name)
            || jobs
                .outcomes
                .get(&package.name)
                .is_some_and(|outcome| outcome.status != "completed")
    };
    let mut policies = policies_for_units(
        CORE_SERVICE_IDS
            .iter()
            .map(|unit| unit.to_string())
            .collect(),
        rclone_vfs_configured,
    );
    let mut include_pm2 = false;
    for package in pkgs.iter().filter(|package| included(package)) {
        if package.service_type == "pm2" {
            include_pm2 = true;
        } else {
            policies.extend(policies_for_units(
                resolve_service_units_with_catalog(&package.name, &pkgs),
                rclone_vfs_configured,
            ));
        }
    }
    let metadata = pkgs
        .iter()
        .filter(|package| included(package))
        .map(|package| package.name.clone())
        .collect();
    let observations = service_observations::collect(policies, include_pm2, metadata, deadline);
    let mut map = HashMap::new();
    let core_info = |unit: &str| {
        let (status, uptime, process, _) = service_info_from_observations(
            unit,
            policies_for_units(vec![unit.to_string()], rclone_vfs_configured),
            |policy| observations.systemd(policy),
        );
        (status, uptime, process)
    };

    // 1. Core Systemd Services (`service_manager.go`: AetherFlow API, AetherFlow Frontend, Apache2 Web Server)
    let (_api_st, api_up, _api_unit) = core_info("aetherflow-api");
    map.insert(
        "AetherFlow API".to_string(),
        ServiceStatusItem {
            id: "aetherflow-api".to_string(),
            status: "running".to_string(),
            uptime: if api_up == "-" {
                "Active".to_string()
            } else {
                api_up
            },
            version: af_release::runtime::runtime_identity().version.clone(),
            managed_by: "systemd".to_string(),
            process: "aetherflow-api".to_string(),
            bind_scope: "network".to_string(),
            control_scope: "service".to_string(),
            components: vec![ServiceComponentStatus {
                unit: "aetherflow-api".to_string(),
                role: "required".to_string(),
                status: "running".to_string(),
                configured: true,
            }],
            units: vec!["aetherflow-api".to_string()],
            ..Default::default()
        },
    );

    let (fe_st, fe_up, _fe_unit) = core_info("aetherflow-frontend");
    let (fe_status, fe_uptime, fe_managed_by) = if matches!(fe_st.as_str(), "running" | "unknown") {
        (fe_st, fe_up, "systemd".to_string())
    } else {
        (
            "running".to_string(),
            "Integrated".to_string(),
            "embedded".to_string(),
        )
    };
    map.insert(
        "AetherFlow Frontend".to_string(),
        ServiceStatusItem {
            id: "aetherflow-frontend".to_string(),
            status: fe_status.clone(),
            uptime: fe_uptime,
            version: af_release::runtime::runtime_identity().version.clone(),
            managed_by: fe_managed_by,
            process: "aetherflow-frontend".to_string(),
            bind_scope: "network".to_string(),
            control_scope: "service".to_string(),
            components: vec![ServiceComponentStatus {
                unit: "aetherflow-frontend".to_string(),
                role: "required".to_string(),
                status: fe_status,
                configured: true,
            }],
            units: vec!["aetherflow-frontend".to_string()],
            ..Default::default()
        },
    );

    let (apache_st, apache_up, _apache_unit) = core_info("apache2");
    map.insert(
        "Apache2 Web Server".to_string(),
        ServiceStatusItem {
            id: "apache2".to_string(),
            status: apache_st.clone(),
            uptime: apache_up,
            version: "system".to_string(),
            managed_by: "systemd".to_string(),
            process: "apache2".to_string(),
            bind_scope: "network".to_string(),
            control_scope: "service".to_string(),
            components: vec![ServiceComponentStatus {
                unit: "apache2".to_string(),
                role: "required".to_string(),
                status: apache_st,
                configured: true,
            }],
            units: vec!["apache2".to_string()],
            ..Default::default()
        },
    );

    // 2. Installed & Active-Job Packages
    let ingress_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();
    let base_domain = resolve_base_domain();
    for p in &pkgs {
        let active_job = jobs.active.get(&p.name).cloned();
        if !included(p) {
            continue;
        }
        let svc_name = if p.service_name.is_empty() {
            p.name.clone()
        } else {
            p.service_name.clone()
        };
        let managed_by = if p.service_type == "pm2" {
            "pm2"
        } else {
            "systemd"
        };

        let units = if managed_by == "systemd" {
            resolve_service_units_with_catalog(&p.name, &pkgs)
        } else {
            vec![svc_name.clone()]
        };

        let (mut svc_status, mut svc_uptime, primary_proc, components) = if managed_by == "pm2" {
            let (st, up) = observations.pm2(&svc_name);
            (
                st.clone(),
                up,
                svc_name.clone(),
                vec![ServiceComponentStatus {
                    unit: svc_name.clone(),
                    role: "required".to_string(),
                    status: st,
                    configured: true,
                }],
            )
        } else {
            service_info_from_observations(
                &p.name,
                policies_for_units(units.clone(), rclone_vfs_configured),
                |policy| observations.systemd(policy),
            )
        };

        let mut job_id = String::new();
        let mut job_status = String::new();
        let mut progress = 0;
        let mut log_line = String::new();
        let mut started_at = String::new();
        if let Some(job) = active_job {
            job_id = job.job_id;
            job_status = job.status.clone();
            progress = job.progress;
            log_line = job.last_line;
            started_at = job.started_at;
            if p.status != "installed" {
                svc_status = job.status;
                svc_uptime = "In progress".to_string();
            }
        }

        let runtime_meta = observations.runtime_meta(&p.name);
        let ing = ingress_map.get(&p.name);
        let mut active_port = ing
            .map(|c| c.listen_port)
            .filter(|&port| port > 0)
            .unwrap_or(0);
        if active_port <= 0 && runtime_meta.configured_port > 0 {
            active_port = runtime_meta.configured_port;
        }
        if active_port <= 0 && p.default_port > 0 {
            active_port = p.default_port;
        }

        let internal_domain = format!("{}.aether.local", p.name.trim().to_lowercase());

        let mut public_domain = ing
            .map(|c| c.public_domain.clone())
            .unwrap_or_default();
        if public_domain.is_empty() && !base_domain.is_empty() && active_port > 0 {
            public_domain = format_app_public_domain(&p.name, &base_domain);
        }

        let external_access_enabled = ing
            .map(|c| c.external_access_enabled)
            .unwrap_or(!public_domain.is_empty());
        let tls_enabled = ing
            .map(|c| c.tls_enabled)
            .unwrap_or(!public_domain.is_empty());

        // An absent measurement remains unknown; it is not evidence of latest.
        let version = p.installed_version.clone();
        let web_scheme =
            service_web_scheme_for_id(&p.name, active_port.max(p.default_port)).to_string();
        let bind_scope = service_bind_scope_for_id(&p.name).to_string();
        let control_scope = service_control_scope_for_id(&p.name).to_string();

        let display_name = p.label_or_name();
        anyhow::ensure!(
            !map.contains_key(&display_name),
            "duplicate service inventory label: {display_name}"
        );
        map.insert(
            display_name,
            ServiceStatusItem {
                id: p.name.clone(),
                status: svc_status,
                uptime: svc_uptime,
                version,
                managed_by: managed_by.to_string(),
                process: if primary_proc.is_empty() {
                    svc_name
                } else {
                    primary_proc
                },
                default_port: p.default_port,
                active_port,
                api_key: runtime_meta.api_key,
                internal_domain,
                public_domain,
                external_access_enabled,
                tls_enabled,
                web_path: p.web_path.clone(),
                web_scheme,
                bind_scope,
                control_scope,
                components,
                units,
                installed_version: p.installed_version.clone(),
                latest_version: p.latest_version.clone(),
                update_available: p.update_available,
                update_checked_at: p.update_checked_at.clone(),
                update_url: p.update_url.clone(),
                update_error: p.update_error.clone(),
                job_id,
                job_status,
                progress,
                log_line,
                started_at,
                last_job: jobs.outcomes.get(&p.name).cloned(),
            },
        );
    }
    Ok(map)
}

trait PackageExt {
    fn label_or_name(&self) -> String;
}

impl PackageExt for Package {
    fn label_or_name(&self) -> String {
        if !self.label.is_empty() {
            self.label.clone()
        } else {
            self.name.clone()
        }
    }
}

#[cfg(unix)]
const RUNNER_SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(45);

#[cfg(unix)]
async fn dispatch_runner_systemctl_unix(action: &str, unit: &str) -> Option<anyhow::Result<()>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let sock_path = af_runner::runner_socket_path();
    if !Path::new(&sock_path).exists() {
        return None;
    }
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&sock_path)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

    let body = serde_json::to_string(&af_models::SystemctlRequest {
        action: action.to_string(),
        service: unit.to_string(),
        lifecycle_job_id: af_runner::current_package_job_id(),
    })
    .ok()?;
    let req = format!(
        "POST /v1/systemctl HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    match tokio::time::timeout(Duration::from_secs(5), stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Some(Err(anyhow::Error::from(error).context(
                "runner request transmission failed; service state is unconfirmed",
            )))
        }
        Err(_) => {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "runner request transmission timed out; service state is unconfirmed",
            )
            .into()))
        }
    }

    let mut resp = String::new();
    match tokio::time::timeout(
        RUNNER_SYSTEMCTL_TIMEOUT,
        stream.take(1024 * 1024 + 1).read_to_string(&mut resp),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Some(Err(anyhow::anyhow!(
                "runner socket read error for systemctl {} {}: {}",
                action,
                unit,
                e
            )));
        }
        Err(_) => {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("runner socket timed out after {}s waiting for systemctl {} {}; resulting state is unconfirmed", RUNNER_SYSTEMCTL_TIMEOUT.as_secs(), action, unit),
            ).into()));
        }
    }

    Some(validate_runner_systemctl_response(&resp))
}

#[cfg(unix)]
fn validate_runner_systemctl_response(response: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.len() <= 1024 * 1024,
        "runner response exceeds acknowledgement limit; service state is unconfirmed"
    );
    let (headers, json_body) = response.split_once("\r\n\r\n").ok_or_else(|| {
        anyhow::anyhow!("malformed runner response; service state is unconfirmed")
    })?;
    let mut lines = headers.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().split_whitespace();
    anyhow::ensure!(
        matches!(status_line.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "invalid runner HTTP version; service state is unconfirmed"
    );
    let status = status_line.next().unwrap_or_default();
    anyhow::ensure!(
        status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid runner HTTP status; service state is unconfirmed"
    );
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("malformed runner header; service state is unconfirmed")
        })?;
        anyhow::ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "unsupported runner acknowledgement framing; service state is unconfirmed"
        );
        if name.eq_ignore_ascii_case("content-length") {
            anyhow::ensure!(
                content_length.is_none(),
                "duplicate runner content length; service state is unconfirmed"
            );
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }
    anyhow::ensure!(
        content_length == Some(json_body.len()),
        "missing or incomplete runner acknowledgement body; service state is unconfirmed"
    );
    if status == "504" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "runner service control timed out; resulting state is unconfirmed",
        )
        .into());
    }
    if status == "409" {
        return Err(af_runner::LifecycleBusy.into());
    }
    let parsed: af_models::RunnerResponse = serde_json::from_str(json_body).map_err(|error| {
        anyhow::anyhow!("invalid runner acknowledgement; service state is unconfirmed: {error}")
    })?;
    anyhow::ensure!(
        status == "200" && parsed.success && parsed.error.trim().is_empty(),
        "runner service control refused (HTTP {}): {} {}",
        status,
        parsed.error.trim(),
        parsed.output.trim()
    );
    Ok(())
}

fn guarded_service_command(
    guard: &af_release::ReleaseLockGuard,
    program: &str,
    arguments: &[&str],
) -> anyhow::Result<Command> {
    #[cfg(unix)]
    {
        let mut command = Command::new("/bin/bash");
        command
            .args([
                "-c",
                "(exec {AF_MAINTENANCE_GUARD_FD}>&-; exec \"$@\"); result=$?; exit \"$result\"",
                "af-service-control",
            ])
            .arg(program)
            .args(arguments);
        let descriptor = guard.preserve_in_child(command.as_std_mut())?;
        command.env("AF_MAINTENANCE_GUARD_FD", descriptor.to_string());
        Ok(command)
    }
    #[cfg(not(unix))]
    {
        let _ = guard;
        let mut command = Command::new(program);
        command.args(arguments);
        Ok(command)
    }
}

const SERVICE_CONTROL_BUDGET: Duration = Duration::from_secs(20);

pub fn is_service_control_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
    })
}

async fn service_command_output(
    command: Command,
    budget: Duration,
) -> std::io::Result<std::process::Output> {
    let result = af_runner::bounded_command::output(command, budget, 1024 * 1024).await;
    clear_service_status_cache();
    result
}

pub async fn control_service_with_manager(
    service_name: &str,
    action: &str,
    managed_by: &str,
) -> anyhow::Result<()> {
    control_service_with_budget(service_name, action, managed_by, SERVICE_CONTROL_BUDGET).await
}

async fn control_service_with_budget(
    service_name: &str,
    action: &str,
    managed_by: &str,
    budget: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + budget;
    let valid_name = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap();
    if !valid_name.is_match(service_name) {
        anyhow::bail!("invalid service name: {}", service_name);
    }
    if !matches!(action, "start" | "stop" | "restart" | "reload" | "status") {
        anyhow::bail!("disallowed action: {}", action);
    }

    if managed_by.eq_ignore_ascii_case("pm2") {
        let _guard = af_runner::acquire_service_maintenance_guard(service_name, action).await?;
        let command = guarded_service_command(&_guard, "pm2", &[action, service_name])?;
        let out =
            service_command_output(command, deadline.saturating_duration_since(Instant::now()))
                .await?;
        clear_service_status_cache();
        if out.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "pm2 {} {} failed: {}",
            action,
            service_name,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let units = if managed_by == "systemd-unit" {
        vec![service_name.to_string()]
    } else {
        let canonical = resolve_canonical_service_id(service_name);
        if resolve_service_control_scope(&canonical) == "shared-vhost" {
            anyhow::bail!(
                "{} is hosted as a shared Apache virtual host; use the Apache2 Web Server card for daemon-wide controls",
                service_name
            );
        }
        resolve_controllable_service_units(&canonical, action)
    };
    for unit in units {
        if !valid_name.is_match(&unit) {
            anyhow::bail!("invalid resolved unit name: {}", unit);
        }

        #[cfg(unix)]
        match dispatch_runner_systemctl_unix(action, &unit).await {
            Some(Ok(())) => continue,
            Some(Err(err_msg)) => {
                clear_service_status_cache();
                let detail = format!("systemctl {} {} failed: {}", action, unit, err_msg);
                return Err(err_msg.context(detail));
            }
            None => {}
        }

        let _guard = af_runner::acquire_service_maintenance_guard(&unit, action).await?;
        let command =
            guarded_service_command(&_guard, "sudo", &["-n", "systemctl", action, "--", &unit])?;
        let out =
            service_command_output(command, deadline.saturating_duration_since(Instant::now()))
                .await;
        match out {
            Ok(o) if o.status.success() => continue,
            // Timeout/output overflow is an unconfirmed mutation, not permission
            // failure. Do not execute the same action again through fallback.
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {
                let command =
                    guarded_service_command(&_guard, "systemctl", &[action, "--", &unit])?;
                let direct = service_command_output(
                    command,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                if !direct.status.success() {
                    clear_service_status_cache();
                    anyhow::bail!(
                        "systemctl {} {} failed: {}",
                        action,
                        unit,
                        String::from_utf8_lossy(&direct.stderr)
                    );
                }
            }
        }
    }

    clear_service_status_cache();
    Ok(())
}

pub async fn control_service(service_name: &str, action: &str) -> anyhow::Result<()> {
    let managed_by = get_package_catalog()
        .unwrap_or_default()
        .into_iter()
        .find(|p| {
            p.name.eq_ignore_ascii_case(service_name)
                || p.service_name.eq_ignore_ascii_case(service_name)
        })
        .map(|p| {
            if p.service_type == "pm2" {
                "pm2".to_string()
            } else {
                "systemd".to_string()
            }
        })
        .unwrap_or_else(|| "systemd".to_string());

    control_service_with_manager(service_name, action, &managed_by).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming Telemetry Monitor (`backend/services/streaming_monitor.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamingLibraryCounts {
    pub movies: i32,
    pub series: i32,
    pub episodes: i32,
    pub audio: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingServerStatus {
    pub provider: String,
    pub name: String,
    pub url: String,
    pub api_key_masked: String,
    pub configured: bool,
    pub enabled: bool,
    pub status: String,
    pub support_stage: String,
    pub server_id: String,
    pub version: String,
    pub operating_system: String,
    pub last_connected_at: String,
    pub library_counts: StreamingLibraryCounts,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActiveStreamSession {
    pub session_id: String,
    pub provider: String,
    pub server_name: String,
    pub user_id: String,
    pub user_name: String,
    pub client_name: String,
    pub device_name: String,
    pub device_id: String,
    pub app_version: String,
    pub ip_address: String,
    pub is_lan: bool,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_id: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub season_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub episode_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub has_artwork: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub artwork_item_id: String,
    pub state: String,
    pub position_secs: i64,
    pub duration_secs: i64,
    pub progress_pct: f64,
    pub play_method: String,
    pub container: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_container: String,
    pub video_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_video_codec: String,
    pub video_resolution: String,
    pub video_range: String,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub video_framerate: f64,
    pub is_video_direct: bool,
    pub audio_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_audio_codec: String,
    pub audio_channels: i32,
    pub audio_layout: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub audio_language: String,
    pub is_audio_direct: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subtitle_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subtitle_language: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hw_accel: String,
    #[serde(default)]
    pub transcode_reasons: Vec<String>,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub transcode_progress_pct: f64,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub transcode_fps: f64,
    pub bitrate_bps: i64,
    pub bandwidth_mbps: f64,
    pub session_data_bytes: i64,
    pub started_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub play_session_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub media_source_id: String,
    pub supports_media_control: bool,
    pub supports_remote_control: bool,
    pub can_send_message: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub supported_commands: Vec<String>,
}

fn is_zero_f64(val: &f64) -> bool {
    *val == 0.0
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingLiveSummary {
    pub active_streams: i32,
    pub direct_play_count: i32,
    pub direct_stream_count: i32,
    pub transcode_count: i32,
    pub total_bitrate_bps: i64,
    pub total_bandwidth_mbps: f64,
    pub active_session_bytes: i64,
    pub lan_streams: i32,
    pub wan_streams: i32,
    pub is_demo_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamTypeDistribution {
    pub direct_play_count: i32,
    pub direct_play_pct: f64,
    pub direct_stream_count: i32,
    pub direct_stream_pct: f64,
    pub transcode_count: i32,
    pub transcode_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BreakdownEntry {
    pub label: String,
    pub count: i32,
    pub pct: f64,
    pub watch_time_secs: i64,
    pub data_used_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingTimeSeriesPoint {
    pub date: String,
    pub plays: i32,
    pub watch_time_secs: i64,
    pub data_used_bytes: i64,
    pub peak_bandwidth_mbps: f64,
    pub direct_play_count: i32,
    pub direct_stream_count: i32,
    pub transcode_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingUserStat {
    pub user_id: String,
    pub user_name: String,
    pub provider: String,
    pub total_plays: i32,
    pub total_watch_secs: i64,
    pub total_data_bytes: i64,
    pub unique_items: i32,
    pub direct_play_count: i32,
    pub transcode_count: i32,
    pub avg_completion_pct: f64,
    pub last_device: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingTitleStat {
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub provider: String,
    pub video_resolution: String,
    pub video_codec: String,
    pub total_plays: i32,
    pub unique_viewers: i32,
    pub total_watch_secs: i64,
    pub total_data_bytes: i64,
    pub avg_completion_pct: f64,
    pub last_watched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingHistoryItem {
    pub id: i64,
    pub session_key: String,
    pub provider: String,
    pub server_name: String,
    pub user_name: String,
    pub client_name: String,
    pub device_name: String,
    pub ip_address: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub season_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub episode_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub play_method: String,
    pub container: String,
    pub video_codec: String,
    pub video_resolution: String,
    pub audio_codec: String,
    pub audio_channels: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hw_accel: String,
    pub bitrate_bps: i64,
    pub bandwidth_mbps: f64,
    pub duration_secs: i64,
    pub watched_secs: i64,
    pub data_used_bytes: i64,
    pub completion_pct: f64,
    pub started_at: String,
    pub last_seen_at: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingHistoryEstimate {
    pub provenance: String,
    pub records: i64,
    pub reported_watch_time_secs: i64,
    pub undated_records: i64,
    pub time_series: Vec<StreamingTimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingAnalytics {
    pub window_days: i32,
    pub total_plays: i32,
    pub total_watch_time_secs: i64,
    pub total_data_used_bytes: i64,
    pub unique_users: i32,
    pub unique_titles: i32,
    pub avg_completion_pct: f64,
    pub peak_bandwidth_mbps: f64,
    pub stream_types: StreamTypeDistribution,
    pub media_type_breakdown: Vec<BreakdownEntry>,
    pub resolution_breakdown: Vec<BreakdownEntry>,
    pub codec_breakdown: Vec<BreakdownEntry>,
    #[serde(default)]
    pub time_series_granularity: String,
    pub time_series: Vec<StreamingTimeSeriesPoint>,
    pub top_users: Vec<StreamingUserStat>,
    pub top_titles: Vec<StreamingTitleStat>,
    pub recent_history: Vec<StreamingHistoryItem>,
    #[serde(default)]
    pub historical_estimates: Vec<StreamingHistoryEstimate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingDashboardResponse {
    pub servers: Vec<StreamingServerStatus>,
    pub live_summary: StreamingLiveSummary,
    pub active_sessions: Vec<ActiveStreamSession>,
    pub analytics: StreamingAnalytics,
    pub updated_at: String,
}

static DEMO_STREAMING_MODE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn set_streaming_demo_mode(enabled: bool) {
    if let Ok(mut guard) = DEMO_STREAMING_MODE.lock() {
        *guard = enabled;
    }
}

pub fn is_streaming_demo_mode() -> bool {
    DEMO_STREAMING_MODE.lock().map(|guard| *guard).unwrap_or(false)
}

pub fn get_streaming_dashboard(window_days: i32, is_admin: bool) -> StreamingDashboardResponse {
    let demo_mode = is_streaming_demo_mode();
    let mut jellyfin_server = StreamingServerStatus {
        provider: "jellyfin".to_string(),
        name: "Jellyfin".to_string(),
        url: "http://127.0.0.1:8096".to_string(),
        api_key_masked: String::new(),
        configured: false,
        enabled: true,
        status: if demo_mode {
            "demo".to_string()
        } else {
            "unconfigured".to_string()
        },
        support_stage: "active".to_string(),
        server_id: String::new(),
        version: String::new(),
        operating_system: "Linux".to_string(),
        last_connected_at: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        error_message: String::new(),
    };

    if let Ok(conn) = af_db::get_conn() {
        if let Ok((name, url, api_key, enabled, srv_id, srv_ver, last_conn)) = conn.query_row(
            "SELECT name, url, api_key, enabled, COALESCE(server_id, ''), COALESCE(server_version, ''), COALESCE(CAST(last_connected_at AS TEXT), '') \
             FROM streaming_servers WHERE provider = 'jellyfin'",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            },
        ) {
            jellyfin_server.name = name;
            jellyfin_server.url = url;
            jellyfin_server.enabled = enabled;
            jellyfin_server.server_id = srv_id;
            jellyfin_server.version = srv_ver;
            jellyfin_server.last_connected_at = last_conn;
            let decrypted = af_db::decrypt_key(&api_key).unwrap_or(api_key);
            if !decrypted.is_empty() {
                jellyfin_server.configured = true;
                if is_admin {
                    let tail: String = decrypted
                        .chars()
                        .rev()
                        .take(4)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    jellyfin_server.api_key_masked = format!("****{}", tail);
                }
                if jellyfin_server.status == "unconfigured" {
                    jellyfin_server.status = "connected".to_string();
                }
            }
        }
    }

    let plex_server = StreamingServerStatus {
        provider: "plex".to_string(),
        name: "Plex Media Server".to_string(),
        url: "http://127.0.0.1:32400".to_string(),
        status: "coming_soon".to_string(),
        support_stage: "coming_soon".to_string(),
        ..Default::default()
    };

    let emby_server = StreamingServerStatus {
        provider: "emby".to_string(),
        name: "Emby Server".to_string(),
        url: "http://127.0.0.1:8096".to_string(),
        status: "coming_soon".to_string(),
        support_stage: "coming_soon".to_string(),
        ..Default::default()
    };

    StreamingDashboardResponse {
        servers: vec![jellyfin_server, plex_server, emby_server],
        live_summary: StreamingLiveSummary {
            is_demo_mode: demo_mode,
            ..Default::default()
        },
        active_sessions: Vec::new(),
        analytics: StreamingAnalytics {
            window_days: window_days.max(1),
            ..Default::default()
        },
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub fn validate_server_url(raw_url: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(raw_url.trim())
        .map_err(|_| anyhow::anyhow!("Invalid server URL format"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        anyhow::bail!("URL scheme must be http or https");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("URL must not contain credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("URL must not include query parameters or fragments");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL host is required"))?
        .to_lowercase();
    if host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(forbidden_streaming_ip)
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
        || host == "metadata.goog"
        || host == "instance-data"
    {
        anyhow::bail!("Disallowed target host");
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn forbidden_streaming_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => address.is_unspecified() || address.is_link_local(),
        std::net::IpAddr::V6(address) => {
            address.to_ipv4_mapped().map(|mapped| forbidden_streaming_ip(mapped.into())).unwrap_or_else(|| {
                address.is_unspecified() || address.is_unicast_link_local()
                    || address.segments()[..2] == [0xfd00, 0x0ec2]
            })
        }
    }
}

struct StreamingResolver;

impl reqwest::dns::Resolve for StreamingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let hostname = name.as_str().to_string();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((hostname.as_str(), 0)).await?.collect();
            if addresses.is_empty() || addresses.iter().any(|address| forbidden_streaming_ip(address.ip())) {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Disallowed resolved media-server address").into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub fn streaming_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(StreamingResolver))
}

// ─────────────────────────────────────────────────────────────────────────────
// Notifications & Rules (`backend/services/notifications.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Notification {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<i64>,
    pub level: String,
    pub title: String,
    pub message: String,
    pub read: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationRule {
    pub id: i64,
    pub name: String,
    pub condition_type: String,
    pub condition_value: String,
    pub level: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationChannel {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
}

pub fn list_notifications(
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<Notification>, i64)> {
    let conn = af_db::get_conn()?;
    let unread: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE (user_id = ?1 OR user_id IS NULL) AND read = 0",
            params![user_id],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let mut stmt = conn.prepare(
        "SELECT id, user_id, level, title, message, read, COALESCE(CAST(created_at AS TEXT), '') \
         FROM notifications WHERE (user_id = ?1 OR user_id IS NULL) \
         ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt.query_map(params![user_id, limit.clamp(1, 200), offset.max(0)], |r| {
        Ok(Notification {
            id: r.get(0)?,
            user_id: r.get(1)?,
            level: r.get(2)?,
            title: r.get(3)?,
            message: r.get(4)?,
            read: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;

    let mut list = Vec::new();
    for r in rows {
        list.push(r?);
    }
    Ok((list, unread))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn local_service_guardian_outlives_parent_guard_without_leaking_into_daemon() {
        use tokio::io::AsyncReadExt;
        let root = env::temp_dir().join(format!("af-service-guardian-{}", uuid::Uuid::new_v4()));
        let path = root.join("maintenance.lock");
        let guard =
            af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).unwrap();
        let mut command = guarded_service_command(&guard, "/bin/sh", &[
            "-c", "test ! -e /proc/self/fd/\"$AF_MAINTENANCE_GUARD_FD\" || exit 92; printf ready; /bin/cat",
        ]).unwrap();
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        drop(command);
        let mut ready = [0u8; 5];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .await
            .unwrap();
        assert_eq!(&ready, b"ready");
        drop(guard);
        assert!(af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).is_err());
        drop(child.stdin.take());
        assert!(child.wait().await.unwrap().success());
        drop(af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_marketplace_service_units_include_companions_and_exact_names() {
        for (package, expected) in [
            ("mcvnc", vec!["af-mcvnc"]),
            ("kasmvnc", vec!["af-kasmvnc"]),
            ("qbittorrent", vec!["qbittorrent"]),
            ("prometheus", vec!["prometheus", "node_exporter"]),
            ("recyclarr", vec!["recyclarr", "recyclarr.timer"]),
            ("rclone", vec!["rclone", "rclone-vfs"]),
        ] {
            assert_eq!(resolve_service_units(package), expected, "{}", package);
        }
        for (package, companion) in [
            ("scrutiny", "scrutiny-collector.timer"),
            ("paperless-ngx", "paperless-worker"),
            ("dispatcharr", "dispatcharr-celerybeat"),
        ] {
            let units = resolve_service_units(package);
            assert!(units.iter().any(|unit| unit == companion));
            assert_eq!(resolve_service_units(companion), units);
        }
    }

    #[test]
    fn test_duplicate_lifecycle_job_is_rejected_atomically() {
        let job = PackageJobInfo {
            job_id: uuid::Uuid::new_v4().to_string(),
            package_id: "jellyfin".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 0,
            last_line: String::new(),
            started_at: String::new(),
        };
        assert!(try_start_package_job(job.clone()));
        assert!(!try_start_package_job(job.clone()));
        clear_package_job_info(&job.package_id);
        assert!(try_start_package_job(job.clone()));
        clear_package_job_info(&job.package_id);
    }

    #[test]
    fn test_streaming_demo_mode_predicate() {
        let previous = is_streaming_demo_mode();
        set_streaming_demo_mode(true);
        assert!(is_streaming_demo_mode());
        set_streaming_demo_mode(false);
        assert!(!is_streaming_demo_mode());
        set_streaming_demo_mode(previous);
    }

    #[test]
    fn test_internal_domains_are_derived_from_blueprints() {
        let blueprint = get_blueprint("jellyfin").unwrap();
        assert_eq!(resolve_app_internal_domain("jellyfin"), blueprint.internal_domain);
        assert_eq!(
            resolve_app_internal_domain("unknown-audit-app"),
            "unknown-audit-app.aether.local"
        );
    }

    #[test]
    fn test_embedded_package_catalog_loads_all_apps() {
        let catalog = get_package_catalog().unwrap();
        assert!(catalog.len() >= 75);
        assert!(catalog.iter().any(|p| p.name == "jellyfin"));
        assert!(catalog.iter().any(|p| p.name == "kasmvnc"));
        assert!(catalog.iter().any(|p| p.name == "mcvnc"));
        assert!(catalog.iter().any(|p| p.name == "xrdp"));
        assert!(catalog.iter().any(|p| p.name == "tailscale"));
        let palate = catalog
            .iter()
            .find(|p| p.name == "palate")
            .expect("palate catalog entry");
        assert_eq!(palate.service_name, "af-palate");
        assert_eq!(palate.default_port, 28014);
        assert_eq!(palate.update_source, "git_tags");
        assert_eq!(palate.update_repo, "McEveritts/Palate");
        assert_eq!(palate.sandbox_profile, "node");
        let palate_bp = get_blueprint("palate").expect("palate blueprint");
        assert_eq!(palate_bp.health_check_path, "/login");
        assert_eq!(palate_bp.dependencies, vec!["jellyfin".to_string()]);
        let ts_bp = get_blueprint("tailscale").expect("tailscale blueprint");
        assert_eq!(ts_bp.service_name, "tailscaled");
        assert!(ts_bp.is_network_app);
    }

    #[test]
    fn test_maintainerr_catalog_and_blueprint() {
        let catalog = get_package_catalog().unwrap();
        let maintainerr = catalog
            .iter()
            .find(|package| package.name == "maintainerr")
            .expect("maintainerr catalog entry");
        assert_eq!(maintainerr.service_name, "af-maintainerr");
        assert_eq!(maintainerr.default_port, 6246);
        assert_eq!(maintainerr.update_source, "github");
        assert_eq!(maintainerr.update_repo, "Maintainerr/Maintainerr");
        assert_eq!(maintainerr.sandbox_profile, "node");
        assert_eq!(
            maintainerr.version_command,
            vec!["cat", "/opt/maintainerr/.af-version"]
        );
        assert!(maintainerr
            .sandbox_read_write
            .iter()
            .any(|path| path == "/var/lib/maintainerr"));
        let blueprint = get_blueprint("maintainerr").expect("maintainerr blueprint");
        assert_eq!(blueprint.port_env_var, "UI_PORT");
        assert_eq!(blueprint.health_check_path, "/api/health/ready");
        assert!(blueprint.dependencies.is_empty());
        assert_eq!(resolve_service_units("maintainerr"), vec!["af-maintainerr"]);
        assert!(!should_pre_stop_on_update("maintainerr"));
        assert!(!should_pre_stop_on_update("af-maintainerr"));
        assert!(!should_pre_stop_on_update("af-maintainerr.service"));
        assert!(should_pre_stop_on_update("radarr"));
        assert!(should_pre_stop_on_update("jellyfin"));
    }

    #[test]
    fn test_embedded_youtube_marketplace_contracts() {
        let catalog: Vec<Package> = serde_json::from_str(EMBEDDED_PACKAGES_JSON).unwrap();
        let automation: HashMap<String, PackageAutomation> =
            serde_json::from_str(EMBEDDED_AUTOMATION_JSON).unwrap();
        for (app, port, units) in [
            (
                "piped",
                8280,
                vec![
                    "af-piped.service",
                    "af-piped-api.service",
                    "af-piped-proxy.service",
                ],
            ),
            (
                "invidious",
                8281,
                vec!["af-invidious.service", "af-invidious-companion.service"],
            ),
        ] {
            let package = catalog.iter().find(|package| package.name == app).unwrap();
            assert_eq!(package.default_port, port);
            assert_eq!(package.category, "Media");
            assert_eq!(package.service_name, format!("af-{app}"));
            let tracking = automation.get(app).unwrap();
            assert_eq!(tracking.update_source, "git");
            assert_eq!(
                tracking.version_command,
                vec!["cat".to_string(), format!("/opt/{app}/.af-version")]
            );
            assert_eq!(tracking.sandbox_service_ids, units);
        }
    }

    #[test]
    fn test_validate_server_url_blocks_ssrf() {
        assert!(validate_server_url("http://127.0.0.1:8096").is_ok());
        assert!(validate_server_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_server_url("http://metadata.google.internal").is_err());
    }

    #[test]
    fn test_resolve_service_units_and_format_uptime() {
        assert_eq!(
            resolve_service_units("deluge"),
            vec!["deluged".to_string(), "deluge-web".to_string()]
        );
        assert_eq!(
            resolve_service_units("plex"),
            vec!["plexmediaserver".to_string()]
        );
        assert_eq!(
            format_uptime_duration(chrono::Duration::seconds(90_060)),
            "1d 1h"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_runner_systemctl_propagates_runner_error_without_unprivileged_fallback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let sock_name = format!("af-services-runner-test-{}.sock", std::process::id());
        let candidate = std::env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(&sock_name);
        let sock_path = if candidate.as_os_str().len() < 95 {
            candidate
        } else {
            std::path::PathBuf::from("/tmp").join(sock_name)
        };
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();

        let prev = std::env::var("AETHERFLOW_RUNNER_SOCK").ok();
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            let body = r#"{"success":false,"output":"Job for jellyfin.service canceled.","error":"exit status: 1"}"#;
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });

        let err = control_service_with_manager("jellyfin", "restart", "systemd")
            .await
            .expect_err("expected runner failure to be returned directly");
        server.await.unwrap();

        match prev {
            Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
            None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
        }
        let _ = std::fs::remove_file(&sock_path);

        let msg = err.to_string();
        assert!(
            msg.contains("Job for jellyfin.service canceled"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn test_service_capabilities_and_scopes() {
        for app in ["maintainerr", "palate", "kasmvnc", "mcvnc"] {
            assert_eq!(
                resolve_service_bind_scope(app),
                "loopback",
                "expected loopback for {}",
                app
            );
        }
        assert_eq!(resolve_service_bind_scope("radarr"), "network");
        assert_eq!(resolve_service_web_scheme("kasmvnc", 6081), "http");
        assert_eq!(resolve_service_web_scheme("radarr", 7878), "http");

        for app in [
            "nextcloud",
            "rutorrent",
            "organizr",
            "Nextcloud",
            "ruTorrent",
            "Organizr",
        ] {
            assert_eq!(resolve_service_control_scope(app), "shared-vhost");
            assert!(!should_pre_stop_on_update(app));
        }
        assert_eq!(resolve_service_control_scope("apache2"), "service");
        assert_eq!(
            resolve_service_control_scope("Apache2 Web Server"),
            "service"
        );
        assert!(!should_pre_stop_on_update("maintainerr"));
        assert!(should_pre_stop_on_update("radarr"));
    }

    #[test]
    fn test_component_policies_and_status_aggregation() {
        let autobrr_unconfigured = resolve_service_component_policies_with("rclone", false);
        assert_eq!(autobrr_unconfigured.len(), 2);
        assert_eq!(autobrr_unconfigured[0].unit, "rclone");
        assert_eq!(autobrr_unconfigured[0].role, "required");
        assert!(autobrr_unconfigured[0].configured);
        assert_eq!(autobrr_unconfigured[1].unit, "rclone-vfs");
        assert_eq!(autobrr_unconfigured[1].role, "optional");
        assert!(!autobrr_unconfigured[1].configured);

        assert_eq!(
            resolve_controllable_service_units_with("rclone", "restart", false),
            vec!["rclone".to_string()]
        );
        assert_eq!(
            resolve_controllable_service_units_with("rclone", "restart", true),
            vec!["rclone".to_string(), "rclone-vfs".to_string()]
        );

        let recyclarr_policies = resolve_service_component_policies_with("recyclarr", false);
        assert_eq!(recyclarr_policies[0].unit, "recyclarr");
        assert_eq!(recyclarr_policies[0].role, "oneshot");
        assert_eq!(recyclarr_policies[1].unit, "recyclarr.timer");
        assert_eq!(recyclarr_policies[1].role, "timer");
        assert_eq!(
            resolve_controllable_service_units_with("recyclarr", "start", false),
            vec!["recyclarr.timer".to_string()]
        );
        assert_eq!(
            resolve_controllable_service_units_with("recyclarr", "stop", false),
            vec!["recyclarr.timer".to_string(), "recyclarr".to_string()]
        );

        let autobrr_components = vec![
            ServiceComponentStatus {
                unit: "rclone".to_string(),
                role: "required".to_string(),
                status: "running".to_string(),
                configured: true,
            },
            ServiceComponentStatus {
                unit: "rclone-vfs".to_string(),
                role: "optional".to_string(),
                status: "stopped".to_string(),
                configured: false,
            },
        ];
        assert_eq!(
            aggregate_component_statuses(&autobrr_components, "rclone"),
            ("running".to_string(), "rclone".to_string())
        );

        let mut configured_mount_components = autobrr_components.clone();
        configured_mount_components[1].configured = true;
        assert_eq!(
            aggregate_component_statuses(&configured_mount_components, "rclone").0,
            "degraded"
        );

        let wire = serde_json::to_value(ServiceStatusItem {
            tls_enabled: false,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(wire["tls_enabled"], false);

        let scrutiny_components = vec![
            ServiceComponentStatus {
                unit: "scrutiny".to_string(),
                role: "required".to_string(),
                status: "running".to_string(),
                configured: true,
            },
            ServiceComponentStatus {
                unit: "scrutiny-collector.timer".to_string(),
                role: "timer".to_string(),
                status: "running".to_string(),
                configured: true,
            },
            ServiceComponentStatus {
                unit: "scrutiny-collector.service".to_string(),
                role: "oneshot".to_string(),
                status: "stopped".to_string(),
                configured: true,
            },
        ];
        assert_eq!(
            aggregate_component_statuses(&scrutiny_components, "scrutiny"),
            ("running".to_string(), "scrutiny".to_string())
        );

        let failed_oneshot = vec![
            ServiceComponentStatus {
                unit: "recyclarr.timer".to_string(),
                role: "timer".to_string(),
                status: "running".to_string(),
                configured: true,
            },
            ServiceComponentStatus {
                unit: "recyclarr.service".to_string(),
                role: "oneshot".to_string(),
                status: "failed".to_string(),
                configured: true,
            },
        ];
        assert_eq!(
            aggregate_component_statuses(&failed_oneshot, "recyclarr.timer"),
            ("degraded".to_string(), "recyclarr.timer".to_string())
        );
    }

    #[tokio::test]
    async fn test_shared_vhost_service_control_rejected() {
        let err = control_service_with_manager("Nextcloud", "restart", "systemd")
            .await
            .expect_err("shared-vhost service control must be rejected");
        assert!(err.to_string().contains("shared Apache virtual host"));
    }

    fn job(pkg: &str, action: &str, status: &str, started_at: &str) -> PackageJobInfo {
        PackageJobInfo {
            job_id: started_at.to_string(),
            package_id: pkg.to_string(),
            action: action.to_string(),
            status: status.to_string(),
            progress: 5,
            last_line: String::new(),
            started_at: started_at.to_string(),
        }
    }

    #[test]
    fn test_failed_lifecycle_outcome_survives_active_job_removal() {
        // Regression: a failed update used to clear the active job and leave
        // the package "installed", which clients reported as a successful update.
        let pkg = "syncthing";
        assert!(try_start_package_job(job(pkg, "update", "updating", "t1")));
        assert!(get_package_job_outcome(pkg).is_none());
        let outcome = finish_package_job(pkg, "update", false, "  exit status 1\n", "t1").unwrap();
        assert_eq!(outcome.status, "failed");
        assert_eq!(outcome.message, "Operation failed. Check authenticated service logs for details; rollback and data recovery are not confirmed.");
        assert!(!outcome.message.contains("exit status 1"));
        assert!(get_package_job_info(pkg).is_none());
        let stored = get_package_job_outcome(pkg).expect("terminal outcome retained");
        assert_eq!(stored.action, "update");
        assert_eq!(stored.started_at, "t1");

        // A new job supersedes the previous outcome atomically with registration.
        assert!(try_start_package_job(job(pkg, "update", "updating", "t2")));
        assert!(get_package_job_outcome(pkg).is_none());
        finish_package_job(pkg, "update", true, "Completed update", "t2");
        assert_eq!(get_package_job_outcome(pkg).unwrap().status, "completed");
    }

    #[test]
    fn test_stale_finish_does_not_remove_newer_active_job() {
        let pkg = "sonarr";
        assert!(try_start_package_job(job(
            pkg,
            "install",
            "installing",
            "new"
        )));
        finish_package_job(pkg, "install", false, "late result from old job", "old");
        let active = get_package_job_info(pkg).expect("newer job must remain active");
        assert_eq!(active.started_at, "new");
        assert!(
            get_package_job_outcome(pkg).is_none(),
            "stale finish must not publish an outcome while a newer job is active"
        );
        assert!(!try_start_package_job(job(
            pkg,
            "remove",
            "uninstalling",
            "other"
        )));
        finish_package_job(pkg, "install", true, "done", "new");
        assert!(get_package_job_info(pkg).is_none());
        // A late duplicate finish from the older job cannot replace the newer outcome.
        finish_package_job(pkg, "install", false, "late again", "mid");
        let stored = get_package_job_outcome(pkg).expect("newer outcome retained");
        assert_eq!(stored.started_at, "new");
        assert_eq!(stored.status, "completed");
    }

    #[test]
    fn test_service_control_target_is_limited_to_card_units() {
        // Core cards control only themselves.
        assert_eq!(
            authorize_service_control_target("AetherFlow API", "aetherflow-api", "systemd")
                .unwrap(),
            "aetherflow-api"
        );
        assert_eq!(
            authorize_service_control_target("Apache2 Web Server", "apache2", "systemd").unwrap(),
            "apache2"
        );
        assert!(authorize_service_control_target("AetherFlow API", "ssh", "systemd").is_err());
        assert!(
            authorize_service_control_target("apache2", "aetherflow-runner", "systemd-unit")
                .is_err()
        );

        // Package cards control their own primary and companion units only.
        assert_eq!(
            authorize_service_control_target("sonarr", "sonarr", "systemd").unwrap(),
            "sonarr"
        );
        assert_eq!(
            authorize_service_control_target("sonarr", "", "systemd").unwrap(),
            "sonarr"
        );
        assert_eq!(
            authorize_service_control_target("sonarr", "sonarr.service", "systemd-unit").unwrap(),
            "sonarr.service"
        );
        for foreign in [
            "ssh",
            "sshd",
            "aetherflow-runner",
            "aetherflow-api",
            "radarr",
            "apache2",
        ] {
            assert!(
                authorize_service_control_target("sonarr", foreign, "systemd-unit").is_err(),
                "sonarr card must not control {}",
                foreign
            );
            assert!(
                authorize_service_control_target("sonarr", foreign, "systemd").is_err(),
                "sonarr card must not control {}",
                foreign
            );
        }
        assert_eq!(
            authorize_service_control_target(
                "paperless-ngx",
                "paperless-worker.service",
                "systemd-unit"
            )
            .unwrap(),
            "paperless-worker.service"
        );
        // Shared-vhost packages cannot reach the shared Apache daemon.
        assert!(authorize_service_control_target("nextcloud", "apache2", "systemd-unit").is_err());
        // Unknown cards are not a back door to arbitrary units.
        assert!(authorize_service_control_target("sshd", "sshd", "systemd").is_err());
        assert!(authorize_service_control_target("", "", "systemd").is_err());
    }

    #[test]
    fn test_companion_units_resolve_to_owning_package() {
        assert_eq!(
            resolve_owning_package_id("sonarr").as_deref(),
            Some("sonarr")
        );
        assert_eq!(
            resolve_owning_package_id("paperless-worker.service").as_deref(),
            Some("paperless-ngx")
        );
        assert_eq!(resolve_owning_package_id("sshd"), None);
        assert_eq!(resolve_owning_package_id("aetherflow-api"), None);
    }
}
