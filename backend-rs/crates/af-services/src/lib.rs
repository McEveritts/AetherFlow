pub mod cluster_daemon;
pub mod mutators;
pub mod plugins;
pub mod workers;

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
use std::process::Command as StdCommand;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
// Package Catalog, Automation & Marketplace Orchestration (`package_service.go`)
// ─────────────────────────────────────────────────────────────────────────────

const EMBEDDED_PACKAGES_JSON: &str =
    include_str!("../../../../config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str =
    include_str!("../../../../config/package_automation.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageJobInfo {
    pub package_id: String,
    pub action: String,
    pub status: String,
    pub progress: i32,
    pub last_line: String,
    pub started_at: String,
}

static ACTIVE_PACKAGE_JOBS: Lazy<RwLock<HashMap<String, PackageJobInfo>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

// Health recovery must finish before a lifecycle job intentionally stops services.
pub static PACKAGE_LIFECYCLE_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

pub fn has_active_package_jobs() -> bool {
    ACTIVE_PACKAGE_JOBS
        .read()
        .map(|jobs| {
            jobs.values().any(|job| {
                matches!(
                    job.status.as_str(),
                    "installing" | "updating" | "uninstalling"
                )
            })
        })
        .unwrap_or(true)
}

pub fn get_package_job_info(pkg_id: &str) -> Option<PackageJobInfo> {
    ACTIVE_PACKAGE_JOBS.read().ok()?.get(pkg_id).cloned()
}

pub fn set_package_job_info(info: PackageJobInfo) {
    if let Ok(mut guard) = ACTIVE_PACKAGE_JOBS.write() {
        guard.insert(info.package_id.clone(), info);
    }
}

pub fn try_start_package_job(info: PackageJobInfo) -> bool {
    let Ok(mut jobs) = ACTIVE_PACKAGE_JOBS.write() else {
        return false;
    };
    if jobs.get(&info.package_id).is_some_and(|job| {
        matches!(
            job.status.as_str(),
            "installing" | "updating" | "uninstalling"
        )
    }) {
        return false;
    }
    jobs.insert(info.package_id.clone(), info);
    true
}

pub fn clear_package_job_info(pkg_id: &str) {
    if let Ok(mut guard) = ACTIVE_PACKAGE_JOBS.write() {
        guard.remove(pkg_id);
    }
}

fn load_config_file_or_embedded(env_var: &str, filename: &str, embedded: &str) -> String {
    if let Ok(explicit) = env::var(env_var) {
        if !explicit.trim().is_empty() {
            if let Ok(s) = fs::read_to_string(explicit.trim()) {
                return s;
            }
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
        if let Ok(s) = fs::read_to_string(&c) {
            return s;
        }
    }
    embedded.to_string()
}

pub fn get_package_catalog() -> anyhow::Result<Vec<Package>> {
    let raw_pkgs = load_config_file_or_embedded(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
    );
    let raw_auto = load_config_file_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
    );

    let mut pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs)?;
    let auto_map: HashMap<String, PackageAutomation> =
        serde_json::from_str(&raw_auto).unwrap_or_default();

    for p in &mut pkgs {
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
    let mut pkgs = get_package_catalog()?;
    let update_map = get_package_update_map();

    for p in &mut pkgs {
        if let Some(job) = get_package_job_info(&p.name) {
            p.status = job.status;
        } else if !p.lock_file.is_empty() && resolve_filesystem_path(&p.lock_file).exists() {
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

    Ok(pkgs)
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
    Some(AppBlueprint {
        app_name: p.name.clone(),
        service_name: if p.service_name.is_empty() {
            p.name.clone()
        } else {
            p.service_name
        },
        category: p.category,
        default_port: p.default_port,
        fallback_port_range: [17000, 19999],
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
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub progress: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub log_line: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub started_at: String,
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
type Pm2ServicesCacheState = (HashMap<String, (String, String)>, Option<Instant>);

static SERVICE_INFO_CACHE: Lazy<RwLock<HashMap<String, ServiceInfoCacheEntry>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

static PM2_SERVICES_CACHE: Lazy<RwLock<Pm2ServicesCacheState>> =
    Lazy::new(|| RwLock::new((HashMap::new(), None)));

pub fn clear_service_status_cache() {
    if let Ok(mut g) = SERVICE_INFO_CACHE.write() {
        g.clear();
    }
    if let Ok(mut g) = PM2_SERVICES_CACHE.write() {
        g.0.clear();
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
            if let Ok(catalog) = get_package_catalog() {
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
            }
            clean
        }
    }
}

pub fn resolve_service_web_scheme(target: &str, default_port: i32) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    if default_port > 0
        || matches!(
            clean.as_str(),
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
    if matches!(
        clean.as_str(),
        "maintainerr" | "palate" | "kasmvnc" | "mcvnc"
    ) {
        "loopback"
    } else {
        "network"
    }
}

pub fn resolve_service_control_scope(target: &str) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    if matches!(clean.as_str(), "nextcloud" | "rutorrent" | "organizr") {
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
    let clean = resolve_canonical_service_id(target);
    let units = resolve_service_units(&clean);
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
    let clean = target.trim().trim_end_matches(".service").to_string();
    if clean.is_empty() {
        return Vec::new();
    }
    let lower = clean.to_lowercase();
    if let Ok(catalog) = get_package_catalog() {
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
        "paperless" | "paperless-ngx" | "paperless-webserver" => {
            vec!["paperless-webserver".to_string()]
        }
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
        let (unit_status, unit_uptime) =
            query_single_systemd_unit_status(&policy.unit, policy.role, policy.configured);
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
    if active_state == "active"
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
    let cache_key = format!("unit:{}:{}:{}", unit, role, configured);
    let now = Instant::now();
    if let Ok(guard) = SERVICE_INFO_CACHE.read() {
        if let Some(((st, up, _), expires_at)) = guard.get(&cache_key) {
            if now < *expires_at {
                return (st.clone(), up.clone());
            }
        }
    }

    let mut systemctl_available = false;
    let mut resolved = ("stopped".to_string(), "-".to_string());

    #[cfg(target_os = "linux")]
    if let Ok(out) = StdCommand::new("systemctl")
        .args([
            "show",
            unit,
            "--property=ActiveState,SubState,ActiveEnterTimestamp",
        ])
        .output()
    {
        if out.status.success() {
            systemctl_available = true;
            let stdout = String::from_utf8_lossy(&out.stdout);
            resolved = classify_systemd_unit_show_output(&stdout, role);
        }
    }

    if !systemctl_available {
        resolved = if role == "oneshot" {
            ("idle".to_string(), "-".to_string())
        } else if role == "optional" && !configured {
            ("stopped".to_string(), "-".to_string())
        } else {
            ("running".to_string(), "Active".to_string())
        };
    }

    if let Ok(mut guard) = SERVICE_INFO_CACHE.write() {
        guard.insert(
            cache_key,
            (
                (resolved.0.clone(), resolved.1.clone(), unit.to_string()),
                now + Duration::from_secs(3),
            ),
        );
    }
    resolved
}

fn get_systemd_units_info(units: Vec<String>, service_name: &str) -> (String, String, String) {
    let primary_unit = units
        .first()
        .cloned()
        .unwrap_or_else(|| service_name.to_string());
    if units.is_empty() {
        return ("stopped".to_string(), "-".to_string(), primary_unit);
    }

    let cache_key = units.join("+");
    let now = Instant::now();
    if let Ok(guard) = SERVICE_INFO_CACHE.read() {
        if let Some((cached, expires_at)) = guard.get(&cache_key) {
            if now < *expires_at {
                return cached.clone();
            }
        }
    }

    let mut systemctl_available = false;
    let mut any_running = false;
    let mut any_restarting = false;
    let mut best_uptime = "-".to_string();

    #[cfg(target_os = "linux")]
    for unit in &units {
        if let Ok(out) = StdCommand::new("systemctl")
            .args([
                "show",
                unit,
                "--property=ActiveState,SubState,ActiveEnterTimestamp",
            ])
            .output()
        {
            if out.status.success() {
                systemctl_available = true;
                let stdout = String::from_utf8_lossy(&out.stdout);
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
                if active_state == "active"
                    || matches!(sub_state.as_str(), "running" | "exited" | "listening")
                {
                    any_running = true;
                    if best_uptime == "-" {
                        best_uptime = format_uptime(&enter_ts);
                    }
                } else if matches!(
                    active_state.as_str(),
                    "activating" | "deactivating" | "reloading"
                ) {
                    any_restarting = true;
                }
            }
        }
    }

    let result = if systemctl_available {
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
    } else {
        // Non-systemd environment (container, dev, or test): default installed services to running
        ("running".to_string(), "Active".to_string(), primary_unit)
    };

    if let Ok(mut guard) = SERVICE_INFO_CACHE.write() {
        guard.insert(cache_key, (result.clone(), now + Duration::from_secs(3)));
    }
    result
}

pub fn get_pm2_services() -> HashMap<String, (String, String)> {
    let now = Instant::now();
    if let Ok(guard) = PM2_SERVICES_CACHE.read() {
        if let Some(exp) = guard.1 {
            if now < exp {
                return guard.0.clone();
            }
        }
    }

    let mut map = HashMap::new();
    #[cfg(target_os = "linux")]
    if let Ok(out) = StdCommand::new("pm2").arg("jlist").output() {
        if out.status.success() {
            if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
                for item in arr {
                    let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let pm2_env = item.get("pm2_env");
                    let raw_status = pm2_env
                        .and_then(|e| e.get("status"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("stopped");
                    let status = match raw_status {
                        "online" => "running",
                        "launching" | "stopping" | "waiting restart" => "restarting",
                        _ => "stopped",
                    };
                    let uptime = if status == "running" {
                        if let Some(ms) = pm2_env
                            .and_then(|e| e.get("pm_uptime"))
                            .and_then(|v| v.as_i64())
                        {
                            let now_ms = Utc::now().timestamp_millis();
                            if ms > 0 && now_ms >= ms {
                                format_uptime_duration(chrono::Duration::milliseconds(now_ms - ms))
                            } else {
                                "Active".to_string()
                            }
                        } else {
                            "Active".to_string()
                        }
                    } else {
                        "-".to_string()
                    };
                    map.insert(name.to_string(), (status.to_string(), uptime));
                }
            }
        }
    }

    if let Ok(mut guard) = PM2_SERVICES_CACHE.write() {
        *guard = (map.clone(), Some(now + Duration::from_secs(3)));
    }
    map
}

pub fn get_pm2_service_info(service_name: &str) -> (String, String) {
    let map = get_pm2_services();
    if let Some(info) = map.get(service_name) {
        return info.clone();
    }
    for (k, v) in map {
        if k.eq_ignore_ascii_case(service_name) {
            return v;
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

pub fn get_active_services() -> HashMap<String, ServiceStatusItem> {
    let mut map = HashMap::new();

    // 1. Core Systemd Services (`service_manager.go`: AetherFlow API, AetherFlow Frontend, Apache2 Web Server)
    let (_api_st, api_up, _api_unit) = get_service_info("aetherflow-api");
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
            version: "v3.2.6".to_string(),
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

    let (fe_st, fe_up, _fe_unit) = get_service_info("aetherflow-frontend");
    let (fe_status, fe_uptime, fe_managed_by) = if fe_st == "running" {
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
            version: "v3.2.6".to_string(),
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

    let (apache_st, apache_up, _apache_unit) = get_service_info("apache2");
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
    let pkgs = get_packages().unwrap_or_default();

    for p in pkgs {
        let active_job = get_package_job_info(&p.name);
        if p.status != "installed" && active_job.is_none() {
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
            resolve_service_units(&p.name)
        } else {
            vec![svc_name.clone()]
        };

        let (mut svc_status, mut svc_uptime, primary_proc, components) = if managed_by == "pm2" {
            let (st, up) = get_pm2_service_info(&svc_name);
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
            get_service_info_detailed(&p.name)
        };

        let mut job_status = String::new();
        let mut progress = 0;
        let mut log_line = String::new();
        let mut started_at = String::new();
        if let Some(job) = active_job {
            job_status = job.status.clone();
            progress = job.progress;
            log_line = job.last_line;
            started_at = job.started_at;
            if p.status != "installed" {
                svc_status = job.status;
                svc_uptime = "In progress".to_string();
            }
        }

        let runtime_meta = mutators::get_app_runtime_meta(&p.name);
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

        let internal_domain = resolve_app_internal_domain(&p.name);

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

        let version = if !p.installed_version.is_empty() {
            p.installed_version.clone()
        } else {
            "latest".to_string()
        };
        let web_scheme =
            resolve_service_web_scheme(&p.name, active_port.max(p.default_port)).to_string();
        let bind_scope = resolve_service_bind_scope(&p.name).to_string();
        let control_scope = resolve_service_control_scope(&p.name).to_string();

        map.insert(
            p.label_or_name(),
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
                installed_version: p.installed_version,
                latest_version: p.latest_version,
                update_available: p.update_available,
                update_checked_at: p.update_checked_at,
                update_url: p.update_url,
                update_error: p.update_error,
                job_status,
                progress,
                log_line,
                started_at,
            },
        );
    }
    map
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
async fn dispatch_runner_systemctl_unix(action: &str, unit: &str) -> Option<Result<(), String>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let sock_path = af_runner::runner_socket_path();
    if !Path::new(&sock_path).exists() {
        return None;
    }
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(5),
        UnixStream::connect(&sock_path),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let body = serde_json::to_string(&af_models::SystemctlRequest {
        action: action.to_string(),
        service: unit.to_string(),
    })
    .ok()?;
    let req = format!(
        "POST /v1/systemctl HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(req.as_bytes()))
        .await
        .ok()
        .and_then(|res| res.ok())?;

    let mut resp = String::new();
    match tokio::time::timeout(RUNNER_SYSTEMCTL_TIMEOUT, stream.read_to_string(&mut resp)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Some(Err(format!(
                "runner socket read error for systemctl {} {}: {}",
                action, unit, e
            )));
        }
        Err(_) => {
            return Some(Err(format!(
                "runner socket timed out after {}s waiting for systemctl {} {}",
                RUNNER_SYSTEMCTL_TIMEOUT.as_secs(),
                action,
                unit
            )));
        }
    }

    let Some((headers, json_body)) = resp.split_once("\r\n\r\n") else {
        return Some(Err(format!(
            "malformed runner response for systemctl {} {}",
            action, unit
        )));
    };
    if headers.starts_with("HTTP/1.1 200") || headers.starts_with("HTTP/1.0 200") {
        if let Ok(parsed) = serde_json::from_str::<af_models::RunnerResponse>(json_body.trim()) {
            if !parsed.success {
                let detail = if !parsed.output.trim().is_empty() {
                    format!("{} ({})", parsed.error.trim(), parsed.output.trim())
                } else {
                    parsed.error.trim().to_string()
                };
                return Some(Err(detail));
            }
        }
        Some(Ok(()))
    } else {
        if let Ok(parsed) = serde_json::from_str::<af_models::RunnerResponse>(json_body.trim()) {
            let detail = if !parsed.output.trim().is_empty() {
                format!("{} ({})", parsed.error.trim(), parsed.output.trim())
            } else if !parsed.error.trim().is_empty() {
                parsed.error.trim().to_string()
            } else {
                json_body.trim().to_string()
            };
            return Some(Err(detail));
        }
        Some(Err(json_body.trim().to_string()))
    }
}

pub async fn control_service_with_manager(
    service_name: &str,
    action: &str,
    managed_by: &str,
) -> anyhow::Result<()> {
    let valid_name = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap();
    if !valid_name.is_match(service_name) {
        anyhow::bail!("invalid service name: {}", service_name);
    }
    if !matches!(action, "start" | "stop" | "restart" | "reload" | "status") {
        anyhow::bail!("disallowed action: {}", action);
    }

    if managed_by.eq_ignore_ascii_case("pm2") {
        let out = Command::new("pm2")
            .args([action, service_name])
            .output()
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
                anyhow::bail!("systemctl {} {} failed: {}", action, unit, err_msg);
            }
            None => {}
        }

        let out = Command::new("sudo")
            .args(["-n", "systemctl", action, "--", &unit])
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => continue,
            _ => {
                let direct = Command::new("systemctl")
                    .args([action, "--", &unit])
                    .output()
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
    if host == "0.0.0.0"
        || host == "::"
        || host.starts_with("169.254.")
        || host.starts_with("fe80:")
        || host.starts_with("fd00:ec2:")
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
        || host == "metadata.goog"
        || host == "instance-data"
    {
        anyhow::bail!("Disallowed target host");
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
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
            package_id: "test-marketplace-duplicate".into(),
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

        let sock_path = std::env::temp_dir().join(format!(
            "af-services-runner-test-{}.sock",
            std::process::id()
        ));
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
}
