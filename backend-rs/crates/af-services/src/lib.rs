pub mod cluster_daemon;
pub mod mutators;
pub mod workers;

use af_models::{Package, PackageAutomation};
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use tokio::process::Command;

// ─────────────────────────────────────────────────────────────────────────────
// Package Catalog, Automation & Marketplace Orchestration (`package_service.go`)
// ─────────────────────────────────────────────────────────────────────────────

const EMBEDDED_PACKAGES_JSON: &str =
    include_str!("../../../../backend/config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str =
    include_str!("../../../../backend/config/package_automation.json");

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

pub fn get_package_job_info(pkg_id: &str) -> Option<PackageJobInfo> {
    ACTIVE_PACKAGE_JOBS.read().ok()?.get(pkg_id).cloned()
}

pub fn set_package_job_info(info: PackageJobInfo) {
    if let Ok(mut guard) = ACTIVE_PACKAGE_JOBS.write() {
        guard.insert(info.package_id.clone(), info);
    }
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
        PathBuf::from("config").join(filename),
        PathBuf::from("backend/config").join(filename),
        PathBuf::from("../backend/config").join(filename),
        PathBuf::from("/opt/AetherFlow/current/config").join(filename),
        PathBuf::from("/opt/AetherFlow/backend/config").join(filename),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.insert(0, exe_dir.join("config").join(filename));
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

pub fn get_blueprint(app_name: &str) -> Option<AppBlueprint> {
    let pkgs = get_package_catalog().ok()?;
    let p = pkgs.into_iter().find(|x| x.name == app_name)?;
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
        port_env_var: "AF_APP_PORT".to_string(),
        port_config_key: "port".to_string(),
        web_path: p.web_path,
        health_check_path: "/".to_string(),
        mutator_type: String::new(),
        config_file_path: String::new(),
        internal_domain: format!("{}.aether.local", p.name),
        is_network_app: matches!(p.name.as_str(), "pihole" | "wireguard" | "tailscale"),
        dependencies: Vec::new(),
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
                .unwrap_or(bp.default_port);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusItem {
    pub status: String,
    pub uptime: String,
    pub version: String,
    pub managed_by: String,
    pub process: String,
}

pub fn get_active_services() -> HashMap<String, ServiceStatusItem> {
    let mut map = HashMap::new();
    let pkgs = get_packages().unwrap_or_default();
    for p in pkgs {
        if p.status != "installed" {
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
        map.insert(
            p.Label_or_name(),
            ServiceStatusItem {
                status: "running".to_string(),
                uptime: "Active".to_string(),
                version: if p.installed_version.is_empty() {
                    "latest".to_string()
                } else {
                    p.installed_version
                },
                managed_by: managed_by.to_string(),
                process: svc_name,
            },
        );
    }
    map
}

trait PackageExt {
    fn Label_or_name(&self) -> String;
}

impl PackageExt for Package {
    fn Label_or_name(&self) -> String {
        if !self.label.is_empty() {
            self.label.clone()
        } else {
            self.name.clone()
        }
    }
}

pub async fn control_service(service_name: &str, action: &str) -> anyhow::Result<()> {
    let valid_name = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap();
    if !valid_name.is_match(service_name) {
        anyhow::bail!("invalid service name: {}", service_name);
    }
    if !matches!(action, "start" | "stop" | "restart" | "status") {
        anyhow::bail!("disallowed action: {}", action);
    }

    let out = Command::new("sudo")
        .args(["-n", "systemctl", action, "--", service_name])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => Ok(()),
        _ => {
            // Try direct systemctl if running as root
            let direct = Command::new("systemctl")
                .args([action, "--", service_name])
                .output()
                .await?;
            if direct.status.success() {
                Ok(())
            } else {
                anyhow::bail!(
                    "systemctl {} {} failed: {}",
                    action,
                    service_name,
                    String::from_utf8_lossy(&direct.stderr)
                )
            }
        }
    }
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
    #[serde(default)]
    pub season_number: i32,
    #[serde(default)]
    pub episode_number: i32,
    #[serde(default)]
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
    pub video_codec: String,
    pub video_resolution: String,
    pub video_range: String,
    pub is_video_direct: bool,
    pub audio_codec: String,
    pub audio_channels: i32,
    pub audio_layout: String,
    pub is_audio_direct: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hw_accel: String,
    #[serde(default)]
    pub transcode_reasons: Vec<String>,
    pub bitrate_bps: i64,
    pub bandwidth_mbps: f64,
    pub session_data_bytes: i64,
    pub started_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub play_session_id: String,
    pub supports_media_control: bool,
    pub supports_remote_control: bool,
    pub can_send_message: bool,
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
    pub media_type_breakdown: Vec<serde_json::Value>,
    pub resolution_breakdown: Vec<serde_json::Value>,
    pub codec_breakdown: Vec<serde_json::Value>,
    pub time_series: Vec<serde_json::Value>,
    pub top_users: Vec<serde_json::Value>,
    pub top_titles: Vec<serde_json::Value>,
    pub recent_history: Vec<serde_json::Value>,
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

pub fn get_streaming_dashboard(window_days: i32, is_admin: bool) -> StreamingDashboardResponse {
    let demo_mode = DEMO_STREAMING_MODE.lock().map(|g| *g).unwrap_or(false);
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
    fn test_embedded_package_catalog_loads_all_apps() {
        let catalog = get_package_catalog().unwrap();
        assert!(catalog.len() >= 69);
        assert!(catalog.iter().any(|p| p.name == "jellyfin"));
        assert!(catalog.iter().any(|p| p.name == "kasmvnc"));
        assert!(catalog.iter().any(|p| p.name == "xrdp"));
    }

    #[test]
    fn test_validate_server_url_blocks_ssrf() {
        assert!(validate_server_url("http://127.0.0.1:8096").is_ok());
        assert!(validate_server_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_server_url("http://metadata.google.internal").is_err());
    }
}
