use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Service Manager
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

pub(crate) fn is_false(v: &bool) -> bool {
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
    #[serde(default)]
    pub external_access_enabled: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_scope: Option<String>,
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

pub(crate) type ServiceInfoCacheEntry = ((String, String, String), Instant);
pub(crate) type Pm2ServicesCacheState =
    (Option<HashMap<String, (String, String)>>, Option<Instant>);

pub(crate) static SERVICE_INFO_CACHE: Lazy<RwLock<HashMap<String, ServiceInfoCacheEntry>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub(crate) static PM2_SERVICES_CACHE: Lazy<RwLock<Pm2ServicesCacheState>> =
    Lazy::new(|| RwLock::new((None, None)));

pub(crate) static SERVICE_STATUS_EPOCH: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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

pub(crate) fn resolve_canonical_service_id_with_catalog(
    target: &str,
    catalog: &[Package],
) -> String {
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
        "novnc-xvnc" | "novnc-session" => "novnc".to_string(),
        "xrdp-sesman" => "xrdp".to_string(),
        "node_exporter" => "prometheus".to_string(),
        "rclone-vfs" => "rclone".to_string(),
        "librespeed.socket" => "librespeed".to_string(),
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

pub fn service_web_scheme_for_id(clean: &str, default_port: i32) -> &'static str {
    if clean == "kasmvnc" {
        return "https";
    }
    if default_port > 0
        || matches!(
            clean,
            "nextcloud" | "rutorrent" | "organizr" | "maintainerr" | "palate" | "mcvnc"
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

pub fn service_bind_scope_for_id(clean: &str) -> &'static str {
    match clean {
        "qbittorrent" => {
            qbittorrent_bind_scope(mutators::qbittorrent_web_bind_address().as_deref())
        }
        // Fresh installs of these web listeners bind to loopback. A managed
        // vhost can expose them, but the backend port isn't a LAN URL.
        "adguardhome" | "audiobookshelf" | "autobrr" | "autoscan" | "bazarr" | "dispatcharr"
        | "filebot" | "filebrowser" | "flaresolverr" | "flood" | "gitea" | "homeassistant"
        | "invidious" | "jackett" | "kasmvnc" | "kavita" | "librespeed" | "lidarr"
        | "listenarr" | "maintainerr" | "mcvnc" | "n8n" | "navidrome" | "netdata" | "nextcloud"
        | "notifiarr" | "novnc" | "nzbget" | "ombi" | "organizr" | "palate" | "paperless-ngx"
        | "piped" | "prometheus" | "prowlarr" | "pyload" | "qui" | "radarr" | "rclone"
        | "readarr" | "rutorrent" | "sabnzbd" | "scrutiny" | "seedcross" | "sonarr"
        | "syncthing" | "tautulli" | "thelounge" | "threadfin" | "transmission" | "unmanic"
        | "vaultwarden" | "znc" => "loopback",
        _ => "network",
    }
}

pub(crate) fn qbittorrent_bind_scope(address: Option<&str>) -> &'static str {
    if address.is_some_and(|address| {
        address == "*"
            || address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| !ip.is_loopback())
    }) {
        "network"
    } else {
        "loopback"
    }
}

pub fn resolve_service_control_scope(target: &str) -> &'static str {
    let clean = resolve_canonical_service_id(target);
    service_control_scope_for_id(&clean)
}

pub(crate) fn service_control_scope_for_id(clean: &str) -> &'static str {
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

pub(crate) fn service_component_policies_with_catalog(
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

pub(crate) fn policies_for_units(
    units: Vec<String>,
    rclone_vfs_configured: bool,
) -> Vec<ServiceComponentPolicy> {
    units
        .into_iter()
        .map(|unit| {
            let unit_lower = unit.to_ascii_lowercase();
            let (role, configured) = if unit_lower.ends_with(".timer") {
                ("timer", true)
            } else if unit_lower.ends_with(".socket") {
                ("socket", true)
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
            "required" | "timer" | "socket" => true,
            "optional" => p.configured || action == "stop",
            "oneshot" => action == "stop",
            _ => true,
        })
        .map(|p| p.unit)
        .collect();
    if action == "stop" {
        af_release::lifecycle::sort_units_for_stop(&mut units);
    } else {
        af_release::lifecycle::sort_units_for_start(&mut units);
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
        .or_else(|| {
            components
                .iter()
                .find(|c| c.role == "timer" || c.role == "socket")
        })
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
        if comp.status == "not-found"
            && af_release::lifecycle::is_legacy_optional_companion_unit(&comp.unit)
        {
            continue;
        }
        match comp.role.as_str() {
            "required" | "timer" | "socket" => {
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
            "oneshot" if comp.status == "failed" => {
                oneshot_failed = true;
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

/// Resolves a logical package or service name into its concrete systemd unit names.
pub fn resolve_service_units(target: &str) -> Vec<String> {
    resolve_service_units_with_catalog(target, &get_package_catalog().unwrap_or_default())
}

pub(crate) fn resolve_service_units_with_catalog(target: &str, catalog: &[Package]) -> Vec<String> {
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
        "librespeed" | "librespeed.socket" => {
            vec!["librespeed".to_string(), "librespeed.socket".to_string()]
        }
        "novnc" | "novnc-xvnc" | "novnc-session" => vec![
            "novnc".to_string(),
            "novnc-xvnc".to_string(),
            "novnc-session".to_string(),
        ],
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

/// Formats systemd's `ActiveEnterTimestamp` string into a concise human-readable uptime.
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
    let date_time_pair = if tokens.len() >= 3 && tokens[0].chars().all(|c| c.is_ascii_alphabetic())
    {
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
/// with a short in-memory cache and graceful fallback on non-systemd platforms.
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

pub(crate) fn get_service_info_for_policies(
    service_name: &str,
    policies: Vec<ServiceComponentPolicy>,
) -> (String, String, String, Vec<ServiceComponentStatus>) {
    service_info_from_observations(service_name, policies, |policy| {
        query_single_systemd_unit_status(&policy.unit, policy.role, policy.configured)
    })
}

pub(crate) fn service_info_from_observations(
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
        if matches!(policy.role, "required" | "timer" | "socket")
            && unit_status == "running"
            && best_uptime == "-"
            && unit_uptime != "-"
        {
            best_uptime = unit_uptime;
        }
        let configured = if unit_status == "not-found"
            && af_release::lifecycle::is_legacy_optional_companion_unit(&policy.unit)
        {
            false
        } else {
            policy.configured
        };
        components.push(ServiceComponentStatus {
            unit: policy.unit.clone(),
            role: policy.role.to_string(),
            status: unit_status,
            configured,
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
    let mut load_state = String::new();
    let mut active_state = String::new();
    let mut sub_state = String::new();
    let mut enter_ts = String::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "LoadState" => load_state = v.trim().to_lowercase(),
                "ActiveState" => active_state = v.trim().to_lowercase(),
                "SubState" => sub_state = v.trim().to_lowercase(),
                "ActiveEnterTimestamp" => enter_ts = v.trim().to_string(),
                _ => {}
            }
        }
    }
    if (active_state.is_empty() && sub_state.is_empty()) || load_state == "error" {
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
    } else if load_state == "not-found"
        && active_state == "inactive"
        && (sub_state.is_empty() || sub_state == "dead")
    {
        ("not-found".to_string(), "-".to_string())
    } else if role == "oneshot" && (active_state == "inactive" || sub_state == "dead") {
        ("idle".to_string(), "-".to_string())
    } else {
        ("stopped".to_string(), "-".to_string())
    }
}

pub(crate) fn query_single_systemd_unit_status(
    unit: &str,
    role: &str,
    configured: bool,
) -> (String, String) {
    query_systemd_unit_with_timeout(unit, role, configured, Duration::from_secs(2))
}

pub(crate) fn query_systemd_unit_with_timeout(
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
            "--property=LoadState,ActiveState,SubState,ActiveEnterTimestamp",
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

pub(crate) fn status_command_output(
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

pub(crate) async fn async_status_command_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let mut command = Command::new(program);
    command.args(args);
    af_runner::bounded_command::output(command, timeout, 1024 * 1024).await
}

pub(crate) fn get_systemd_units_info(
    units: Vec<String>,
    service_name: &str,
) -> (String, String, String) {
    let primary_unit = units
        .first()
        .cloned()
        .unwrap_or_else(|| service_name.to_string());
    if units.is_empty() {
        return ("stopped".to_string(), "-".to_string(), primary_unit);
    }

    let mut any_running = false;
    let mut any_restarting = false;
    let mut all_not_found = true;
    let mut best_uptime = "-".to_string();

    for unit in &units {
        let (status, uptime) = query_single_systemd_unit_status(unit, "required", true);
        if status == "unknown" {
            return (status, "-".to_string(), primary_unit);
        }
        if status != "not-found" {
            all_not_found = false;
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
    } else if all_not_found {
        ("not-found".to_string(), "-".to_string(), primary_unit)
    } else {
        ("stopped".to_string(), "-".to_string(), primary_unit)
    }
}

pub fn get_pm2_services() -> anyhow::Result<HashMap<String, (String, String)>> {
    get_pm2_services_with_timeout(Duration::from_secs(2))
}

pub(crate) fn get_pm2_services_with_timeout(
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

pub(crate) fn pm2_service_info_from_observations(
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
    let installed_packages = populate_package_core_statuses(&mut pkgs, jobs)?;
    let rclone_vfs_configured = is_rclone_vfs_configured();
    let included = |package: &Package| {
        package.status == "installed"
            || jobs.active.contains_key(&package.name)
            || jobs
                .outcomes
                .get(&package.name)
                .is_some_and(|outcome| outcome.status != "completed")
    };
    let mut core_units = INVENTORY_CORE_UNITS.to_vec();
    if ["/etc", "/run", "/usr/local/lib", "/usr/lib", "/lib"]
        .into_iter()
        .any(|root| {
            mutators::resolve_config_path(&format!(
                "{root}/systemd/system/aetherflow-frontend.service"
            ))
            .is_file()
        })
    {
        core_units.push(("aetherflow-frontend", "AetherFlow Frontend"));
    }
    let core_policies = policies_for_units(
        core_units
            .iter()
            .map(|(unit, _)| unit.to_string())
            .collect(),
        rclone_vfs_configured,
    );
    let mut policies = core_policies.clone();
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
    for ((unit, label), policy) in core_units.into_iter().zip(core_policies) {
        let (status, uptime, _, components) =
            service_info_from_observations(unit, vec![policy], |policy| {
                observations.systemd(policy)
            });
        map.insert(
            label.to_string(),
            ServiceStatusItem {
                id: unit.to_string(),
                status,
                uptime,
                version: if unit == "apache2" {
                    "system".to_string()
                } else {
                    af_release::runtime::runtime_identity().version.clone()
                },
                managed_by: "systemd".to_string(),
                process: unit.to_string(),
                bind_scope: "network".to_string(),
                control_scope: "service".to_string(),
                components,
                units: vec![unit.to_string()],
                ..Default::default()
            },
        );
    }

    // 2. Installed & Active-Job Packages
    let ingress_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()?
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();
    let base_domain = resolve_base_domain();
    let launch_host = mutators::detect_lan_ip();
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

        let internal_domain = resolve_app_internal_domain(&p.name);

        let mut public_domain = ing.map(|c| c.public_domain.clone()).unwrap_or_default();
        if public_domain.is_empty() && !base_domain.is_empty() && active_port > 0 {
            public_domain = format_app_public_domain(&p.name, &base_domain);
        }

        let external_access_enabled = ing.is_some_and(|c| c.external_access_enabled);
        let tls_enabled = ing
            .map(|c| c.tls_enabled)
            .unwrap_or(!public_domain.is_empty());

        // An absent measurement remains unknown; it is not evidence of latest.
        let version = p.installed_version.clone();
        let web_scheme =
            service_web_scheme_for_id(&p.name, active_port.max(p.default_port)).to_string();
        let bind_scope = service_bind_scope_for_id(&p.name).to_string();
        let control_scope = service_control_scope_for_id(&p.name).to_string();

        let installed = installed_packages.contains(&p.name);
        let web_path = if installed {
            af_models::app_metadata::effective_app_web_path(&runtime_meta.url_base, &p.web_path)
        } else {
            p.web_path.clone()
        };
        let (launch_url, launch_scope) = if installed {
            launch_target(&p.name, active_port, &web_path, ing, &launch_host)
        } else {
            (None, Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE.into()))
        };
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
                web_path,
                launch_url,
                launch_scope,
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

pub(crate) trait PackageExt {
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
