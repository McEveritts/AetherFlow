use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceGroup {
    Core,
    Active,
    Stopped,
    Other,
    Exception,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TopologyTier {
    Gateway,
    Service,
    Dependency,
}

impl TopologyTier {
    pub fn label_key(self) -> &'static str {
        match self {
            Self::Gateway => "Gateway",
            Self::Service => "Services",
            Self::Dependency => "Dependencies",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Service => "service",
            Self::Dependency => "dependency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TopologyIconKind {
    Gateway,
    Api,
    Runner,
    Database,
    Media,
    Network,
    Cloud,
    Service,
}

impl TopologyIconKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Api => "api",
            Self::Runner => "runner",
            Self::Database => "database",
            Self::Media => "media",
            Self::Network => "network",
            Self::Cloud => "cloud",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TopologyEdgeKind {
    Active,
    Standby,
    Exception,
    TwoWay,
}

impl TopologyEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Exception => "exception",
            Self::TwoWay => "two-way",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TopologyColumnHeader {
    pub tier: TopologyTier,
    pub label_key: &'static str,
    /// Left edge X coordinate of the column's cards (matches left-aligned column headers).
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopologyCardNode {
    pub id: String,
    pub service_id: String,
    pub label: String,
    pub subtitle: String,
    pub details: String,
    pub status: String,
    pub group: ServiceGroup,
    pub tier: TopologyTier,
    pub icon: TopologyIconKind,
    /// Center X coordinate of the card.
    pub x: f64,
    /// Center Y coordinate of the card.
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub outgoing_count: usize,
    pub incoming_count: usize,
    pub signal_bars: u8,
    pub dashed_border: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopologyEdgeRoute {
    pub source: String,
    pub target: String,
    pub label: String,
    pub kind: TopologyEdgeKind,
    pub x1: f64,
    pub y1: f64,
    pub x2: f64,
    pub y2: f64,
    pub path_d: String,
    pub label_x: f64,
    pub label_y: f64,
    pub is_two_way: bool,
    pub has_arrow: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TieredTopologyLayout {
    pub width: f64,
    pub height: f64,
    pub columns: Vec<TopologyColumnHeader>,
    pub nodes: Vec<TopologyCardNode>,
    pub edges: Vec<TopologyEdgeRoute>,
}

const GATEWAY_WIDTH: f64 = 196.0;
const GATEWAY_HEIGHT: f64 = 56.0;
const SERVICE_WIDTH: f64 = 228.0;
const SERVICE_HEIGHT: f64 = 72.0;
const DEPENDENCY_WIDTH: f64 = 228.0;
const DEPENDENCY_HEIGHT: f64 = 64.0;

const GATEWAY_PITCH: f64 = 88.0;
const SERVICE_PITCH: f64 = 98.0;
const DEPENDENCY_PITCH: f64 = 92.0;

const GAP_GATEWAY_TO_SERVICE: f64 = 200.0;
const GAP_SERVICE_TO_DEPENDENCY: f64 = 152.0;
const GAP_GATEWAY_TO_DEPENDENCY: f64 = 180.0;

const PAD_X: f64 = 48.0;
const SAME_COL_LEFT_PAD: f64 = 128.0;
const HEADER_Y: f64 = 34.0;
const TOP_CONTENT_Y: f64 = 66.0;
const PAD_BOTTOM: f64 = 44.0;
const MIN_CANVAS_WIDTH: f64 = 720.0;
const MIN_CANVAS_HEIGHT: f64 = 360.0;

fn normalize_slug(slug: &str) -> String {
    slug.to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect()
}

pub fn is_core_service(slug: &str) -> bool {
    matches!(
        normalize_slug(slug).as_str(),
        "aetherflowapi"
            | "aetherflowfrontend"
            | "aetherflow"
            | "aetherflowrunner"
            | "runnerdaemon"
            | "apache2"
            | "apache2webserver"
            | "nginx"
    )
}

pub fn is_service_exception(info: &Value) -> bool {
    matches!(
        info["status"].as_str(),
        Some("failed" | "error" | "degraded")
    ) || matches!(
        info["job_status"].as_str(),
        Some("install_failed" | "failed")
    ) || info["last_job"]["status"] == "failed"
        || (info["last_job"]["action"] == "install"
            && info["last_job"]["status"] != "completed"
            && info["last_job"]["error"]
                .as_str()
                .is_some_and(|e| !e.is_empty()))
        || matches!(info["health"].as_str(), Some("degraded" | "unhealthy"))
        || info["degraded_components"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
}

pub fn service_group(slug: &str, info: &Value) -> ServiceGroup {
    if is_service_exception(info) {
        ServiceGroup::Exception
    } else if is_core_service(slug) {
        ServiceGroup::Core
    } else if matches!(info["status"].as_str(), Some("running" | "active")) {
        ServiceGroup::Active
    } else if matches!(
        info["status"].as_str(),
        Some("stopped" | "inactive" | "disabled")
    ) {
        ServiceGroup::Stopped
    } else {
        ServiceGroup::Other
    }
}

pub fn format_service_name(slug: &str) -> String {
    match slug.to_lowercase().as_str() {
        "aetherflow-api" | "aetherflow_api" => "AetherFlow API".into(),
        "aetherflow-frontend" | "aetherflow_frontend" => "AetherFlow Frontend".into(),
        "aetherflow-runner" | "aetherflow_runner" => "AetherFlow Runner".into(),
        "aetherflow" => "AetherFlow Core".into(),
        "apache2" => "Apache Gateway".into(),
        "calibreweb" => "Calibre-Web".into(),
        "qbittorrent" => "qBittorrent".into(),
        "homeassistant" => "Home Assistant".into(),
        "vaultwarden" => "Vaultwarden".into(),
        "wireguard" => "WireGuard".into(),
        "paperless" => "Paperless-ngx".into(),
        _ => slug
            .split(['-', '_'])
            .map(|word| {
                let mut chars = word.chars();
                chars
                    .next()
                    .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub group: ServiceGroup,
    pub x: f64,
    pub y: f64,
}

/// Sorted grid seed followed by bounded deterministic repulsion/spring relaxation.
pub fn compute_topology_layout(
    services: &[(String, Value)],
    width: f64,
    height: f64,
) -> Vec<TopologyNode> {
    let width = if width.is_finite() {
        width.max(160.0)
    } else {
        800.0
    };
    let height = if height.is_finite() {
        height.max(120.0)
    } else {
        400.0
    };
    let mut sorted = services.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let columns = ((sorted.len() as f64 * width / height).sqrt().ceil() as usize).max(1);
    let rows = sorted.len().div_ceil(columns).max(1);
    let mut nodes: Vec<_> = sorted
        .iter()
        .enumerate()
        .map(|(i, (id, info))| TopologyNode {
            id: id.clone(),
            label: format_service_name(id),
            group: service_group(id, info),
            x: (i % columns + 1) as f64 * width / (columns + 1) as f64,
            y: (i / columns + 1) as f64 * height / (rows + 1) as f64,
        })
        .collect();
    // Bound work for large service catalogs; all nodes remain available in list mode.
    if nodes.len() <= 200 {
        for _ in 0..48 {
            let mut forces = vec![(0.0, 0.0); nodes.len()];
            for i in 0..nodes.len() {
                for j in i + 1..nodes.len() {
                    let dx = nodes[i].x - nodes[j].x;
                    let dy = nodes[i].y - nodes[j].y;
                    let d2 = (dx * dx + dy * dy).max(1.0);
                    let strength = 1400.0 / d2;
                    forces[i].0 += dx * strength;
                    forces[i].1 += dy * strength;
                    forces[j].0 -= dx * strength;
                    forces[j].1 -= dy * strength;
                }
            }
            for (node, (fx, fy)) in nodes.iter_mut().zip(forces) {
                node.x = (node.x + (fx + (width / 2.0 - node.x) * 0.02) * 0.15)
                    .clamp(60.0, width - 60.0);
                node.y = (node.y + (fy + (height / 2.0 - node.y) * 0.02) * 0.15)
                    .clamp(40.0, height - 40.0);
            }
        }
    }
    nodes
}

fn is_gateway_node(id: &str, service_id: &str, info: &Value) -> bool {
    if info["group"].as_i64() == Some(3) {
        return true;
    }
    for candidate in [id, service_id] {
        let norm = normalize_slug(candidate);
        if matches!(
            norm.as_str(),
            "apache2"
                | "apache2webserver"
                | "nginx"
                | "caddy"
                | "traefik"
                | "haproxy"
                | "gateway"
                | "ingress"
        ) || norm.ends_with("gateway")
            || norm.ends_with("webserver")
        {
            return true;
        }
    }
    false
}

fn is_dependency_node(id: &str, service_id: &str, info: &Value) -> bool {
    if info["group"].as_i64() == Some(2) {
        return true;
    }
    for candidate in [id, service_id] {
        let norm = normalize_slug(candidate);
        if norm.starts_with("sqlite")
            || norm.starts_with("postgres")
            || norm.starts_with("mariadb")
            || norm.starts_with("mysql")
            || norm.starts_with("redis")
            || norm.starts_with("mongo")
            || norm.starts_with("valkey")
            || matches!(
                norm.as_str(),
                "aetherflowrunner" | "runnerdaemon" | "database" | "db"
            )
        {
            return true;
        }
    }
    false
}

fn classify_icon(id: &str, service_id: &str, tier: TopologyTier) -> TopologyIconKind {
    for candidate in [service_id, id] {
        let norm = normalize_slug(candidate);
        if norm.is_empty() {
            continue;
        }
        if matches!(
            norm.as_str(),
            "apache2"
                | "apache2webserver"
                | "nginx"
                | "caddy"
                | "traefik"
                | "haproxy"
                | "gateway"
                | "ingress"
        ) || norm.ends_with("gateway")
            || norm.ends_with("webserver")
        {
            return TopologyIconKind::Gateway;
        }
        if norm.starts_with("sqlite")
            || norm.starts_with("postgres")
            || norm.starts_with("mariadb")
            || norm.starts_with("mysql")
            || norm.starts_with("redis")
            || norm.starts_with("mongo")
            || norm.starts_with("valkey")
            || matches!(norm.as_str(), "database" | "db")
        {
            return TopologyIconKind::Database;
        }
        if matches!(norm.as_str(), "aetherflowrunner" | "runnerdaemon")
            || norm.contains("runner")
            || norm.contains("worker")
        {
            return TopologyIconKind::Runner;
        }
        if matches!(
            norm.as_str(),
            "aetherflowapi" | "aetherflowfrontend" | "aetherflow" | "api"
        ) || norm.ends_with("api")
        {
            return TopologyIconKind::Api;
        }
        if norm.starts_with("jellyfin")
            || norm.starts_with("plex")
            || norm.starts_with("emby")
            || norm.starts_with("sonarr")
            || norm.starts_with("radarr")
            || norm.starts_with("lidarr")
            || norm.starts_with("bazarr")
            || norm.starts_with("prowlarr")
            || norm.starts_with("overseerr")
            || norm.starts_with("jellyseerr")
            || norm.starts_with("navidrome")
            || norm.starts_with("audiobookshelf")
            || norm.starts_with("immich")
            || norm.starts_with("calibre")
            || norm.starts_with("kavita")
            || norm.starts_with("tautulli")
            || norm.contains("media")
        {
            return TopologyIconKind::Media;
        }
        if norm.starts_with("librespeed")
            || norm.starts_with("wireguard")
            || norm.starts_with("tailscale")
            || norm.starts_with("qbittorrent")
            || norm.starts_with("transmission")
            || norm.starts_with("deluge")
            || norm.starts_with("rtorrent")
            || norm.starts_with("sabnzbd")
            || norm.starts_with("nzbget")
            || norm.starts_with("pihole")
            || norm.starts_with("adguard")
            || norm.starts_with("gluetun")
            || norm.contains("speed")
            || norm.contains("vpn")
            || norm.contains("dns")
        {
            return TopologyIconKind::Network;
        }
        if norm.starts_with("nextcloud")
            || norm.starts_with("owncloud")
            || norm.starts_with("syncthing")
            || norm.starts_with("paperless")
            || norm.starts_with("vaultwarden")
            || norm.starts_with("filebrowser")
            || norm.starts_with("minio")
            || norm.starts_with("restic")
            || norm.starts_with("rclone")
            || norm.contains("cloud")
            || norm.contains("storage")
        {
            return TopologyIconKind::Cloud;
        }
    }
    match tier {
        TopologyTier::Gateway => TopologyIconKind::Gateway,
        TopologyTier::Service | TopologyTier::Dependency => TopologyIconKind::Service,
    }
}

fn is_healthy_status(status: &str) -> bool {
    matches!(
        status.to_lowercase().as_str(),
        "running" | "active" | "healthy" | "ok" | "online"
    )
}

fn compute_signal_bars(info: &Value, group: ServiceGroup, status: &str) -> u8 {
    let status_lower = status.to_lowercase();
    let health_lower = info["health"].as_str().unwrap_or("").to_lowercase();
    let job_failed = matches!(
        info["job_status"].as_str(),
        Some("install_failed" | "failed")
    ) || info["last_job"]["status"] == "failed";

    if matches!(status_lower.as_str(), "failed" | "error")
        || health_lower == "unhealthy"
        || job_failed
    {
        return 1;
    }
    if status_lower == "degraded"
        || health_lower == "degraded"
        || info["degraded_components"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    {
        return 2;
    }
    match group {
        ServiceGroup::Exception => 1,
        ServiceGroup::Stopped => 0,
        ServiceGroup::Core | ServiceGroup::Active | ServiceGroup::Other => {
            if is_healthy_status(&status_lower) {
                4
            } else if matches!(
                status_lower.as_str(),
                "stopped" | "inactive" | "disabled" | "offline"
            ) {
                0
            } else {
                2
            }
        }
    }
}

fn format_card_subtitle(
    tier: TopologyTier,
    details: &str,
    status: &str,
    group: ServiceGroup,
    outgoing_count: usize,
) -> String {
    let clean_details = details.trim();
    let details_useful = !clean_details.is_empty() && !clean_details.eq_ignore_ascii_case(status);
    match tier {
        TopologyTier::Gateway => {
            if details_useful {
                clean_details.to_string()
            } else {
                "Gateway".into()
            }
        }
        TopologyTier::Dependency => {
            if details_useful {
                clean_details.to_string()
            } else if group == ServiceGroup::Exception {
                "Degraded".into()
            } else {
                capitalize_word(status)
            }
        }
        TopologyTier::Service => {
            if outgoing_count == 1 {
                "1 link out".into()
            } else if outgoing_count > 1 {
                format!("{outgoing_count} links out")
            } else if details_useful {
                clean_details
                    .split('|')
                    .next()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(clean_details)
                    .to_string()
            } else {
                "No links out".into()
            }
        }
    }
}

fn capitalize_word(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "Unknown".into();
    }
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Unknown".into(),
    }
}

fn extract_port_label(details: &str) -> Option<String> {
    let trimmed = details.trim();
    let rest = trimmed.strip_prefix("Port ")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("Port {digits}"))
    }
}

fn derive_edge_label(
    source: &TopologyCardNode,
    target: &TopologyCardNode,
    kind: TopologyEdgeKind,
    is_two_way: bool,
) -> String {
    if kind == TopologyEdgeKind::Exception {
        let target_status = target.status.to_lowercase();
        let source_status = source.status.to_lowercase();
        if matches!(target_status.as_str(), "failed" | "error")
            || matches!(source_status.as_str(), "failed" | "error")
        {
            return "Failed".into();
        }
        return "Degraded".into();
    }
    if kind == TopologyEdgeKind::Standby {
        if target.group == ServiceGroup::Stopped || source.group == ServiceGroup::Stopped {
            return "Stopped".into();
        }
        return "Standby".into();
    }
    if is_two_way {
        return "Two-way".into();
    }

    let target_norm = normalize_slug(&target.id);
    let target_sid = normalize_slug(&target.service_id);
    if target.icon == TopologyIconKind::Database {
        if target_norm.contains("sqlite") || target_sid.contains("sqlite") {
            return "SQLite".into();
        }
        if target_norm.contains("postgres") || target_sid.contains("postgres") {
            return "Postgres".into();
        }
        if target_norm.contains("redis") || target_sid.contains("redis") {
            return "Redis".into();
        }
        return "Database".into();
    }
    if target.icon == TopologyIconKind::Runner {
        return "Socket".into();
    }
    if source.tier == TopologyTier::Gateway {
        if target.icon == TopologyIconKind::Api || is_core_service(&target.id) {
            return "Core".into();
        }
        if target.details.contains('|') {
            return "HTTPS".into();
        }
        if let Some(port) = extract_port_label(&target.details) {
            return port;
        }
        return "Proxy".into();
    }
    if let Some(port) = extract_port_label(&target.details) {
        return port;
    }
    if target.tier == TopologyTier::Dependency {
        return "Link".into();
    }
    "Direct".into()
}

fn card_dimensions(tier: TopologyTier) -> (f64, f64) {
    match tier {
        TopologyTier::Gateway => (GATEWAY_WIDTH, GATEWAY_HEIGHT),
        TopologyTier::Service => (SERVICE_WIDTH, SERVICE_HEIGHT),
        TopologyTier::Dependency => (DEPENDENCY_WIDTH, DEPENDENCY_HEIGHT),
    }
}

fn tier_pitch(tier: TopologyTier) -> f64 {
    match tier {
        TopologyTier::Gateway => GATEWAY_PITCH,
        TopologyTier::Service => SERVICE_PITCH,
        TopologyTier::Dependency => DEPENDENCY_PITCH,
    }
}

fn column_gap(left: TopologyTier, right: TopologyTier) -> f64 {
    match (left, right) {
        (TopologyTier::Gateway, TopologyTier::Service) => GAP_GATEWAY_TO_SERVICE,
        (TopologyTier::Service, TopologyTier::Dependency) => GAP_SERVICE_TO_DEPENDENCY,
        _ => GAP_GATEWAY_TO_DEPENDENCY,
    }
}

fn cubic_bezier_point(p0: f64, p1: f64, p2: f64, p3: f64, t: f64) -> f64 {
    let u = 1.0 - t;
    u * u * u * p0 + 3.0 * u * u * t * p1 + 3.0 * u * t * t * p2 + t * t * t * p3
}

fn estimate_pill_width(label: &str) -> f64 {
    ((label.chars().count() as f64) * 7.6 + 24.0).max(58.0)
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

struct CanonicalEdge {
    source: String,
    target: String,
    is_two_way: bool,
    same_column: bool,
}

/// Deterministic, link-aware 3-tier left-to-right column layout inspired by T3 Code's Environments Map.
pub fn compute_tiered_topology_layout(
    services: &[(String, Value)],
    links: &[(String, String)],
) -> TieredTopologyLayout {
    if services.is_empty() {
        return TieredTopologyLayout {
            width: MIN_CANVAS_WIDTH,
            height: MIN_CANVAS_HEIGHT,
            columns: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
        };
    }

    // Deduplicate and order services deterministically so output is strictly order-independent.
    let mut service_map: BTreeMap<String, Value> = BTreeMap::new();
    for (id, info) in services {
        service_map
            .entry(id.clone())
            .or_insert_with(|| info.clone());
    }

    // Filter and deduplicate links (ignore self-loops and missing endpoints).
    let mut directed_links: BTreeSet<(String, String)> = BTreeSet::new();
    for (src, dst) in links {
        if src != dst && service_map.contains_key(src) && service_map.contains_key(dst) {
            directed_links.insert((src.clone(), dst.clone()));
        }
    }

    let mut incoming: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut outgoing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in service_map.keys() {
        incoming.insert(id.clone(), Vec::new());
        outgoing.insert(id.clone(), Vec::new());
    }
    for (src, dst) in &directed_links {
        if let Some(list) = outgoing.get_mut(src) {
            list.push(dst.clone());
        }
        if let Some(list) = incoming.get_mut(dst) {
            list.push(src.clone());
        }
    }

    // Step 1: Assign tiers deterministically.
    let mut tiers: BTreeMap<String, TopologyTier> = BTreeMap::new();
    let mut has_explicit_gateway = false;
    for (id, info) in &service_map {
        let sid = info["service_id"].as_str().unwrap_or(id.as_str());
        if is_gateway_node(id, sid, info) {
            tiers.insert(id.clone(), TopologyTier::Gateway);
            has_explicit_gateway = true;
        }
    }
    if !has_explicit_gateway && !directed_links.is_empty() {
        for (id, info) in &service_map {
            let sid = info["service_id"].as_str().unwrap_or(id.as_str());
            let in_deg = incoming.get(id).map_or(0, Vec::len);
            let out_deg = outgoing.get(id).map_or(0, Vec::len);
            if out_deg > 0 && in_deg == 0 && !is_dependency_node(id, sid, info) {
                tiers.insert(id.clone(), TopologyTier::Gateway);
            }
        }
    }
    for (id, info) in &service_map {
        if tiers.contains_key(id) {
            continue;
        }
        let sid = info["service_id"].as_str().unwrap_or(id.as_str());
        if is_dependency_node(id, sid, info) {
            tiers.insert(id.clone(), TopologyTier::Dependency);
        } else {
            tiers.insert(id.clone(), TopologyTier::Service);
        }
    }

    // Promote downstream leaf nodes fed by Tier 1 (not directly by Gateway) into Dependency.
    let mut promoted_deps = Vec::new();
    for (id, &tier) in &tiers {
        if tier != TopologyTier::Service {
            continue;
        }
        let in_list = &incoming[id];
        let out_deg = outgoing[id].len();
        if !in_list.is_empty()
            && out_deg == 0
            && in_list
                .iter()
                .all(|src| tiers.get(src) == Some(&TopologyTier::Service))
        {
            promoted_deps.push(id.clone());
        }
    }
    for id in promoted_deps {
        tiers.insert(id, TopologyTier::Dependency);
    }

    // Build initial card metadata (positions populated below).
    let mut cards: BTreeMap<String, TopologyCardNode> = BTreeMap::new();
    for (id, info) in &service_map {
        let tier = tiers[id];
        let service_id = info["service_id"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(id.as_str())
            .to_string();
        let label = format_service_name(id);
        let details = info["details"].as_str().unwrap_or("").trim().to_string();
        let status_raw = info["status"].as_str().unwrap_or("").trim();
        let status = if status_raw.is_empty() {
            "unknown".to_string()
        } else {
            status_raw.to_string()
        };
        let group = service_group(id, info);
        let icon = classify_icon(id, &service_id, tier);
        let outgoing_count = outgoing[id].len();
        let incoming_count = incoming[id].len();
        let signal_bars = compute_signal_bars(info, group, &status);
        let dashed_border = tier == TopologyTier::Dependency
            && (group == ServiceGroup::Stopped
                || group == ServiceGroup::Exception
                || group == ServiceGroup::Other
                || !is_healthy_status(&status));
        let subtitle = format_card_subtitle(tier, &details, &status, group, outgoing_count);
        let (width, height) = card_dimensions(tier);

        cards.insert(
            id.clone(),
            TopologyCardNode {
                id: id.clone(),
                service_id,
                label,
                subtitle,
                details,
                status,
                group,
                tier,
                icon,
                x: 0.0,
                y: 0.0,
                width,
                height,
                outgoing_count,
                incoming_count,
                signal_bars,
                dashed_border,
            },
        );
    }

    // Group node IDs per tier.
    let mut gateway_ids: Vec<String> = Vec::new();
    let mut service_ids: Vec<String> = Vec::new();
    let mut dependency_ids: Vec<String> = Vec::new();
    for (id, card) in &cards {
        match card.tier {
            TopologyTier::Gateway => gateway_ids.push(id.clone()),
            TopologyTier::Service => service_ids.push(id.clone()),
            TopologyTier::Dependency => dependency_ids.push(id.clone()),
        }
    }

    // Order Tier 1 (Service) first: nodes linking out to Dependencies or peers sit near the top,
    // followed by Core, connected services, and isolated services, tie-broken lexicographically.
    service_ids.sort_by(|a, b| {
        let dep_out_a = outgoing[a]
            .iter()
            .filter(|t| tiers.get(*t) == Some(&TopologyTier::Dependency))
            .count();
        let dep_out_b = outgoing[b]
            .iter()
            .filter(|t| tiers.get(*t) == Some(&TopologyTier::Dependency))
            .count();
        let out_a = outgoing[a].len();
        let out_b = outgoing[b].len();
        let core_a = is_core_service(a);
        let core_b = is_core_service(b);
        let conn_a = (incoming[a].len() + out_a) > 0;
        let conn_b = (incoming[b].len() + out_b) > 0;
        dep_out_b
            .cmp(&dep_out_a)
            .then_with(|| out_b.cmp(&out_a))
            .then_with(|| core_b.cmp(&core_a))
            .then_with(|| conn_b.cmp(&conn_a))
            .then_with(|| cards[a].label.cmp(&cards[b].label))
            .then_with(|| a.cmp(b))
    });

    let service_rank: BTreeMap<String, usize> = service_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id.clone(), idx))
        .collect();

    // Order Gateway and Dependency columns by barycenter of their Tier 1 neighbors to avoid crossings.
    gateway_ids.sort_by(|a, b| {
        let avg_a = average_rank(&outgoing[a], &service_rank);
        let avg_b = average_rank(&outgoing[b], &service_rank);
        avg_a
            .total_cmp(&avg_b)
            .then_with(|| cards[a].label.cmp(&cards[b].label))
            .then_with(|| a.cmp(b))
    });
    dependency_ids.sort_by(|a, b| {
        let avg_a = average_rank(&incoming[a], &service_rank);
        let avg_b = average_rank(&incoming[b], &service_rank);
        avg_a
            .total_cmp(&avg_b)
            .then_with(|| cards[a].label.cmp(&cards[b].label))
            .then_with(|| a.cmp(b))
    });

    // Determine active columns (collapse completely empty tiers).
    let mut active_tiers: Vec<(TopologyTier, Vec<String>)> = Vec::new();
    if !gateway_ids.is_empty() {
        active_tiers.push((TopologyTier::Gateway, gateway_ids));
    }
    if !service_ids.is_empty() {
        active_tiers.push((TopologyTier::Service, service_ids));
    }
    if !dependency_ids.is_empty() {
        active_tiers.push((TopologyTier::Dependency, dependency_ids));
    }

    // Check whether the leftmost active column has any same-column edges so we reserve left room for U-curves.
    let leftmost_tier = active_tiers[0].0;
    let leftmost_has_same_col_edge = directed_links
        .iter()
        .any(|(s, t)| tiers[s] == leftmost_tier && tiers[t] == leftmost_tier);
    let left_pad = if leftmost_has_same_col_edge {
        SAME_COL_LEFT_PAD
    } else {
        PAD_X
    };

    // Compute horizontal X positions for each active column.
    let mut col_center_x: BTreeMap<TopologyTier, f64> = BTreeMap::new();
    let mut col_left_x: BTreeMap<TopologyTier, f64> = BTreeMap::new();
    let mut cursor_x = left_pad;
    let mut prev_tier: Option<TopologyTier> = None;
    for (tier, _) in &active_tiers {
        if let Some(prev) = prev_tier {
            cursor_x += column_gap(prev, *tier);
        }
        let (col_w, _) = card_dimensions(*tier);
        col_left_x.insert(*tier, cursor_x);
        col_center_x.insert(*tier, cursor_x + col_w / 2.0);
        cursor_x += col_w;
        prev_tier = Some(*tier);
    }
    let natural_width = cursor_x + PAD_X;

    // Compute column vertical spans and tallest column span.
    let mut max_span: f64 = 0.0;
    for (tier, ids) in &active_tiers {
        let (_, card_h) = card_dimensions(*tier);
        let pitch = tier_pitch(*tier);
        let span = if ids.is_empty() {
            0.0
        } else {
            (ids.len() - 1) as f64 * pitch + card_h
        };
        max_span = max_span.max(span);
    }

    // Place Tier 1 (Service) first as vertical reference.
    if let Some((_, ids)) = active_tiers
        .iter()
        .find(|(tier, _)| *tier == TopologyTier::Service)
    {
        let span = (ids.len() - 1) as f64 * SERVICE_PITCH + SERVICE_HEIGHT;
        let top_y = TOP_CONTENT_Y + (max_span - span) / 2.0;
        let cx = col_center_x[&TopologyTier::Service];
        for (idx, id) in ids.iter().enumerate() {
            if let Some(card) = cards.get_mut(id) {
                card.x = cx;
                card.y = top_y + SERVICE_HEIGHT / 2.0 + idx as f64 * SERVICE_PITCH;
            }
        }
    }

    // Place Tier 0 (Gateway) vertically centered against the tallest column.
    if let Some((_, ids)) = active_tiers
        .iter()
        .find(|(tier, _)| *tier == TopologyTier::Gateway)
    {
        let span = (ids.len() - 1) as f64 * GATEWAY_PITCH + GATEWAY_HEIGHT;
        let top_y = TOP_CONTENT_Y + (max_span - span) / 2.0;
        let cx = col_center_x[&TopologyTier::Gateway];
        for (idx, id) in ids.iter().enumerate() {
            if let Some(card) = cards.get_mut(id) {
                card.x = cx;
                card.y = top_y + GATEWAY_HEIGHT / 2.0 + idx as f64 * GATEWAY_PITCH;
            }
        }
    }

    // Place Tier 2 (Dependency): align to the mean Y of incoming Tier 1 parents when connected,
    // mirroring T3 Code's horizontal alignment of Linked machines with their parent Environment.
    if let Some((_, ids)) = active_tiers
        .iter()
        .find(|(tier, _)| *tier == TopologyTier::Dependency)
    {
        let span = (ids.len() - 1) as f64 * DEPENDENCY_PITCH + DEPENDENCY_HEIGHT;
        let parent_ys: Vec<f64> = ids
            .iter()
            .flat_map(|id| incoming[id].iter())
            .filter(|src| tiers.get(*src) == Some(&TopologyTier::Service))
            .filter_map(|src| cards.get(src).map(|c| c.y))
            .collect();
        let top_y = if !parent_ys.is_empty() {
            let mean_parent_y = parent_ys.iter().sum::<f64>() / parent_ys.len() as f64;
            let ideal_top = mean_parent_y - span / 2.0;
            let min_top = TOP_CONTENT_Y;
            let max_top = (TOP_CONTENT_Y + max_span - span).max(min_top);
            ideal_top.clamp(min_top, max_top)
        } else {
            TOP_CONTENT_Y + (max_span - span) / 2.0
        };
        let cx = col_center_x[&TopologyTier::Dependency];
        for (idx, id) in ids.iter().enumerate() {
            if let Some(card) = cards.get_mut(id) {
                card.x = cx;
                card.y = top_y + DEPENDENCY_HEIGHT / 2.0 + idx as f64 * DEPENDENCY_PITCH;
            }
        }
    }

    // Compute final canvas bounds and center smaller topologies cleanly.
    let max_card_bottom = cards
        .values()
        .map(|c| c.y + c.height / 2.0)
        .fold(TOP_CONTENT_Y, f64::max);
    let natural_height = max_card_bottom + PAD_BOTTOM;

    let width = natural_width.max(MIN_CANVAS_WIDTH);
    let height = natural_height.max(MIN_CANVAS_HEIGHT);
    let offset_x = ((width - natural_width) / 2.0).max(0.0);
    let offset_y = ((height - natural_height) / 2.0).max(0.0);

    for card in cards.values_mut() {
        card.x = round1(card.x + offset_x);
        card.y = round1(card.y + offset_y);
    }

    let min_card_top = cards
        .values()
        .map(|c| c.y - c.height / 2.0)
        .fold(f64::INFINITY, f64::min);
    let header_y = if min_card_top.is_finite() {
        round1((min_card_top - 26.0).max(HEADER_Y))
    } else {
        HEADER_Y
    };

    let columns: Vec<TopologyColumnHeader> = active_tiers
        .iter()
        .map(|(tier, _)| TopologyColumnHeader {
            tier: *tier,
            label_key: tier.label_key(),
            x: round1(col_left_x[tier] + offset_x),
            y: header_y,
        })
        .collect();

    // Canonicalize edges: collapse bidirectional pairs (A->B and B->A) into a single TwoWay edge.
    let mut visited_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    let mut canonical_edges: Vec<CanonicalEdge> = Vec::new();
    for (src, dst) in &directed_links {
        let pair_key = if src < dst {
            (src.clone(), dst.clone())
        } else {
            (dst.clone(), src.clone())
        };
        if !visited_pairs.insert(pair_key) {
            continue;
        }
        let has_reverse = directed_links.contains(&(dst.clone(), src.clone()));
        let same_column = cards[src].tier == cards[dst].tier;
        let (ordered_src, ordered_dst) = if same_column {
            // Top card first so U-curves orient consistently top -> bottom.
            if cards[src].y < cards[dst].y
                || ((cards[src].y - cards[dst].y).abs() < f64::EPSILON && src < dst)
            {
                (src.clone(), dst.clone())
            } else {
                (dst.clone(), src.clone())
            }
        } else if has_reverse {
            // Leftmost tier first for cross-column bidirectional links.
            if cards[src].tier <= cards[dst].tier {
                (src.clone(), dst.clone())
            } else {
                (dst.clone(), src.clone())
            }
        } else {
            (src.clone(), dst.clone())
        };
        canonical_edges.push(CanonicalEdge {
            source: ordered_src,
            target: ordered_dst,
            is_two_way: has_reverse || same_column,
            same_column,
        });
    }

    // Sort canonical edges deterministically by source tier, source Y, target Y, then IDs.
    canonical_edges.sort_by(|a, b| {
        let sa = &cards[&a.source];
        let sb = &cards[&b.source];
        let ta = &cards[&a.target];
        let tb = &cards[&b.target];
        sa.tier
            .cmp(&sb.tier)
            .then_with(|| sa.y.total_cmp(&sb.y))
            .then_with(|| ta.y.total_cmp(&tb.y))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.target.cmp(&b.target))
    });

    // Compute per-node outgoing and incoming port orderings for cross-column edges.
    let mut out_ports: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut in_ports: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, edge) in canonical_edges.iter().enumerate() {
        if !edge.same_column {
            out_ports.entry(edge.source.clone()).or_default().push(idx);
            in_ports.entry(edge.target.clone()).or_default().push(idx);
        }
    }
    for indices in out_ports.values_mut() {
        indices.sort_by(|&i, &j| {
            let ti = &cards[&canonical_edges[i].target];
            let tj = &cards[&canonical_edges[j].target];
            ti.y.total_cmp(&tj.y)
                .then_with(|| canonical_edges[i].target.cmp(&canonical_edges[j].target))
        });
    }
    for indices in in_ports.values_mut() {
        indices.sort_by(|&i, &j| {
            let si = &cards[&canonical_edges[i].source];
            let sj = &cards[&canonical_edges[j].source];
            si.y.total_cmp(&sj.y)
                .then_with(|| canonical_edges[i].source.cmp(&canonical_edges[j].source))
        });
    }

    // Route edges with smooth cubic Béziers.
    let mut same_col_slot: BTreeMap<TopologyTier, usize> = BTreeMap::new();
    let mut routes: Vec<TopologyEdgeRoute> = Vec::with_capacity(canonical_edges.len());

    for (idx, edge) in canonical_edges.iter().enumerate() {
        let src = &cards[&edge.source];
        let dst = &cards[&edge.target];

        let kind = if edge.is_two_way {
            TopologyEdgeKind::TwoWay
        } else if src.group == ServiceGroup::Exception || dst.group == ServiceGroup::Exception {
            TopologyEdgeKind::Exception
        } else if src.group == ServiceGroup::Stopped
            || dst.group == ServiceGroup::Stopped
            || src.group == ServiceGroup::Other
            || dst.group == ServiceGroup::Other
            || !is_healthy_status(&src.status)
            || !is_healthy_status(&dst.status)
        {
            TopologyEdgeKind::Standby
        } else {
            TopologyEdgeKind::Active
        };

        let label = derive_edge_label(src, dst, kind, edge.is_two_way);
        let has_arrow = edge.is_two_way
            || kind == TopologyEdgeKind::Exception
            || dst.tier == TopologyTier::Dependency;

        if edge.same_column {
            let slot = same_col_slot.entry(src.tier).or_insert(0);
            let slot_idx = *slot;
            *slot += 1;

            let x1 = round1(src.x - src.width / 2.0);
            let y1 = round1(src.y + 10.0);
            let x2 = round1(dst.x - dst.width / 2.0);
            let y2 = round1(dst.y - 10.0);
            let bow = 38.0 + 16.0 * slot_idx as f64;
            let cx = round1(x1 - bow);
            let path_d = format!("M {x1},{y1} C {cx},{y1} {cx},{y2} {x2},{y2}");
            let label_x = round1(cubic_bezier_point(x1, cx, cx, x2, 0.5));
            let label_y = round1((y1 + y2) / 2.0);

            routes.push(TopologyEdgeRoute {
                source: edge.source.clone(),
                target: edge.target.clone(),
                label,
                kind,
                x1,
                y1,
                x2,
                y2,
                path_d,
                label_x,
                label_y,
                is_two_way: edge.is_two_way,
                has_arrow,
            });
        } else {
            let forward = src.x <= dst.x;
            let x1 = round1(if forward {
                src.x + src.width / 2.0
            } else {
                src.x - src.width / 2.0
            });
            let x2 = round1(if forward {
                dst.x - dst.width / 2.0
            } else {
                dst.x + dst.width / 2.0
            });

            let out_offset = port_offset(
                &out_ports[&edge.source],
                idx,
                if src.tier == TopologyTier::Gateway {
                    12.0
                } else {
                    6.0
                },
            );
            let in_offset = port_offset(&in_ports[&edge.target], idx, 10.0);
            let y1 = round1(src.y + out_offset);
            let y2 = round1(dst.y + in_offset);

            let dx = x2 - x1;
            let cx1 = round1(x1 + dx * 0.42);
            let cx2 = round1(x1 + dx * 0.48);
            let path_d = format!("M {x1},{y1} C {cx1},{y1} {cx2},{y2} {x2},{y2}");

            // Place pill slightly toward target card (just like T3 Code's fanned pills)
            // so multi-edge fan-outs have generous vertical separation.
            let t_label = if out_ports[&edge.source].len() > 2 {
                0.66
            } else {
                0.56
            };
            let label_x = round1(cubic_bezier_point(x1, cx1, cx2, x2, t_label));
            let label_y = round1(cubic_bezier_point(y1, y1, y2, y2, t_label));

            routes.push(TopologyEdgeRoute {
                source: edge.source.clone(),
                target: edge.target.clone(),
                label,
                kind,
                x1,
                y1,
                x2,
                y2,
                path_d,
                label_x,
                label_y,
                is_two_way: edge.is_two_way,
                has_arrow,
            });
        }
    }

    // Guarantee non-overlapping edge pill positions even on dense or multi-source graphs.
    deoverlap_edge_pills(&mut routes, height);

    // Emit nodes in clean column-top-to-bottom deterministic order.
    let mut ordered_nodes: Vec<TopologyCardNode> = Vec::with_capacity(cards.len());
    for (_, ids) in &active_tiers {
        for id in ids {
            if let Some(card) = cards.remove(id) {
                ordered_nodes.push(card);
            }
        }
    }

    TieredTopologyLayout {
        width: round1(width),
        height: round1(height),
        columns,
        nodes: ordered_nodes,
        edges: routes,
    }
}

fn average_rank(neighbors: &[String], ranks: &BTreeMap<String, usize>) -> f64 {
    let mut sum = 0.0;
    let mut count = 0usize;
    for neighbor in neighbors {
        if let Some(&rank) = ranks.get(neighbor) {
            sum += rank as f64;
            count += 1;
        }
    }
    if count == 0 {
        f64::INFINITY
    } else {
        sum / count as f64
    }
}

fn port_offset(port_list: &[usize], edge_idx: usize, max_half_band: f64) -> f64 {
    let count = port_list.len();
    if count <= 1 {
        return 0.0;
    }
    let pos = port_list.iter().position(|&i| i == edge_idx).unwrap_or(0);
    let band = max_half_band.min((count - 1) as f64 * 4.5);
    let t = (pos as f64) / ((count - 1) as f64) - 0.5;
    t * 2.0 * band
}

fn deoverlap_edge_pills(routes: &mut [TopologyEdgeRoute], canvas_height: f64) {
    if routes.len() < 2 {
        return;
    }
    const MIN_DY: f64 = 30.0;
    const HORIZ_MARGIN: f64 = 8.0;
    let min_y = TOP_CONTENT_Y - 12.0;
    let max_y = (canvas_height - 18.0).max(min_y + MIN_DY);

    for _ in 0..24 {
        let mut moved = false;
        for i in 0..routes.len() {
            for j in (i + 1)..routes.len() {
                let half_w = (estimate_pill_width(&routes[i].label)
                    + estimate_pill_width(&routes[j].label))
                    / 2.0
                    + HORIZ_MARGIN;
                if (routes[i].label_x - routes[j].label_x).abs() < half_w {
                    let dy = routes[j].label_y - routes[i].label_y;
                    if dy.abs() < MIN_DY {
                        let push = (MIN_DY - dy.abs()) / 2.0 + 0.5;
                        if dy >= 0.0 {
                            routes[i].label_y =
                                round1((routes[i].label_y - push).clamp(min_y, max_y));
                            routes[j].label_y =
                                round1((routes[j].label_y + push).clamp(min_y, max_y));
                        } else {
                            routes[i].label_y =
                                round1((routes[i].label_y + push).clamp(min_y, max_y));
                            routes[j].label_y =
                                round1((routes[j].label_y - push).clamp(min_y, max_y));
                        }
                        moved = true;
                    }
                }
            }
        }
        if !moved {
            break;
        }
    }
}

/// Case-insensitive multi-token search matcher across service identity, status, details, tier, and group.
pub fn matches_topology_query(node: &TopologyCardNode, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return true;
    }
    let tier_tokens = match node.tier {
        TopologyTier::Gateway => "gateway ingress proxy",
        TopologyTier::Service => "service services environment",
        TopologyTier::Dependency => "dependency dependencies linked",
    };
    let group_tokens = match node.group {
        ServiceGroup::Core => "core platform",
        ServiceGroup::Active => "active running healthy",
        ServiceGroup::Stopped => "stopped inactive offline standby",
        ServiceGroup::Exception => "exception degraded failed error unhealthy",
        ServiceGroup::Other => "other standby unknown",
    };
    let haystack = format!(
        "{} {} {} {} {} {} {} {}",
        node.id,
        node.service_id,
        node.label,
        node.subtitle,
        node.details,
        node.status,
        tier_tokens,
        group_tokens
    )
    .to_lowercase();

    trimmed
        .split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_groups_follow_health_and_core_contracts() {
        assert!(is_core_service(" AetherFlow_API"));
        assert_eq!(
            service_group("nginx", &json!({"status":"running"})),
            ServiceGroup::Core
        );
        assert_eq!(
            service_group("sonarr", &json!({"status":"error"})),
            ServiceGroup::Exception
        );
        assert_eq!(
            service_group("x", &json!({"status":"stopped"})),
            ServiceGroup::Stopped
        );
    }

    #[test]
    fn exception_catches_install_and_component_failures() {
        for info in [
            json!({"last_job":{"action":"install","error":"failed"}}),
            json!({"health":"unhealthy"}),
            json!({"degraded_components":["db"]}),
            json!({"job_status":"install_failed"}),
        ] {
            assert!(is_service_exception(&info));
        }
        assert!(!is_service_exception(&json!({"status":"running"})));
    }

    #[test]
    fn layout_is_deterministic_bounded_and_order_independent() {
        let mut services = vec![("b".into(), json!({})), ("a".into(), json!({}))];
        let a = compute_topology_layout(&services, 800.0, 400.0);
        services.reverse();
        assert_eq!(a, compute_topology_layout(&services, 800.0, 400.0));
        assert!(a
            .iter()
            .all(|n| n.x >= 60.0 && n.x <= 740.0 && n.y.is_finite()));
        assert!(compute_topology_layout(&[], f64::NAN, 0.0).is_empty());
    }

    #[test]
    fn names_preserve_known_brands() {
        assert_eq!(format_service_name("qbittorrent"), "qBittorrent");
        assert_eq!(format_service_name("new_service"), "New Service");
        assert_eq!(
            format_service_name("aetherflow-runner"),
            "AetherFlow Runner"
        );
    }

    #[test]
    fn tiered_layout_places_seven_node_production_topology_cleanly() {
        let mut services = vec![
            (
                "Apache2 Web Server".into(),
                json!({"service_id":"apache2","group":3,"status":"running","details":"Port 443"}),
            ),
            (
                "AetherFlow API".into(),
                json!({"service_id":"aetherflow-api","group":1,"status":"running","details":"Port 8080"}),
            ),
            (
                "Jellyfin".into(),
                json!({"service_id":"jellyfin","group":4,"status":"running","details":"Port 8096 | media.example.com"}),
            ),
            (
                "LibreSpeed".into(),
                json!({"service_id":"librespeed","group":4,"status":"running","details":"Port 8081"}),
            ),
            (
                "Nextcloud".into(),
                json!({"service_id":"nextcloud","group":4,"status":"degraded","details":"Port 8443"}),
            ),
            (
                "AetherFlow Runner".into(),
                json!({"service_id":"aetherflow-runner","group":1,"status":"running","details":"Privileged runner socket"}),
            ),
            (
                "SQLite WAL".into(),
                json!({"group":2,"status":"running","details":"SQLite (WAL mode)"}),
            ),
        ];
        let mut links = vec![
            ("Apache2 Web Server".into(), "AetherFlow API".into()),
            ("Apache2 Web Server".into(), "Jellyfin".into()),
            ("Apache2 Web Server".into(), "LibreSpeed".into()),
            ("Apache2 Web Server".into(), "Nextcloud".into()),
            ("AetherFlow API".into(), "AetherFlow Runner".into()),
            ("AetherFlow API".into(), "SQLite WAL".into()),
        ];

        let layout = compute_tiered_topology_layout(&services, &links);
        assert_eq!(layout.columns.len(), 3);
        assert_eq!(layout.columns[0].tier, TopologyTier::Gateway);
        assert_eq!(layout.columns[1].tier, TopologyTier::Service);
        assert_eq!(layout.columns[2].tier, TopologyTier::Dependency);
        assert_eq!(layout.nodes.len(), 7);
        assert_eq!(layout.edges.len(), 6);

        let node = |id: &str| layout.nodes.iter().find(|n| n.id == id).unwrap();
        assert_eq!(node("Apache2 Web Server").tier, TopologyTier::Gateway);
        assert_eq!(node("Apache2 Web Server").icon, TopologyIconKind::Gateway);
        assert_eq!(node("Apache2 Web Server").outgoing_count, 4);

        assert_eq!(node("AetherFlow API").tier, TopologyTier::Service);
        assert_eq!(node("AetherFlow API").icon, TopologyIconKind::Api);
        assert_eq!(node("AetherFlow API").outgoing_count, 2);
        assert_eq!(node("Jellyfin").icon, TopologyIconKind::Media);
        assert_eq!(node("LibreSpeed").icon, TopologyIconKind::Network);
        assert_eq!(node("Nextcloud").icon, TopologyIconKind::Cloud);
        assert_eq!(node("Nextcloud").group, ServiceGroup::Exception);
        assert_eq!(node("Nextcloud").signal_bars, 2);

        assert_eq!(node("AetherFlow Runner").tier, TopologyTier::Dependency);
        assert_eq!(node("AetherFlow Runner").icon, TopologyIconKind::Runner);
        assert!(!node("AetherFlow Runner").dashed_border);
        assert_eq!(node("SQLite WAL").tier, TopologyTier::Dependency);
        assert_eq!(node("SQLite WAL").icon, TopologyIconKind::Database);
        assert_eq!(node("SQLite WAL").signal_bars, 4);

        // Columns must flow strictly left-to-right.
        assert!(node("Apache2 Web Server").x < node("AetherFlow API").x);
        assert!(node("AetherFlow API").x < node("SQLite WAL").x);

        // Edge kinds and labels.
        let edge = |s: &str, t: &str| {
            layout
                .edges
                .iter()
                .find(|e| e.source == s && e.target == t)
                .unwrap()
        };
        assert_eq!(edge("Apache2 Web Server", "AetherFlow API").label, "Core");
        assert_eq!(edge("Apache2 Web Server", "Jellyfin").label, "HTTPS");
        assert_eq!(edge("Apache2 Web Server", "LibreSpeed").label, "Port 8081");
        assert_eq!(
            edge("Apache2 Web Server", "Nextcloud").kind,
            TopologyEdgeKind::Exception
        );
        assert!(edge("Apache2 Web Server", "Nextcloud").has_arrow);
        assert_eq!(edge("AetherFlow API", "AetherFlow Runner").label, "Socket");
        assert!(edge("AetherFlow API", "AetherFlow Runner").has_arrow);
        assert_eq!(edge("AetherFlow API", "SQLite WAL").label, "SQLite");
        assert!(edge("AetherFlow API", "SQLite WAL")
            .path_d
            .starts_with("M "));

        // Exact order independence.
        services.reverse();
        links.reverse();
        assert_eq!(layout, compute_tiered_topology_layout(&services, &links));
    }

    #[test]
    fn tiered_layout_handles_gateway_chain_and_isolated_service() {
        let services = vec![
            ("Gateway".into(), json!({"status":"running"})),
            ("Service A".into(), json!({"status":"running"})),
            ("Service B".into(), json!({"status":"stopped"})),
            ("Isolated".into(), json!({"status":"running"})),
        ];
        let links = vec![
            ("Gateway".into(), "Service A".into()),
            ("Service A".into(), "Service B".into()),
        ];

        let layout = compute_tiered_topology_layout(&services, &links);
        assert_eq!(layout.columns.len(), 3);
        assert_eq!(layout.nodes.len(), 4);
        assert_eq!(layout.edges.len(), 2);

        let node = |id: &str| layout.nodes.iter().find(|n| n.id == id).unwrap();
        assert_eq!(node("Gateway").tier, TopologyTier::Gateway);
        assert_eq!(node("Service A").tier, TopologyTier::Service);
        assert_eq!(node("Isolated").tier, TopologyTier::Service);
        assert_eq!(node("Service B").tier, TopologyTier::Dependency);
        assert!(node("Service B").dashed_border);
        assert_eq!(node("Service B").signal_bars, 0);

        let dep_edge = layout
            .edges
            .iter()
            .find(|e| e.source == "Service A" && e.target == "Service B")
            .unwrap();
        assert_eq!(dep_edge.kind, TopologyEdgeKind::Standby);
        assert_eq!(dep_edge.label, "Stopped");
        assert!(dep_edge.has_arrow);
    }

    #[test]
    fn tiered_layout_collapses_empty_columns_for_unlinked_and_empty_inputs() {
        let empty = compute_tiered_topology_layout(&[], &[]);
        assert!(empty.nodes.is_empty());
        assert!(empty.edges.is_empty());
        assert!(empty.columns.is_empty());
        assert!(empty.width >= MIN_CANVAS_WIDTH);
        assert!(empty.height >= MIN_CANVAS_HEIGHT);

        let services = vec![
            ("Alpha".into(), json!({"status":"running"})),
            ("Beta".into(), json!({"status":"running"})),
        ];
        let unlinked = compute_tiered_topology_layout(&services, &[]);
        assert_eq!(unlinked.columns.len(), 1);
        assert_eq!(unlinked.columns[0].tier, TopologyTier::Service);
        assert_eq!(unlinked.nodes.len(), 2);
        assert!(unlinked.edges.is_empty());
        // Centered horizontally inside the canvas.
        assert!((unlinked.nodes[0].x - unlinked.width / 2.0).abs() < 1.0);
    }

    #[test]
    fn tiered_layout_routes_bidirectional_and_same_column_links_as_two_way() {
        let services = vec![
            ("Gateway".into(), json!({"status":"running"})),
            ("Node Alpha".into(), json!({"status":"running"})),
            ("Node Beta".into(), json!({"status":"running"})),
        ];
        let links = vec![
            ("Gateway".into(), "Node Alpha".into()),
            ("Gateway".into(), "Node Beta".into()),
            ("Node Alpha".into(), "Node Beta".into()),
            ("Node Beta".into(), "Node Alpha".into()),
        ];

        let layout = compute_tiered_topology_layout(&services, &links);
        assert_eq!(layout.edges.len(), 3);
        let peer_edge = layout
            .edges
            .iter()
            .find(|e| e.is_two_way)
            .expect("expected collapsed two-way edge");
        assert_eq!(peer_edge.kind, TopologyEdgeKind::TwoWay);
        assert!(peer_edge.has_arrow);
        assert_eq!(peer_edge.label, "Two-way");
        // Left-bowing U-curve stays to the left of the column cards.
        let alpha = layout.nodes.iter().find(|n| n.id == "Node Alpha").unwrap();
        assert!(peer_edge.label_x < alpha.x - alpha.width / 2.0);
    }

    #[test]
    fn edge_pills_never_overlap_on_fanned_topology() {
        let services = vec![
            ("Apache2 Web Server".into(), json!({"status":"running"})),
            ("Svc 1".into(), json!({"status":"running"})),
            ("Svc 2".into(), json!({"status":"running"})),
            ("Svc 3".into(), json!({"status":"running"})),
            ("Svc 4".into(), json!({"status":"running"})),
            ("Svc 5".into(), json!({"status":"failed"})),
        ];
        let links = vec![
            ("Apache2 Web Server".into(), "Svc 1".into()),
            ("Apache2 Web Server".into(), "Svc 2".into()),
            ("Apache2 Web Server".into(), "Svc 3".into()),
            ("Apache2 Web Server".into(), "Svc 4".into()),
            ("Apache2 Web Server".into(), "Svc 5".into()),
        ];

        let layout = compute_tiered_topology_layout(&services, &links);
        assert_eq!(layout.edges.len(), 5);
        for i in 0..layout.edges.len() {
            for j in (i + 1)..layout.edges.len() {
                let a = &layout.edges[i];
                let b = &layout.edges[j];
                let half_w = (estimate_pill_width(&a.label) + estimate_pill_width(&b.label)) / 2.0;
                let overlaps_x = (a.label_x - b.label_x).abs() < half_w;
                let overlaps_y = (a.label_y - b.label_y).abs() < 26.0;
                assert!(
                    !(overlaps_x && overlaps_y),
                    "pills overlapped: {:?} vs {:?}",
                    (a.label.as_str(), a.label_x, a.label_y),
                    (b.label.as_str(), b.label_x, b.label_y)
                );
            }
        }
    }

    #[test]
    fn topology_query_matches_id_label_details_status_tier_and_group() {
        let services = vec![
            (
                "Jellyfin".into(),
                json!({"service_id":"jellyfin","status":"running","details":"Port 8096 | media.local"}),
            ),
            (
                "Nextcloud".into(),
                json!({"service_id":"nextcloud","status":"failed","details":"Port 8443"}),
            ),
        ];
        let layout = compute_tiered_topology_layout(&services, &[]);
        let jellyfin = layout.nodes.iter().find(|n| n.id == "Jellyfin").unwrap();
        let nextcloud = layout.nodes.iter().find(|n| n.id == "Nextcloud").unwrap();

        assert!(matches_topology_query(jellyfin, ""));
        assert!(matches_topology_query(jellyfin, "  "));
        assert!(matches_topology_query(jellyfin, "jelly"));
        assert!(matches_topology_query(jellyfin, "8096 running"));
        assert!(matches_topology_query(jellyfin, "media.local"));
        assert!(!matches_topology_query(jellyfin, "nextcloud"));
        assert!(matches_topology_query(nextcloud, "exception"));
        assert!(matches_topology_query(nextcloud, "failed 8443"));
        assert!(!matches_topology_query(nextcloud, "8096"));
    }
}
