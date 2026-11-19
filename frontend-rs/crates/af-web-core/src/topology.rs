use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceGroup {
    Core,
    Active,
    Stopped,
    Other,
    Exception,
}
pub fn is_core_service(slug: &str) -> bool {
    matches!(
        slug.to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .collect::<String>()
            .as_str(),
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
    }
}
