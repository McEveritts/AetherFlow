use super::*;

pub(super) const DEFAULT_SCAN_DIRECTORY: &str = "/mnt";

pub(super) fn is_terminal_mediaflow_event(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "complete"
            | "completed"
            | "failed"
            | "error"
            | "success"
            | "done"
            | "cancelled"
            | "needs_rescan"
    )
}

pub(super) fn queue_status_tone(status: &str) -> &'static str {
    match status {
        "COMPLETED" => "success",
        "FAILED" => "danger",
        "PENDING_APPROVAL" | "NEEDS_RESCAN" | "CANCELLED" => "warning",
        "APPROVED" | "PROCESSING" => "indigo",
        _ => "",
    }
}

pub(super) fn source_fingerprint(value: &Value) -> Option<String> {
    value["sourceFingerprint"]
        .as_str()
        .or_else(|| value["source_fingerprint"].as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub(super) fn short_source_fingerprint(value: &Value) -> Option<String> {
    let raw = source_fingerprint(value)?;
    let trimmed = raw.strip_prefix("v1:").unwrap_or(&raw);
    if let Some(hex_part) = trimmed.strip_prefix("sha256:") {
        let short: String = hex_part.chars().take(12).collect();
        return Some(format!("sha256:{short}"));
    }
    Some(trimmed.chars().take(16).collect())
}

pub(super) fn approve_payload_for_row(row: &Value) -> Option<Value> {
    source_fingerprint(row).map(|fp| json!({ "sourceFingerprint": fp }))
}

pub(super) fn decision_endpoint_and_payload(
    id: i64,
    verb: &str,
    row: &Value,
) -> (String, Option<Value>) {
    if verb == "approve" {
        (
            format!("/api/v1/admin/mediaflow/approve/{id}"),
            approve_payload_for_row(row),
        )
    } else {
        (format!("/api/v1/admin/mediaflow/decline/{id}"), None)
    }
}

pub(super) fn format_live_transcode_metrics(locale: &str, item: &MediaFlowLiveProgress) -> String {
    af_web_core::i18n::translate_with(
        locale,
        "Frame {frame} · {fps} fps · {speed} · {time} · {size}",
        &[
            ("frame", &item.frame),
            ("fps", &item.fps),
            ("speed", &item.speed),
            ("time", &item.time),
            ("size", &item.size),
        ],
    )
}

pub(super) const STAGES: [(&str, &[&str]); 5] = [
    ("1 · Request", &["jellyseerr", "overseerr", "ombi", "seer"]),
    ("2 · Indexer", &["prowlarr", "jackett"]),
    (
        "3 · Downloader",
        &["qbittorrent", "sabnzbd", "nzbget", "transmission", "deluge"],
    ),
    (
        "4 · Automation / Import",
        &["sonarr", "radarr", "lidarr", "bazarr"],
    ),
    ("5 · Media Server", &["jellyfin", "plex", "emby"]),
];
pub(super) fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}
pub(super) fn services(value: &Value) -> Vec<Value> {
    if let Some(entries) = value.as_object() {
        if value["services"].is_array() {
            return json_rows(value);
        }
        return entries
            .iter()
            .filter(|(_, v)| v.is_object())
            .map(|(name, v)| {
                let mut v = v.clone();
                if !v["id"].is_string() {
                    v["id"] = json!(name.to_ascii_lowercase());
                }
                if !v["name"].is_string() {
                    v["name"] = json!(name);
                }
                v
            })
            .collect();
    }
    json_rows(value)
}
pub(super) fn installed(service: &Value) -> bool {
    let service =
        crate::tabs::contracts::decode::<crate::tabs::contracts::MediaFlowServiceContract>(service);
    service.installed.unwrap_or({
        !matches!(
            service.status.as_str(),
            "" | "not_installed" | "not-installed" | "uninstalled" | "available"
        )
    })
}
pub(super) const DOWNLOAD_CLIENT_IDS: &[&str] = &[
    "qbittorrent",
    "sabnzbd",
    "nzbget",
    "transmission",
    "deluge",
    "rtorrent",
];

pub(super) const AUTOMATION_APP_IDS: &[&str] = &[
    "sonarr",
    "radarr",
    "lidarr",
    "prowlarr",
    "bazarr",
    "overseerr",
    "jellyseerr",
];

pub(super) fn pipeline_service_counts(rows: &[Value], ids: &[&str]) -> (usize, usize) {
    let mut active = 0usize;
    let mut installed_count = 0usize;
    for service in rows {
        let id = text(service, "id").to_ascii_lowercase();
        if !ids.contains(&id.as_str()) || !installed(service) {
            continue;
        }
        installed_count += 1;
        let contract = crate::tabs::contracts::decode::<
            crate::tabs::contracts::MediaFlowServiceContract,
        >(service);
        if matches!(
            contract.status.to_ascii_lowercase().as_str(),
            "running" | "active"
        ) {
            active += 1;
        }
    }
    (active, installed_count)
}

fn is_safe_launch_url(url: &str) -> bool {
    (url.starts_with('/') && !url.starts_with("//") && !url.contains('\\'))
        || url::Url::parse(url).ok().is_some_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.username().is_empty()
                && u.password().is_none()
        })
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

pub(super) fn safe_launch_url(service: &Value) -> Option<String> {
    if service["launch_scope"] == af_models::APP_LAUNCH_SCOPE_UNAVAILABLE {
        return None;
    }
    for key in ["launch_url", "launchUrl"] {
        if let Some(raw) = service[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return is_safe_launch_url(raw).then(|| raw.to_string());
        }
    }
    if service["launch_scope"].is_string() {
        return None;
    }
    for key in ["web_ui_url", "webUiUrl", "public_url", "url"] {
        if let Some(raw) = service[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return is_safe_launch_url(raw).then(|| raw.to_string());
        }
    }
    let path = service["web_path"]
        .as_str()
        .or_else(|| service["webPath"].as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("/{}", s.trim_start_matches('/')))
        .unwrap_or_default();
    if service["external_access_enabled"] != false {
        if let Some(public) = service["public_domain"]
            .as_str()
            .or_else(|| service["publicDomain"].as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if public.starts_with("http://") || public.starts_with("https://") {
                if is_safe_launch_url(public) {
                    return Some(public.to_string());
                }
            } else if valid_domain(public) {
                let scheme = if service["tls_enabled"] == false {
                    "http"
                } else {
                    "https"
                };
                return Some(format!("{scheme}://{public}{path}"));
            }
        }
    }
    for key in [
        "local_domain",
        "localDomain",
        "internal_domain",
        "internalDomain",
    ] {
        if let Some(local) = service[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if local.starts_with("http://") || local.starts_with("https://") {
                if is_safe_launch_url(local) {
                    return Some(local.to_string());
                }
            } else if valid_domain(local) {
                return Some(format!("http://{local}{path}"));
            }
        }
    }
    None
}
pub(super) fn bytes(bytes: f64) -> String {
    if !bytes.is_finite() || bytes <= 0.0 {
        return "0 B".into();
    }
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let i = ((bytes.ln() / 1024f64.ln()).floor() as usize).min(units.len() - 1);
    format!("{:.1} {}", bytes / 1024f64.powi(i as i32), units[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_launch_url_takes_precedence_over_domain_fallbacks() {
        assert_eq!(
            safe_launch_url(&json!({
                "launch_scope": "unavailable",
                "internal_domain": "sonarr.aether.local"
            })),
            None
        );
        assert_eq!(
            safe_launch_url(&json!({
                "launch_url": "https://sonarr.example.com/sonarr",
                "public_domain": "ignored.example.com",
                "local_domain": "sonarr.aether.local"
            })),
            Some("https://sonarr.example.com/sonarr".into())
        );
        assert_eq!(
            safe_launch_url(&json!({
                "launchUrl": "http://localhost:8989/sonarr",
                "public_domain": "ignored.example.com"
            })),
            Some("http://localhost:8989/sonarr".into())
        );
        assert_eq!(
            safe_launch_url(&json!({
                "launch_url": null,
                "public_domain": "sonarr.example.com",
                "external_access_enabled": true,
                "tls_enabled": true,
                "web_path": "sonarr"
            })),
            Some("https://sonarr.example.com/sonarr".into())
        );
        assert_eq!(
            safe_launch_url(&json!({
                "public_domain": "sonarr.example.com",
                "external_access_enabled": false,
                "local_domain": "sonarr.aether.local",
                "web_path": "/sonarr"
            })),
            Some("http://sonarr.aether.local/sonarr".into())
        );
        assert_eq!(
            safe_launch_url(&json!({
                "launch_url": "javascript:alert(1)",
                "public_domain": "sonarr.example.com"
            })),
            None
        );
    }

    #[test]
    fn pipeline_service_counts_tracks_installed_and_active_services() {
        let rows = vec![
            json!({"id": "qBittorrent", "status": "running", "installed": true}),
            json!({"id": "sabnzbd", "status": "stopped", "installed": true}),
            json!({"id": "deluge", "status": "available", "installed": false}),
            json!({"id": "sonarr", "status": "active"}),
            json!({"id": "radarr", "status": "running"}),
            json!({"id": "bazarr", "status": "not_installed"}),
        ];
        assert_eq!(pipeline_service_counts(&rows, DOWNLOAD_CLIENT_IDS), (1, 2));
        assert_eq!(pipeline_service_counts(&rows, AUTOMATION_APP_IDS), (2, 2));
    }
}
