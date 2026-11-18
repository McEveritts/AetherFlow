use super::*;

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
pub(super) fn safe_launch_url(service: &Value) -> Option<String> {
    ["web_ui_url", "webUiUrl", "public_url", "url"]
        .iter()
        .filter_map(|key| service[*key].as_str())
        .find(|url| {
            (url.starts_with('/') && !url.starts_with("//") && !url.contains('\\'))
                || url::Url::parse(url).ok().is_some_and(|u| {
                    matches!(u.scheme(), "http" | "https")
                        && u.username().is_empty()
                        && u.password().is_none()
                })
        })
        .map(str::to_string)
}
pub(super) fn bytes(bytes: f64) -> String {
    if !bytes.is_finite() || bytes <= 0.0 {
        return "0 B".into();
    }
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let i = ((bytes.ln() / 1024f64.ln()).floor() as usize).min(units.len() - 1);
    format!("{:.1} {}", bytes / 1024f64.powi(i as i32), units[i])
}
