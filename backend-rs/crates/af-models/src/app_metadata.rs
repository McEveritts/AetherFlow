//! Shared parsing for application metadata probes.

use crate::AppRuntimeMeta;

pub fn normalize_app_slug(app_name: &str) -> String {
    let clean = app_name
        .trim()
        .to_lowercase()
        .trim_end_matches(".service")
        .to_string();
    match clean.as_str() {
        "plexmediaserver" => "plex".to_string(),
        "emby-server" => "emby".to_string(),
        "pihole-ftl" => "pihole".to_string(),
        "transmission-daemon" => "transmission".to_string(),
        "deluged" | "deluge-web" => "deluge".to_string(),
        "paperless-webserver" | "paperless" => "paperless-ngx".to_string(),
        "qbittorrent-nox" => "qbittorrent".to_string(),
        "calibre-web" => "calibreweb".to_string(),
        "grafana-server" => "grafana".to_string(),
        "uptime-kuma" => "uptimekuma".to_string(),
        "adguard-home" => "adguardhome".to_string(),
        "pyload-ng" => "pyload".to_string(),
        "af-maintainerr" => "maintainerr".to_string(),
        "af-palate" => "palate".to_string(),
        "af-kasmvnc" => "kasmvnc".to_string(),
        "af-mcvnc" => "mcvnc".to_string(),
        "af-piped" => "piped".to_string(),
        "af-invidious" => "invidious".to_string(),
        "home-assistant@homeassistant" => "homeassistant".to_string(),
        _ => clean,
    }
}

pub const CALIBRE_WEB_DATABASES: &[&str] = &[
    "/var/lib/calibreweb/app.db",
    "/opt/calibreweb/app.db",
    "/var/lib/calibre-web/app.db",
    "/opt/calibre-web/app.db",
];
pub const CALIBRE_WEB_PORT_QUERY: &str = "SELECT CAST(config_port AS TEXT) FROM settings LIMIT 1";
const UPTIME_KUMA_UNITS: &[&str] = &[
    "/etc/systemd/system/uptime-kuma.service",
    "/etc/systemd/system/uptimekuma.service",
];
const UPTIME_KUMA_CONFIGS: &[&str] = &[
    "/var/lib/uptime-kuma/.env",
    "/opt/uptime-kuma/.env",
    "/etc/default/uptime-kuma",
];
const NZBGET_CONFIGS: &[&str] = &[
    "/var/lib/nzbget/nzbget.conf",
    "/etc/nzbget.conf",
    "/opt/nzbget/nzbget.conf",
];

fn valid_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    match clean.parse::<i32>() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => 0,
    }
}

fn ini_value(content: &str, keys: &[&str]) -> String {
    if content.is_empty() || keys.is_empty() {
        return String::new();
    }
    for want_key in keys {
        let want_lower = want_key.trim().to_lowercase();
        for line in content.lines() {
            let mut trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
                || trimmed.starts_with('[')
            {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export ") {
                trimmed = rest.trim();
            }
            let Some(idx) = trimmed.find(['=', ':']) else {
                continue;
            };
            if idx == 0 {
                continue;
            }
            let k = trimmed[..idx].trim().to_lowercase();
            if k != want_lower {
                continue;
            }
            let mut val = trimmed[idx + 1..].trim();
            if !val.starts_with('"') && !val.starts_with('\'') {
                if let Some(hash_idx) = val.find(" #") {
                    val = val[..hash_idx].trim();
                }
            }
            let val = val.trim_matches(['"', '\'']).trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    String::new()
}

pub fn uptime_kuma_port(mut read: impl FnMut(&str) -> Option<String>) -> i32 {
    let keys = ["UPTIME_KUMA_PORT", "PORT"];
    for path in UPTIME_KUMA_UNITS {
        if let Some(contents) = read(path) {
            for line in contents.lines() {
                if let Some(environment) = line.trim().strip_prefix("Environment=") {
                    let port = valid_port(&ini_value(environment.trim_matches(['"', '\'']), &keys));
                    if port > 0 {
                        return port;
                    }
                }
            }
        }
    }
    UPTIME_KUMA_CONFIGS
        .iter()
        .filter_map(|path| read(path))
        .map(|text| valid_port(&ini_value(&text, &keys)))
        .find(|&port| port > 0)
        .unwrap_or_default()
}

pub fn nzbget_meta(mut read: impl FnMut(&str) -> Option<String>) -> AppRuntimeMeta {
    let mut meta = AppRuntimeMeta::default();
    for path in NZBGET_CONFIGS {
        if let Some(text) = read(path) {
            if meta.api_key.is_empty() {
                meta.api_key = ini_value(&text, &["ControlPassword"]);
            }
            if meta.configured_port == 0 {
                meta.configured_port = valid_port(&ini_value(&text, &["ControlPort"]));
            }
        }
    }
    meta
}

pub fn whisparr_meta(mut read: impl FnMut(&str) -> Option<String>) -> AppRuntimeMeta {
    let mut meta = AppRuntimeMeta::default();
    for path in [
        "/var/lib/whisparr/config.xml",
        "/var/lib/whisparr/config/config.xml",
        "/var/lib/whisparr/.config/whisparr/config.xml",
        "/etc/whisparr/config.xml",
    ] {
        if let Some(text) = read(path) {
            let lower = text.to_ascii_lowercase();
            let tag_value = |open: &str, close: &str| {
                lower
                    .find(open)
                    .and_then(|index| {
                        let start = index + open.len();
                        lower[start..]
                            .find(close)
                            .map(|end| text[start..start + end].trim())
                    })
                    .filter(|value| !value.contains('<'))
                    .unwrap_or_default()
            };
            if meta.api_key.is_empty() {
                meta.api_key = tag_value("<apikey>", "</apikey>").to_string();
            }
            if meta.configured_port == 0 {
                meta.configured_port = valid_port(tag_value("<port>", "</port>"));
            }
        }
    }
    meta
}
