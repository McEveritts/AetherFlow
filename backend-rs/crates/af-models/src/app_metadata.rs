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
        "paperless" | "paperless-webserver" | "paperless-worker" | "paperless-scheduler" => {
            "paperless-ngx".to_string()
        }
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
        "dispatcharr-celery" | "dispatcharr-celerybeat" => "dispatcharr".to_string(),
        "novnc-xvnc" | "novnc-session" => "novnc".to_string(),
        "xrdp-sesman" => "xrdp".to_string(),
        "node_exporter" => "prometheus".to_string(),
        "rclone-vfs" => "rclone".to_string(),
        "librespeed.socket" => "librespeed".to_string(),
        "scrutiny-collector" | "scrutiny-collector.timer" => "scrutiny".to_string(),
        "recyclarr.timer" => "recyclarr".to_string(),
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

/// Reads only the Pi-hole v6 webserver table, with a Pi-hole v5 lighttpd fallback.
pub fn pihole_web_port(mut read: impl FnMut(&str) -> Option<String>) -> i32 {
    if let Some(content) = read("/etc/pihole/pihole.toml") {
        let mut webserver = false;
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.starts_with('[') {
                webserver = line
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .is_some_and(|section| section.trim() == "webserver");
                continue;
            }
            if let Some(("port", value)) = line.split_once('=').map(|(key, val)| (key.trim(), val))
            {
                if webserver {
                    let port = pihole_listener_port(value);
                    if port > 0 {
                        return port;
                    }
                }
            }
        }
    }
    read("/etc/lighttpd/lighttpd.conf")
        .map(|content| valid_port(&ini_value(&content, &["server.port"])))
        .unwrap_or(0)
}

fn pihole_listener_port(value: &str) -> i32 {
    let mut first = 0;
    for listener in value.trim().trim_matches(['"', '\'']).split(',') {
        let listener = listener.trim().rsplit(':').next().unwrap_or_default();
        let number = listener.trim_end_matches(['o', 'O', 's', 'S', 'r', 'R']);
        let port = valid_port(number);
        if port > 0 {
            if !listener[number.len()..].contains(['s', 'S']) {
                return port;
            }
            if first == 0 {
                first = port;
            }
        }
    }
    first
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

#[cfg(test)]
mod pihole_tests {
    use super::*;

    #[test]
    fn selects_http_listener_in_webserver_section() {
        let config = "[dns]\nport = 53\n[webserver] # v6\nport = \"8089o,8443os\"\n";
        assert_eq!(pihole_web_port(|_| Some(config.into())), 8089);
        assert_eq!(pihole_listener_port("\"443os,[::]:8080o\""), 8080);
        assert_eq!(pihole_listener_port("443os,8443s"), 443);
    }

    #[test]
    fn ignores_other_tables_and_falls_back_to_lighttpd() {
        assert_eq!(
            pihole_web_port(|path| match path {
                "/etc/pihole/pihole.toml" =>
                    Some("[dns]\nport = 53\n[webserver.api]\nport = 99".into()),
                "/etc/lighttpd/lighttpd.conf" => Some("server.port = 8082".into()),
                _ => None,
            }),
            8082
        );
    }
}
