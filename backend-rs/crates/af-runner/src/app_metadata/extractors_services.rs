use super::extractors_media::extract_media_app_runtime_meta;
use super::normalize_runner_app_name;
use super::parsers::{
    extract_runner_ini_value, extract_runner_json_key_and_port,
    extract_runner_systemd_or_apache_port, extract_runner_yaml_key_in_section,
    parse_host_port_or_port, parse_valid_runner_port, query_app_metadata_sqlite,
    read_runner_config_text, resolve_runner_fs_path,
};
use super::rclone::{
    effective_rclone_metadata_root, parse_rclone_unit_ports, read_rclone_unit_text_for_root,
};
use af_models::AppRuntimeMeta;
use std::path::Path;
use std::time::Duration;

pub fn extract_app_runtime_meta_local(app_name: &str) -> AppRuntimeMeta {
    extract_app_runtime_meta_local_until(
        app_name,
        std::time::Instant::now() + Duration::from_secs(1),
    )
}

pub fn extract_app_runtime_meta_local_until(
    app_name: &str,
    deadline: std::time::Instant,
) -> AppRuntimeMeta {
    let query_runner_sqlite_single_string = |raw_path: &str, queries: &[&str]| {
        query_app_metadata_sqlite(
            &resolve_runner_fs_path(raw_path),
            Path::new(raw_path),
            queries,
            deadline,
        )
        .unwrap_or_default()
    };
    let canonical = normalize_runner_app_name(app_name);
    let mut meta = AppRuntimeMeta::default();

    if !extract_media_app_runtime_meta(
        canonical.as_str(),
        &mut meta,
        &query_runner_sqlite_single_string,
    ) {
        extract_service_app_runtime_meta(
            canonical.as_str(),
            &mut meta,
            &query_runner_sqlite_single_string,
        );
    }

    if meta.configured_port <= 0 && canonical != "rclone" {
        let mut fallback_candidates = vec![
            format!("/etc/systemd/system/{canonical}.service"),
            format!("/etc/systemd/system/af-{canonical}.service"),
            format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
            format!("/etc/apache2/sites-available/{canonical}.conf"),
            format!("/etc/apache2/sites-available/aetherflow-app-{canonical}.conf"),
        ];
        if canonical == "uptime-kuma" {
            fallback_candidates.push("/etc/systemd/system/uptimekuma.service".to_string());
            fallback_candidates
                .push("/etc/apache2/sites-available/aetherflow-app-uptimekuma.conf".to_string());
        } else if canonical == "calibre-web" {
            fallback_candidates.push("/etc/systemd/system/calibreweb.service".to_string());
            fallback_candidates
                .push("/etc/apache2/sites-available/aetherflow-app-calibreweb.conf".to_string());
        }
        for raw_path in &fallback_candidates {
            if let Some(content) = read_runner_config_text(raw_path) {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                    break;
                }
            }
        }
    }

    meta
}

fn extract_service_app_runtime_meta(
    canonical: &str,
    meta: &mut AppRuntimeMeta,
    query_runner_sqlite_single_string: &dyn Fn(&str, &[&str]) -> String,
) {
    match canonical {
        "qbittorrent" => {
            let candidates = [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &[r"WebUI\Port", "Port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "deluge" => {
            if let Some(content) =
                read_runner_config_text("/var/lib/deluge/.config/deluge/web.conf")
            {
                let (_, port) = extract_runner_json_key_and_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "transmission" => {
            let candidates = [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "nzbget" => *meta = af_models::app_metadata::nzbget_meta(read_runner_config_text),

        "gitea" => {
            let candidates = ["/etc/gitea/app.ini", "/var/lib/gitea/custom/conf/app.ini"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["HTTP_PORT"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "znc" => {
            let candidates = [
                "/var/lib/znc/configs/znc.conf",
                "/var/lib/znc/.znc/configs/znc.conf",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["Port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "thelounge" => {
            let candidates = ["/var/lib/thelounge/config.js", "/etc/thelounge/config.js"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(
                        extract_runner_ini_value(&content, &["port"]).trim_end_matches(','),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "filebrowser" => {
            if let Some(content) =
                read_runner_config_text("/etc/systemd/system/filebrowser.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                let candidates = [
                    "/etc/filebrowser/filebrowser.json",
                    "/etc/filebrowser/config.json",
                    "/var/lib/filebrowser/filebrowser.json",
                    "/var/lib/filebrowser/.filebrowser.json",
                    "/etc/filebrowser/.filebrowser.json",
                    "/opt/filebrowser/filebrowser.json",
                ];
                for raw_path in &candidates {
                    if let Some(content) = read_runner_config_text(raw_path) {
                        let (_, port) = extract_runner_json_key_and_port(&content);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }

        "navidrome" => {
            let candidates = [
                "/var/lib/navidrome/navidrome.toml",
                "/etc/navidrome/navidrome.toml",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["Port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "calibre-web" | "calibreweb" => {
            for raw_path in af_models::app_metadata::CALIBRE_WEB_DATABASES {
                let port_str = query_runner_sqlite_single_string(
                    raw_path,
                    &[af_models::app_metadata::CALIBRE_WEB_PORT_QUERY],
                );
                let port = parse_valid_runner_port(&port_str);
                if port > 0 {
                    meta.configured_port = port;
                    break;
                }
            }
        }

        "grafana" => {
            let candidates = ["/etc/grafana/grafana.ini", "/var/lib/grafana/grafana.ini"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["http_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "prometheus" => {
            let candidates = [
                "/etc/systemd/system/prometheus.service",
                "/etc/default/prometheus",
                "/etc/sysconfig/prometheus",
                "/etc/prometheus/prometheus.yml",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["PORT", "port"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "uptimekuma" => {
            meta.configured_port =
                af_models::app_metadata::uptime_kuma_port(read_runner_config_text);
        }

        "maintainerr" => {
            for raw_path in &[
                "/etc/systemd/system/af-maintainerr.service",
                "/etc/systemd/system/maintainerr.service",
                "/var/lib/maintainerr/.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["UI_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "flaresolverr" => {
            for raw_path in &[
                "/etc/systemd/system/flaresolverr.service",
                "/opt/flaresolverr/.env",
                "/etc/default/flaresolverr",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["PORT"])),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "threadfin" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/threadfin.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                if let Some(content) =
                    read_runner_config_text("/var/lib/threadfin/conf/settings.json")
                {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                    }
                }
            }
        }

        "flood" => {
            for raw_path in &["/etc/systemd/system/flood.service", "/etc/default/flood"] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "nextcloud" | "rutorrent" => {
            for raw_path in &[
                format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
                format!("/etc/apache2/sites-available/{canonical}.conf"),
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "netdata" => {
            for raw_path in &[
                "/etc/netdata/netdata.conf",
                "/etc/systemd/system/netdata.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["default port", "port"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "homeassistant" => {
            for raw_path in &[
                "/home/homeassistant/.homeassistant/configuration.yaml",
                "/var/lib/homeassistant/configuration.yaml",
                "/etc/homeassistant/configuration.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_yaml_key_in_section(
                        &content,
                        "http",
                        "server_port",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["server_port"],
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "adguardhome" => {
            for raw_path in &[
                "/opt/AdGuardHome/AdGuardHome.yaml",
                "/etc/AdGuardHome/AdGuardHome.yaml",
                "/var/lib/AdGuardHome/AdGuardHome.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let addr = extract_runner_yaml_key_in_section(&content, "http", "address");
                    let mut port = parse_host_port_or_port(&addr);
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["bind_port"],
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "rclone" => {
            let root = effective_rclone_metadata_root();
            if let Some(content) = read_rclone_unit_text_for_root(&root, None) {
                let parsed = parse_rclone_unit_ports(&content);
                if let Some(gui_port) = parsed.gui_port {
                    meta.configured_port = gui_port as i32;
                }
                if let Some(api_port) = parsed.api_port {
                    if meta.configured_port <= 0 || api_port as i32 != meta.configured_port {
                        meta.secondary_port = api_port as i32;
                    }
                }
            }
            if meta.configured_port <= 0 {
                for raw_path in &[
                    crate::package_executor::RCLONE_ENV,
                    crate::package_executor::RCLONE_LEGACY_ENV,
                ] {
                    if let Some(content) = read_runner_config_text(raw_path) {
                        let port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["RCLONE_PORT", "PORT"],
                        ));
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }

        "autoscan" => {
            for raw_path in &["/etc/autoscan/config.yml", "/var/lib/autoscan/config.yml"] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "librespeed" => {
            for raw_path in &[
                "/opt/librespeed/settings.toml",
                "/etc/librespeed/settings.toml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["listen_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "scrutiny" => {
            for raw_path in &[
                "/etc/scrutiny/scrutiny.yaml",
                "/opt/scrutiny/config/scrutiny.yaml",
                "/etc/systemd/system/scrutiny.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]))
                            .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "n8n" => {
            for raw_path in &[
                "/etc/systemd/system/n8n.service",
                "/var/lib/n8n/.env",
                "/etc/n8n/n8n.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["N8N_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "palate" => {
            for raw_path in &[
                "/etc/palate/palate.env",
                "/etc/systemd/system/af-palate.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["PORT", "PALATE_PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "duplicati" => {
            for raw_path in &[
                "/etc/duplicati/duplicati.env",
                "/etc/default/duplicati",
                "/etc/systemd/system/duplicati.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["DUPLICATI_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "filebot" => {
            for raw_path in &[
                "/var/lib/filebot/filebot-node.env",
                "/etc/default/filebot",
                "/etc/systemd/system/filebot.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["FILEBOT_NODE_HTTP_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "novnc" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/novnc.service") {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "kasmvnc" => {
            for raw_path in &[
                "/var/lib/kasmvnc/.vnc/kasmvnc.yaml",
                "/etc/kasmvnc/kasmvnc.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["websocket_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "mcvnc" => {
            for raw_path in &[
                "/etc/mcvnc/mcvnc.env",
                "/etc/systemd/system/af-mcvnc.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_host_port_or_port(&extract_runner_ini_value(
                        &content,
                        &["MCVNC_BIND", "MCVNC_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "pyload" => {
            for raw_path in &[
                "/var/lib/pyload/settings/pyload.cfg",
                "/var/lib/pyload/.pyload/settings/pyload.cfg",
                "/etc/systemd/system/pyload.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let raw_val = extract_runner_ini_value(&content, &["int port", "port"]);
                    let rhs = raw_val.rsplit('=').next().unwrap_or(&raw_val).trim();
                    let port = parse_valid_runner_port(rhs)
                        .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "unmanic" => {
            for raw_path in &[
                "/var/lib/unmanic/.unmanic/config/settings.json",
                "/etc/systemd/system/unmanic.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, json_port) = extract_runner_json_key_and_port(&content);
                    let port = json_port.max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "piped" => {
            for raw_path in &[
                "/etc/piped/httpd.conf",
                "/etc/af-piped/httpd.conf",
                "/etc/systemd/system/af-piped.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "invidious" => {
            for raw_path in &[
                "/etc/invidious/config.yml",
                "/etc/af-invidious/config.yml",
                "/var/lib/invidious/config/config.yml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        _ => {}
    }
}
