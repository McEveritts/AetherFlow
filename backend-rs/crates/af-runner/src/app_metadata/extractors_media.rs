use super::parsers::{
    dispatcharr_runtime_port, extract_runner_ini_value, extract_runner_json_key_and_port,
    extract_runner_systemd_or_apache_port, extract_runner_xml_tag,
    extract_runner_yaml_key_in_section, parse_host_port_or_port, parse_valid_runner_port,
    read_runner_config_text, PHP_ORGANIZR_KEY_RE, PLEX_TOKEN_ATTR_RE,
};
use af_models::AppRuntimeMeta;
use std::env;

pub(super) fn extract_media_app_runtime_meta(
    canonical: &str,
    meta: &mut AppRuntimeMeta,
    query_runner_sqlite_single_string: &dyn Fn(&str, &[&str]) -> String,
) -> bool {
    match canonical {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            let candidates = [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/config/config.xml", canonical),
            ];
            let mut url_base_seen = canonical == "listenarr";
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_xml_tag(&content, "ApiKey");
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_xml_tag(&content, "Port"));
                }
                if !url_base_seen {
                    if let Some(raw_base) =
                        af_models::app_metadata::extract_xml_tag_value(&content, "UrlBase")
                    {
                        meta.url_base = af_models::app_metadata::validate_app_web_path(&raw_base)
                            .unwrap_or_default();
                        url_base_seen = true;
                    }
                }
                if !meta.api_key.is_empty() && meta.configured_port > 0 && url_base_seen {
                    break;
                }
            }
        }

        "bazarr" => {
            let mut url_base_seen = false;
            let yaml_paths = [
                "/var/lib/bazarr/config/config.yaml",
                "/var/lib/bazarr/config.yaml",
                "/opt/bazarr/data/config/config.yaml",
            ];
            for raw_path in &yaml_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = af_models::app_metadata::extract_yaml_section_value(
                        &content, "auth", "apikey",
                    )
                    .unwrap_or_default();
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_yaml_key_in_section(&content, "", "apikey");
                    }
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(
                        &af_models::app_metadata::extract_yaml_section_value(
                            &content, "general", "port",
                        )
                        .unwrap_or_default(),
                    );
                }
                if !url_base_seen {
                    if let Some(raw_base) = af_models::app_metadata::extract_yaml_section_value(
                        &content, "general", "base_url",
                    ) {
                        meta.url_base = af_models::app_metadata::validate_app_web_path(&raw_base)
                            .unwrap_or_default();
                        url_base_seen = true;
                    }
                }
            }
            let ini_paths = [
                "/var/lib/bazarr/config/config.ini",
                "/var/lib/bazarr/config.ini",
                "/opt/bazarr/data/config/config.ini",
            ];
            for raw_path in &ini_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["apikey", "api_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                }
                if !url_base_seen {
                    if let Some(raw_base) = af_models::app_metadata::extract_ini_section_value(
                        &content, "general", "base_url",
                    ) {
                        meta.url_base = af_models::app_metadata::validate_app_web_path(&raw_base)
                            .unwrap_or_default();
                        url_base_seen = true;
                    }
                }
            }
        }

        "sabnzbd" => {
            let mut url_base_seen = false;
            let candidates = [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["api_key", "nzb_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                }
                if !url_base_seen {
                    if let Some(raw_base) = af_models::app_metadata::extract_ini_section_value(
                        &content, "misc", "url_base",
                    ) {
                        meta.url_base = af_models::app_metadata::validate_app_web_path(&raw_base)
                            .unwrap_or_default();
                        url_base_seen = true;
                    }
                }
            }
        }

        "tautulli" => {
            let mut url_base_seen = false;
            let candidates = [
                "/var/lib/tautulli/config.ini",
                "/opt/Tautulli/config.ini",
                "/etc/tautulli/config.ini",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["api_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["http_port", "port"],
                    ));
                }
                if !url_base_seen {
                    if let Some(raw_base) = af_models::app_metadata::extract_ini_section_value(
                        &content,
                        "General",
                        "http_root",
                    ) {
                        meta.url_base = af_models::app_metadata::validate_app_web_path(&raw_base)
                            .unwrap_or_default();
                        url_base_seen = true;
                    }
                }
            }
        }

        "jackett" => {
            let candidates = [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let (key, port) = extract_runner_json_key_and_port(&content);
                if meta.api_key.is_empty() && !key.is_empty() {
                    meta.api_key = key;
                }
                if meta.configured_port <= 0 && port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "overseerr" | "jellyseerr" => {
            let candidates = [
                format!("/var/lib/{}/settings.json", canonical),
                format!("/var/lib/{}/config/settings.json", canonical),
                format!("/opt/{}/config/settings.json", canonical),
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let (key, port) = extract_runner_json_key_and_port(&content);
                if meta.api_key.is_empty() && !key.is_empty() {
                    meta.api_key = key;
                }
                if meta.configured_port <= 0 && port > 0 {
                    meta.configured_port = port;
                }
            }
            let env_paths = [
                format!("/etc/{}/{}.conf", canonical, canonical),
                format!("/etc/default/{}", canonical),
            ];
            for raw_path in &env_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "port"],
                        ));
                    }
                }
            }
        }

        "syncthing" => {
            let candidates = [
                "/var/lib/syncthing/config.xml",
                "/var/lib/syncthing/.local/state/syncthing/config.xml",
                "/var/lib/syncthing/.config/syncthing/config.xml",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_xml_tag(&content, "apikey");
                }
                if meta.configured_port <= 0 {
                    let addr = extract_runner_xml_tag(&content, "address");
                    meta.configured_port = parse_host_port_or_port(&addr);
                }
            }
        }

        "plex" => {
            let candidates = [
                "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
                "/var/lib/plex/Plex Media Server/Preferences.xml",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if let Some(caps) = PLEX_TOKEN_ATTR_RE.captures(&content) {
                    if let Some(m) = caps.get(1) {
                        meta.api_key = m.as_str().trim().to_string();
                        break;
                    }
                }
            }
        }

        "jellyfin" => {
            if let Ok(env_key) = env::var("JELLYFIN_API_KEY") {
                if !env_key.trim().is_empty() {
                    meta.api_key = env_key.trim().to_string();
                }
            }
            if meta.api_key.is_empty() {
                let db_paths = [
                    "/var/lib/jellyfin/data/jellyfin.db",
                    "/var/lib/jellyfin/jellyfin.db",
                ];
                for raw_path in &db_paths {
                    let token = query_runner_sqlite_single_string(
                        raw_path,
                        &[
                            "SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                            "SELECT AccessToken FROM Devices WHERE AccessToken IS NOT NULL AND AccessToken != '' ORDER BY DateLastActivity DESC LIMIT 1",
                        ],
                    );
                    if !token.is_empty() {
                        meta.api_key = token;
                        break;
                    }
                }
            }
            let net_paths = [
                "/etc/jellyfin/network.xml",
                "/var/lib/jellyfin/config/network.xml",
            ];
            for raw_path in &net_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_xml_tag(
                        &content,
                        "InternalHttpPort",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_xml_tag(
                            &content,
                            "HttpServerPortNumber",
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "emby" => {
            if let Ok(env_key) = env::var("EMBY_API_KEY") {
                if !env_key.trim().is_empty() {
                    meta.api_key = env_key.trim().to_string();
                }
            }
            if meta.api_key.is_empty() {
                let db_paths = [
                    "/var/lib/emby/data/authentication.db",
                    "/var/lib/emby/data/users.db",
                ];
                for raw_path in &db_paths {
                    let token = query_runner_sqlite_single_string(
                        raw_path,
                        &[
                            "SELECT AccessToken FROM Tokens WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                            "SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                        ],
                    );
                    if !token.is_empty() {
                        meta.api_key = token;
                        break;
                    }
                }
            }
            let sys_paths = ["/var/lib/emby/config/system.xml", "/etc/emby/system.xml"];
            for raw_path in &sys_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_xml_tag(
                        &content,
                        "HttpServerPortNumber",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_xml_tag(
                            &content,
                            "PublicPort",
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "ombi" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/ombi.service") {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            for raw_path in &[
                "/var/lib/ombi/database.json",
                "/etc/Ombi/database.json",
                "/var/lib/ombi/appsettings.json",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 && meta.configured_port <= 0 {
                        meta.configured_port = port;
                    }
                }
            }
            let db_paths = [
                "/var/lib/ombi/OmbiSettings.db",
                "/etc/Ombi/OmbiSettings.db",
                "/opt/Ombi/OmbiSettings.db",
            ];
            for raw_path in &db_paths {
                let raw_json = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT Content FROM GlobalSettings WHERE SettingsName = 'OmbiSettings' LIMIT 1"],
                );
                if !raw_json.is_empty() {
                    let (key, port) = extract_runner_json_key_and_port(&raw_json);
                    if !key.is_empty() {
                        meta.api_key = key;
                    }
                    if port > 0 && meta.configured_port <= 0 {
                        meta.configured_port = port;
                    }
                    if !meta.api_key.is_empty() {
                        break;
                    }
                }
            }
        }

        "autobrr" | "qui" => {
            let toml_paths = [
                format!("/var/lib/{}/config.toml", canonical),
                format!("/var/lib/{}/.config/{}/config.toml", canonical, canonical),
            ];
            for raw_path in &toml_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port =
                            parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    }
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_ini_value(&content, &["api_key", "apikey"]);
                    }
                }
            }
            let db_paths = [
                format!("/var/lib/{}/{}.db", canonical, canonical),
                format!(
                    "/var/lib/{}/.config/{}/{}.db",
                    canonical, canonical, canonical
                ),
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT key FROM api_key WHERE key IS NOT NULL AND key != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "kavita" => {
            let json_paths = [
                "/var/lib/kavita/config/appsettings.json",
                "/opt/Kavita/config/appsettings.json",
            ];
            for raw_path in &json_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            let db_paths = [
                "/var/lib/kavita/config/kavita.db",
                "/opt/Kavita/config/kavita.db",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT ApiKey FROM AspNetUsers WHERE ApiKey IS NOT NULL AND ApiKey != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "audiobookshelf" => {
            if let Some(content) =
                read_runner_config_text("/etc/systemd/system/audiobookshelf.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            let env_paths = [
                "/etc/default/audiobookshelf",
                "/var/lib/audiobookshelf/config.env",
                "/var/lib/audiobookshelf/config/.env",
            ];
            for raw_path in &env_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "port"],
                        ));
                    }
                }
            }
            let db_paths = [
                "/var/lib/audiobookshelf/config/absdatabase.sqlite",
                "/var/lib/audiobookshelf/absdatabase.sqlite",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &[
                        "SELECT apiKey FROM apiKeys WHERE apiKey IS NOT NULL AND apiKey != '' LIMIT 1",
                        "SELECT token FROM users WHERE token IS NOT NULL AND token != '' LIMIT 1",
                    ],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "notifiarr" => {
            let candidates = [
                "/etc/notifiarr/notifiarr.conf",
                "/var/lib/notifiarr/notifiarr.conf",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let key = extract_runner_ini_value(&content, &["api_key"]);
                if !key.is_empty()
                    && key != "00000000-0000-0000-0000-000000000000"
                    && !key.eq_ignore_ascii_case("api-key-from-notifiarr.com")
                {
                    meta.api_key = key;
                }
                let bind_addr = extract_runner_ini_value(&content, &["bind_addr"]);
                if !bind_addr.is_empty() {
                    meta.configured_port = parse_host_port_or_port(&bind_addr);
                }
            }
        }

        "vaultwarden" => {
            let token_paths = [
                "/opt/AetherFlow/logs/vaultwarden_admin_token.txt",
                "/etc/vaultwarden/admin_token.txt",
            ];
            for raw_path in &token_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if let Some(first_line) = content.lines().next() {
                        let trimmed = first_line.trim();
                        if !trimmed.is_empty() {
                            meta.api_key = trimmed.to_string();
                            break;
                        }
                    }
                }
            }
            let env_paths = [
                "/etc/vaultwarden/vaultwarden.env",
                "/var/lib/vaultwarden/.env",
            ];
            for raw_path in &env_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    let token = extract_runner_ini_value(&content, &["ADMIN_TOKEN"]);
                    if !token.is_empty() {
                        meta.api_key = token;
                    }
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["ROCKET_PORT", "PORT"],
                    ));
                }
            }
        }

        "organizr" => {
            let php_paths = [
                "/var/www/organizr/api/config/config.php",
                "/var/lib/organizr/www/api/config/config.php",
            ];
            for raw_path in &php_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if let Some(caps) = PHP_ORGANIZR_KEY_RE.captures(&content) {
                    if let Some(m) = caps.get(1) {
                        meta.api_key = m.as_str().trim().to_string();
                        break;
                    }
                }
            }
        }

        "pihole" => {
            if let Some(content) = read_runner_config_text("/etc/pihole/setupVars.conf") {
                meta.api_key = extract_runner_ini_value(&content, &["WEBPASSWORD"]);
            }
            meta.configured_port =
                af_models::app_metadata::pihole_web_port(read_runner_config_text);
        }

        "dispatcharr" => {
            if let Some(content) = read_runner_config_text("/etc/dispatcharr/dispatcharr.env") {
                meta.configured_port = dispatcharr_runtime_port(&content);
            }
        }

        "paperless-ngx" => {
            let conf_paths = [
                "/etc/paperless.conf",
                "/opt/paperless/paperless.conf",
                "/var/lib/paperless/paperless.conf",
            ];
            for raw_path in &conf_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PAPERLESS_PORT", "PORT"],
                        ));
                    }
                }
            }
            let db_paths = [
                "/var/lib/paperless/db.sqlite3",
                "/opt/paperless/data/db.sqlite3",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT key FROM authtoken_token WHERE key IS NOT NULL AND key != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "requestrr" => {
            let candidates = [
                "/var/lib/requestrr/config/settings.json",
                "/opt/requestrr/config/settings.json",
                "/var/lib/requestrr/settings.json",
                "/opt/requestrr/settings.json",
                "/opt/requestrr/Settings/settings.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (key, port) = extract_runner_json_key_and_port(&content);
                    if meta.api_key.is_empty() && !key.is_empty() {
                        meta.api_key = key;
                    }
                    if meta.configured_port <= 0 && port > 0 {
                        meta.configured_port = port;
                    }
                }
            }
        }

        "seedcross" => {
            for raw_path in &[
                "/opt/seedcross/start-seedcross.sh",
                "/etc/systemd/system/seedcross.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            let candidates = [
                "/var/lib/seedcross/.env",
                "/opt/seedcross/.env",
                "/etc/seedcross/seedcross.env",
                "/etc/seedcross/config.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (json_key, json_port) = extract_runner_json_key_and_port(&content);
                    if meta.api_key.is_empty() && !json_key.is_empty() {
                        meta.api_key = json_key;
                    }
                    if meta.configured_port <= 0 && json_port > 0 {
                        meta.configured_port = json_port;
                    }
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_ini_value(
                            &content,
                            &["API_KEY", "SEEDCROSS_API_KEY", "AUTH_TOKEN"],
                        );
                    }
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "SEEDCROSS_PORT"],
                        ));
                    }
                }
            }
        }

        _ => return false,
    }
    true
}
