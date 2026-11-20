use super::*;

pub use af_models::AppRuntimeMeta;

pub(super) static PLEX_TOKEN_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bPlexOnlineToken\s*=\s*"([^"]+)""#).unwrap());
pub(super) static PHP_ORGANIZR_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap());

pub use af_models::app_metadata::normalize_app_slug as normalize_runner_app_name;

pub(super) fn resolve_runner_fs_path(raw_path: &str) -> PathBuf {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return PathBuf::new();
    }
    for env_key in ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let root_trim = root.trim();
            if !root_trim.is_empty() {
                let rel = trimmed.trim_start_matches(['/', '\\']);
                return Path::new(root_trim).join(rel);
            }
        }
    }
    PathBuf::from(trimmed)
}

pub(super) fn app_metadata_users(logical: &Path) -> Vec<String> {
    if let Ok(path) = logical.strip_prefix("/var/www") {
        if matches!(
            path.iter().next().and_then(|name| name.to_str()),
            Some("organizr" | "nextcloud" | "rutorrent")
        ) {
            return vec!["www-data".into()];
        }
    }
    if let Ok(path) = logical.strip_prefix("/home") {
        return path
            .iter()
            .next()
            .and_then(|name| name.to_str())
            .filter(|name| SAFE_USERNAME.is_match(name))
            .map(str::to_owned)
            .into_iter()
            .collect();
    }
    let service = ["/var/lib", "/etc", "/opt"]
        .into_iter()
        .find_map(|prefix| {
            let path = logical.strip_prefix(prefix).ok()?;
            let mut segments = path.iter();
            let name = segments.next()?.to_str()?.to_ascii_lowercase();
            if prefix == "/etc" && segments.next().is_none() {
                if let Some((stem, "conf" | "ini" | "yaml" | "yml" | "json" | "toml" | "cfg")) =
                    name.rsplit_once('.')
                {
                    return Some(stem.to_owned());
                }
            }
            Some(name)
        })
        .filter(|name| SAFE_USERNAME.is_match(name));
    let aliases: &[&str] = match service.as_deref() {
        Some("systemd" | "default" | "aetherflow" | "apache2") | None => &[],
        Some("plexmediaserver") => &["plex"],
        Some("emby-server") => &["emby"],
        Some("kasmvnc") => &["af-kasmvnc"],
        Some("mcvnc") => &["af-mcvnc"],
        Some("transmission-daemon") => &["debian-transmission", "transmission"],
        Some("paperless" | "paperless-ngx") => &["paperless", "paperless-ngx"],
        Some("calibre-web" | "calibreweb") => &["calibre-web", "calibreweb"],
        Some("uptime-kuma" | "uptimekuma") => &["uptime-kuma", "uptimekuma"],
        Some(_) => return service.into_iter().collect(),
    };
    aliases.iter().map(|name| (*name).to_owned()).collect()
}

pub fn read_app_metadata_config(path: &Path, logical: &Path) -> std::io::Result<String> {
    let users = app_metadata_users(logical);
    read_confined_text(path, &users.iter().map(String::as_str).collect::<Vec<_>>())
}

pub(super) fn read_runner_config_text(raw_path: &str) -> Option<String> {
    read_app_metadata_config(&resolve_runner_fs_path(raw_path), Path::new(raw_path)).ok()
}

pub(super) fn parse_valid_runner_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    match clean.parse::<i32>() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => 0,
    }
}

pub(super) fn parse_host_port_or_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    if let Some((_, port_str)) = clean.rsplit_once(':') {
        let p = parse_valid_runner_port(port_str);
        if p > 0 {
            return p;
        }
    }
    parse_valid_runner_port(clean)
}

pub(super) fn extract_runner_xml_tag(content: &str, tag: &str) -> String {
    if content.is_empty() || tag.is_empty() {
        return String::new();
    }
    let pattern = format!(r"(?is)<{0}>\s*([^<]*?)\s*</{0}>", regex::escape(tag));
    let Ok(re) = Regex::new(&pattern) else {
        return String::new();
    };
    if let Some(caps) = re.captures(content) {
        if let Some(m) = caps.get(1) {
            return m.as_str().trim().to_string();
        }
    }
    String::new()
}

pub(super) fn extract_runner_ini_value(content: &str, keys: &[&str]) -> String {
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

pub(super) fn extract_runner_yaml_key_in_section(
    content: &str,
    section: &str,
    key: &str,
) -> String {
    if content.is_empty() || key.is_empty() {
        return String::new();
    }
    let want_section = section.trim().to_lowercase();
    let want_key = key.trim().to_lowercase();
    let mut in_section = want_section.is_empty();

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let is_indented = raw_line.starts_with(' ') || raw_line.starts_with('\t');
        if !is_indented && trimmed.ends_with(':') {
            let sec_name = trimmed.trim_end_matches(':').trim().to_lowercase();
            if !want_section.is_empty() {
                in_section = sec_name == want_section;
            }
            continue;
        }
        if !in_section {
            continue;
        }
        let Some(idx) = trimmed.find(':') else {
            continue;
        };
        if idx == 0 {
            continue;
        }
        let k = trimmed[..idx].trim().to_lowercase();
        if k != want_key {
            continue;
        }
        let mut val = trimmed[idx + 1..].trim();
        if !val.starts_with('"') && !val.starts_with('\'') {
            if let Some(hash_idx) = val.find(" #") {
                val = val[..hash_idx].trim();
            }
        }
        let val = val.trim_matches(['"', '\'']).trim();
        if !val.is_empty() && val != "null" && val != "~" {
            return val.to_string();
        }
    }
    String::new()
}

pub(super) fn json_value_to_port(v: &Value) -> i32 {
    match v {
        Value::Number(n) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .filter(|&p| (1..=65535).contains(&p))
            .unwrap_or(0),
        Value::String(s) => parse_valid_runner_port(s),
        _ => 0,
    }
}

pub(super) fn extract_runner_json_key_and_port(content: &str) -> (String, i32) {
    let mut parsed_obj: Option<serde_json::Map<String, Value>> = None;
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(content) {
        parsed_obj = Some(map);
    } else {
        // Support concatenated JSON objects like Deluge web.conf
        let mut stream = serde_json::Deserializer::from_str(content).into_iter::<Value>();
        if let Some(Ok(Value::Object(first))) = stream.next() {
            if let Some(Ok(Value::Object(second))) = stream.next() {
                parsed_obj = Some(second);
            } else {
                parsed_obj = Some(first);
            }
        }
    }

    let Some(raw) = parsed_obj else {
        return (String::new(), 0);
    };

    let mut api_key = String::new();
    for k in ["APIKey", "ApiKey", "apiKey", "api_key", "apikey", "token"] {
        if let Some(Value::String(s)) = raw.get(k) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                api_key = trimmed.to_string();
                break;
            }
        }
    }

    let mut port = 0;
    for k in ["Port", "port", "rpc-port", "http_port"] {
        if let Some(v) = raw.get(k) {
            let p = json_value_to_port(v);
            if p > 0 {
                port = p;
                break;
            }
        }
    }

    if let Some(Value::Object(main_obj)) = raw.get("main") {
        if api_key.is_empty() {
            for k in ["apiKey", "APIKey", "api_key"] {
                if let Some(Value::String(s)) = main_obj.get(k) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        api_key = trimmed.to_string();
                        break;
                    }
                }
            }
        }
        if port <= 0 {
            for k in ["port", "Port"] {
                if let Some(v) = main_obj.get(k) {
                    let p = json_value_to_port(v);
                    if p > 0 {
                        port = p;
                        break;
                    }
                }
            }
        }
    }

    (api_key, port)
}

pub fn query_app_metadata_sqlite(
    path: &Path,
    logical: &Path,
    queries: &[&str],
    deadline: std::time::Instant,
) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    const MAX_DB_SIZE: u64 = 512 * 1024 * 1024;
    let users = app_metadata_users(logical);
    let source =
        open_confined_file(path, &users.iter().map(String::as_str).collect::<Vec<_>>()).ok()?;
    let size = source.metadata().ok()?.len();
    if size == 0 || size > MAX_DB_SIZE || std::time::Instant::now() >= deadline {
        return None;
    }

    // SQLite reopens its filename internally. Only hand it a private snapshot of the
    // verified descriptor, with a fixed filename so no service-controlled URI is parsed.
    let scratch =
        Path::new("/var/tmp").join(format!("aetherflow-app-meta-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&scratch).ok()?;
    let result = (|| {
        let copy = scratch.join("snapshot.sqlite");
        let mut destination = fs::File::create_new(&copy).ok()?;
        let mut source = source.take(MAX_DB_SIZE + 1);
        let mut buffer = [0; 64 * 1024];
        use std::io::Write;
        loop {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            let count = source.read(&mut buffer).ok()?;
            if count == 0 {
                break;
            }
            destination.write_all(&buffer[..count]).ok()?;
        }
        if source.limit() == 0 {
            return None;
        }
        drop(destination);
        use rusqlite::OpenFlags;
        let conn = rusqlite::Connection::open_with_flags(
            format!("file:{}?mode=ro&immutable=1", copy.display()),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        for query in queries {
            if std::time::Instant::now() >= deadline {
                break;
            }
            if let Ok(value) = conn.query_row(query, [], |row| row.get::<_, String>(0)) {
                if !value.trim().is_empty() {
                    return Some(value.trim().to_owned());
                }
            }
        }
        None
    })();
    let _ = fs::remove_dir_all(scratch);
    result
}

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

    match canonical.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            let candidates = [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/config/config.xml", canonical),
            ];
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
                if !meta.api_key.is_empty() && meta.configured_port > 0 {
                    break;
                }
            }
        }

        "bazarr" => {
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
                    meta.api_key = extract_runner_yaml_key_in_section(&content, "auth", "apikey");
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_yaml_key_in_section(&content, "", "apikey");
                    }
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(
                        &extract_runner_yaml_key_in_section(&content, "general", "port"),
                    );
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
            }
        }

        "sabnzbd" => {
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
            }
        }

        "tautulli" => {
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

        "nzbget" => meta = af_models::app_metadata::nzbget_meta(read_runner_config_text),

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
            for raw_path in &[
                "/etc/systemd/system/rclone.service",
                "/etc/rclone/rclone.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["RCLONE_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
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

    if meta.configured_port <= 0 {
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

pub(super) fn extract_runner_systemd_or_apache_port(text: &str) -> i32 {
    static ENV_PORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^\s*(?:Environment\s*=\s*["']?|export\s+)?(?:[A-Z0-9_]*_PORT|PORT)\s*=\s*["']?([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static ENV_BIND_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^\s*(?:Environment\s*=\s*["']?|export\s+)?(?:[A-Z0-9_]*_BIND|ASPNETCORE_URLS)\s*=\s*["']?(?:https?://)?[^:\s"']+:([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static CLI_PORT_FLAG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)(?:--(?:webservice-)?port|-port|-p)(?:\s+|=)["']?([0-9]{2,5})\b"#)
            .unwrap()
    });
    static CLI_ADDR_FLAG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)(?:--(?:web\.listen-address|rc-addr|bind|host|listen)|websockify[^\n]*?)(?:\s+|=)["']?(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\*)?:([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static APACHE_LISTEN_VHOST_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)(?:^\s*Listen\s+(?:[0-9.]+:)?([0-9]{2,5})\b|<VirtualHost\s+[^>:]+:([0-9]{2,5})>|ProxyPass\s+/[^\s]*\s+(?:http|ws)s?://(?:127\.0\.0\.1|localhost):([0-9]{2,5})\b)"#,
        )
        .unwrap()
    });

    for re in [
        &*ENV_PORT_RE,
        &*ENV_BIND_RE,
        &*CLI_PORT_FLAG_RE,
        &*CLI_ADDR_FLAG_RE,
    ] {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                let p = parse_valid_runner_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    if let Some(caps) = APACHE_LISTEN_VHOST_RE.captures(text) {
        for idx in [1, 2, 3] {
            if let Some(m) = caps.get(idx) {
                let p = parse_valid_runner_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    0
}

pub(super) fn dispatcharr_runtime_port(content: &str) -> i32 {
    parse_valid_runner_port(&extract_runner_ini_value(content, &["DISPATCHARR_PORT"]))
}

pub(super) const DISPATCHARR_ADMIN_SCRIPT: &str = r#"import os
from django.contrib.auth import get_user_model
from django.db import transaction

with transaction.atomic():
    user, _ = get_user_model().objects.get_or_create(username=os.environ["AF_ADMIN_USER"])
    user.email = os.environ["AF_ADMIN_EMAIL"]
    user.user_level = 10
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.set_password(os.environ["AF_ADMIN_PASS"])
    user.save()
"#;

#[derive(Deserialize)]
pub(super) struct DispatcharrCredentialsRequest {
    pub(super) username: String,
    pub(super) password: String,
}

pub(super) fn dispatcharr_credentials_command(username: &str, password: &str) -> Command {
    let mut command = Command::new("runuser");
    command
        .args([
            "-u", "dispatcharr", "--", "/bin/bash", "-ec",
            "set -a; source /etc/dispatcharr/dispatcharr.env; set +a; cd /opt/dispatcharr; exec /opt/dispatcharr/env/bin/python manage.py shell",
        ])
        .env("AF_ADMIN_USER", username)
        .env("AF_ADMIN_PASS", password)
        .env("AF_ADMIN_EMAIL", format!("{}@localhost", username))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    command
}

pub(super) async fn handle_dispatcharr_credentials(
    Json(req): Json<DispatcharrCredentialsRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let username = req.username.trim();
    if username.is_empty()
        || req.password.is_empty()
        || username.len() > 256
        || req.password.len() > 4096
        || username.contains('\0')
        || req.password.contains('\0')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid Dispatcharr credentials".to_string(),
            }),
        );
    }
    if !Path::new("/opt/dispatcharr/manage.py").is_file() {
        return (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "Dispatcharr is not installed".to_string(),
                error: String::new(),
            }),
        );
    }
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        use tokio::io::AsyncWriteExt;
        let mut child = dispatcharr_credentials_command(username, &req.password).spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing stdin"))?;
        input.write_all(DISPATCHARR_ADMIN_SCRIPT.as_bytes()).await?;
        drop(input);
        child.wait().await
    })
    .await;
    let success = matches!(result, Ok(Ok(status)) if status.success());
    (
        if success {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Json(RunnerResponse {
            success,
            output: String::new(),
            error: if success {
                String::new()
            } else {
                "Dispatcharr credential sync failed".to_string()
            },
        }),
    )
}

pub(super) async fn handle_app_meta(
    Json(req): Json<AppMetaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_SCRIPT_NAME.is_match(&req.app_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid application identifier".to_string(),
            }),
        );
    }
    let meta = extract_app_runtime_meta_local(&req.app_name);
    let output = serde_json::to_string(&json!({
        "api_key": meta.api_key,
        "configured_port": meta.configured_port,
    }))
    .unwrap_or_else(|_| "{\"api_key\":\"\",\"configured_port\":0}".to_string());

    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output,
            error: String::new(),
        }),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVersionProbeRunnerRequest {
    pub package_id: String,
}

pub(super) async fn handle_package_version_probe(
    Json(req): Json<PackageVersionProbeRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_SCRIPT_NAME.is_match(&req.package_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }
    let pkg_id = req.package_id;
    let outcome = tokio::task::spawn_blocking(move || {
        let env_cfg = package_executor::PackageExecutionEnv::default();
        package_lifecycle::probe_live_runtime_version(&pkg_id, &env_cfg)
    })
    .await;

    match outcome {
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::Verified(ver)) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: ver,
                error: String::new(),
            }),
        ),
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::Failed(err)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err,
            }),
        ),
        Ok(package_lifecycle::LiveRuntimeProbeOutcome::NotConfigured) => (
            StatusCode::NOT_FOUND,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "no live version probe configured".to_string(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: format!("probe task failed: {}", e),
            }),
        ),
    }
}

pub async fn probe_package_version_via_runner(package_id: &str) -> anyhow::Result<String> {
    let req = PackageVersionProbeRunnerRequest {
        package_id: package_id.to_string(),
    };
    let result =
        post_runner_json("/v1/package/probe-version", &req, Duration::from_secs(12)).await?;
    if !result.success {
        anyhow::bail!(
            "{}",
            if result.error.is_empty() {
                "runner version probe failed".to_string()
            } else {
                result.error
            }
        );
    }
    Ok(result.output)
}

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Apache Ingress Vhost & Certbot Sync Endpoints
// ─────────────────────────────────────────────────────────────────────────────
