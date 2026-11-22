use crate::*;

pub(crate) static PLEX_TOKEN_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bPlexOnlineToken\s*=\s*"([^"]+)""#).unwrap());
pub(crate) static PHP_ORGANIZR_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap());

pub(crate) fn resolve_runner_fs_path(raw_path: &str) -> PathBuf {
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

pub(crate) fn app_metadata_users(logical: &Path) -> Vec<String> {
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

pub(crate) fn read_runner_config_text(raw_path: &str) -> Option<String> {
    read_app_metadata_config(&resolve_runner_fs_path(raw_path), Path::new(raw_path)).ok()
}

pub(crate) fn parse_valid_runner_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    match clean.parse::<i32>() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => 0,
    }
}

pub(crate) fn parse_host_port_or_port(raw: &str) -> i32 {
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

pub(crate) fn extract_runner_xml_tag(content: &str, tag: &str) -> String {
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

pub(crate) fn extract_runner_ini_value(content: &str, keys: &[&str]) -> String {
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

pub(crate) fn extract_runner_yaml_key_in_section(
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

pub(crate) fn json_value_to_port(v: &Value) -> i32 {
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

pub(crate) fn extract_runner_json_key_and_port(content: &str) -> (String, i32) {
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

pub(crate) fn extract_runner_systemd_or_apache_port(text: &str) -> i32 {
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

pub(crate) fn dispatcharr_runtime_port(content: &str) -> i32 {
    parse_valid_runner_port(&extract_runner_ini_value(content, &["DISPATCHARR_PORT"]))
}
