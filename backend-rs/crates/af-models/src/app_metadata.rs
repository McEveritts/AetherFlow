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

pub const MAX_APP_WEB_PATH_LEN: usize = 128;

/// Applications whose retained native configuration supports a non-root URL base,
/// matching `packages/common.sh:application_readiness_url`.
pub fn supports_native_url_base(app_name: &str) -> bool {
    matches!(
        normalize_app_slug(app_name).as_str(),
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "bazarr" | "sabnzbd" | "tautulli"
    )
}

/// Validates and normalizes a single native URL base or catalog web path component.
///
/// - Empty or `"/"` normalizes to `Ok(String::new())` (root).
/// - Valid non-root paths normalize to `Ok("/seg1/seg2")` with a single leading `/`
///   and no trailing `/`.
/// - Rejects schemes, authorities (`//`), backslashes, query/fragment delimiters,
///   percent-encoding, whitespace/control characters, dot segments (`.` / `..`),
///   reserved `/.well-known` paths, and paths longer than `MAX_APP_WEB_PATH_LEN`.
pub fn validate_app_web_path(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim_matches([' ', '\t']);
    if trimmed.bytes().any(|b| b.is_ascii_control()) {
        return Err("path contains control characters");
    }
    if trimmed.is_empty() || trimmed == "/" {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_APP_WEB_PATH_LEN {
        return Err("path exceeds maximum length");
    }
    if trimmed.contains("//") || trimmed.contains('\\') {
        return Err("path contains invalid slash sequence");
    }
    let body = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Err("path contains empty segment");
    }
    for (index, segment) in body.split('/').enumerate() {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("path contains empty or traversal segment");
        }
        if index == 0 && segment.eq_ignore_ascii_case(".well-known") {
            return Err("path uses reserved .well-known prefix");
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err("path contains disallowed characters");
        }
    }
    Ok(format!("/{body}"))
}

/// Composes an optional retained native URL base with a catalog web UI subpath.
///
/// Invalid inputs fall back safely to empty/root while preserving any valid side.
/// Equivalent prefix or suffix segments are never doubled on segment boundaries.
pub fn compose_app_web_path(native_url_base: &str, catalog_web_path: &str) -> String {
    let base = validate_app_web_path(native_url_base).unwrap_or_default();
    let suffix = validate_app_web_path(catalog_web_path).unwrap_or_default();
    match (base.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix,
        (false, true) => base,
        (false, false) => {
            if suffix.eq_ignore_ascii_case(&base) {
                base
            } else if suffix.len() > base.len()
                && suffix.as_bytes()[base.len()] == b'/'
                && suffix[..base.len()].eq_ignore_ascii_case(&base)
            {
                format!("{base}{}", &suffix[base.len()..])
            } else if base.len() > suffix.len()
                && base[base.len() - suffix.len()..].eq_ignore_ascii_case(&suffix)
            {
                base
            } else {
                format!("{base}{suffix}")
            }
        }
    }
}

/// Computes the effective `web_path` field for an installed application, preserving
/// the catalog root default (`"/"`) when both base and suffix resolve to root.
pub fn effective_app_web_path(native_url_base: &str, catalog_web_path: &str) -> String {
    let composed = compose_app_web_path(native_url_base, catalog_web_path);
    if !composed.is_empty() {
        composed
    } else if catalog_web_path.trim() == "/" {
        "/".to_string()
    } else {
        String::new()
    }
}

fn strip_xml_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + 4..];
        let Some(end) = after_open.find("-->") else {
            return out;
        };
        rest = &after_open[end + 3..];
    }
    out.push_str(rest);
    out
}

/// Extracts a simple XML element value while rejecting DOCTYPE/ENTITY declarations
/// and ignoring XML comments. Returns `Some("")` for empty or self-closing tags,
/// and `None` if the tag is absent or unclosed.
pub fn extract_xml_tag_value(content: &str, tag: &str) -> Option<String> {
    if content.is_empty() || tag.is_empty() {
        return None;
    }
    let upper = content.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return None;
    }
    let cleaned = strip_xml_comments(content);
    let cleaned_bytes = cleaned.as_bytes();
    let tag_bytes = tag.as_bytes();
    let mut pos = 0;
    while let Some(rel) = cleaned[pos..].find('<') {
        let lt = pos + rel;
        let name_start = lt + 1;
        let name_end = name_start + tag_bytes.len();
        if name_end <= cleaned_bytes.len()
            && cleaned[name_start..name_end].eq_ignore_ascii_case(tag)
        {
            let next_byte = cleaned_bytes.get(name_end).copied();
            if matches!(next_byte, Some(b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n')) {
                let Some(gt_rel) = cleaned[name_end..].find('>') else {
                    return None;
                };
                let open_end = name_end + gt_rel;
                let attrs = cleaned[name_end..open_end].trim_end();
                if attrs.ends_with('/') {
                    return Some(String::new());
                }
                let value_start = open_end + 1;
                let mut close_pos = value_start;
                while let Some(close_rel) = cleaned[close_pos..].find("</") {
                    let close_lt = close_pos + close_rel;
                    let close_name_start = close_lt + 2;
                    let close_name_end = close_name_start + tag_bytes.len();
                    if close_name_end <= cleaned_bytes.len()
                        && cleaned[close_name_start..close_name_end].eq_ignore_ascii_case(tag)
                    {
                        let after_close_name = &cleaned[close_name_end..];
                        let ws_len = after_close_name
                            .bytes()
                            .take_while(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                            .count();
                        if after_close_name.as_bytes().get(ws_len) == Some(&b'>') {
                            let inner = &cleaned[value_start..close_lt];
                            if inner.contains('<') {
                                return None;
                            }
                            return Some(inner.trim().to_string());
                        }
                    }
                    close_pos = close_lt + 2;
                }
                return None;
            }
        }
        pos = lt + 1;
    }
    None
}

fn parse_scalar_value(raw: &str, allow_semicolon_comment: bool, treat_yaml_null: bool) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || (allow_semicolon_comment && trimmed.starts_with(';'))
    {
        return String::new();
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.char_indices();
        while let Some((idx, ch)) = chars.next() {
            if ch == '\\' {
                if let Some((_, esc)) = chars.next() {
                    out.push(esc);
                    continue;
                }
                return trimmed.to_string();
            }
            if ch == '"' {
                let tail = &rest[idx + 1..];
                if tail.is_empty()
                    || ((tail.starts_with(' ') || tail.starts_with('\t'))
                        && (tail.trim_start().is_empty()
                            || tail.trim_start().starts_with('#')
                            || (allow_semicolon_comment && tail.trim_start().starts_with(';'))))
                {
                    return out;
                }
                return trimmed.to_string();
            }
            out.push(ch);
        }
        return trimmed.to_string();
    }
    if let Some(rest) = trimmed.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = rest.char_indices().peekable();
        while let Some((idx, ch)) = chars.next() {
            if ch == '\'' {
                if let Some(&(_, '\'')) = chars.peek() {
                    chars.next();
                    out.push('\'');
                    continue;
                }
                let tail = &rest[idx + 1..];
                if tail.is_empty()
                    || ((tail.starts_with(' ') || tail.starts_with('\t'))
                        && (tail.trim_start().is_empty()
                            || tail.trim_start().starts_with('#')
                            || (allow_semicolon_comment && tail.trim_start().starts_with(';'))))
                {
                    return out;
                }
                return trimmed.to_string();
            }
            out.push(ch);
        }
        return trimmed.to_string();
    }
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    for i in 1..bytes.len() {
        let is_comment_start = bytes[i] == b'#' || (allow_semicolon_comment && bytes[i] == b';');
        if is_comment_start && matches!(bytes[i - 1], b' ' | b'\t') {
            end = i;
            break;
        }
    }
    let value = trimmed[..end].trim();
    if treat_yaml_null && (value == "~" || value.eq_ignore_ascii_case("null")) {
        return String::new();
    }
    value.to_string()
}

fn unquote_key(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Some(inner);
    }
    if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
    {
        return Some(inner);
    }
    Some(trimmed)
}

/// Extracts a key's value from an explicit INI `[section]` (case-insensitive).
/// Ignores sibling sections and ConfigObj nested `[[subsection]]` headers.
pub fn extract_ini_section_value(content: &str, section: &str, key: &str) -> Option<String> {
    let want_section = section.trim();
    let want_key = key.trim();
    if content.is_empty() || want_section.is_empty() || want_key.is_empty() {
        return None;
    }
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut in_section = false;
    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(after_open) = trimmed.strip_prefix('[') {
            if let Some(close_idx) = after_open.find(']') {
                let tail = after_open[close_idx + 1..].trim();
                let valid_tail = tail.is_empty() || tail.starts_with('#') || tail.starts_with(';');
                if valid_tail {
                    let header = after_open[..close_idx].trim();
                    in_section =
                        !header.starts_with('[') && header.eq_ignore_ascii_case(want_section);
                } else {
                    in_section = false;
                }
            } else {
                in_section = false;
            }
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        if lhs.trim().eq_ignore_ascii_case(want_key) {
            return Some(parse_scalar_value(rhs, true, false));
        }
    }
    None
}

fn extract_yaml_flow_mapping_key(flow_rest: &str, want_key: &str) -> Option<String> {
    let after_brace = flow_rest.strip_prefix('{')?;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth = 1usize;
    let mut close_idx = None;
    for (idx, ch) in after_brace.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 && ch == '}' {
                    close_idx = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &after_brace[..close_idx?];
    let mut entries = Vec::new();
    let mut start = 0usize;
    in_single = false;
    in_double = false;
    escaped = false;
    depth = 0;
    for (idx, ch) in body.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                entries.push(&body[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    entries.push(&body[start..]);
    for entry in entries {
        let Some((lhs, rhs)) = entry.split_once(':') else {
            continue;
        };
        if unquote_key(lhs).is_some_and(|k| k.eq_ignore_ascii_case(want_key)) {
            return Some(parse_scalar_value(rhs, false, true));
        }
    }
    None
}

/// Extracts a direct child key from a top-level YAML mapping section (such as
/// Bazarr's `general.base_url`), skipping nested sub-mappings, sequences, and
/// sibling sections while supporting inline comments, quotes, and flow mappings.
pub fn extract_yaml_section_value(content: &str, section: &str, key: &str) -> Option<String> {
    let want_section = section.trim();
    let want_key = key.trim();
    if content.is_empty() || want_section.is_empty() || want_key.is_empty() {
        return None;
    }
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut in_section = false;
    let mut child_indent: Option<usize> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim_end_matches('\r');
        let indent = line
            .bytes()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .count();
        let trimmed = line[indent..].trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !in_section {
            if indent != 0 || trimmed == "---" || trimmed == "..." {
                continue;
            }
            let Some((lhs, rhs)) = trimmed.split_once(':') else {
                continue;
            };
            if !unquote_key(lhs).is_some_and(|k| k.eq_ignore_ascii_case(want_section)) {
                continue;
            }
            let rest = rhs.trim();
            if rest.is_empty() || rest.starts_with('#') {
                in_section = true;
                child_indent = None;
            } else if rest.starts_with('{') {
                return extract_yaml_flow_mapping_key(rest, want_key);
            }
            continue;
        }
        if indent == 0 {
            break;
        }
        if trimmed.starts_with('-') {
            continue;
        }
        let target_indent = *child_indent.get_or_insert(indent);
        if indent != target_indent {
            continue;
        }
        let Some((lhs, rhs)) = trimmed.split_once(':') else {
            continue;
        };
        if !unquote_key(lhs).is_some_and(|k| k.eq_ignore_ascii_case(want_key)) {
            continue;
        }
        return Some(parse_scalar_value(rhs, false, true));
    }
    None
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

    #[test]
    fn validates_and_composes_native_url_bases_without_doubling() {
        assert_eq!(validate_app_web_path("").unwrap(), "");
        assert_eq!(validate_app_web_path(" / ").unwrap(), "");
        assert_eq!(validate_app_web_path(" /sonarr/ ").unwrap(), "/sonarr");
        assert_eq!(validate_app_web_path("radarr").unwrap(), "/radarr");
        assert_eq!(
            validate_app_web_path("/music/lidarr/").unwrap(),
            "/music/lidarr"
        );
        assert_eq!(validate_app_web_path("/vnc.html").unwrap(), "/vnc.html");

        for bad in [
            "//evil.test",
            "//evil.test/sonarr",
            "//",
            "/sonarr//",
            "/sonarr//ui",
            "https://evil.test/sonarr",
            "http://127.0.0.1:8989/sonarr",
            "javascript:alert(1)",
            "../admin",
            "/sonarr/../admin",
            "/./sonarr",
            ".",
            "..",
            "/sonarr?next=1",
            "/sonarr#frag",
            "/sonarr%2fadmin",
            "/sonarr\\admin",
            "/sonarr@evil.test",
            "/my app",
            "/sonarr\r\nX-Injected: 1",
            "/.well-known/aetherflow/app-launch",
            "/.well-known/acme-challenge",
            &format!("/{}", "a".repeat(MAX_APP_WEB_PATH_LEN)),
        ] {
            assert!(validate_app_web_path(bad).is_err(), "must reject {bad:?}");
        }

        // Root defaults & catalog suffixes preserved; equivalent prefixes never doubled.
        assert_eq!(compose_app_web_path("", "/"), "");
        assert_eq!(compose_app_web_path("/", "/"), "");
        assert_eq!(compose_app_web_path("", "/web"), "/web");
        assert_eq!(compose_app_web_path("/", "/vnc.html"), "/vnc.html");
        assert_eq!(compose_app_web_path("/sonarr/", "/"), "/sonarr");
        assert_eq!(compose_app_web_path("/media", "/web"), "/media/web");
        assert_eq!(compose_app_web_path("/web", "/web"), "/web");
        assert_eq!(compose_app_web_path("/Web/", "/web"), "/Web");
        assert_eq!(
            compose_app_web_path("/sonarr", "/sonarr/web"),
            "/sonarr/web"
        );
        assert_eq!(
            compose_app_web_path("/Sonarr", "/sonarr/web"),
            "/Sonarr/web"
        );
        assert_eq!(compose_app_web_path("/proxy/web", "/web"), "/proxy/web");
        assert_eq!(
            compose_app_web_path("/proxy/myweb", "/web"),
            "/proxy/myweb/web"
        );
        assert_eq!(compose_app_web_path("/app", "/apple"), "/app/apple");
        assert_eq!(compose_app_web_path("/../bad", "/web"), "/web");
        assert_eq!(compose_app_web_path("https://evil.test", "/"), "");

        assert_eq!(effective_app_web_path("", "/"), "/");
        assert_eq!(effective_app_web_path("", ""), "");
        assert_eq!(effective_app_web_path("/../bad", "/"), "/");
        assert_eq!(effective_app_web_path("/sonarr/", "/"), "/sonarr");
        assert_eq!(effective_app_web_path("/media", "/web"), "/media/web");
    }

    #[test]
    fn parses_representative_xml_ini_and_bazarr_yaml_syntaxes() {
        let xml = concat!(
            "<Config>\n",
            "  <!-- <UrlBase>/commented</UrlBase> -->\n",
            "  <Port>18989</Port>\n",
            "  <UrlBase> /tv/sonarr/ </UrlBase>\n",
            "</Config>\n"
        );
        assert_eq!(
            extract_xml_tag_value(xml, "UrlBase").as_deref(),
            Some("/tv/sonarr/")
        );
        assert_eq!(
            extract_xml_tag_value("<Config><UrlBase /></Config>", "UrlBase").as_deref(),
            Some("")
        );
        assert_eq!(
            extract_xml_tag_value(
                "<!DOCTYPE x><Config><UrlBase>/a</UrlBase></Config>",
                "UrlBase"
            ),
            None
        );

        let bazarr_yaml = concat!(
            "auth:\n",
            "  apikey: abc123\n",
            "general: # retained settings\n",
            "  proxy:\n",
            "    exclude:\n",
            "    - localhost\n",
            "    base_url: /nested-must-ignore\n",
            "  ip: 127.0.0.1\n",
            "  port: 6767\n",
            "  base_url: '/subs/bazarr/' # trailing comment\n",
            "sonarr:\n",
            "  base_url: /sonarr\n",
        );
        assert_eq!(
            extract_yaml_section_value(bazarr_yaml, "general", "base_url").as_deref(),
            Some("/subs/bazarr/")
        );
        let bazarr_flow = "general: { ip: 127.0.0.1, base_url: \"/bazarr\", port: 6767 }\n";
        assert_eq!(
            extract_yaml_section_value(bazarr_flow, "general", "base_url").as_deref(),
            Some("/bazarr")
        );
        let bazarr_missing = "general:\n  ip: 127.0.0.1\nsonarr:\n  base_url: /sonarr\n";
        assert_eq!(
            extract_yaml_section_value(bazarr_missing, "general", "base_url"),
            None
        );
        let bazarr_null = "general:\n  base_url: null\n";
        assert_eq!(
            extract_yaml_section_value(bazarr_null, "general", "base_url").as_deref(),
            Some("")
        );
        let bazarr_frag = "general:\n  base_url: /bazarr#frag\n";
        let raw_frag = extract_yaml_section_value(bazarr_frag, "general", "base_url").unwrap();
        assert!(validate_app_web_path(&raw_frag).is_err());

        let sab_ini = concat!(
            "__version__ = 19\n",
            "[servers]\n",
            "[[news.example]]\n",
            "url_base = /wrong-sub\n",
            "[misc] # main section\n",
            "host = 127.0.0.1\n",
            "url_base = /sabnzbd/ # comment\n",
        );
        assert_eq!(
            extract_ini_section_value(sab_ini, "misc", "url_base").as_deref(),
            Some("/sabnzbd/")
        );

        let tautulli_ini = "[Other]\nhttp_root = /wrong\n[General]\nhttp_root = \"/tautulli\"\n";
        assert_eq!(
            extract_ini_section_value(tautulli_ini, "General", "http_root").as_deref(),
            Some("/tautulli")
        );

        let bazarr_ini = "[sonarr]\nbase_url = /sonarr\n[general]\nbase_url = /bazarr\n";
        assert_eq!(
            extract_ini_section_value(bazarr_ini, "general", "base_url").as_deref(),
            Some("/bazarr")
        );
    }
}
