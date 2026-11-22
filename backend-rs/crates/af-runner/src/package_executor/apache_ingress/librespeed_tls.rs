use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibreSpeedUpstreamTlsConfig {
    pub enabled: bool,
    pub ca_cert_file: Option<String>,
}

pub fn librespeed_runner_settings_tls_enabled(settings_path: &Path) -> bool {
    librespeed_runner_settings_tls_config(settings_path, None).enabled
}

pub fn librespeed_runner_settings_tls_config(
    settings_path: &Path,
    fs_root: Option<&Path>,
) -> LibreSpeedUpstreamTlsConfig {
    try_librespeed_runner_settings_tls_config(settings_path, fs_root).unwrap_or_default()
}

/// Reads `/opt/librespeed/settings.toml` safely (`O_NOFOLLOW` + non-symlink ancestors).
/// Returns `None` when `PermissionDenied` prevents an unprivileged caller from inspecting
/// `settings.toml`, allowing callers with an existing vhost to preserve current TLS directives.
pub fn try_librespeed_runner_settings_tls_config(
    settings_path: &Path,
    fs_root: Option<&Path>,
) -> Option<LibreSpeedUpstreamTlsConfig> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut cur = settings_path.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() || dir == Path::new("/") {
            break;
        }
        match fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Some(LibreSpeedUpstreamTlsConfig::default());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => return Some(LibreSpeedUpstreamTlsConfig::default()),
        }
        cur = dir.parent();
    }

    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let file = match opts.open(settings_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(_) => return Some(LibreSpeedUpstreamTlsConfig::default()),
    };
    let Ok(meta) = file.metadata() else {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    };
    if !meta.is_file() || meta.len() > 1_048_576 {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    }
    let mut raw = String::new();
    if file.take(1_048_576).read_to_string(&mut raw).is_err() {
        return Some(LibreSpeedUpstreamTlsConfig::default());
    }
    let (enabled, raw_cert) = parse_librespeed_root_tls_config(&raw);
    let ca_cert_file = if enabled {
        raw_cert.and_then(|cert_str| validate_librespeed_apache_ca_cert(&cert_str, fs_root))
    } else {
        None
    };
    Some(LibreSpeedUpstreamTlsConfig {
        enabled,
        ca_cert_file,
    })
}

pub(in crate::package_executor) fn validate_librespeed_apache_ca_cert(
    cert_str: &str,
    fs_root: Option<&Path>,
) -> Option<String> {
    let trimmed = cert_str.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with('/')
        || trimmed.len() > 512
        || trimmed.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'"' | b'\'' | b'\\' | b'#')
        })
    {
        return None;
    }
    let cert_path = Path::new(trimmed);
    for comp in cert_path.components() {
        if matches!(
            comp,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return None;
        }
    }
    let disk_path = match fs_root {
        Some(root) => root.join(trimmed.trim_start_matches('/')),
        None => cert_path.to_path_buf(),
    };
    for anc in disk_path.ancestors().skip(1) {
        if anc.as_os_str().is_empty() || anc == Path::new("/") {
            break;
        }
        if fs::symlink_metadata(anc)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return None;
        }
    }
    let meta = fs::symlink_metadata(&disk_path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() == 0 || meta.len() > 1_048_576
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
pub(in crate::package_executor) fn parse_librespeed_root_tls_flag(raw: &str) -> bool {
    parse_librespeed_root_tls_config(raw).0
}

pub(in crate::package_executor) fn scan_librespeed_toml_statements(
    input: &str,
) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QuoteState {
        None,
        Single,
        Double,
        TripleSingle,
        TripleDouble,
    }

    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = QuoteState::None;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let bytes = input.as_bytes();
    let mut i: usize = 0;

    while i < bytes.len() {
        let ch = input[i..].chars().next()?;
        let ch_len = ch.len_utf8();
        match quote {
            QuoteState::None => {
                if ch == '#' {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::TripleDouble;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                if input[i..].starts_with("'''") {
                    quote = QuoteState::TripleSingle;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                match ch {
                    '"' => {
                        quote = QuoteState::Double;
                        cur.push(ch);
                    }
                    '\'' => {
                        quote = QuoteState::Single;
                        cur.push(ch);
                    }
                    '[' => {
                        bracket_depth += 1;
                        cur.push(ch);
                    }
                    ']' => {
                        bracket_depth = bracket_depth.checked_sub(1)?;
                        cur.push(ch);
                    }
                    '{' => {
                        brace_depth += 1;
                        cur.push(ch);
                    }
                    '}' => {
                        brace_depth = brace_depth.checked_sub(1)?;
                        cur.push(ch);
                    }
                    '\n' => {
                        if bracket_depth == 0 && brace_depth == 0 {
                            let trimmed = cur.trim();
                            if !trimmed.is_empty() {
                                out.push(trimmed.to_string());
                            }
                            cur.clear();
                        } else {
                            cur.push(' ');
                        }
                    }
                    '\r' => {}
                    _ => cur.push(ch),
                }
            }
            QuoteState::Double => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next()?;
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if ch == '\n' {
                    return None;
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::Single => {
                if ch == '\n' {
                    return None;
                }
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::TripleDouble => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next()?;
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::None;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                cur.push(ch);
            }
            QuoteState::TripleSingle => {
                if input[i..].starts_with("'''") {
                    quote = QuoteState::None;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                cur.push(ch);
            }
        }
        i += ch_len;
    }

    if quote != QuoteState::None || bracket_depth > 0 || brace_depth > 0 {
        return None;
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    Some(out)
}

pub(in crate::package_executor) fn split_librespeed_toml_kv(stmt: &str) -> Option<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut in_triple_double = false;
    let mut in_triple_single = false;
    let mut escaped = false;
    let mut bracket_depth = 0usize;
    let bytes = stmt.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = stmt[i..].chars().next()?;
        let ch_len = ch.len_utf8();
        if in_triple_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if stmt[i..].starts_with("\"\"\"") {
                in_triple_double = false;
                i += 3;
                continue;
            }
            i += ch_len;
            continue;
        }
        if in_triple_single {
            if stmt[i..].starts_with("'''") {
                in_triple_single = false;
                i += 3;
                continue;
            }
            i += ch_len;
            continue;
        }
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            i += ch_len;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            i += ch_len;
            continue;
        }
        if stmt[i..].starts_with("\"\"\"") {
            in_triple_double = true;
            i += 3;
            continue;
        }
        if stmt[i..].starts_with("'''") {
            in_triple_single = true;
            i += 3;
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '=' if bracket_depth == 0 => return Some((&stmt[..i], &stmt[i + 1..])),
            _ => {}
        }
        i += ch_len;
    }
    None
}

pub(in crate::package_executor) fn unquote_librespeed_toml_scalar(raw_val: &str) -> String {
    let trimmed = raw_val.trim();
    if trimmed.starts_with("\"\"\"") && trimmed.ends_with("\"\"\"") && trimmed.len() >= 6 {
        let inner = &trimmed[3..trimmed.len() - 3];
        let inner = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return inner.to_string();
    }
    if trimmed.starts_with("'''") && trimmed.ends_with("'''") && trimmed.len() >= 6 {
        let inner = &trimmed[3..trimmed.len() - 3];
        let inner = inner
            .strip_prefix("\r\n")
            .or_else(|| inner.strip_prefix('\n'))
            .unwrap_or(inner);
        return inner.to_string();
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        if let Ok(parsed) = serde_json::from_str::<String>(trimmed) {
            return parsed;
        }
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    trimmed.to_string()
}

pub(in crate::package_executor) fn parse_librespeed_root_tls_config(
    raw: &str,
) -> (bool, Option<String>) {
    let mut enabled = false;
    let mut cert_file: Option<String> = None;
    let Some(stmts) = scan_librespeed_toml_statements(raw) else {
        return (false, None);
    };
    for stmt in stmts {
        if stmt.starts_with('[') && split_librespeed_toml_kv(&stmt).is_none() {
            break;
        }
        if let Some((k, v)) = split_librespeed_toml_kv(&stmt) {
            let key = unquote_librespeed_toml_scalar(k);
            let val = unquote_librespeed_toml_scalar(v);
            if key == "enable_tls" {
                enabled = val.trim().eq_ignore_ascii_case("true");
            } else if key == "tls_cert_file" {
                let trimmed = val.trim();
                cert_file = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
        }
    }
    (enabled, cert_file)
}
