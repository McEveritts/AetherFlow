use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

static SAFE_XML_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_.:-]{0,127}$").unwrap());

fn is_allowed_os_root_symlink(path: &Path) -> bool {
    for var in [
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_INSTALL_ROOT",
        "AETHERFLOW_PACKAGE_FS_ROOT",
    ] {
        if let Ok(raw) = env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                let root = Path::new(trimmed);
                if path.starts_with(root) {
                    return false;
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    if matches!(
        path.to_str(),
        Some("/tmp" | "/var" | "/etc" | "/var/run" | "/bin" | "/sbin" | "/lib" | "/lib64")
    ) {
        return true;
    }
    #[cfg(not(target_os = "macos"))]
    matches!(
        path.to_str(),
        Some("/var/run" | "/bin" | "/sbin" | "/lib" | "/lib32" | "/lib64" | "/libx32")
    )
}

/// Walks all ancestor directory components of `file_path` using `fs::symlink_metadata`
/// and rejects any symlinked or non-directory parent component.
pub(super) fn validate_no_symlink_parents(
    file_path: &Path,
    require_exists: bool,
) -> Result<(), String> {
    let Some(parent) = file_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    let mut cur = PathBuf::new();
    for comp in parent.components() {
        use std::path::Component;
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "refusing to write through parent traversal component in {}",
                    file_path.display()
                ));
            }
            Component::Normal(seg) => {
                cur.push(seg);
                match fs::symlink_metadata(&cur) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            if is_allowed_os_root_symlink(&cur) {
                                continue;
                            }
                            return Err(format!(
                                "refusing to traverse symlink parent directory {} for {}",
                                cur.display(),
                                file_path.display()
                            ));
                        }
                        if !meta.file_type().is_dir() {
                            return Err(format!(
                                "refusing to traverse non-directory parent {} for {}",
                                cur.display(),
                                file_path.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound && !require_exists => {
                        break;
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to inspect parent directory {} for {}: {}",
                            cur.display(),
                            file_path.display(),
                            e
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn normalized_mutation_path(path: &Path) -> std::io::Result<PathBuf> {
    validate_no_symlink_parents(path, false).map_err(std::io::Error::other)?;
    #[cfg(target_os = "macos")]
    if let Some(parent) = path.parent().and_then(|parent| parent.canonicalize().ok()) {
        return Ok(parent.join(crate::confined_file_name(path)?));
    }
    Ok(path.to_path_buf())
}

pub(crate) fn open_mutation_file(path: &Path) -> std::io::Result<fs::File> {
    let target = normalized_mutation_path(path)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = crate::job_receipts::ReceiptDirectory::open_existing(parent)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    directory.open_file(crate::confined_file_name(&target)?, libc::O_RDONLY, 0)
}

pub(super) fn read_mutation_text(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
    let mut text = String::new();
    open_mutation_file(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration exceeds 2 MiB",
        ));
    }
    Ok(text)
}

/// Writes `content` atomically to `file_path` via a `.tmp.<nanos>` sibling file and rename,
/// preserving existing file permissions and ownership (or defaulting new files to mode `0o600`).
pub fn write_file_atomic(file_path: &Path, content: &[u8]) -> Result<(), String> {
    write_file_atomic_mode(file_path, content, None)
}

/// Writes `content` atomically to `file_path` with an optional forced permission mode (e.g. `Some(0o600)`),
/// rejecting symlink targets and symlinked parent directories.
pub fn write_file_atomic_mode(
    file_path: &Path,
    content: &[u8],
    force_mode: Option<u32>,
) -> Result<(), String> {
    validate_no_symlink_parents(file_path, false)?;
    if let Some(parent) = file_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create directory {}: {err}", parent.display()))?;
    }
    validate_no_symlink_parents(file_path, true)?;
    let target = normalized_mutation_path(file_path).map_err(|err| err.to_string())?;
    crate::replace_confined_file(&target, content, None, force_mode, false, false, None).map_err(
        |err| {
            format!(
                "atomic config write to {} failed: {err}",
                file_path.display()
            )
        },
    )
}

/// Creates a `.bak` backup copy of `file_path` if `file_path` exists.
pub fn backup_config_file(file_path: &Path) -> Result<Option<PathBuf>, String> {
    use std::io::Read;
    let mut file = match open_mutation_file(file_path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(format!(
                "failed to open {} for backup: {err}",
                file_path.display()
            ))
        }
    };
    let mut bak_os = file_path.as_os_str().to_os_string();
    bak_os.push(".bak");
    let bak_path = PathBuf::from(bak_os);
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|err| format!("failed to read {} for backup: {err}", file_path.display()))?;
    // Backups may contain credentials even if the original was world-readable.
    write_file_atomic_mode(&bak_path, &content, Some(0o600)).map_err(|e| {
        format!(
            "failed to back up {} to {}: {e}",
            file_path.display(),
            bak_path.display()
        )
    })?;
    Ok(Some(bak_path))
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. XML Mutator & Reader (`*arr` config.xml, Jellyfin network.xml / system.xml)
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the inner text of `<tag_name>...</tag_name>` from an XML file on disk.
pub fn read_xml_element(file_path: &Path, tag_name: &str) -> Option<String> {
    if !SAFE_XML_TAG.is_match(tag_name) {
        return None;
    }
    let content = read_mutation_text(file_path).ok()?;
    extract_xml_tag_text(&content, tag_name)
}

pub fn extract_xml_tag_text(content: &str, tag_name: &str) -> Option<String> {
    if content.is_empty() || !SAFE_XML_TAG.is_match(tag_name) {
        return None;
    }
    let escaped = regex::escape(tag_name);
    let pattern = format!(r"(?is)<{0}>\s*([^<]*?)\s*</{0}>", escaped);
    let re = Regex::new(&pattern).ok()?;
    let caps = re.captures(content)?;
    Some(caps.get(1)?.as_str().trim().to_string())
}

fn infer_xml_root_tag(file_path: &Path, existing_content: &str) -> &'static str {
    if existing_content.contains("<NetworkConfiguration") {
        return "NetworkConfiguration";
    }
    if existing_content.contains("<ServerConfiguration") {
        return "ServerConfiguration";
    }
    let lower = file_path.to_string_lossy().to_lowercase();
    if lower.contains("network.xml") || lower.contains("jellyfin") {
        "NetworkConfiguration"
    } else if lower.contains("system.xml") {
        "ServerConfiguration"
    } else {
        "Config"
    }
}

/// Mutates or inserts `<tag_name>new_value</tag_name>` in an XML configuration file
/// (`*arr` `config.xml` and Jellyfin `network.xml`/`system.xml`), writing atomically via `.tmp` rename.
/// Returns `Ok(true)` if the file was created or modified, or `Ok(false)` if the value was already set.
pub fn mutate_xml_element(
    file_path: &Path,
    tag_name: &str,
    new_value: &str,
) -> Result<bool, String> {
    if !SAFE_XML_TAG.is_match(tag_name) {
        return Err(format!("invalid XML tag name: {:?}", tag_name));
    }

    let existing = match read_mutation_text(file_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read XML file {}: {}",
                file_path.display(),
                e
            ))
        }
    };

    let root_tag = infer_xml_root_tag(file_path, &existing);
    if !existing.trim().is_empty() && file_path.exists() {
        if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
            let escaped_val = regex::escape(new_value.trim());
            let known_re = Regex::new(&format!(
                r"(?is)<KnownProxies>\s*<string>\s*{}\s*</string>\s*</KnownProxies>",
                escaped_val
            ))
            .ok();
            if known_re.is_some_and(|re| re.is_match(&existing)) {
                return Ok(false);
            }
        } else if let Some(current_val) = extract_xml_tag_text(&existing, tag_name) {
            if current_val == new_value.trim() {
                return Ok(false);
            }
        }
    }

    let mut content = if existing.trim().is_empty() {
        if root_tag == "NetworkConfiguration" {
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<NetworkConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n</NetworkConfiguration>\n".to_string()
        } else {
            format!("<{0}>\n</{0}>\n", root_tag)
        }
    } else {
        existing.clone()
    };

    let closing_tag = format!("</{}>", root_tag);

    if tag_name == "KnownProxies" && root_tag == "NetworkConfiguration" {
        let re_known =
            Regex::new(r"(?s)<KnownProxies\s*/>|<KnownProxies>.*?</KnownProxies>").unwrap();
        let replacement = format!(
            "<KnownProxies>\n    <string>{}</string>\n  </KnownProxies>",
            new_value
        );
        if re_known.is_match(&content) {
            content = re_known
                .replace_all(&content, replacement.as_str())
                .into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", replacement));
        } else {
            content.push_str(&format!("  {}\n", replacement));
        }
    } else {
        let escaped = regex::escape(tag_name);
        let pattern = format!(r"(?s)<{0}>.*?</{0}>|<{0}\s*/>", escaped);
        let re_tag = Regex::new(&pattern).map_err(|e| e.to_string())?;
        let new_elem = format!("<{0}>{1}</{0}>", tag_name, new_value);

        if re_tag.is_match(&content) {
            content = re_tag.replace_all(&content, new_elem.as_str()).into_owned();
        } else if let Some(idx) = content.rfind(&closing_tag) {
            content.insert_str(idx, &format!("  {}\n", new_elem));
        } else {
            content.push_str(&format!("\n<{0}>\n  {1}\n</{0}>\n", root_tag, new_elem));
        }
    }

    if content == existing && file_path.exists() {
        return Ok(false);
    }

    backup_config_file(file_path)?;
    write_file_atomic(file_path, content.as_bytes())?;
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. INI Mutator (`qBittorrent.conf`, `sabnzbd.ini`, `tautulli/config.ini`)
// ─────────────────────────────────────────────────────────────────────────────

/// Mutates or inserts `key=new_value` inside `[section]` (or globally if `section` is empty)
/// of an INI configuration file, writing atomically via `.tmp` rename.
/// Returns `Ok(true)` if the file was created or modified, or `Ok(false)` if unchanged.
pub fn mutate_ini_key(
    file_path: &Path,
    section: &str,
    key: &str,
    new_value: &str,
) -> Result<bool, String> {
    let key_trimmed = key.trim();
    if key_trimmed.is_empty() || key_trimmed.contains('\n') || key_trimmed.contains('\r') {
        return Err(format!("invalid INI key: {:?}", key));
    }
    let section_trimmed = section.trim();
    let target_section = if section_trimmed.is_empty() {
        "Preferences"
    } else {
        section_trimmed
    };

    let existing = match read_mutation_text(file_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read INI file {}: {}",
                file_path.display(),
                e
            ))
        }
    };

    if existing.trim().is_empty() {
        let content = if section_trimmed.is_empty() {
            format!("[{}]\n{}={}\n", target_section, key_trimmed, new_value)
        } else {
            format!("[{}]\n{}={}\n", section_trimmed, key_trimmed, new_value)
        };
        write_file_atomic(file_path, content.as_bytes())?;
        return Ok(true);
    }

    let want_sec_lower = section_trimmed.to_lowercase();
    let mut current_section = String::new();
    let mut found_section = want_sec_lower.is_empty();
    let mut key_updated = false;
    let mut output_lines: Vec<String> = Vec::new();
    let mut insert_after_section_idx: Option<usize> = None;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
            let sec_name = trimmed[1..trimmed.len() - 1].trim().to_lowercase();
            current_section = sec_name.clone();
            output_lines.push(line.to_string());
            if !want_sec_lower.is_empty() && current_section == want_sec_lower {
                found_section = true;
                insert_after_section_idx = Some(output_lines.len());
            }
            continue;
        }

        let in_matching_section = want_sec_lower.is_empty()
            || current_section == want_sec_lower
            || current_section.is_empty();

        if !key_updated
            && in_matching_section
            && !trimmed.starts_with('#')
            && !trimmed.starts_with(';')
        {
            if let Some((lhs, rhs)) = line.split_once('=') {
                if lhs.trim().eq_ignore_ascii_case(key_trimmed) {
                    if rhs.trim() == new_value.trim() {
                        return Ok(false);
                    }
                    output_lines.push(format!("{}={}", lhs, new_value));
                    key_updated = true;
                    continue;
                }
            }
        }

        output_lines.push(line.to_string());
        if !want_sec_lower.is_empty() && current_section == want_sec_lower {
            insert_after_section_idx = Some(output_lines.len());
        }
    }

    if !key_updated {
        let new_line = format!("{}={}", key_trimmed, new_value);
        if let Some(idx) = insert_after_section_idx {
            output_lines.insert(idx, new_line);
        } else if !found_section && !want_sec_lower.is_empty() {
            if !output_lines.is_empty() && !output_lines.last().unwrap().trim().is_empty() {
                output_lines.push(String::new());
            }
            output_lines.push(format!("[{}]", section_trimmed));
            output_lines.push(new_line);
        } else {
            output_lines.push(new_line);
        }
    }

    let final_content = format!("{}\n", output_lines.join("\n"));
    if final_content == existing {
        return Ok(false);
    }

    backup_config_file(file_path)?;
    let mode = (section == "misc" && key.eq_ignore_ascii_case("password")).then_some(0o600);
    write_file_atomic_mode(file_path, final_content.as_bytes(), mode)?;
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. JSON Mutator (Transmission `settings.json`, Overseerr, Jackett, etc.)
// ─────────────────────────────────────────────────────────────────────────────

/// Mutates or inserts `key: new_value` in a JSON object file (supports top-level keys
/// and dotted paths like `"main.port"`), writing pretty-printed JSON atomically via `.tmp` rename.
/// Returns `Ok(true)` if the file was created or modified, or `Ok(false)` if unchanged.
pub fn mutate_json_key(file_path: &Path, key: &str, new_value: Value) -> Result<bool, String> {
    let key_trimmed = key.trim();
    if key_trimmed.is_empty() {
        return Err("JSON key cannot be empty".to_string());
    }

    let existing = match read_mutation_text(file_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read JSON file {}: {}",
                file_path.display(),
                e
            ))
        }
    };

    let mut root: Value = if existing.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(&existing)
            .map_err(|e| format!("failed to parse JSON file {}: {}", file_path.display(), e))?
    };

    if !root.is_object() {
        return Err(format!(
            "JSON root in {} is not an object",
            file_path.display()
        ));
    }

    let mut changed = !file_path.exists();
    if let Some((parent_key, child_key)) = key_trimmed.split_once('.') {
        let obj = root.as_object_mut().unwrap();
        // If the literal dotted key exists at top level, update it directly
        if obj.contains_key(key_trimmed) {
            if obj.get(key_trimmed) != Some(&new_value) {
                obj.insert(key_trimmed.to_string(), new_value);
                changed = true;
            }
        } else {
            let entry = obj
                .entry(parent_key.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(sub_obj) = entry.as_object_mut() {
                if sub_obj.get(child_key) != Some(&new_value) {
                    sub_obj.insert(child_key.to_string(), new_value);
                    changed = true;
                }
            } else {
                return Err(format!(
                    "nested JSON key {:?} is not an object in {}",
                    parent_key,
                    file_path.display()
                ));
            }
        }
    } else {
        let obj = root.as_object_mut().unwrap();
        if obj.get(key_trimmed) != Some(&new_value) {
            obj.insert(key_trimmed.to_string(), new_value);
            changed = true;
        }
    }

    if !changed {
        return Ok(false);
    }

    let serialized = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("failed to serialize JSON: {}", e))?;
    let final_content = format!("{}\n", serialized);

    backup_config_file(file_path)?;
    write_file_atomic(file_path, final_content.as_bytes())?;
    Ok(true)
}

pub fn extract_ini_value(content: &str, keys: &[&str]) -> Option<String> {
    if content.is_empty() || keys.is_empty() {
        return None;
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
            let unquoted = val.trim_matches(['"', '\'']).trim();
            if !unquoted.is_empty() {
                return Some(unquoted.to_string());
            }
        }
    }
    None
}

fn app_metadata_logical_path(path: &Path) -> PathBuf {
    for key in ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"] {
        if let Some(root) = env::var_os(key).filter(|value| !value.is_empty()) {
            if let Ok(relative) = path.strip_prefix(&root) {
                return Path::new("/").join(relative);
            }
        }
    }
    path.to_path_buf()
}

pub fn read_metadata_config(path: impl AsRef<Path>) -> std::io::Result<String> {
    let path = path.as_ref();
    crate::read_app_metadata_config(path, &app_metadata_logical_path(path))
}

pub fn mutate_pihole_toml(file_path: &Path, port: i32) -> Result<bool, String> {
    if !file_path.is_file() {
        return Ok(false);
    }
    let existing = read_mutation_text(file_path)
        .map_err(|e| format!("failed to read {}: {}", file_path.display(), e))?;
    let port_str = format!("{}o", port);

    let re_port_line = Regex::new(r#"^(\s*port\s*=\s*).*$"#).unwrap();
    let re_dnsmasq_line = Regex::new(r"^(\s*etc_dnsmasq_d\s*=\s*)(?:true|false)(.*)$").unwrap();

    let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
    let mut current_section = String::new();
    let mut found_webserver = false;
    let mut webserver_end = lines.len();
    let mut replaced_webserver_port = false;

    for idx in 0..lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if let Some(end) = trimmed.find(']') {
                let sec = trimmed[1..end].trim().to_string();
                if current_section == "webserver" && webserver_end == lines.len() {
                    webserver_end = idx;
                }
                current_section = sec.clone();
                if sec == "webserver" {
                    found_webserver = true;
                }
                continue;
            }
        }
        if current_section == "webserver" {
            if let Some(caps) = re_port_line.captures(&lines[idx]) {
                lines[idx] = format!("{}\"{}\"", &caps[1], port_str);
                replaced_webserver_port = true;
            }
        } else if (current_section == "misc" || current_section.is_empty())
            && re_dnsmasq_line.is_match(&lines[idx])
        {
            lines[idx] = re_dnsmasq_line
                .replace(&lines[idx], "${1}true${2}")
                .into_owned();
        }
    }

    if !replaced_webserver_port {
        if found_webserver {
            lines.insert(webserver_end, format!("  port = \"{}\"", port_str));
        } else {
            if !lines.is_empty() && !lines.last().unwrap().trim().is_empty() {
                lines.push(String::new());
            }
            lines.push("[webserver]".to_string());
            lines.push(format!("  port = \"{}\"", port_str));
        }
    }

    let mut content = lines.join("\n");
    if existing.ends_with('\n') || !content.is_empty() {
        content.push('\n');
    }

    if content == existing {
        return Ok(false);
    }
    backup_config_file(file_path)?;
    write_file_atomic(file_path, content.as_bytes())?;
    Ok(true)
}

pub fn mutate_yaml_section_key(
    file_path: &Path,
    section: &str,
    key: &str,
    new_val: &str,
) -> Result<bool, String> {
    let existing = read_mutation_text(file_path)
        .map_err(|e| format!("failed to read {}: {}", file_path.display(), e))?;
    let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();

    let mut in_section = false;
    let mut found_section = false;
    let mut section_end = lines.len();
    let mut section_indent = "  ".to_string();
    let mut replaced = false;

    for (idx, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent_len = line.len() - line.trim_start().len();
        if indent_len == 0 {
            if in_section {
                section_end = idx;
                in_section = false;
            }
            if let Some(header) = trimmed.strip_suffix(':') {
                if header.trim() == section {
                    in_section = true;
                    found_section = true;
                }
            }
            continue;
        }
        if in_section {
            section_indent = line[..indent_len].to_string();
            let line_no_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
            if let Some((lhs, _rhs)) = line_no_comment.split_once(':') {
                if lhs.trim() == key {
                    let prefix = &line[..indent_len];
                    *line = format!("{}{}: {}", prefix, key, new_val);
                    replaced = true;
                    break;
                }
            }
        }
    }

    if !replaced {
        if found_section {
            lines.insert(
                section_end,
                format!("{}{}: {}", section_indent, key, new_val),
            );
        } else {
            if !lines.is_empty() && !lines.last().unwrap().trim().is_empty() {
                lines.push(String::new());
            }
            lines.push(format!("{}:", section));
            lines.push(format!("  {}: {}", key, new_val));
        }
    }

    let mut updated = lines.join("\n");
    if existing.ends_with('\n') || !updated.is_empty() {
        updated.push('\n');
    }
    if updated == existing {
        return Ok(false);
    }
    backup_config_file(file_path)?;
    write_file_atomic(file_path, updated.as_bytes())?;
    Ok(true)
}

pub fn mutate_systemd_aspnetcore_urls(file_path: &Path, port: i32) -> Result<bool, String> {
    let existing = read_mutation_text(file_path)
        .map_err(|e| format!("failed to read {}: {}", file_path.display(), e))?;
    let re = Regex::new(
        r#"(?m)^(\s*Environment\s*=\s*["']?ASPNETCORE_URLS\s*=\s*https?://(?:\[[^\]]+\]|[^:\s"']+):)[0-9]{1,5}([^"'\s]*["']?\s*)$"#,
    )
    .unwrap();
    let updated = if re.is_match(&existing) {
        re.replace_all(&existing, format!("${{1}}{}${{2}}", port))
            .into_owned()
    } else {
        let re_service = Regex::new(r"(?m)^(\s*\[Service\]\s*)$").unwrap();
        let line = format!("Environment=\"ASPNETCORE_URLS=http://127.0.0.1:{}\"", port);
        if re_service.is_match(&existing) {
            re_service
                .replace(&existing, format!("${{1}}\n{}", line))
                .into_owned()
        } else {
            return Ok(false);
        }
    };
    if updated == existing {
        return Ok(false);
    }
    backup_config_file(file_path)?;
    write_file_atomic(file_path, updated.as_bytes())?;
    Ok(true)
}

pub fn mutate_dispatcharr_port(file_path: &Path, port: i32) -> Result<bool, String> {
    let existing = read_mutation_text(file_path).map_err(|error| error.to_string())?;
    let port_str = port.to_string();
    for line in existing.lines() {
        let trimmed = line.trim();
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            if lhs.trim() == "DISPATCHARR_PORT" {
                let clean_rhs = rhs.trim().trim_matches('"').trim_matches('\'').trim();
                if clean_rhs == port_str {
                    return Ok(false);
                }
            }
        }
    }
    let setting = format!("DISPATCHARR_PORT={}", port);
    let pattern = Regex::new(r"(?m)^\s*DISPATCHARR_PORT\s*=.*$").unwrap();
    let updated = if pattern.is_match(&existing) {
        pattern
            .replace_all(&existing, setting.as_str())
            .into_owned()
    } else {
        format!(
            "{}{}{}\n",
            existing,
            if existing.ends_with('\n') || existing.is_empty() {
                ""
            } else {
                "\n"
            },
            setting
        )
    };
    if updated == existing {
        return Ok(false);
    }
    backup_config_file(file_path)?;
    write_file_atomic(file_path, updated.as_bytes())?;
    Ok(true)
}

pub(crate) fn mutate_transmission_whitelist(
    path: &Path,
    base_domain: &str,
    ingress: Option<&af_models::AppIngressConfig>,
) -> Result<bool, String> {
    let text = read_mutation_text(path).map_err(|err| {
        format!(
            "failed to read Transmission settings {}: {err}",
            path.display()
        )
    })?;
    let settings: Value = serde_json::from_str(&text)
        .map_err(|err| format!("invalid Transmission settings {}: {err}", path.display()))?;
    let mut hosts: Vec<_> = settings["rpc-host-whitelist"]
        .as_str()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect();
    let public = ingress
        .map(|ingress| ingress.public_domain.trim().to_ascii_lowercase())
        .filter(|domain| af_models::valid_ingress_hostname(domain));
    let base_host = (!base_domain.is_empty()).then(|| format!("transmission.{base_domain}"));
    for host in ["transmission.aether.local", "localhost", "127.0.0.1"]
        .into_iter()
        .chain(base_host.as_deref())
        .chain(public.as_deref())
    {
        if !hosts
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(host))
        {
            hosts.push(host.to_owned());
        }
    }
    mutate_json_key(path, "rpc-host-whitelist", json!(hosts.join(",")))
}

pub(crate) fn mutate_systemd_port(path: &Path, port: i32) -> Result<bool, String> {
    let original = read_mutation_text(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    static PORT_LINE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"^([ \t]*Environment[ \t]*=[ \t]*["']?PORT=)[0-9]+(["']?[ \t]*\r?\n?)$"#)
            .expect("valid port directive regex")
    });
    let mut lines: Vec<_> = original.split_inclusive('\n').map(str::to_owned).collect();
    let Some(header) = lines.iter().rposition(|line| line.trim() == "[Service]") else {
        return Err(format!("missing [Service] section in {}", path.display()));
    };
    let end = (header + 1..lines.len())
        .find(|&index| lines[index].trim_start().starts_with('['))
        .unwrap_or(lines.len());
    let last_environment = (header + 1..end).rev().find(|&index| {
        lines[index]
            .split_once('=')
            .is_some_and(|(name, _)| name.trim() == "Environment")
    });
    if let Some(index) = last_environment
        .filter(|&index| {
            !lines[header + 1..index]
                .iter()
                .any(|line| line.trim_end().ends_with('\\'))
        })
        .filter(|&index| PORT_LINE.is_match(&lines[index]))
    {
        let captured = PORT_LINE
            .captures(&lines[index])
            .expect("matched port directive");
        lines[index] = format!("{}{port}{}", &captured[1], &captured[2]);
    } else {
        let newline = if lines[header].ends_with("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        if !lines[end - 1].ends_with('\n') {
            lines[end - 1].push_str(newline);
        }
        // Appending after existing directives handles resets and mixed assignments.
        lines.insert(end, format!("Environment=PORT={port}{newline}"));
    }
    let updated = lines.concat();
    if updated == original {
        return Ok(false);
    }
    backup_config_file(path)?;
    write_file_atomic(path, updated.as_bytes())?;
    Ok(true)
}
