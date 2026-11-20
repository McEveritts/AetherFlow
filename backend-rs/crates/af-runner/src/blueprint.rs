//! Native application configuration shared by the API and privileged runner.

use af_models::{RunnerBlueprintApplyRequest, RunnerBlueprintApplyResponse};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::resolve_runner_fs_path as resolve_config_path;

pub const MASTER_CREDS_SYSTEM_KEY: &str = "master_credentials";

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
fn validate_no_symlink_parents(file_path: &Path, require_exists: bool) -> Result<(), String> {
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

fn read_mutation_text(path: &Path) -> std::io::Result<String> {
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

// ─────────────────────────────────────────────────────────────────────────────
// 4. SQLite Setting Mutator & `*arr` DownloadClients Route Injector
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrites `DownloadClients.Settings` JSON blobs in `*arr` SQLite databases (`sonarr.db`, `radarr.db`, etc.)
/// to route matching `Host` entries through the AetherFlow internal switchboard domain and port.
pub fn inject_arr_download_client_routes(
    db_path: &Path,
    routes: &HashMap<String, String>,
    target_port: i32,
) -> Result<usize, String> {
    if !db_path.is_file() || routes.is_empty() {
        return Ok(0);
    }

    let mut conn = Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| format!("failed to open *arr DB {}: {}", db_path.display(), e))?;
    conn.busy_timeout(Duration::from_millis(2500))
        .map_err(|err| err.to_string())?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| format!("failed to start transaction for *arr route update: {err}"))?;
    let has_clients: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'DownloadClients' AND type = 'table')",
        [],
        |row| row.get(0),
    ).map_err(|err| format!("cannot inspect *arr download clients: {err}"))?;
    if !has_clients {
        return Ok(0);
    }
    let has_implementation: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('DownloadClients') WHERE name = 'Implementation' COLLATE NOCASE)",
        [],
        |row| row.get(0),
    ).map_err(|err| format!("cannot inspect *arr download client settings: {err}"))?;

    let collected_rows: Vec<(i64, String, String)> = {
        let query = if has_implementation {
            "SELECT Id, COALESCE(Implementation, ''), Settings FROM DownloadClients"
        } else {
            "SELECT Id, '', Settings FROM DownloadClients"
        };
        let mut stmt = tx.prepare(query).map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<_, _>>()
            .map_err(|err| err.to_string())?
    };

    let mut updates: Vec<(i64, String)> = Vec::new();
    for (id, implementation, settings_str) in collected_rows {
        let Ok(mut settings_json) = serde_json::from_str::<Value>(&settings_str) else {
            continue;
        };
        let Some(obj) = settings_json.as_object_mut() else {
            continue;
        };
        let current_host = obj
            .get("Host")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("host").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let existing_port = obj
            .get("Port")
            .and_then(|v| v.as_i64())
            .or_else(|| obj.get("port").and_then(|v| v.as_i64()))
            .unwrap_or(0) as i32;

        if let Some(host_val) = current_host {
            if let Some(default_host) = routes.get(&host_val) {
                let impl_lower = implementation.trim().to_ascii_lowercase();
                let (new_host, desired_port) = match impl_lower.as_str() {
                    "transmission" => ("transmission.aether.local".to_string(), {
                        let p =
                            crate::extract_app_runtime_meta_local("transmission").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "deluge" => ("deluge.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("deluge").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "sabnzbd" => ("sabnzbd.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("sabnzbd").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "nzbget" => ("nzbget.aether.local".to_string(), {
                        let p = crate::extract_app_runtime_meta_local("nzbget").configured_port;
                        if p > 0 {
                            p
                        } else {
                            existing_port
                        }
                    }),
                    "" if existing_port == 9091 => {
                        ("transmission.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 8112 || existing_port == 58846 => {
                        ("deluge.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 8085 => {
                        ("sabnzbd.aether.local".to_string(), existing_port)
                    }
                    "" if existing_port == 6789 => {
                        ("nzbget.aether.local".to_string(), existing_port)
                    }
                    "qbittorrent" | "" => (default_host.clone(), target_port),
                    _ => continue,
                };
                if obj.contains_key("Host") {
                    obj.insert("Host".to_string(), Value::String(new_host));
                } else {
                    obj.insert("host".to_string(), Value::String(new_host));
                }
                if desired_port > 0 {
                    if obj.contains_key("Port") {
                        obj.insert("Port".to_string(), json!(desired_port));
                    } else {
                        obj.insert("port".to_string(), json!(desired_port));
                    }
                }
                if let Ok(serialized) = serde_json::to_string(&settings_json) {
                    updates.push((id, serialized));
                }
            }
        }
    }

    let count = updates.len();
    for (id, new_settings) in updates {
        tx.execute(
            "UPDATE DownloadClients SET Settings = ?1 WHERE Id = ?2",
            params![new_settings, id],
        )
        .map_err(|err| format!("failed to update DownloadClients Id={id}: {err}"))?;
    }
    tx.commit()
        .map_err(|err| format!("failed to commit *arr DB updates: {err}"))?;

    Ok(count)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Local DNS `/etc/hosts` + Pi-hole / dnsmasq Synchronizer
// ─────────────────────────────────────────────────────────────────────────────

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterCreds {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ha1: String,
}

pub fn master_ha1(username: &str, password: &str) -> Result<String, String> {
    let digest = af_models::md5::md5_digest(
        format!("{username}:Welcome to AetherFlow:{password}").as_bytes(),
    );
    Ok(hex::encode(digest))
}

fn pbkdf2_hmac_sha512_block1(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    // HMAC-SHA512 block size is 128 bytes
    let mut key_block = [0u8; 128];
    if password.len() > 128 {
        let hashed = Sha512::digest(password);
        key_block[..64].copy_from_slice(&hashed);
    } else {
        key_block[..password.len()].copy_from_slice(password);
    }

    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_base = Sha512::new();
    inner_base.update(ipad);
    let mut outer_base = Sha512::new();
    outer_base.update(opad);

    // U_1 = HMAC-SHA512(password, salt || INT_32_BE(1))
    let mut inner = inner_base.clone();
    inner.update(salt);
    inner.update(1u32.to_be_bytes());
    let inner_hash = inner.finalize();

    let mut outer = outer_base.clone();
    outer.update(inner_hash);
    let mut u: [u8; 64] = outer.finalize().into();
    let mut dk = u;

    for _ in 1..iterations {
        let mut i_ctx = inner_base.clone();
        i_ctx.update(u);
        let i_out = i_ctx.finalize();

        let mut o_ctx = outer_base.clone();
        o_ctx.update(i_out);
        u = o_ctx.finalize().into();

        for (d_byte, u_byte) in dk.iter_mut().zip(u.iter()) {
            *d_byte ^= *u_byte;
        }
    }

    dk
}

/// Generates qBittorrent's `WebUI\Password_PBKDF2` format:
/// `"@ByteArray(<base64-16B-salt>:<base64-64B-PBKDF2-HMAC-SHA512-100000>)"`
pub fn generate_qbittorrent_pbkdf2(password: &str) -> String {
    let entropy = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
    let salt = &Sha256::digest(
        [
            entropy[0].as_bytes().as_slice(),
            entropy[1].as_bytes().as_slice(),
        ]
        .concat(),
    )[..16];
    let dk = pbkdf2_hmac_sha512_block1(password.as_bytes(), salt, 100_000);
    let salt_b64 = BASE64_STD.encode(salt);
    let dk_b64 = BASE64_STD.encode(dk);
    format!("\"@ByteArray({}:{})\"", salt_b64, dk_b64)
}

fn default_master_cred_paths() -> Vec<PathBuf> {
    vec![resolve_config_path("/var/lib/aetherflow/.master.creds")]
}

pub fn master_cred_paths() -> Vec<PathBuf> {
    if let Ok(custom) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return vec![PathBuf::from(trimmed)];
        }
    }
    default_master_cred_paths()
}

fn decode_stored_master_creds(creds: MasterCreds) -> Option<(String, String, String)> {
    let user = creds.username.trim().to_string();
    if user.is_empty() || creds.password.trim().is_empty() {
        return None;
    }
    let password = af_db::decrypt_secret_if_needed(creds.password.trim()).ok()?;
    if password.is_empty() || password == "adminadmin" {
        return None;
    }
    let ha1 = match load_install_master_conf() {
        Some((loaded_user, loaded_password, loaded_ha1))
            if loaded_user == user && loaded_password == password =>
        {
            loaded_ha1
        }
        _ => master_ha1(&user, &password).ok()?,
    };
    Some((user, password, ha1))
}

fn hmac_sha256_bytes(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut block_key = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        block_key[..32].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_digest);
    out
}

/// Derives a domain-separated, irreversible 32-hex-character WebUI password for
/// applications that store cleartext passwords in their local INI/TOML configs
/// (such as SABnzbd), preventing recovery of the shared provisioning secret.
pub fn derive_app_webui_password(app_id: &str, master_pass: &str) -> String {
    let msg = format!("aetherflow:{}:webui:v1", app_id.trim().to_ascii_lowercase());
    let digest = hmac_sha256_bytes(master_pass.as_bytes(), msg.as_bytes());
    hex::encode(&digest[..16])
}

/// Loads `(username, password, ha1)` from the master credentials file, the installer
/// conf, or a previously encrypted `system_config` row.
pub fn load_master_credentials() -> (String, String, String) {
    load_master_credentials_with(|| {
        let conn = af_db::get_conn().ok()?;
        database_master_credentials(&conn)
    })
}

fn load_master_credentials_with(
    load_database: impl FnOnce() -> Option<(String, String, String)>,
) -> (String, String, String) {
    let mut read_paths = master_cred_paths();
    if env::var("AETHERFLOW_MASTER_CREDS_FILE")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        read_paths.push(resolve_config_path(
            "/opt/AetherFlow/backend/data/.master.creds",
        ));
    }
    for path in read_paths {
        if let Ok(data) = crate::read_confined_text(&path, &["aetherflow"]) {
            if let Ok(creds) = serde_json::from_str::<MasterCreds>(&data) {
                if let Some(decoded) = decode_stored_master_creds(creds) {
                    return decoded;
                }
            }
        }
    }
    if let Some(from_conf) = load_install_master_conf() {
        return from_conf;
    }
    load_database().unwrap_or_default()
}

fn database_master_credentials(conn: &Connection) -> Option<(String, String, String)> {
    let raw: String = conn
        .query_row(
            "SELECT value FROM system_config WHERE key = ?1",
            params![MASTER_CREDS_SYSTEM_KEY],
            |row| row.get(0),
        )
        .ok()?;
    let decrypted = af_db::decrypt_secret_if_needed(&raw)
        .or_else(|_| af_db::decrypt_key(&raw))
        .ok()?;
    decode_stored_master_creds(serde_json::from_str::<MasterCreds>(&decrypted).ok()?)
}

fn load_install_master_conf() -> Option<(String, String, String)> {
    let text = read_metadata_config(resolve_config_path("/install/.aetherflow.conf")).ok()?;
    let mut username = String::new();
    let mut password = String::new();
    let mut ha1 = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let val = value
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_string();
        match key.trim() {
            "username" => username = val,
            "passwd" => password = val,
            "ha1pass" => ha1 = val,
            _ => {}
        }
    }
    if username.is_empty() || password.is_empty() {
        return None;
    }
    if ha1.len() != 32 || !ha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        ha1 = master_ha1(&username, &password).ok()?;
    }
    Some((username, password, ha1))
}

pub struct NativeAppSpec {
    pub config_paths: Vec<String>,
    pub sqlite_db_path: Option<String>,
}

pub fn native_app_spec(canonical_app: &str, bp_config_path: &str) -> NativeAppSpec {
    let mut paths = Vec::new();
    if !bp_config_path.trim().is_empty() {
        paths.push(bp_config_path.trim().to_string());
    }

    match canonical_app {
        "dispatcharr" => NativeAppSpec {
            config_paths: vec!["/etc/dispatcharr/dispatcharr.env".to_string()],
            sqlite_db_path: None,
        },
        "gitea" => NativeAppSpec {
            config_paths: vec!["/etc/gitea/app.ini".to_string()],
            sqlite_db_path: None,
        },
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
            for candidate in [
                format!("/var/lib/{}/config.xml", canonical_app),
                format!("/var/lib/{}/config/config.xml", canonical_app),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: Some(format!("/var/lib/{}/{}.db", canonical_app, canonical_app)),
            }
        }
        "listenarr" => {
            for candidate in [
                "/var/lib/listenarr/config.xml".to_string(),
                "/var/lib/listenarr/config/config.xml".to_string(),
                "/etc/systemd/system/listenarr.service".to_string(),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "bazarr" => {
            for candidate in [
                "/var/lib/bazarr/config/config.yaml".to_string(),
                "/var/lib/bazarr/data/config/config.yaml".to_string(),
                "/opt/bazarr/data/config/config.yaml".to_string(),
                "/etc/bazarr/config.yaml".to_string(),
                "/var/lib/bazarr/config/config.ini".to_string(),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "jellyfin" => {
            for p in [
                "/etc/jellyfin/network.xml",
                "/var/lib/jellyfin/config/network.xml",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "emby" => {
            for p in ["/var/lib/emby/config/system.xml", "/etc/emby/system.xml"] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "qbittorrent" => {
            for p in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "sabnzbd" => {
            for p in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "tautulli" => {
            for p in [
                "/var/lib/tautulli/config.ini",
                "/opt/Tautulli/config.ini",
                "/etc/tautulli/config.ini",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "transmission" | "transmission-daemon" => {
            for p in TRANSMISSION_CONFIG_PATHS {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "overseerr" | "jellyseerr" => {
            for candidate in [
                format!("/etc/systemd/system/{canonical_app}.service"),
                format!("/var/lib/{canonical_app}/settings.json"),
                format!("/var/lib/{canonical_app}/config/settings.json"),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "jackett" => {
            for p in [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "pihole" => {
            let s = "/etc/pihole/pihole.toml".to_string();
            if !paths.contains(&s) {
                paths.push(s);
            }
            NativeAppSpec {
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        _ => NativeAppSpec {
            config_paths: paths,
            sqlite_db_path: None,
        },
    }
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

/// Whether file mutations are explicitly scoped to a filesystem fixture.
pub fn has_config_root() -> bool {
    resolve_config_path("/etc/apache2") != Path::new("/etc/apache2")
}

fn check_app_file(path: &Path, logical: &str) -> Result<bool, String> {
    let users = crate::app_metadata_users(Path::new(logical));
    match crate::open_confined_file(path, &users.iter().map(String::as_str).collect::<Vec<_>>()) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "cannot access blueprint file {}: {err}",
            path.display()
        )),
    }
}

pub fn apply_host_config(
    req: &RunnerBlueprintApplyRequest,
) -> anyhow::Result<RunnerBlueprintApplyResponse> {
    apply_host_config_with_state(req, None)
}

pub(crate) fn apply_host_config_with_state(
    req: &RunnerBlueprintApplyRequest,
    state: Option<&Connection>,
) -> anyhow::Result<RunnerBlueprintApplyResponse> {
    // Serialize native config writers across API callers. API-driven calls also
    // hold the cross-process blueprint admission lock until this request returns.
    static MUTATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = MUTATION_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let app = match req.app_name.as_str() {
        "transmission-daemon" => "transmission",
        app => app,
    };
    anyhow::ensure!(crate::SAFE_PKG_ID.is_match(app), "invalid blueprint app");
    anyhow::ensure!(
        (0..=65535).contains(&req.listen_port),
        "invalid blueprint port"
    );
    let spec = native_app_spec(app, "");
    if spec.config_paths.is_empty() {
        return Ok(RunnerBlueprintApplyResponse {
            mutated_files: Vec::new(),
            sqlite_routes_injected: 0,
        });
    }
    let existing_ingress = if matches!(app, "sabnzbd" | "transmission") {
        match state {
            Some(conn) => af_db::load_lifecycle_ingress(conn, app)?,
            None if req.lifecycle_job_id.is_empty() => af_db::get_app_ingress_config(app)?,
            None => {
                let conn = af_db::get_conn()?;
                af_db::load_lifecycle_ingress(&conn, app)?
            }
        }
    } else {
        None
    };
    let master = if matches!(app, "qbittorrent" | "sabnzbd" | "transmission") {
        match state {
            Some(conn) => load_master_credentials_with(|| database_master_credentials(conn)),
            None => load_master_credentials(),
        }
    } else {
        Default::default()
    };
    let real_host = !has_config_root() && cfg!(target_os = "linux");
    let transmission = real_host
        && app == "transmission"
        && spec
            .config_paths
            .iter()
            .any(|path| resolve_config_path(path).symlink_metadata().is_ok());
    with_transmission_stopped(transmission, run_systemctl, || {
        let mut changes = crate::package_executor::RunnerBlueprintConfigChanges::new(None);
        let result = apply_native_config(
            app,
            req.listen_port,
            &spec,
            existing_ingress,
            master,
            state,
            &mut changes,
        );
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                return Err(changes
                    .rollback(
                        crate::package_executor::PackageExecutorError::VerificationFailed(error),
                    )
                    .into())
            }
        };
        if real_host && service_units_changed(&response.mutated_files) {
            if let Err(error) = reload_changed_units(&response.mutated_files, run_systemctl) {
                let rollback = changes.rollback(
                    crate::package_executor::PackageExecutorError::VerificationFailed(
                        error.to_string(),
                    ),
                );
                if let Err(error) = reload_changed_units(&response.mutated_files, run_systemctl) {
                    anyhow::bail!("{rollback}; reloading restored systemd units failed: {error}");
                }
                return Err(rollback.into());
            }
        }
        Ok(response)
    })
}

fn apply_native_config(
    app: &str,
    effective_port: i32,
    spec: &NativeAppSpec,
    existing_ingress: Option<af_models::AppIngressConfig>,
    (master_user, master_pass, _): (String, String, String),
    state: Option<&Connection>,
    changes: &mut crate::package_executor::RunnerBlueprintConfigChanges<'_>,
) -> Result<RunnerBlueprintApplyResponse, String> {
    let mut mutated_files = Vec::new();
    static KNOWN_PROXIES_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)<KnownProxies>\s*(.*?)\s*</KnownProxies>").expect("valid regex")
    });
    for raw_path in &spec.config_paths {
        let resolved = resolve_config_path(raw_path);
        if app == "transmission" && is_transmission_config_alias(&resolved, resolve_config_path) {
            continue;
        }
        let best_effort = matches!(app, "overseerr" | "jellyseerr") && raw_path.ends_with(".json");
        let checked = check_app_file(&resolved, raw_path).and_then(|exists| {
            if exists {
                changes.capture(&resolved).map_err(|err| err.to_string())?;
            }
            Ok(exists)
        });
        match checked {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) if best_effort => {
                tracing::warn!(path = %resolved.display(), %error, "Skipping optional Seerr configuration");
                continue;
            }
            Err(error) => return Err(error),
        }
        let port_str = effective_port.to_string();
        match app {
            "dispatcharr" => {
                if effective_port > 0 && mutate_dispatcharr_port(&resolved, effective_port)? {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "gitea" => {
                if effective_port > 0
                    && mutate_ini_key(&resolved, "server", "HTTP_PORT", &port_str)?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= mutate_xml_element(&resolved, "Port", &port_str)?;
                }
                let has_bind = read_xml_element(&resolved, "BindAddress")
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_bind {
                    file_changed |= mutate_xml_element(&resolved, "BindAddress", "127.0.0.1")?;
                }
                file_changed |= mutate_xml_element(&resolved, "AuthenticationMethod", "Forms")?;
                file_changed |= mutate_xml_element(&resolved, "AnalyticsEnabled", "False")?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "listenarr" => {
                let ext = resolved
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if ext == "service" {
                    if effective_port > 0
                        && mutate_systemd_aspnetcore_urls(&resolved, effective_port)?
                    {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                } else {
                    let mut file_changed = false;
                    if effective_port > 0 {
                        file_changed |= mutate_xml_element(&resolved, "Port", &port_str)?;
                    }
                    let has_bind = read_xml_element(&resolved, "BindAddress")
                        .is_some_and(|v| !v.trim().is_empty());
                    if !has_bind {
                        file_changed |= mutate_xml_element(&resolved, "BindAddress", "127.0.0.1")?;
                    }
                    file_changed |= mutate_xml_element(&resolved, "AuthenticationMethod", "Forms")?;
                    file_changed |= mutate_xml_element(&resolved, "AnalyticsEnabled", "False")?;
                    if file_changed {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
            }
            "bazarr" => {
                if effective_port > 0 {
                    let ext = resolved
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let changed = if ext == "ini" {
                        mutate_ini_key(&resolved, "general", "port", &port_str)?
                    } else {
                        mutate_yaml_section_key(&resolved, "general", "port", &port_str)?
                    };
                    if changed {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
            }
            "jellyfin" => {
                let mut file_changed = false;
                let existing_xml = read_mutation_text(&resolved).map_err(|err| err.to_string())?;
                let has_remote_access = extract_xml_tag_text(&existing_xml, "EnableRemoteAccess")
                    .is_some_and(|v| !v.trim().is_empty());
                let has_known_proxies = KNOWN_PROXIES_RE
                    .captures(&existing_xml)
                    .and_then(|c| c.get(1))
                    .is_some_and(|m| !m.as_str().trim().is_empty());
                if effective_port > 0 {
                    file_changed |= mutate_xml_element(&resolved, "InternalHttpPort", &port_str)?;
                    file_changed |= mutate_xml_element(&resolved, "PublicHttpPort", &port_str)?;
                }
                file_changed |= mutate_xml_element(&resolved, "EnableIPV4", "true")?;
                if !has_remote_access {
                    file_changed |= mutate_xml_element(&resolved, "EnableRemoteAccess", "true")?;
                }
                if !has_known_proxies {
                    file_changed |= mutate_xml_element(&resolved, "KnownProxies", "127.0.0.1")?;
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "emby" => {
                if effective_port > 0 {
                    let mut file_changed = false;
                    file_changed |=
                        mutate_xml_element(&resolved, "HttpServerPortNumber", &port_str)?;
                    file_changed |= mutate_xml_element(&resolved, "PublicPort", &port_str)?;
                    if file_changed {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
            }
            "qbittorrent" => {
                let mut file_changed = false;
                let existing_ini = read_mutation_text(&resolved).map_err(|err| err.to_string())?;
                if effective_port > 0 {
                    file_changed |=
                        mutate_ini_key(&resolved, "Preferences", r"WebUI\Port", &port_str)?;
                }
                let has_addr = extract_ini_value(&existing_ini, &[r"WebUI\Address"])
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_addr {
                    file_changed |=
                        mutate_ini_key(&resolved, "Preferences", r"WebUI\Address", "127.0.0.1")?;
                }
                if !master_user.is_empty() && !master_pass.is_empty() {
                    let has_user = extract_ini_value(&existing_ini, &[r"WebUI\Username"])
                        .is_some_and(|v| !v.trim().is_empty());
                    let has_pass = extract_ini_value(&existing_ini, &[r"WebUI\Password_PBKDF2"])
                        .is_some_and(|v| !v.trim().is_empty());
                    if !has_user || !has_pass {
                        let qbit_hash = generate_qbittorrent_pbkdf2(&master_pass);
                        file_changed |= mutate_ini_key(
                            &resolved,
                            "Preferences",
                            r"WebUI\Username",
                            &master_user,
                        )?;
                        file_changed |= mutate_ini_key(
                            &resolved,
                            "Preferences",
                            r"WebUI\Password_PBKDF2",
                            &qbit_hash,
                        )?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "sabnzbd" => {
                let mut file_changed = false;
                let existing_ini = read_mutation_text(&resolved).map_err(|err| err.to_string())?;
                if effective_port > 0 {
                    file_changed |= mutate_ini_key(&resolved, "misc", "port", &port_str)?;
                }
                let has_host = extract_ini_value(&existing_ini, &["host"])
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_host {
                    file_changed |= mutate_ini_key(&resolved, "misc", "host", "127.0.0.1")?;
                }
                let mut whitelist = "sabnzbd.aether.local, localhost, 127.0.0.1".to_string();
                let base_domain = blueprint_base_domain(state).map_err(|err| err.to_string())?;
                if !base_domain.is_empty() {
                    let public_domain = format!("sabnzbd.{base_domain}");
                    if !public_domain.is_empty() {
                        whitelist = format!("{}, {}", public_domain, whitelist);
                    }
                }
                if let Some(custom) = existing_ingress
                    .as_ref()
                    .filter(|ing| ing.external_access_enabled)
                    .map(|ing| ing.public_domain.trim().to_ascii_lowercase())
                    .filter(|custom| af_models::valid_ingress_hostname(custom))
                {
                    if !whitelist
                        .split(", ")
                        .any(|domain| domain.eq_ignore_ascii_case(&custom))
                    {
                        whitelist = format!("{custom}, {whitelist}");
                    }
                }
                file_changed |= mutate_ini_key(&resolved, "misc", "host_whitelist", &whitelist)?;
                if !master_user.is_empty() && !master_pass.is_empty() {
                    let has_user = extract_ini_value(&existing_ini, &["username"])
                        .is_some_and(|v| !v.trim().is_empty());
                    let has_pass = extract_ini_value(&existing_ini, &["password"])
                        .is_some_and(|v| !v.trim().is_empty());
                    if !has_user || !has_pass {
                        let sab_pass = derive_app_webui_password("sabnzbd", &master_pass);
                        file_changed |=
                            mutate_ini_key(&resolved, "misc", "username", &master_user)?;
                        file_changed |= mutate_ini_key(&resolved, "misc", "password", &sab_pass)?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "tautulli" => {
                if effective_port > 0
                    && mutate_ini_key(&resolved, "General", "http_port", &port_str)?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "transmission" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= mutate_json_key(&resolved, "rpc-port", json!(effective_port))?;
                }
                let existing_json: Value = read_mutation_text(&resolved)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_else(|| json!({}));
                if existing_json.get("rpc-whitelist-enabled").is_none() {
                    file_changed |=
                        mutate_json_key(&resolved, "rpc-whitelist-enabled", json!(false))?;
                }
                if existing_json.get("rpc-host-whitelist-enabled").is_none() {
                    file_changed |=
                        mutate_json_key(&resolved, "rpc-host-whitelist-enabled", json!(false))?;
                }
                let base_domain = blueprint_base_domain(state).map_err(|err| err.to_string())?;
                file_changed |= mutate_transmission_whitelist(
                    &resolved,
                    &base_domain,
                    existing_ingress.as_ref(),
                )?;
                if !master_user.is_empty() && !master_pass.is_empty() {
                    let has_user = existing_json
                        .get("rpc-username")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.trim().is_empty());
                    let has_pass = existing_json
                        .get("rpc-password")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.trim().is_empty());
                    if !has_user || !has_pass {
                        file_changed |=
                            mutate_json_key(&resolved, "rpc-username", json!(master_user))?;
                        file_changed |=
                            mutate_json_key(&resolved, "rpc-password", json!(master_pass))?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "overseerr" | "jellyseerr" => {
                if effective_port > 0 {
                    let changed = if best_effort {
                        mutate_json_key(&resolved, "main.port", json!(effective_port))
                            .unwrap_or_else(|error| {
                                tracing::warn!(path = %resolved.display(), %error, "Could not update optional Seerr settings");
                                false
                            })
                    } else {
                        mutate_systemd_port(&resolved, effective_port)?
                    };
                    if changed {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
            }
            "jackett" => {
                if effective_port > 0 && mutate_json_key(&resolved, "Port", json!(effective_port))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "pihole" => {
                let file_changed =
                    effective_port > 0 && mutate_pihole_toml(&resolved, effective_port)?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            _ => {}
        }
    }

    let mut sqlite_routes_injected = 0;
    if let Some(raw_db) = &spec.sqlite_db_path {
        let db_path = resolve_config_path(raw_db);
        if check_app_file(&db_path, raw_db)? {
            for suffix in ["-wal", "-shm", "-journal"] {
                check_app_file(&resolve_config_path(&format!("{raw_db}{suffix}")), raw_db)?;
            }
            let routes = HashMap::from([
                (
                    "localhost".to_owned(),
                    "qbittorrent.aether.local".to_owned(),
                ),
                (
                    "127.0.0.1".to_owned(),
                    "qbittorrent.aether.local".to_owned(),
                ),
            ]);
            let runtime_port = crate::extract_app_runtime_meta_local("qbittorrent").configured_port;
            let configured_port = || {
                if let Some(conn) = state {
                    conn.query_row(
                        "SELECT listen_port FROM app_ingress_configs WHERE app_name = 'qbittorrent'",
                        [], |row| row.get(0),
                    ).ok()
                } else {
                    af_db::get_app_ingress_config("qbittorrent")
                        .ok()
                        .flatten()
                        .map(|cfg| cfg.listen_port)
                }
            };
            let qbit_port = if runtime_port > 0 {
                runtime_port
            } else {
                configured_port().filter(|&port| port > 0).unwrap_or(8180)
            };
            sqlite_routes_injected =
                inject_arr_download_client_routes(&db_path, &routes, qbit_port)?;
            if sqlite_routes_injected > 0 {
                mutated_files.push(db_path.to_string_lossy().into_owned());
            }
        }
    }
    Ok(RunnerBlueprintApplyResponse {
        mutated_files,
        sqlite_routes_injected,
    })
}

pub(crate) const TRANSMISSION_CONFIG_PATHS: [&str; 3] = [
    "/etc/transmission-daemon/settings.json",
    "/var/lib/transmission-daemon/info/settings.json",
    "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
];

pub(crate) fn service_units_changed(files: &[String]) -> bool {
    files.iter().any(|path| path.ends_with(".service"))
}

pub(crate) fn is_transmission_config_alias(path: &Path, resolve: impl Fn(&str) -> PathBuf) -> bool {
    if validate_no_symlink_parents(path, true).is_err()
        || !path.symlink_metadata().is_ok_and(|meta| meta.is_symlink())
    {
        return false;
    }
    path.canonicalize().is_ok_and(|destination| {
        TRANSMISSION_CONFIG_PATHS.into_iter().any(|candidate| {
            let candidate = resolve(candidate);
            candidate != path
                && candidate == destination
                && candidate
                    .symlink_metadata()
                    .is_ok_and(|meta| meta.is_file())
        })
    })
}

pub(crate) fn reload_changed_units(
    files: &[String],
    mut run: impl FnMut(&[&str]) -> std::io::Result<std::process::Output>,
) -> anyhow::Result<()> {
    if !service_units_changed(files) {
        return Ok(());
    }
    systemctl_success(&mut run, &["daemon-reload"])?;
    for unit in files
        .iter()
        .filter_map(|path| Path::new(path).file_name()?.to_str())
    {
        if unit.ends_with(".service") {
            anyhow::ensure!(
                crate::SAFE_SERVICE_NAME.is_match(unit),
                "invalid systemd unit {unit}"
            );
            systemctl_success(&mut run, &["try-restart", "--", unit])?;
        }
    }
    Ok(())
}

pub(crate) fn run_systemctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new(
        std::env::var_os("AETHERFLOW_SYSTEMCTL_BIN").unwrap_or_else(|| "/usr/bin/systemctl".into()),
    )
    .args(args)
    .output()
}

pub(crate) fn systemctl_success(
    mut run: impl FnMut(&[&str]) -> std::io::Result<std::process::Output>,
    args: &[&str],
) -> anyhow::Result<()> {
    let output = run(args)?;
    anyhow::ensure!(
        output.status.success(),
        "systemctl {} failed: {} ({})",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim(),
        output.status
    );
    Ok(())
}

pub(crate) fn with_transmission_stopped<T>(
    enabled: bool,
    mut run: impl FnMut(&[&str]) -> std::io::Result<std::process::Output>,
    mutate: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    const UNIT: &str = "transmission-daemon.service";
    if !enabled {
        return mutate();
    }
    let output = run(&["show", "--property=ActiveState", "--value", UNIT])?;
    anyhow::ensure!(
        output.status.success(),
        "could not determine Transmission service state: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    match String::from_utf8_lossy(&output.stdout).trim() {
        "inactive" | "failed" => return mutate(),
        "active" | "reloading" | "refreshing" | "activating" => {}
        state => anyhow::bail!("Transmission has unexpected service state {state:?}"),
    }
    systemctl_success(&mut run, &["stop", UNIT])?;
    let result = mutate();
    let restart = systemctl_success(&mut run, &["start", UNIT]);
    match (result, restart) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(start)) => {
            Err(error.context(format!("Transmission start failed: {start}")))
        }
    }
}

pub(crate) fn blueprint_base_domain(state: Option<&Connection>) -> anyhow::Result<String> {
    let base = if let Some(conn) = state {
        conn.query_row("SELECT base_domain FROM settings WHERE id = 1", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .map(|domain| af_db::normalize_base_domain(&domain))
        .unwrap_or_default()
    } else {
        af_db::get_base_domain()
    };
    if base.is_empty() {
        return Ok(std::env::var("AETHERFLOW_BASE_DOMAIN")
            .or_else(|_| std::env::var("AETHERFLOW_DOMAIN"))
            .map(|domain| af_db::normalize_base_domain(&domain))
            .unwrap_or_default());
    }
    Ok(base)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    fn output(status: i32, stdout: &str) -> std::io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(status << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    #[test]
    fn port_mutation_preserves_service_settings_and_reloads_before_restarting() {
        let root = std::env::temp_dir().join(format!("af-unit-port-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let mut changed = Vec::new();
        for app in ["overseerr", "jellyseerr", "listenarr"] {
            let name = format!("{app}.service");
            let spec = native_app_spec(app, "");
            assert!(spec.config_paths.iter().any(|path| path.ends_with(&name)));
            let path = root.join(name);
            let (directive, updated) = if app == "listenarr" {
                (
                    "Environment=ASPNETCORE_URLS=http://127.0.0.1:5055",
                    "Environment=ASPNETCORE_URLS=http://127.0.0.1:18990",
                )
            } else {
                ("Environment=\"PORT=5055\"", "Environment=\"PORT=18990\"")
            };
            let unit = format!("[Unit]\nDescription=Fixture\n[Service]\nEnvironment=CONFIG_DIRECTORY=/var/lib/{app}\n{directive}\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n");
            fs::write(&path, &unit).unwrap();
            let mutate = if app == "listenarr" {
                mutate_systemd_aspnetcore_urls
            } else {
                mutate_systemd_port
            };
            assert!(mutate(&path, 18990).unwrap());
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                unit.replace(directive, updated)
            );
            assert!(!mutate(&path, 18990).unwrap());
            changed.push(path.to_string_lossy().into_owned());
        }
        let mut commands = Vec::new();
        reload_changed_units(&changed, |args| {
            commands.push(args.join(" "));
            output(0, "")
        })
        .unwrap();
        assert_eq!(
            commands,
            [
                "daemon-reload",
                "try-restart -- overseerr.service",
                "try-restart -- jellyseerr.service",
                "try-restart -- listenarr.service",
            ]
        );
        assert!(!service_units_changed(&[
            "settings.json".into(),
            "foo.service.bak".into()
        ]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transmission_stops_before_mutation_and_recovers_after_a_write_error() {
        for (state, stop, fail_write) in [
            ("active", 0, false),
            ("active", 0, true),
            ("active", 1, false),
            ("inactive", 0, false),
        ] {
            let commands = RefCell::new(Vec::new());
            let result = with_transmission_stopped(
                true,
                |args| {
                    commands.borrow_mut().push(args[0].to_owned());
                    match args[0] {
                        "show" => output(0, state),
                        "stop" => output(stop, ""),
                        "start" => output(0, ""),
                        cmd => panic!("unexpected command {cmd}"),
                    }
                },
                || {
                    commands.borrow_mut().push("write".into());
                    anyhow::ensure!(!fail_write, "fixture write error");
                    Ok(())
                },
            );
            assert_eq!(result.is_err(), stop != 0 || fail_write);
            let expected: &[_] = match (state, stop) {
                ("active", 0) => &["show", "stop", "write", "start"],
                ("active", _) => &["show", "stop"],
                _ => &["show", "write"],
            };
            assert_eq!(*commands.borrow(), expected);
        }
    }

    #[test]
    fn transmission_repairs_an_enabled_empty_host_whitelist() {
        assert!(native_app_spec("transmission", "")
            .config_paths
            .iter()
            .any(|path| path == TRANSMISSION_CONFIG_PATHS[2]));
        let root = std::env::temp_dir().join(format!(
            "af-transmission-whitelist-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("settings.json");
        fs::write(
            &path,
            r#"{"rpc-host-whitelist-enabled": true, "rpc-host-whitelist": ""}"#,
        )
        .unwrap();
        let ingress = af_models::AppIngressConfig {
            public_domain: "downloads.example.net".into(),
            ..Default::default()
        };
        assert!(mutate_transmission_whitelist(&path, "example.org", Some(&ingress)).unwrap());
        assert!(!mutate_transmission_whitelist(&path, "example.org", Some(&ingress)).unwrap());
        let settings: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(settings["rpc-host-whitelist-enabled"], true);
        assert_eq!(settings["rpc-host-whitelist"],
            "transmission.aether.local,localhost,127.0.0.1,transmission.example.org,downloads.example.net");
        fs::remove_dir_all(root).unwrap();
    }
}
