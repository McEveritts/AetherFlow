use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HOSTS_BLOCK_START: &str = "# --- AETHERFLOW INTERNAL DNS ---";
const HOSTS_BLOCK_END: &str = "# --- END AETHERFLOW INTERNAL DNS ---";
const PIHOLE_BLOCK_START: &str = "# --- AETHERFLOW MANAGED DNS ---";
const PIHOLE_BLOCK_END: &str = "# --- END AETHERFLOW MANAGED DNS ---";

static SAFE_SQL_IDENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$").unwrap());
static SAFE_XML_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_.:-]{0,127}$").unwrap());
static PLEX_TOKEN_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bPlexOnlineToken\s*=\s*"([^"]+)""#).unwrap());
static PHP_ORGANIZR_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap());

/// Resolves a filesystem path respecting `AETHERFLOW_CONFIG_ROOT` or `AETHERFLOW_FS_ROOT` overrides.
pub fn resolve_config_path(raw_path: &str) -> PathBuf {
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

/// Writes `content` atomically to `file_path` via a `.tmp.<nanos>` sibling file and rename.
pub fn write_file_atomic(file_path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
        }
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");
    let tmp_path = file_path.with_file_name(format!("{}.tmp.{}", file_name, nanos));

    fs::write(&tmp_path, content)
        .map_err(|e| format!("failed to write temp file {}: {}", tmp_path.display(), e))?;

    if let Err(rename_err) = fs::rename(&tmp_path, file_path) {
        // Fallback for cross-device or Windows target-exists edge cases
        if fs::write(file_path, content).is_err() {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "atomic rename to {} failed: {}",
                file_path.display(),
                rename_err
            ));
        }
        let _ = fs::remove_file(&tmp_path);
    }

    Ok(())
}

/// Creates a `.bak` backup copy of `file_path` if `file_path` exists.
pub fn backup_config_file(file_path: &Path) -> Result<Option<PathBuf>, String> {
    if !file_path.is_file() {
        return Ok(None);
    }
    let mut bak_os = file_path.as_os_str().to_os_string();
    bak_os.push(".bak");
    let bak_path = PathBuf::from(bak_os);
    fs::copy(file_path, &bak_path)
        .map_err(|e| format!("failed to backup {} to {}: {}", file_path.display(), bak_path.display(), e))?;
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
    let content = fs::read_to_string(file_path).ok()?;
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

    let existing = match fs::read_to_string(file_path) {
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
            content = re_known.replace_all(&content, replacement.as_str()).into_owned();
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

    let _ = backup_config_file(file_path);
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

    let existing = match fs::read_to_string(file_path) {
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

        let in_matching_section =
            want_sec_lower.is_empty() || current_section == want_sec_lower || current_section.is_empty();

        if !key_updated && in_matching_section && !trimmed.starts_with('#') && !trimmed.starts_with(';')
        {
            if let Some((lhs, _rhs)) = line.split_once('=') {
                if lhs.trim().eq_ignore_ascii_case(key_trimmed) {
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

    let _ = backup_config_file(file_path);
    write_file_atomic(file_path, final_content.as_bytes())?;
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. JSON Mutator (Transmission `settings.json`, Overseerr, Jackett, etc.)
// ─────────────────────────────────────────────────────────────────────────────

/// Mutates or inserts `key: new_value` in a JSON object file (supports top-level keys
/// and dotted paths like `"main.port"`), writing pretty-printed JSON atomically via `.tmp` rename.
/// Returns `Ok(true)` if the file was created or modified, or `Ok(false)` if unchanged.
pub fn mutate_json_key(
    file_path: &Path,
    key: &str,
    new_value: Value,
) -> Result<bool, String> {
    let key_trimmed = key.trim();
    if key_trimmed.is_empty() {
        return Err("JSON key cannot be empty".to_string());
    }

    let existing = match fs::read_to_string(file_path) {
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
        serde_json::from_str(&existing).map_err(|e| {
            format!(
                "failed to parse JSON file {}: {}",
                file_path.display(),
                e
            )
        })?
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

    let _ = backup_config_file(file_path);
    write_file_atomic(file_path, final_content.as_bytes())?;
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SQLite Setting Mutator & `*arr` DownloadClients Route Injector
// ─────────────────────────────────────────────────────────────────────────────

fn validate_sql_identifier(ident: &str, label: &str) -> Result<(), String> {
    if !SAFE_SQL_IDENT.is_match(ident) {
        return Err(format!("invalid SQL {} identifier: {:?}", label, ident));
    }
    Ok(())
}

/// Validates SQL identifiers (`table`, `key_col`, `val_col`) against a strict `[a-zA-Z_][a-zA-Z0-9_]*`
/// allowlist and safely updates or inserts `(key, val)` in the target SQLite database using
/// parameterized queries via `rusqlite::Connection::open`.
pub fn mutate_sqlite_setting(
    db_path: &Path,
    table: &str,
    key_col: &str,
    val_col: &str,
    key: &str,
    val: &str,
) -> Result<bool, String> {
    validate_sql_identifier(table, "table")?;
    validate_sql_identifier(key_col, "key_col")?;
    validate_sql_identifier(val_col, "val_col")?;

    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
        }
    }

    let _ = backup_config_file(db_path);

    let conn = Connection::open(db_path)
        .map_err(|e| format!("failed to open SQLite DB {}: {}", db_path.display(), e))?;
    let _ = conn.busy_timeout(Duration::from_millis(2500));

    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{}\" (\"{}\" TEXT PRIMARY KEY, \"{}\" TEXT)",
        table, key_col, val_col
    );
    conn.execute(&create_sql, [])
        .map_err(|e| format!("failed to ensure table {}: {}", table, e))?;

    let select_sql = format!(
        "SELECT \"{}\" FROM \"{}\" WHERE \"{}\" = ?1 LIMIT 1",
        val_col, table, key_col
    );
    let existing_val: Option<String> = conn
        .query_row(&select_sql, params![key], |row| row.get(0))
        .ok();

    if existing_val.as_deref() == Some(val) {
        return Ok(false);
    }

    let update_sql = format!(
        "UPDATE \"{}\" SET \"{}\" = ?1 WHERE \"{}\" = ?2",
        table, val_col, key_col
    );
    let rows_updated = conn
        .execute(&update_sql, params![val, key])
        .map_err(|e| format!("failed to update {}.{}: {}", table, key_col, e))?;

    if rows_updated == 0 {
        let insert_sql = format!(
            "INSERT INTO \"{}\" (\"{}\", \"{}\") VALUES (?1, ?2)",
            table, key_col, val_col
        );
        conn.execute(&insert_sql, params![key, val])
            .map_err(|e| format!("failed to insert into {}: {}", table, e))?;
    }

    Ok(true)
}

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

    let _ = backup_config_file(db_path);
    let conn = Connection::open(db_path)
        .map_err(|e| format!("failed to open *arr DB {}: {}", db_path.display(), e))?;
    let _ = conn.busy_timeout(Duration::from_millis(2500));

    let mut stmt = match conn.prepare("SELECT Id, Settings FROM DownloadClients") {
        Ok(s) => s,
        Err(_) => return Ok(0), // Table does not exist yet on fresh install
    };

    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| format!("failed to query DownloadClients: {}", e))?;

    let mut updates: Vec<(i64, String)> = Vec::new();
    for row in rows.flatten() {
        let (id, settings_str) = row;
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

        if let Some(host_val) = current_host {
            if let Some(new_host) = routes.get(&host_val) {
                if obj.contains_key("Host") {
                    obj.insert("Host".to_string(), Value::String(new_host.clone()));
                } else {
                    obj.insert("host".to_string(), Value::String(new_host.clone()));
                }
                if target_port > 0 {
                    if obj.contains_key("Port") {
                        obj.insert("Port".to_string(), json!(target_port));
                    } else {
                        obj.insert("port".to_string(), json!(target_port));
                    }
                }
                if let Ok(serialized) = serde_json::to_string(&settings_json) {
                    updates.push((id, serialized));
                }
            }
        }
    }
    drop(stmt);

    let count = updates.len();
    for (id, new_settings) in updates {
        conn.execute(
            "UPDATE DownloadClients SET Settings = ?1 WHERE Id = ?2",
            params![new_settings, id],
        )
        .map_err(|e| format!("failed to update DownloadClients Id={}: {}", id, e))?;
    }

    Ok(count)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Local DNS `/etc/hosts` + Pi-hole / dnsmasq Synchronizer
// ─────────────────────────────────────────────────────────────────────────────

fn validate_dns_domain(domain: &str) -> Result<String, String> {
    let clean = domain.trim().to_lowercase();
    if clean.is_empty() || clean.len() > 253 {
        return Err(format!("invalid domain length: {:?}", domain));
    }
    if clean
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        || clean.starts_with('.')
        || clean.ends_with('.')
        || clean.contains("..")
    {
        return Err(format!("invalid domain format: {:?}", domain));
    }
    Ok(clean)
}

fn detect_primary_lan_ip() -> String {
    if let Ok(ip) = env::var("AETHERFLOW_LAN_IP") {
        let trimmed = ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "127.0.0.1".to_string()
}

fn update_hosts_atomic_fallback(domains: &[String], remove: bool) -> Result<(), String> {
    let hosts_path_str =
        env::var("AETHERFLOW_HOSTS_FILE").unwrap_or_else(|_| "/etc/hosts".to_string());
    let hosts_path = Path::new(&hosts_path_str);

    let existing = match fs::read_to_string(hosts_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read hosts file {}: {}",
                hosts_path.display(),
                e
            ))
        }
    };

    let mut outside_lines: Vec<String> = Vec::new();
    let mut managed_domains: BTreeSet<String> = BTreeSet::new();
    let mut in_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == HOSTS_BLOCK_START {
            in_block = true;
            continue;
        }
        if trimmed == HOSTS_BLOCK_END {
            in_block = false;
            continue;
        }
        if in_block {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "127.0.0.1" {
                for dom in &parts[1..] {
                    managed_domains.insert((*dom).to_string());
                }
            }
        } else {
            outside_lines.push(line.to_string());
        }
    }

    if remove {
        for d in domains {
            managed_domains.remove(d.trim());
        }
    } else {
        for d in domains {
            managed_domains.insert(d.trim().to_lowercase());
        }
    }

    while outside_lines
        .last()
        .map(|l| l.trim().is_empty())
        .unwrap_or(false)
    {
        outside_lines.pop();
    }

    let mut final_lines = outside_lines;
    if !managed_domains.is_empty() {
        if !final_lines.is_empty() {
            final_lines.push(String::new());
        }
        final_lines.push(HOSTS_BLOCK_START.to_string());
        for dom in &managed_domains {
            final_lines.push(format!("127.0.0.1\t{}", dom));
        }
        final_lines.push(HOSTS_BLOCK_END.to_string());
    }

    let final_content = format!("{}\n", final_lines.join("\n"));
    write_file_atomic(hosts_path, final_content.as_bytes())
}

fn update_pihole_custom_list(
    custom_list_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    let existing = match fs::read_to_string(custom_list_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read Pi-hole custom.list {}: {}",
                custom_list_path.display(),
                e
            ))
        }
    };

    let mut preserved: Vec<String> = Vec::new();
    let mut managed: BTreeSet<String> = BTreeSet::new();
    let mut in_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == PIHOLE_BLOCK_START {
            in_block = true;
            continue;
        }
        if trimmed == PIHOLE_BLOCK_END {
            in_block = false;
            continue;
        }
        if in_block {
            if let Some(dom) = trimmed.split_whitespace().nth(1) {
                managed.insert(dom.to_lowercase());
            }
        } else {
            preserved.push(line.to_string());
        }
    }

    for d in domains {
        managed.insert(d.to_lowercase());
    }

    let mut final_lines = preserved;
    final_lines.push(PIHOLE_BLOCK_START.to_string());
    for dom in &managed {
        final_lines.push(format!("{} {}", lan_ip, dom));
    }
    final_lines.push(PIHOLE_BLOCK_END.to_string());

    let content = format!("{}\n", final_lines.join("\n"));
    write_file_atomic(custom_list_path, content.as_bytes())
}

fn update_dnsmasq_conf(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    let existing = fs::read_to_string(dnsmasq_conf_path).unwrap_or_default();
    let mut managed: BTreeSet<String> = BTreeSet::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("address=/") {
            if let Some((dom, _ip)) = rest.split_once('/') {
                if !dom.trim().is_empty() {
                    managed.insert(dom.trim().to_lowercase());
                }
            }
        }
    }

    for d in domains {
        managed.insert(d.to_lowercase());
    }

    let mut lines = vec!["# Automatically managed by AetherFlow Blueprint Engine".to_string()];
    for dom in &managed {
        lines.push(format!("address=/{}/{}", dom, lan_ip));
    }
    let content = format!("{}\n", lines.join("\n"));
    write_file_atomic(dnsmasq_conf_path, content.as_bytes())
}

/// Synchronizes internal `.aether.local` (and configured public) domains into:
/// 1. `/etc/hosts` (via `af_runner::update_hosts_file_local` or atomic local fallback),
/// 2. `/etc/dnsmasq.d/aetherflow-local.conf` (and `05-aetherflow-dns.conf`) if `/etc/dnsmasq.d` exists,
/// 3. `/etc/pihole/custom.list` if `/etc/pihole` exists.
pub async fn sync_local_dns_domains(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() {
        return Ok(());
    }

    let mut validated: Vec<String> = Vec::with_capacity(domains.len());
    let mut aether_local_domains: Vec<String> = Vec::new();
    for d in domains {
        let clean = validate_dns_domain(d)?;
        if clean.ends_with(".aether.local") {
            aether_local_domains.push(clean.clone());
        }
        validated.push(clean);
    }

    // 1. Update /etc/hosts for .aether.local domains
    if !aether_local_domains.is_empty() {
        if let Err(runner_err) = af_runner::update_hosts_file_local(&aether_local_domains, false) {
            // Try atomic fallback if direct write failed or when using custom path
            if let Err(fallback_err) = update_hosts_atomic_fallback(&aether_local_domains, false) {
                tracing::warn!(
                    runner_error = %runner_err,
                    fallback_error = %fallback_err,
                    "Notice: /etc/hosts update skipped (insufficient privileges or read-only fs)"
                );
            }
        }
    }

    let lan_ip = detect_primary_lan_ip();

    // 2. Write /etc/dnsmasq.d/aetherflow-local.conf if directory exists
    let dnsmasq_dir = env::var("AETHERFLOW_DNSMASQ_DIR")
        .ok()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| resolve_config_path("/etc/dnsmasq.d"));

    if dnsmasq_dir.is_dir() {
        let conf_path = dnsmasq_dir.join("aetherflow-local.conf");
        if let Err(e) = update_dnsmasq_conf(&conf_path, &lan_ip, &validated) {
            tracing::warn!(path = %conf_path.display(), error = %e, "Failed to update dnsmasq aetherflow-local.conf");
        }
    }

    // 3. Write Pi-hole custom.list if /etc/pihole exists
    let pihole_dir = env::var("AETHERFLOW_PIHOLE_DIR")
        .ok()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| resolve_config_path("/etc/pihole"));

    if pihole_dir.is_dir() {
        let custom_list = pihole_dir.join("custom.list");
        if let Err(e) = update_pihole_custom_list(&custom_list, &lan_ip, &validated) {
            tracing::warn!(path = %custom_list.display(), error = %e, "Failed to update Pi-hole custom.list");
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// App Credential & Runtime Metadata Discovery (`app_credentials.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppRuntimeMeta {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub api_key: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub configured_port: i32,
}

fn is_zero_i32(v: &i32) -> bool {
    *v <= 0
}

static APP_META_CACHE: Lazy<RwLock<HashMap<String, (AppRuntimeMeta, Instant)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub fn clear_app_runtime_meta_cache() {
    if let Ok(mut guard) = APP_META_CACHE.write() {
        guard.clear();
    }
}

pub fn normalize_app_key_name(app_name: &str) -> String {
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
        _ => clean,
    }
}

fn parse_valid_port(raw: &str) -> i32 {
    let clean = raw
        .trim()
        .trim_matches(['"', '\''])
        .trim_end_matches(['o', 'O', 's', 'S']);
    match clean.parse::<i32>() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => 0,
    }
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

/// Discovers runtime API key and configured port from an application's native config files.
pub fn get_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    let canonical = normalize_app_key_name(app_name);
    if canonical.is_empty() {
        return AppRuntimeMeta::default();
    }

    let now = Instant::now();
    if let Ok(guard) = APP_META_CACHE.read() {
        if let Some((meta, expires_at)) = guard.get(&canonical) {
            if now < *expires_at {
                return meta.clone();
            }
        }
    }

    let mut meta = AppRuntimeMeta::default();
    match canonical.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            let candidates = [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/config/config.xml", canonical),
            ];
            for raw in candidates {
                let p = resolve_config_path(&raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_xml_tag_text(&text, "ApiKey") {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(port_str) = extract_xml_tag_text(&text, "Port") {
                            meta.configured_port = parse_valid_port(&port_str);
                        }
                    }
                }
            }
        }
        "jellyfin" => {
            for raw in ["/etc/jellyfin/network.xml", "/var/lib/jellyfin/config/network.xml"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_xml_tag_text(&text, "InternalHttpPort")
                        .or_else(|| extract_xml_tag_text(&text, "HttpServerPortNumber"))
                        .map(|s| parse_valid_port(&s))
                        .unwrap_or(0);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "qbittorrent" => {
            for raw in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &[r"WebUI\Port", "Port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "sabnzbd" => {
            for raw in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_ini_value(&text, &["api_key", "nzb_key"]) {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(v) = extract_ini_value(&text, &["port"]) {
                            meta.configured_port = parse_valid_port(&v);
                        }
                    }
                }
            }
        }
        "transmission" => {
            for raw in [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val.get("rpc-port").and_then(|v| v.as_i64()) {
                            meta.configured_port = port as i32;
                            break;
                        }
                    }
                }
            }
        }
        "plex" => {
            for raw in [
                "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
                "/var/lib/plex/Plex Media Server/Preferences.xml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(caps) = PLEX_TOKEN_ATTR_RE.captures(&text) {
                        if let Some(m) = caps.get(1) {
                            meta.api_key = m.as_str().trim().to_string();
                            break;
                        }
                    }
                }
            }
        }
        "organizr" => {
            for raw in [
                "/var/www/organizr/api/config/config.php",
                "/var/lib/organizr/www/api/config/config.php",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(caps) = PHP_ORGANIZR_KEY_RE.captures(&text) {
                        if let Some(m) = caps.get(1) {
                            meta.api_key = m.as_str().trim().to_string();
                            break;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    if let Ok(mut guard) = APP_META_CACHE.write() {
        guard.insert(canonical, (meta.clone(), now + Duration::from_secs(15)));
    }
    meta
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Blueprint App Config Orchestrator (`apply_blueprint_app_config`)
// ─────────────────────────────────────────────────────────────────────────────

struct NativeAppSpec {
    mutator_type: &'static str,
    config_paths: Vec<String>,
    sqlite_db_path: Option<String>,
}

fn native_app_spec(canonical_app: &str, bp_config_path: &str) -> NativeAppSpec {
    let mut paths = Vec::new();
    if !bp_config_path.trim().is_empty() {
        paths.push(bp_config_path.trim().to_string());
    }

    match canonical_app {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
            let def_xml = format!("/var/lib/{}/config.xml", canonical_app);
            if !paths.contains(&def_xml) {
                paths.push(def_xml);
            }
            let alt_xml = format!("/var/lib/{}/config/config.xml", canonical_app);
            if !paths.contains(&alt_xml) {
                paths.push(alt_xml);
            }
            NativeAppSpec {
                mutator_type: "xml",
                config_paths: paths,
                sqlite_db_path: Some(format!("/var/lib/{}/{}.db", canonical_app, canonical_app)),
            }
        }
        "jellyfin" => {
            for p in ["/etc/jellyfin/network.xml", "/var/lib/jellyfin/config/network.xml"] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                mutator_type: "xml",
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
                mutator_type: "xml",
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
                mutator_type: "ini",
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
                mutator_type: "ini",
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
                mutator_type: "ini",
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        "transmission" => {
            for p in [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
            ] {
                let s = p.to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
            }
            NativeAppSpec {
                mutator_type: "json",
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
                mutator_type: "pihole",
                config_paths: paths,
                sqlite_db_path: None,
            }
        }
        _ => NativeAppSpec {
            mutator_type: "",
            config_paths: paths,
            sqlite_db_path: None,
        },
    }
}

fn mutate_pihole_toml(file_path: &Path, port: i32) -> Result<bool, String> {
    if !file_path.is_file() {
        return Ok(false);
    }
    let existing = fs::read_to_string(file_path)
        .map_err(|e| format!("failed to read {}: {}", file_path.display(), e))?;
    let mut content = existing.clone();
    let port_str = format!("{}o", port);

    let re_port = Regex::new(r#"(?m)^(\s*port\s*=\s*)"[^"]*""#).unwrap();
    if re_port.is_match(&content) {
        content = re_port
            .replace_all(&content, format!("${{1}}\"{}\"", port_str))
            .into_owned();
    } else {
        content.push_str(&format!("\n[webserver]\n  port = \"{}\"\n", port_str));
    }

    let re_dnsmasq = Regex::new(r"(?m)^(\s*etc_dnsmasq_d\s*=\s*)(?:true|false)").unwrap();
    if re_dnsmasq.is_match(&content) {
        content = re_dnsmasq.replace_all(&content, "${1}true").into_owned();
    }

    if content == existing {
        return Ok(false);
    }
    let _ = backup_config_file(file_path);
    write_file_atomic(file_path, content.as_bytes())?;
    Ok(true)
}

/// Applies an application's blueprint configuration:
/// 1. Looks up `crate::get_blueprint(app_name)`.
/// 2. If the app has a native config file (`config.xml`, `qBittorrent.conf`, `settings.json`, `network.xml`, etc.)
///    on disk, mutates its port/bind settings to match `listen_port`.
/// 3. Synchronizes `<app_name>.aether.local` via `sync_local_dns_domains`.
/// 4. Returns a structured JSON summary of mutated files and synchronized DNS entries.
pub async fn apply_blueprint_app_config(
    app_name: &str,
    listen_port: i32,
) -> Result<Value, String> {
    let canonical = normalize_app_key_name(app_name);
    let bp = crate::get_blueprint(&canonical)
        .or_else(|| crate::get_blueprint(app_name))
        .ok_or_else(|| format!("blueprint not found for {:?}", app_name))?;

    let effective_port = if listen_port > 0 {
        listen_port
    } else {
        bp.default_port
    };

    let spec = native_app_spec(&canonical, &bp.config_file_path);
    let mut mutated_files: Vec<String> = Vec::new();
    let mut sqlite_routes_injected: usize = 0;

    for raw_path in &spec.config_paths {
        let resolved = resolve_config_path(raw_path);
        if !resolved.is_file() {
            continue;
        }

        let port_str = effective_port.to_string();
        match canonical.as_str() {
            "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= mutate_xml_element(&resolved, "Port", &port_str)?;
                }
                file_changed |= mutate_xml_element(&resolved, "BindAddress", "*")?;
                file_changed |= mutate_xml_element(&resolved, "AuthenticationMethod", "Forms")?;
                file_changed |= mutate_xml_element(&resolved, "AnalyticsEnabled", "False")?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "jellyfin" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= mutate_xml_element(&resolved, "InternalHttpPort", &port_str)?;
                    file_changed |= mutate_xml_element(&resolved, "PublicHttpPort", &port_str)?;
                }
                file_changed |= mutate_xml_element(&resolved, "EnableIPV4", "true")?;
                file_changed |= mutate_xml_element(&resolved, "EnableRemoteAccess", "true")?;
                file_changed |= mutate_xml_element(&resolved, "KnownProxies", "127.0.0.1")?;
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
                if effective_port > 0 {
                    file_changed |=
                        mutate_ini_key(&resolved, "Preferences", r"WebUI\Port", &port_str)?;
                }
                file_changed |= mutate_ini_key(&resolved, "Preferences", r"WebUI\Address", "*")?;
                file_changed |= mutate_ini_key(
                    &resolved,
                    "Preferences",
                    r"WebUI\HostHeaderValidation",
                    "false",
                )?;
                file_changed |=
                    mutate_ini_key(&resolved, "Preferences", r"WebUI\CSRFProtection", "false")?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "sabnzbd" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= mutate_ini_key(&resolved, "misc", "port", &port_str)?;
                }
                file_changed |= mutate_ini_key(&resolved, "misc", "host", "0.0.0.0")?;
                file_changed |= mutate_ini_key(&resolved, "misc", "inet_exposure", "4")?;
                file_changed |= mutate_ini_key(
                    &resolved,
                    "misc",
                    "host_whitelist",
                    "sabnzbd.aether.local, localhost, 127.0.0.1",
                )?;
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
                    file_changed |=
                        mutate_json_key(&resolved, "rpc-port", json!(effective_port))?;
                }
                file_changed |=
                    mutate_json_key(&resolved, "rpc-whitelist-enabled", json!(false))?;
                file_changed |=
                    mutate_json_key(&resolved, "rpc-host-whitelist-enabled", json!(false))?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "pihole" => {
                if effective_port > 0 && mutate_pihole_toml(&resolved, effective_port)? {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            _ => match spec.mutator_type {
                "xml" if effective_port > 0 && !bp.port_config_key.is_empty() => {
                    if mutate_xml_element(&resolved, &bp.port_config_key, &port_str)? {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
                "ini" if effective_port > 0 && !bp.port_config_key.is_empty() => {
                    if mutate_ini_key(&resolved, "Preferences", &bp.port_config_key, &port_str)? {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
                "json" if effective_port > 0 && !bp.port_config_key.is_empty() => {
                    if mutate_json_key(&resolved, &bp.port_config_key, json!(effective_port))? {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
                _ => {}
            },
        }
    }

    if let Some(raw_db) = &spec.sqlite_db_path {
        let db_path = resolve_config_path(raw_db);
        if db_path.is_file() {
            let mut routes = HashMap::new();
            routes.insert(
                "localhost".to_string(),
                "qbittorrent.aether.local".to_string(),
            );
            routes.insert(
                "127.0.0.1".to_string(),
                "qbittorrent.aether.local".to_string(),
            );
            if let Ok(n) = inject_arr_download_client_routes(&db_path, &routes, 8080) {
                sqlite_routes_injected = n;
                if n > 0 {
                    mutated_files.push(db_path.to_string_lossy().to_string());
                }
            }
        }
    }

    let internal_domain = if !bp.internal_domain.trim().is_empty() {
        bp.internal_domain.trim().to_lowercase()
    } else {
        format!("{}.aether.local", bp.app_name.trim().to_lowercase())
    };

    let mut dns_domains = vec![internal_domain.clone()];
    let base_domain = crate::resolve_base_domain();
    if !base_domain.is_empty() && effective_port > 0 {
        let pub_dom = crate::format_app_public_domain(&bp.app_name, &base_domain);
        if !pub_dom.is_empty() && !dns_domains.contains(&pub_dom) {
            dns_domains.push(pub_dom);
        }
    }

    let dns_synced = sync_local_dns_domains(&dns_domains).await.is_ok();
    clear_app_runtime_meta_cache();

    let mut summary = BTreeMap::new();
    summary.insert("app_name", json!(bp.app_name));
    summary.insert("service_name", json!(bp.service_name));
    summary.insert("listen_port", json!(effective_port));
    summary.insert("default_port", json!(bp.default_port));
    summary.insert(
        "port_reassigned",
        json!(effective_port > 0 && effective_port != bp.default_port),
    );
    summary.insert("internal_domain", json!(internal_domain));
    summary.insert("config_applied", json!(!mutated_files.is_empty()));
    summary.insert("mutated_files", json!(mutated_files));
    summary.insert("sqlite_routes_injected", json!(sqlite_routes_injected));
    summary.insert("dns_domains", json!(dns_domains));
    summary.insert("dns_synced", json!(dns_synced));

    Ok(json!(summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("af_mutators_test_{}_{}", prefix, nanos));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_mutate_and_read_xml_element() {
        let dir = temp_test_dir("xml");
        let xml_path = dir.join("config.xml");
        fs::write(
            &xml_path,
            "<Config>\n  <Port>8989</Port>\n  <ApiKey>abc123xyz</ApiKey>\n</Config>\n",
        )
        .unwrap();

        assert_eq!(
            read_xml_element(&xml_path, "Port").as_deref(),
            Some("8989")
        );
        assert_eq!(
            read_xml_element(&xml_path, "ApiKey").as_deref(),
            Some("abc123xyz")
        );

        let changed = mutate_xml_element(&xml_path, "Port", "18989").unwrap();
        assert!(changed);
        assert_eq!(
            read_xml_element(&xml_path, "Port").as_deref(),
            Some("18989")
        );

        let added = mutate_xml_element(&xml_path, "UrlBase", "/sonarr").unwrap();
        assert!(added);
        assert_eq!(
            read_xml_element(&xml_path, "UrlBase").as_deref(),
            Some("/sonarr")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mutate_ini_key() {
        let dir = temp_test_dir("ini");
        let ini_path = dir.join("qBittorrent.conf");
        fs::write(
            &ini_path,
            "[LegalNotice]\nAccepted=true\n\n[Preferences]\nWebUI\\Port=8080\nWebUI\\Address=*\n",
        )
        .unwrap();

        let changed = mutate_ini_key(&ini_path, "Preferences", r"WebUI\Port", "18180").unwrap();
        assert!(changed);
        let added = mutate_ini_key(
            &ini_path,
            "Preferences",
            r"WebUI\HostHeaderValidation",
            "false",
        )
        .unwrap();
        assert!(added);

        let content = fs::read_to_string(&ini_path).unwrap();
        assert!(content.contains("WebUI\\Port=18180"));
        assert!(content.contains("WebUI\\HostHeaderValidation=false"));
        assert!(content.contains("Accepted=true"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mutate_json_key() {
        let dir = temp_test_dir("json");
        let json_path = dir.join("settings.json");
        fs::write(
            &json_path,
            "{\n  \"rpc-port\": 9091,\n  \"rpc-whitelist-enabled\": true\n}\n",
        )
        .unwrap();

        assert!(mutate_json_key(&json_path, "rpc-port", json!(19091)).unwrap());
        assert!(mutate_json_key(&json_path, "rpc-whitelist-enabled", json!(false)).unwrap());

        let parsed: Value =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(parsed["rpc-port"], json!(19091));
        assert_eq!(parsed["rpc-whitelist-enabled"], json!(false));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mutate_sqlite_setting_and_sql_ident_validation() {
        let dir = temp_test_dir("sqlite");
        let db_path = dir.join("app.db");

        // Reject SQL injection in table or column identifiers
        assert!(
            mutate_sqlite_setting(&db_path, "Config; DROP TABLE x", "Key", "Value", "k", "v")
                .is_err()
        );

        let changed =
            mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17878").unwrap();
        assert!(changed);

        let unchanged =
            mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17878").unwrap();
        assert!(!unchanged);

        let updated =
            mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17879").unwrap();
        assert!(updated);

        let _ = fs::remove_dir_all(&dir);
    }
}
