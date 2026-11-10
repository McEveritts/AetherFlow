use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static SAFE_SQL_IDENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$").unwrap());
static SAFE_XML_TAG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_.:-]{0,127}$").unwrap());
static PLEX_TOKEN_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bPlexOnlineToken\s*=\s*"([^"]+)""#).unwrap());
static PHP_ORGANIZR_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap());

tokio::task_local! {
    static BLUEPRINT_ADMISSION: std::sync::Arc<af_release::ReleaseLockGuard>;
}

pub async fn with_blueprint_admission<Output, Operation>(
    operation: Operation,
) -> anyhow::Result<Output>
where
    Operation: std::future::Future<Output = anyhow::Result<Output>>,
{
    if BLUEPRINT_ADMISSION.try_with(|_| ()).is_ok() {
        return operation.await;
    }
    let guard =
        tokio::task::spawn_blocking(|| af_runner::acquire_lifecycle_admission_lock(None)).await??;
    let status =
        af_runner::dispatch_self_update_status_request(&af_models::SelfUpdateStatusRequest {
            job_unit: String::new(),
        })
        .await?;
    anyhow::ensure!(
        status.completed
            && matches!(status.status.as_str(), "succeeded" | "failed")
            && (status.job_unit.is_empty() || status.validate_invariants(None).is_ok()),
        af_runner::LifecycleBusy
    );
    BLUEPRINT_ADMISSION
        .scope(std::sync::Arc::new(guard), operation)
        .await
}

pub async fn with_blueprint_mutation<Output, Operation>(
    app_name: &str,
    operation: Operation,
) -> anyhow::Result<Output>
where
    Operation: std::future::Future<Output = anyhow::Result<Output>>,
{
    let canonical = crate::get_blueprint(app_name)
        .or_else(|| crate::get_blueprint(&normalize_app_key_name(app_name)))
        .ok_or_else(|| anyhow::anyhow!("blueprint package identity is unavailable"))?
        .app_name;
    let owner = af_runner::current_package_job_id();
    with_blueprint_admission(async move {
        let admission = BLUEPRINT_ADMISSION.with(std::sync::Arc::clone);
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let _admission = admission;
            let units = af_runner::package_lifecycle::package_service_units(&canonical)?;
            let conn = af_db::get_conn()?;
            let database = conn.path().ok_or_else(|| {
                anyhow::anyhow!("blueprint lifecycle database path is unavailable")
            })?;
            af_release::lifecycle::reconcile_jobs(&conn, Path::new(database))?;
            af_release::lifecycle::check_package_reservation(
                &conn, &canonical, &units, &owner, None,
            )
            .map_err(|error| error.context(af_runner::LifecycleBusy))?;
            if !owner.is_empty() {
                let action: String = conn.query_row(
                    "SELECT action FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                    params![canonical, owner],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(
                    matches!(action.as_str(), "install" | "reinstall" | "update"),
                    "removal cannot own blueprint configuration mutations"
                );
            }
            Ok(())
        })
        .await??;
        operation.await
    })
    .await
}

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
    if matches!(
        path.to_str(),
        Some("/var/run" | "/bin" | "/sbin" | "/lib" | "/lib32" | "/lib64" | "/libx32")
    ) {
        return true;
    }
    false
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

/// Returns true when the current process is unprivileged (`geteuid() != 0`), no test root override
/// is active, and `err` indicates a host permission or read-only filesystem error (`EACCES`, `EPERM`, `EROFS`).
pub fn is_unprivileged_host_write_error(err: &str) -> bool {
    for var in [
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_INSTALL_ROOT",
        "AETHERFLOW_PACKAGE_FS_ROOT",
    ] {
        if let Ok(raw) = env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                return false;
            }
        }
    }
    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        if unsafe { geteuid() == 0 } {
            return false;
        }
    }
    let lower = err.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("read-only file system")
        || lower.contains("readonly file system")
        || lower.contains("os error 13")
        || lower.contains("os error 1")
        || lower.contains("os error 30")
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
    use std::io::Write;

    validate_no_symlink_parents(file_path, false)?;

    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {}", parent.display(), e))?;
        }
    }

    validate_no_symlink_parents(file_path, true)?;

    let existing_meta = match fs::symlink_metadata(file_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing to overwrite symlink config file {}",
                    file_path.display()
                ));
            }
            if !meta.file_type().is_file() {
                return Err(format!(
                    "refusing to overwrite non-regular file {}",
                    file_path.display()
                ));
            }
            Some(meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(format!(
                "failed to inspect metadata for {}: {}",
                file_path.display(),
                e
            ));
        }
    };

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config");

    let mut attempt = 0u32;
    let (mut tmp_file, tmp_path) = loop {
        let suffix = if attempt == 0 {
            format!("{}.tmp.{}", file_name, nanos)
        } else {
            format!("{}.tmp.{}.{}", file_name, nanos, attempt)
        };
        let candidate = file_path.with_file_name(suffix);
        let mut open_opts = fs::OpenOptions::new();
        open_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let initial_mode = force_mode.unwrap_or(0o600);
            #[cfg(target_os = "linux")]
            open_opts.mode(initial_mode).custom_flags(0o400000); // O_NOFOLLOW on Linux
            #[cfg(not(target_os = "linux"))]
            open_opts.mode(initial_mode);
        }
        match open_opts.open(&candidate) {
            Ok(f) => break (f, candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                attempt += 1;
            }
            Err(e) => {
                return Err(format!(
                    "failed to create temp file {}: {}",
                    candidate.display(),
                    e
                ));
            }
        }
    };

    if let Err(e) = tmp_file
        .write_all(content)
        .and_then(|_| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "failed to write temp file {}: {}",
            tmp_path.display(),
            e
        ));
    }
    drop(tmp_file);

    if let Some(mode) = force_mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode)).map_err(|e| {
                let _ = fs::remove_file(&tmp_path);
                format!(
                    "failed to set {:04o} permissions on temp file {}: {}",
                    mode,
                    tmp_path.display(),
                    e
                )
            })?;
        }
    } else if let Some(ref meta) = existing_meta {
        fs::set_permissions(&tmp_path, meta.permissions()).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!(
                "failed to preserve permissions on temp file {}: {}",
                tmp_path.display(),
                e
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            let orig_uid = meta.uid();
            let orig_gid = meta.gid();
            if let Err(chown_err) = chown(&tmp_path, Some(orig_uid), Some(orig_gid)) {
                let is_eperm = chown_err.raw_os_error() == Some(1) // EPERM
                    || chown_err.kind() == std::io::ErrorKind::PermissionDenied;
                if !is_eperm {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(format!(
                        "failed to preserve ownership on temp file {}: {}",
                        tmp_path.display(),
                        chown_err
                    ));
                }
            }
            let _ = fs::set_permissions(&tmp_path, meta.permissions());
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                let _ = fs::remove_file(&tmp_path);
                format!(
                    "failed to set 0600 permissions on temp file {}: {}",
                    tmp_path.display(),
                    e
                )
            })?;
        }
    }

    if let Err(rename_err) = fs::rename(&tmp_path, file_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "atomic rename to {} failed: {}",
            file_path.display(),
            rename_err
        ));
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
    let content = fs::read(file_path)
        .map_err(|e| format!("failed to read {} for backup: {}", file_path.display(), e))?;
    write_file_atomic(&bak_path, &content)
        .map_err(|e| format!("failed to backup {} to {}: {}", file_path.display(), bak_path.display(), e))?;
    if let Ok(meta) = fs::symlink_metadata(file_path) {
        let _ = fs::set_permissions(&bak_path, meta.permissions());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            let _ = chown(&bak_path, Some(meta.uid()), Some(meta.gid()));
            let _ = fs::set_permissions(&bak_path, meta.permissions());
        }
    }
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

    let collected_rows: Vec<(i64, String, String)> =
        if let Ok(mut stmt) = conn.prepare("SELECT Id, Implementation, Settings FROM DownloadClients") {
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| format!("failed to query DownloadClients: {}", e))?
            .flatten()
            .collect()
        } else if let Ok(mut stmt) = conn.prepare("SELECT Id, Settings FROM DownloadClients") {
            stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, String::new(), r.get::<_, String>(1)?))
            })
            .map_err(|e| format!("failed to query DownloadClients: {}", e))?
            .flatten()
            .collect()
        } else {
            return Ok(0); // Table does not exist yet on fresh install
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
                    "transmission" => (
                        "transmission.aether.local".to_string(),
                        {
                            let p = get_app_runtime_meta("transmission").configured_port;
                            if p > 0 { p } else { existing_port }
                        },
                    ),
                    "deluge" => (
                        "deluge.aether.local".to_string(),
                        {
                            let p = get_app_runtime_meta("deluge").configured_port;
                            if p > 0 { p } else { existing_port }
                        },
                    ),
                    "sabnzbd" => (
                        "sabnzbd.aether.local".to_string(),
                        {
                            let p = get_app_runtime_meta("sabnzbd").configured_port;
                            if p > 0 { p } else { existing_port }
                        },
                    ),
                    "nzbget" => (
                        "nzbget.aether.local".to_string(),
                        {
                            let p = get_app_runtime_meta("nzbget").configured_port;
                            if p > 0 { p } else { existing_port }
                        },
                    ),
                    "" if existing_port == 9091 => ("transmission.aether.local".to_string(), existing_port),
                    "" if existing_port == 8112 || existing_port == 58846 => ("deluge.aether.local".to_string(), existing_port),
                    "" if existing_port == 8085 => ("sabnzbd.aether.local".to_string(), existing_port),
                    "" if existing_port == 6789 => ("nzbget.aether.local".to_string(), existing_port),
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
    if count > 0 {
        let mut conn = conn;
        let tx = conn
            .transaction()
            .map_err(|e| format!("failed to start transaction on *arr DB: {}", e))?;
        {
            let mut update_stmt = tx
                .prepare("UPDATE DownloadClients SET Settings = ?1 WHERE Id = ?2")
                .map_err(|e| format!("failed to prepare statement: {}", e))?;
            for (id, new_settings) in updates {
                update_stmt
                    .execute(params![new_settings, id])
                    .map_err(|e| format!("failed to update DownloadClients Id={}: {}", id, e))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("failed to commit *arr DB updates: {}", e))?;
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

pub fn detect_lan_ip_strict() -> Result<String, String> {
    if let Ok(raw_val) = env::var("AETHERFLOW_LAN_IP") {
        af_runner::validate_hosts_ip(&raw_val)
            .map_err(|e| format!("Invalid AETHERFLOW_LAN_IP: {e}"))?;
        return Ok(raw_val);
    }
    Ok("127.0.0.1".to_string())
}

fn detect_primary_lan_ip() -> String {
    detect_lan_ip()
}

pub fn detect_lan_ip() -> String {
    detect_lan_ip_strict().unwrap_or_else(|_| "127.0.0.1".to_string())
}

pub fn remove_dns_provider_domain(domain: &str) -> Result<(), String> {
    af_runner::remove_dns_provider_domain(domain).map_err(|e| e.to_string())
}

pub fn update_pihole_custom_list(
    custom_list_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for Pi-hole custom list: {e}"))?;

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

    let content = af_runner::reconcile_pihole_custom_list_content(&existing, lan_ip, domains, false);
    if content == existing && custom_list_path.exists() {
        return Ok(());
    }
    write_file_atomic(custom_list_path, content.as_bytes())
}

pub fn update_dnsmasq_conf(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for dnsmasq config: {e}"))?;

    let existing = match fs::read_to_string(dnsmasq_conf_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read dnsmasq config {}: {}",
                dnsmasq_conf_path.display(),
                e
            ))
        }
    };
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
    if content == existing && dnsmasq_conf_path.exists() {
        return Ok(());
    }
    write_file_atomic(dnsmasq_conf_path, content.as_bytes())
}

pub fn update_dnsmasq_config(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    update_dnsmasq_conf(dnsmasq_conf_path, lan_ip, domains)
}

/// Synchronizes internal `.aether.local` (and configured public) domains into:
/// 1. `/etc/hosts` (via `af_runner::update_hosts_file_local` or atomic local fallback),
/// 2. `/etc/dnsmasq.d/aetherflow-local.conf` (and `05-aetherflow-dns.conf`) if `/etc/dnsmasq.d` exists,
/// 3. `/etc/pihole/custom.list` if `/etc/pihole` exists.
pub async fn sync_local_dns_domains(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() {
        return Ok(());
    }

    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip)
        .map_err(|e| format!("Invalid LAN IP: {e}"))?;

    let mut validated: Vec<String> = Vec::with_capacity(domains.len());
    let mut aether_local_domains: Vec<String> = Vec::new();
    for d in domains {
        let clean = validate_dns_domain(d)?;
        if clean.ends_with(".aether.local") {
            aether_local_domains.push(clean.clone());
        }
        validated.push(clean);
    }

    #[cfg(unix)]
    let is_root = {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    };
    #[cfg(not(unix))]
    let is_root = false;

    let test_override = env::var("AF_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_DNSMASQ_DIR").is_ok()
        || env::var("AETHERFLOW_PIHOLE_DIR").is_ok()
        || env::var("AETHERFLOW_FS_ROOT").is_ok()
        || env::var("AETHERFLOW_CONFIG_ROOT").is_ok();

    if is_root || test_override {
        // 1. Update /etc/hosts for .aether.local domains locally
        if !aether_local_domains.is_empty() {
            af_runner::update_hosts_file(&aether_local_domains, "127.0.0.1")
                .map_err(|e| format!("Local DNS synchronization failed: {e}"))?;
        }

        // 2. Write /etc/dnsmasq.d/aetherflow-local.conf if directory exists
        let dnsmasq_dir = env::var("AETHERFLOW_DNSMASQ_DIR")
            .ok()
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| resolve_config_path("/etc/dnsmasq.d"));

        if dnsmasq_dir.is_dir() {
            let conf_path = dnsmasq_dir.join("aetherflow-local.conf");
            update_dnsmasq_conf(&conf_path, &lan_ip, &validated)?;
            let local_dns_path = dnsmasq_dir.join("aetherflow-local-dns.conf");
            update_dnsmasq_conf(&local_dns_path, &lan_ip, &validated)?;
            let custom_dns_path = dnsmasq_dir.join("05-aetherflow-dns.conf");
            update_dnsmasq_conf(&custom_dns_path, &lan_ip, &validated)?;
        }

        // 3. Write Pi-hole custom.list if /etc/pihole exists
        let pihole_dir = env::var("AETHERFLOW_PIHOLE_DIR")
            .ok()
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| resolve_config_path("/etc/pihole"));

        if pihole_dir.is_dir() {
            let custom_list = pihole_dir.join("custom.list");
            update_pihole_custom_list(&custom_list, &lan_ip, &validated)?;
        }
    } else {
        run_privileged_hosts_command_with_provider(
            "update",
            "127.0.0.1",
            &aether_local_domains,
            Some(&lan_ip),
            Some(&validated),
        )
        .await?;
    }

    Ok(())
}

/// Fully reconciles internal `.aether.local` domains in `/etc/hosts` against the authoritative complete list of active domains.
pub async fn reconcile_local_dns_domains(authoritative_domains: &[String]) -> Result<(), String> {
    if authoritative_domains.is_empty() {
        return Ok(());
    }

    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip)
        .map_err(|e| format!("Invalid LAN IP: {e}"))?;

    let mut aether_local_domains: Vec<String> = Vec::new();
    let mut validated_authoritative: Vec<String> = Vec::with_capacity(authoritative_domains.len());
    for d in authoritative_domains {
        let clean = validate_dns_domain(d)?;
        if clean.ends_with(".aether.local") {
            aether_local_domains.push(clean.clone());
        }
        validated_authoritative.push(clean);
    }

    #[cfg(unix)]
    let is_root = {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    };
    #[cfg(not(unix))]
    let is_root = false;

    let test_override = env::var("AF_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_DNSMASQ_DIR").is_ok()
        || env::var("AETHERFLOW_PIHOLE_DIR").is_ok()
        || env::var("AETHERFLOW_FS_ROOT").is_ok()
        || env::var("AETHERFLOW_CONFIG_ROOT").is_ok();

    if is_root || test_override {
        af_runner::reconcile_hosts_file(&aether_local_domains, "127.0.0.1")
            .map_err(|e| format!("Local DNS reconciliation failed: {e}"))?;
        af_runner::sync_dns_provider_files(&lan_ip, &validated_authoritative)
            .map_err(|e| format!("Local DNS provider synchronization failed: {e}"))?;
    } else {
        run_privileged_hosts_command_with_provider(
            "reconcile",
            "127.0.0.1",
            &aether_local_domains,
            Some(&lan_ip),
            Some(&validated_authoritative),
        )
        .await?;
    }

    Ok(())
}

/// Executes privileged hosts manipulation via the privileged runner socket daemon.
pub async fn run_privileged_hosts_command(
    action: &str,
    ip: &str,
    domains: &[String],
) -> Result<(), String> {
    run_privileged_hosts_command_with_provider(action, ip, domains, None, None).await
}

pub async fn run_privileged_hosts_command_with_provider(
    action: &str,
    ip: &str,
    domains: &[String],
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> Result<(), String> {
    match action {
        "reconcile" => af_runner::dispatch_hosts_reconcile_with_provider(
            domains,
            ip,
            provider_ip,
            provider_domains,
        )
        .await
        .map_err(|e| format!("privileged runner hosts reconcile failed: {e}")),
        "remove" => af_runner::dispatch_hosts_remove(domains)
            .await
            .map_err(|e| format!("privileged runner hosts remove failed: {e}")),
        _ => af_runner::dispatch_hosts_update_with_provider(
            domains,
            provider_ip,
            provider_domains,
        )
        .await
        .map_err(|e| format!("privileged runner hosts update failed: {e}")),
    }
}

/// Collects all active internal (`.aether.local`) and external (`public_domain` / `<app>.<baseDomain>`)
/// domains for installed apps and synchronizes them to `/etc/hosts`, Pi-hole `custom.list`, and `dnsmasq.d`.
pub async fn sync_network_dns_providers() -> Result<bool, String> {
    let mut domain_set: BTreeSet<String> = BTreeSet::new();
    let base_domain = crate::resolve_base_domain();

    let configs = af_db::get_all_app_ingress_configs().map_err(|error| error.to_string())?;
    {
        for cfg in configs {
            if !cfg.app_name.trim().is_empty() {
                domain_set.insert(crate::resolve_app_internal_domain(&cfg.app_name));
            }
            if !cfg.public_domain.trim().is_empty() {
                domain_set.insert(cfg.public_domain.trim().to_lowercase());
            } else if !base_domain.is_empty() && cfg.listen_port > 0 {
                let pub_dom = crate::format_app_public_domain(&cfg.app_name, &base_domain);
                if !pub_dom.is_empty() {
                    domain_set.insert(pub_dom);
                }
            }
        }
    }

    let pkgs = crate::get_packages().map_err(|error| error.to_string())?;
    {
        for p in pkgs {
            if p.status != "installed" {
                continue;
            }
            if let Some(bp) = crate::get_blueprint(&p.name) {
                if !bp.internal_domain.trim().is_empty() {
                    domain_set.insert(bp.internal_domain.trim().to_lowercase());
                } else {
                    domain_set.insert(format!("{}.aether.local", p.name.to_lowercase()));
                }
                if !base_domain.is_empty() && bp.default_port > 0 {
                    let pub_dom = crate::format_app_public_domain(&p.name, &base_domain);
                    if !pub_dom.is_empty() {
                        domain_set.insert(pub_dom);
                    }
                }
            }
        }
    }

    // Always keep the core domain so removing the last app clears stale
    // managed DNS entries instead of skipping synchronization entirely.
    domain_set.insert("aetherflow.aether.local".into());

    let domains: Vec<String> = domain_set.into_iter().collect();
    reconcile_local_dns_domains(&domains).await?;
    sync_local_dns_domains(&domains).await?;
    Ok(true)
}

/// Synchronizes Apache2 virtual host reverse-proxy configurations when `/etc/apache2/sites-available` is present.
pub fn sync_apache_app_vhost(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
) -> Result<bool, String> {
    if listen_port <= 0 {
        return Ok(false);
    }
    let sites_avail = resolve_config_path("/etc/apache2/sites-available");
    let sites_en = resolve_config_path("/etc/apache2/sites-enabled");
    if !sites_avail.is_dir() {
        return Ok(false);
    }
    let clean_app: String = app_name
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if clean_app.is_empty() {
        return Ok(false);
    }

    let mut candidate_vhosts = Vec::new();
    for dir in [&sites_avail, &sites_en] {
        if dir.is_dir() {
            candidate_vhosts.push(dir.join(format!("aetherflow-app-{}.conf", clean_app)));
            candidate_vhosts.push(dir.join(format!("aetherflow-ext-{}.conf", clean_app)));
            candidate_vhosts.push(dir.join(format!("{}.conf", clean_app)));
        }
    }
    let preserved_blocks = extract_apache_custom_blocks(&candidate_vhosts);

    let mut backups: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut modified_any = false;
    let mut wrote_any = false;

    if !internal_domain.trim().is_empty() {
        let int_dom = validate_dns_domain(internal_domain)?;
        let default_vhost = format!(
            "# Managed by AetherFlow v3.2.6\n<VirtualHost *:80>\n    ServerName {int_dom}\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:{listen_port}/$1 [P,L]\n    ProxyPass / http://127.0.0.1:{listen_port}/\n    ProxyPassReverse / http://127.0.0.1:{listen_port}/\n    RequestHeader set X-Forwarded-Proto \"http\"\n</VirtualHost>\n"
        );
        let conf_file = sites_avail.join(format!("aetherflow-app-{}.conf", clean_app));
        let prev_int = fs::read_to_string(&conf_file).ok();
        let vhost = render_or_update_apache_vhost(
            prev_int.as_deref(),
            &default_vhost,
            Some(&int_dom),
            listen_port,
            &preserved_blocks,
        );
        if prev_int.as_deref() != Some(vhost.as_str()) {
            match write_file_atomic(&conf_file, vhost.as_bytes()) {
                Ok(()) => {
                    backups.push((conf_file.clone(), prev_int));
                    modified_any = true;
                    wrote_any = true;
                }
                Err(error) if is_unprivileged_host_write_error(&error) => {
                    tracing::info!(
                        app = %clean_app,
                        path = %conf_file.display(),
                        "skipping Apache internal vhost write in unprivileged API process (handled by privileged runner): {}",
                        error
                    );
                }
                Err(error) => return Err(error),
            }
        } else {
            wrote_any = true;
        }
    }

    let ext_conf_file = sites_avail.join(format!("aetherflow-ext-{}.conf", clean_app));
    if external_access && !public_domain.trim().is_empty() {
        let pub_dom = validate_dns_domain(public_domain)?;
        let default_ext_vhost = format!(
            "# Managed by AetherFlow v3.2.6 (External Ingress)\n<VirtualHost *:80>\n    ServerName {pub_dom}\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:{listen_port}/$1 [P,L]\n    ProxyPass / http://127.0.0.1:{listen_port}/\n    ProxyPassReverse / http://127.0.0.1:{listen_port}/\n</VirtualHost>\n"
        );
        let prev_ext = fs::read_to_string(&ext_conf_file).ok();
        let ext_vhost = render_or_update_apache_vhost(
            prev_ext.as_deref(),
            &default_ext_vhost,
            Some(&pub_dom),
            listen_port,
            &preserved_blocks,
        );
        if prev_ext.as_deref() != Some(ext_vhost.as_str()) {
            match write_file_atomic(&ext_conf_file, ext_vhost.as_bytes()) {
                Ok(()) => {
                    backups.push((ext_conf_file.clone(), prev_ext));
                    modified_any = true;
                    wrote_any = true;
                }
                Err(error) if is_unprivileged_host_write_error(&error) => {
                    tracing::info!(
                        app = %clean_app,
                        path = %ext_conf_file.display(),
                        "skipping Apache external vhost write in unprivileged API process (handled by privileged runner): {}",
                        error
                    );
                }
                Err(error) => return Err(error),
            }
        } else {
            wrote_any = true;
        }
    } else if ext_conf_file.exists() {
        let prev_ext = fs::read_to_string(&ext_conf_file).ok();
        if let Err(error) = fs::remove_file(&ext_conf_file) {
            let err_msg = format!("failed to remove external vhost: {error}");
            if is_unprivileged_host_write_error(&err_msg) {
                tracing::info!(
                    app = %clean_app,
                    path = %ext_conf_file.display(),
                    "skipping Apache external vhost removal in unprivileged API process: {}",
                    err_msg
                );
            } else {
                return Err(err_msg);
            }
        } else {
            backups.push((ext_conf_file.clone(), prev_ext));
            modified_any = true;
        }
    }

    // Also update any existing regular (non-symlink) vhost files for this app in sites-available or sites-enabled
    let mut extra_existing_paths = vec![
        sites_avail.join(format!("{}.conf", clean_app)),
        sites_en.join(format!("aetherflow-app-{}.conf", clean_app)),
        sites_en.join(format!("{}.conf", clean_app)),
    ];
    if external_access && !public_domain.trim().is_empty() {
        extra_existing_paths.push(sites_en.join(format!("aetherflow-ext-{}.conf", clean_app)));
    }
    for path in extra_existing_paths {
        let is_symlink = fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !is_symlink && path.is_file() {
            if let Ok(prev_raw) = fs::read_to_string(&path) {
                let updated = render_or_update_apache_vhost(
                    Some(&prev_raw),
                    &prev_raw,
                    None,
                    listen_port,
                    &preserved_blocks,
                );
                if prev_raw != updated {
                    if write_file_atomic(&path, updated.as_bytes()).is_ok() {
                        backups.push((path.clone(), Some(prev_raw)));
                        modified_any = true;
                        wrote_any = true;
                    }
                }
            }
        }
    }

    if modified_any
        && sites_avail == Path::new("/etc/apache2/sites-available")
        && Path::new("/etc/apache2/apache2.conf").is_file()
    {
        if let Err(err) = verify_apache_configtest() {
            for (path, prev_content) in backups.into_iter().rev() {
                match prev_content {
                    Some(raw) => {
                        let _ = write_file_atomic(&path, raw.as_bytes());
                    }
                    None => {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
            return Err(format!(
                "apache2ctl configtest failed for {}: {}",
                clean_app, err
            ));
        }
    }

    Ok(wrote_any)
}

fn rewrite_apache_proxy_url_port(token: &str, listen_port: i32) -> Option<String> {
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        if let Some(rest) = token.strip_prefix(scheme) {
            for host in ["127.0.0.1:", "localhost:", "0.0.0.0:", "[::1]:"] {
                if let Some(after_host) = rest.strip_prefix(host) {
                    let digit_len = after_host
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .count();
                    if digit_len > 0 {
                        let suffix = &after_host[digit_len..];
                        return Some(format!("{scheme}{host}{listen_port}{suffix}"));
                    }
                }
            }
        }
    }
    None
}

fn extract_apache_custom_blocks(paths: &[PathBuf]) -> Vec<String> {
    let mut blocks = Vec::new();
    for path in paths {
        let Ok(raw) = fs::read_to_string(path) else {
            continue;
        };
        let mut current_block: Option<(String, Vec<String>)> = None;
        for line in raw.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            if let Some((ref end_tag, ref mut buf)) = current_block {
                buf.push(line.to_string());
                if lower.starts_with(end_tag.as_str()) {
                    let joined = buf.join("\n");
                    if !blocks.iter().any(|b: &String| b.trim() == joined.trim()) {
                        blocks.push(joined);
                    }
                    current_block = None;
                }
                continue;
            }
            if lower.starts_with("<location") {
                current_block = Some(("</location>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<directory") {
                current_block = Some(("</directory>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<requireall") {
                current_block = Some(("</requireall>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<requireany") {
                current_block = Some(("</requireany>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("<files") {
                current_block = Some(("</files>".to_string(), vec![line.to_string()]));
            } else if lower.starts_with("authtype ")
                || lower.starts_with("authname ")
                || lower.starts_with("authuserfile ")
                || lower.starts_with("authgroupfile ")
                || lower.starts_with("authbasicprovider ")
                || lower.starts_with("require ")
                || lower.starts_with("include ")
                || lower.starts_with("includeoptional ")
            {
                let single = line.to_string();
                if !blocks.iter().any(|b: &String| b.trim() == single.trim()) {
                    blocks.push(single);
                }
            }
        }
    }
    blocks
}

fn render_or_update_apache_vhost(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    preserved_blocks: &[String],
) -> String {
    let base = match existing_raw {
        Some(raw) if raw.to_ascii_lowercase().contains("<virtualhost") => {
            let mut out_lines = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim_start();
                let indent = &line[..line.len() - trimmed.len()];
                let lower = trimmed.to_ascii_lowercase();
                if let Some(dom) = desired_server_name {
                    if lower.starts_with("servername ") || lower.starts_with("servername\t") {
                        out_lines.push(format!("{indent}ServerName {dom}"));
                        continue;
                    }
                }
                if lower.starts_with("proxypass ")
                    || lower.starts_with("proxypass\t")
                    || lower.starts_with("proxypassreverse ")
                    || lower.starts_with("proxypassreverse\t")
                    || lower.starts_with("rewriterule ")
                    || lower.starts_with("rewriterule\t")
                {
                    let tokens: Vec<String> = trimmed
                        .split_whitespace()
                        .map(|tok| {
                            rewrite_apache_proxy_url_port(tok, listen_port)
                                .unwrap_or_else(|| tok.to_string())
                        })
                        .collect();
                    out_lines.push(format!("{indent}{}", tokens.join(" ")));
                } else {
                    out_lines.push(line.to_string());
                }
            }
            let mut joined = out_lines.join("\n");
            joined.push('\n');
            joined
        }
        _ => default_template.to_string(),
    };

    if preserved_blocks.is_empty() {
        return base;
    }

    let mut missing = Vec::new();
    for block in preserved_blocks {
        let trimmed_block = block.trim();
        if !trimmed_block.is_empty() && !base.contains(trimmed_block) {
            missing.push(block.clone());
        }
    }
    if missing.is_empty() {
        return base;
    }

    let mut final_lines = Vec::new();
    let mut inserted = false;
    for line in base.lines() {
        if !inserted && line.trim().eq_ignore_ascii_case("</virtualhost>") {
            for block in &missing {
                final_lines.push(block.clone());
            }
            inserted = true;
        }
        final_lines.push(line.to_string());
    }
    if !inserted {
        for block in &missing {
            final_lines.push(block.clone());
        }
    }
    let mut out = final_lines.join("\n");
    out.push('\n');
    out
}

fn verify_apache_configtest() -> Result<(), String> {
    for bin in ["/usr/sbin/apache2ctl", "/usr/sbin/apachectl", "apache2ctl", "apachectl"] {
        match std::process::Command::new(bin).arg("-t").output() {
            Ok(out) => {
                if out.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                return Err(format!("{} {}", stderr.trim(), stdout.trim()).trim().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// Triggers `/usr/local/bin/aetherflow-apache-cert-sync` when present on the system.
pub async fn trigger_apache_cert_sync() {
    let script_path = Path::new("/usr/local/bin/aetherflow-apache-cert-sync");
    if !script_path.exists() {
        return;
    }
    let _ = tokio::process::Command::new("sudo")
        .args(["-n", "/usr/local/bin/aetherflow-apache-cert-sync"])
        .output()
        .await;
}

/// Retroactively provisions `<app>.<baseDomain>` public domains for all installed apps
/// and updates existing ingress records when the base domain changes (`blueprint_lifecycle.go`).
pub async fn provision_all_installed_app_subdomains() -> usize {
    provision_installed_app_subdomains(&crate::resolve_base_domain()).await
}

async fn provision_installed_app_subdomains(base_domain: &str) -> usize {
    match with_blueprint_admission(async {
        provision_installed_app_subdomains_admitted(base_domain)
            .await
            .map_err(anyhow::Error::msg)
    })
    .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(detail = %format!("{error:#}"), "installed application subdomain synchronization failed");
            0
        }
    }
}

async fn provision_installed_app_subdomains_admitted(base_domain: &str) -> Result<usize, String> {
    let norm_base = af_db::normalize_base_domain(base_domain);
    let mut updated_count = 0usize;

    let existing_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();

    let pkgs = crate::get_packages().map_err(|error| error.to_string())?;
    for package in &pkgs {
        if package.status == "installed" {
            with_blueprint_mutation(&package.name, async { Ok(()) })
                .await
                .map_err(|error| format!("{error:#}"))?;
        }
    }
    {
        for p in pkgs {
            if p.status != "installed" {
                continue;
            }
            let Some(bp) = crate::get_blueprint(&p.name) else {
                continue;
            };
            if bp.default_port <= 0 {
                continue;
            }
            let new_pub = if norm_base.is_empty() {
                String::new()
            } else {
                crate::format_app_public_domain(&bp.app_name, &norm_base)
            };

            let mut cfg =
                existing_map
                    .get(&bp.app_name)
                    .cloned()
                    .unwrap_or(af_models::AppIngressConfig {
                        app_name: bp.app_name.clone(),
                        listen_port: bp.default_port,
                        public_domain: new_pub.clone(),
                        external_access_enabled: false,
                        tls_enabled: false,
                        ..Default::default()
                    });

            if cfg.listen_port <= 0 {
                cfg.listen_port = bp.default_port;
            }
            cfg.public_domain = new_pub;

            af_db::set_app_ingress_config(&cfg).map_err(|error| error.to_string())?;
            sync_apache_app_vhost(
                &cfg.app_name,
                cfg.listen_port,
                &crate::resolve_app_internal_domain(&cfg.app_name),
                &cfg.public_domain,
                cfg.external_access_enabled,
            )?;
            updated_count += 1;
        }
    }

    sync_network_dns_providers().await?;
    trigger_apache_cert_sync().await;
    Ok(updated_count)
}

/// Alias matching Go's `SyncInstalledAppsBaseDomain(oldBaseDomain, newBaseDomain)`.
pub async fn sync_installed_apps_base_domain(_old_base_domain: &str, new_base_domain: &str) -> usize {
    provision_installed_app_subdomains(new_base_domain).await
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

const APP_META_BUDGET: Duration = Duration::from_millis(1500);
const MAX_APP_META_PROBES: usize = 4;
const MAX_RUNNER_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Default)]
struct AppMetaState {
    generation: u64,
    cached: HashMap<String, (AppRuntimeMeta, Instant)>,
    in_flight: BTreeSet<String>,
}

static APP_META_CACHE: Lazy<(Mutex<AppMetaState>, Condvar)> =
    Lazy::new(|| (Mutex::new(AppMetaState::default()), Condvar::new()));

static PROMETHEUS_LISTEN_PORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"--web\.listen-address=[^\s'\x22]*:(\d{2,5})").unwrap());

pub fn clear_app_runtime_meta_cache() {
    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    state.generation = state.generation.wrapping_add(1);
    state.cached.clear();
    drop(state);
    crate::service_observations::invalidate();
}

pub(super) fn app_runtime_meta_epoch() -> u64 {
    APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .generation
}

pub(super) fn cached_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    let state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    state
        .cached
        .get(&normalize_app_key_name(app_name))
        .filter(|(_, expires)| Instant::now() < *expires)
        .map(|(meta, _)| meta.clone())
        .unwrap_or_default()
}

struct AppMetaFlight(String);

impl Drop for AppMetaFlight {
    fn drop(&mut self) {
        let mut state = APP_META_CACHE
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.in_flight.remove(&self.0);
        APP_META_CACHE.1.notify_all();
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
        "calibreweb" => "calibre-web".to_string(),
        "grafana-server" => "grafana".to_string(),
        "uptimekuma" => "uptime-kuma".to_string(),
        "adguard-home" => "adguardhome".to_string(),
        "pyload-ng" => "pyload".to_string(),
        "af-maintainerr" => "maintainerr".to_string(),
        "af-palate" => "palate".to_string(),
        "af-mcvnc" => "mcvnc".to_string(),
        "af-piped" => "piped".to_string(),
        "af-invidious" => "invidious".to_string(),
        "home-assistant@homeassistant" => "homeassistant".to_string(),
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

fn parse_port_from_host_port(addr: &str) -> i32 {
    let clean = addr.trim().trim_matches(['"', '\'']);
    if let Some((_host, port_part)) = clean.rsplit_once(':') {
        parse_valid_port(port_part)
    } else {
        parse_valid_port(clean)
    }
}

fn extract_port_from_systemd_or_apache_text(text: &str) -> i32 {
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
        Regex::new(
            r#"(?i)(?:--(?:webservice-)?port|-port|-p)(?:\s+|=)["']?([0-9]{2,5})\b"#,
        )
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
                let p = parse_valid_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    if let Some(caps) = APACHE_LISTEN_VHOST_RE.captures(text) {
        for idx in [1, 2, 3] {
            if let Some(m) = caps.get(idx) {
                let p = parse_valid_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    0
}

fn extract_fallback_unit_or_apache_port(canonical: &str) -> i32 {
    let mut candidates = vec![
        format!("/etc/systemd/system/{canonical}.service"),
        format!("/etc/systemd/system/af-{canonical}.service"),
        format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
        format!("/etc/apache2/sites-available/{canonical}.conf"),
        format!("/etc/apache2/sites-available/aetherflow-app-{canonical}.conf"),
    ];
    if canonical == "uptime-kuma" {
        candidates.push("/etc/systemd/system/uptimekuma.service".to_string());
        candidates.push("/etc/apache2/sites-available/aetherflow-app-uptimekuma.conf".to_string());
    } else if canonical == "calibre-web" {
        candidates.push("/etc/systemd/system/calibreweb.service".to_string());
        candidates.push("/etc/apache2/sites-available/aetherflow-app-calibreweb.conf".to_string());
    }
    for raw in candidates {
        let p = resolve_config_path(&raw);
        if let Ok(text) = fs::read_to_string(&p) {
            let port = extract_port_from_systemd_or_apache_text(&text);
            if port > 0 {
                return port;
            }
        }
    }
    0
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

fn extract_yaml_section_value(content: &str, section: &str, key: &str) -> Option<String> {
    let want_sec = format!("{}:", section.trim().to_lowercase());
    let want_key = key.trim().to_lowercase();
    let mut in_sec = false;

    for line in content.lines() {
        let trimmed_end = line.trim_end();
        let trimmed = trimmed_end.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let is_top_level = !trimmed_end.starts_with(' ') && !trimmed_end.starts_with('\t');
        if is_top_level {
            in_sec = trimmed.to_lowercase() == want_sec;
            continue;
        }
        if in_sec {
            if let Some((k, v)) = trimmed.split_once(':') {
                if k.trim().to_lowercase() == want_key {
                    let mut val = v.trim();
                    if !val.starts_with('"') && !val.starts_with('\'') {
                        if let Some(hash_idx) = val.find(" #") {
                            val = val[..hash_idx].trim();
                        }
                    }
                    let unquoted = val.trim_matches(['"', '\'']).trim();
                    if !unquoted.is_empty() && unquoted != "null" && unquoted != "~" {
                        return Some(unquoted.to_string());
                    }
                }
            }
        }
    }
    None
}

fn parse_deluge_conf_json(content: &str) -> Option<Value> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(first_brace) = trimmed.find('{') {
        let after_first = &trimmed[first_brace + 1..];
        if let Some(second_rel) = after_first.find('{') {
            let second_start = first_brace + 1 + second_rel;
            if let Ok(val) = serde_json::from_str::<Value>(&trimmed[second_start..]) {
                return Some(val);
            }
        }
        if let Ok(val) = serde_json::from_str::<Value>(&trimmed[first_brace..]) {
            return Some(val);
        }
    }
    None
}

fn query_sqlite_first_text(db_path: &Path, queries: &[&str], deadline: Instant) -> Option<String> {
    if Instant::now() >= deadline || !db_path.is_file() {
        return None;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(db_path, flags).ok()?;
    for &q in queries {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        conn.busy_timeout(remaining.min(APP_META_BUDGET)).ok()?;
        if let Ok(val) = conn.query_row(q, [], |r| r.get::<_, String>(0)) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(unix)]
fn query_runner_app_meta_unix(canonical_app: &str, deadline: Instant) -> Option<AppRuntimeMeta> {
    let response = request_runner_unix_until(
        "/v1/app-meta",
        json!({ "app_name": canonical_app }),
        deadline,
    )?;
    parse_runner_app_meta(&response)
}

#[cfg(unix)]
fn request_runner_unix(route: &str, payload: Value, timeout: Duration) -> Option<String> {
    request_runner_unix_until(route, payload, Instant::now() + timeout)
}

#[cfg(unix)]
fn request_runner_unix_until(route: &str, payload: Value, deadline: Instant) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"].iter().any(|key| {
        env::var(key).ok().is_some_and(|value| !value.trim().is_empty())
    }) {
        return None;
    }
    let sock_path = af_runner::runner_socket_path();
    if Instant::now() >= deadline {
        return None;
    }

    let body = serde_json::to_string(&payload).ok()?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        route,
        body.len(),
        body
    );
    if req.len() > MAX_RUNNER_RESPONSE_BYTES as usize {
        return None;
    }
    let bytes = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                runtime.block_on(async {
                    tokio::time::timeout_at(deadline.into(), async {
                        let mut stream = tokio::net::UnixStream::connect(&sock_path).await.ok()?;
                        stream.write_all(req.as_bytes()).await.ok()?;
                        let mut bytes = Vec::new();
                        stream
                            .take(MAX_RUNNER_RESPONSE_BYTES + 1)
                            .read_to_end(&mut bytes)
                            .await
                            .ok()?;
                        (bytes.len() <= MAX_RUNNER_RESPONSE_BYTES as usize).then_some(bytes)
                    })
                    .await
                    .ok()
                    .flatten()
                })
            })
            .join()
            .ok()
            .flatten()
    })?;
    let resp = String::from_utf8(bytes).ok()?;
    let (headers, json_body) = resp.split_once("\r\n\r\n")?;
    if !headers.starts_with("HTTP/1.1 200 ") && !headers.starts_with("HTTP/1.0 200 ") {
        return None;
    }
    Some(json_body.to_string())
}

fn parse_runner_app_meta(json_body: &str) -> Option<AppRuntimeMeta> {
    let response: Value = serde_json::from_str(json_body).ok()?;
    let success = response.get("ok").or_else(|| response.get("success"));
    if success.and_then(Value::as_bool) != Some(true) {
        return None;
    }
    if let Some(data) = response.get("data") {
        return serde_json::from_value(data.clone()).ok();
    }
    serde_json::from_str(response.get("output")?.as_str()?).ok()
}

/// Discovers runtime API key and configured port from an application's native config files.
pub fn get_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    get_app_runtime_meta_until(app_name, Instant::now() + APP_META_BUDGET)
}

pub(super) fn get_app_runtime_meta_until(app_name: &str, deadline: Instant) -> AppRuntimeMeta {
    let canonical = normalize_app_key_name(app_name);
    if canonical.is_empty() {
        return AppRuntimeMeta::default();
    }

    let deadline = deadline.min(Instant::now() + APP_META_BUDGET);
    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    loop {
        if let Some((meta, expires)) = state.cached.get(&canonical) {
            if Instant::now() < *expires {
                return meta.clone();
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return AppRuntimeMeta::default();
        }
        if !state.in_flight.contains(&canonical) && state.in_flight.len() < MAX_APP_META_PROBES {
            break;
        }
        state = APP_META_CACHE
            .1
            .wait_timeout(state, remaining)
            .unwrap_or_else(|error| error.into_inner())
            .0;
    }
    state.in_flight.insert(canonical.clone());
    let generation = state.generation;
    drop(state);
    let _flight = AppMetaFlight(canonical.clone());

    let mut meta = AppRuntimeMeta::default();
    match canonical.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            let candidates = [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/config/config.xml", canonical),
                format!("/var/lib/{}/.config/{}/config.xml", canonical, canonical),
                format!("/etc/{}/config.xml", canonical),
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
        "bazarr" => {
            for raw in [
                "/var/lib/bazarr/config/config.yaml",
                "/var/lib/bazarr/data/config/config.yaml",
                "/opt/bazarr/data/config/config.yaml",
                "/etc/bazarr/config.yaml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_yaml_section_value(&text, "auth", "apikey")
                            .or_else(|| extract_ini_value(&text, &["apikey", "api_key"]))
                        {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(v) = extract_yaml_section_value(&text, "general", "port")
                            .or_else(|| extract_ini_value(&text, &["port"]))
                        {
                            meta.configured_port = parse_valid_port(&v);
                        }
                    }
                }
            }
            for raw in [
                "/var/lib/bazarr/config/config.ini",
                "/var/lib/bazarr/data/config/config.ini",
                "/opt/bazarr/data/config/config.ini",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_ini_value(&text, &["apikey", "api_key"]) {
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
        "tautulli" => {
            for raw in [
                "/var/lib/tautulli/config.ini",
                "/opt/Tautulli/config.ini",
                "/etc/tautulli/config.ini",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_ini_value(&text, &["api_key"]) {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(v) = extract_ini_value(&text, &["http_port", "port"]) {
                            meta.configured_port = parse_valid_port(&v);
                        }
                    }
                }
            }
        }
        "sabnzbd" => {
            for raw in [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/config/sabnzbd.ini",
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
        "jackett" => {
            for raw in [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
                "/etc/jackett/ServerConfig.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if meta.api_key.is_empty() {
                            if let Some(k) = val
                                .get("APIKey")
                                .or_else(|| val.get("api_key"))
                                .and_then(|v| v.as_str())
                            {
                                meta.api_key = k.trim().to_string();
                            }
                        }
                        if meta.configured_port <= 0 {
                            if let Some(port) = val
                                .get("Port")
                                .or_else(|| val.get("port"))
                                .and_then(|v| v.as_i64())
                            {
                                meta.configured_port = port as i32;
                            }
                        }
                    }
                }
            }
        }
        "overseerr" | "jellyseerr" => {
            let candidates = [
                format!("/var/lib/{}/config/settings.json", canonical),
                format!("/var/lib/{}/settings.json", canonical),
                format!("/etc/{}/settings.json", canonical),
            ];
            for raw in candidates {
                let p = resolve_config_path(&raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        let main_obj = val.get("main");
                        if meta.api_key.is_empty() {
                            if let Some(k) = main_obj
                                .and_then(|m| m.get("apiKey"))
                                .or_else(|| val.get("apiKey"))
                                .and_then(|v| v.as_str())
                            {
                                meta.api_key = k.trim().to_string();
                            }
                        }
                        if meta.configured_port <= 0 {
                            if let Some(port) = main_obj
                                .and_then(|m| m.get("port"))
                                .or_else(|| val.get("port"))
                                .and_then(|v| v.as_i64())
                            {
                                meta.configured_port = port as i32;
                            }
                        }
                    }
                }
            }
        }
        "ombi" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/ombi.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            for raw in [
                "/var/lib/ombi/database.json",
                "/etc/Ombi/database.json",
                "/var/lib/ombi/appsettings.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val
                            .get("port")
                            .or_else(|| val.get("Port"))
                            .and_then(|v| v.as_i64())
                        {
                            if port > 0 && meta.configured_port <= 0 {
                                meta.configured_port = port as i32;
                            }
                        }
                    }
                }
            }
            for raw_db in ["/var/lib/ombi/OmbiSettings.db", "/etc/Ombi/OmbiSettings.db"] {
                let db_path = resolve_config_path(raw_db);
                if let Some(content_str) = query_sqlite_first_text(
                    &db_path,
                    &["SELECT Content FROM GlobalSettings WHERE SettingsName = 'OmbiSettings' LIMIT 1"],
                    deadline,
                ) {
                    if let Ok(val) = serde_json::from_str::<Value>(&content_str) {
                        if meta.api_key.is_empty() {
                            if let Some(k) = val
                                .get("ApiKey")
                                .or_else(|| val.get("apiKey"))
                                .and_then(|v| v.as_str())
                            {
                                meta.api_key = k.trim().to_string();
                            }
                        }
                        if meta.configured_port <= 0 {
                            if let Some(port) = val
                                .get("Port")
                                .or_else(|| val.get("port"))
                                .and_then(|v| v.as_i64())
                            {
                                meta.configured_port = port as i32;
                            }
                        }
                    }
                }
            }
        }
        "autobrr" | "qui" => {
            let candidates = [
                format!("/var/lib/{}/config.toml", canonical),
                format!("/var/lib/{}/.config/{}/config.toml", canonical, canonical),
                format!("/etc/{}/config.toml", canonical),
            ];
            for raw in candidates {
                let p = resolve_config_path(&raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "qbittorrent" => {
            for raw in [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
                "/var/lib/qbittorrent/qBittorrent.conf",
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
        "transmission" => {
            for raw in [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
                "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
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
        "deluge" => {
            for raw in [
                "/var/lib/deluge/.config/deluge/web.conf",
                "/var/lib/deluge/web.conf",
                "/etc/deluge/web.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(val) = parse_deluge_conf_json(&text) {
                        if let Some(port) = val.get("port").and_then(|v| v.as_i64()) {
                            if port > 0 {
                                meta.configured_port = port as i32;
                                break;
                            }
                        }
                    }
                }
            }
            if meta.configured_port <= 0 {
                for raw in [
                    "/var/lib/deluge/.config/deluge/core.conf",
                    "/var/lib/deluge/core.conf",
                ] {
                    let p = resolve_config_path(raw);
                    if let Ok(text) = fs::read_to_string(&p) {
                        if let Some(val) = parse_deluge_conf_json(&text) {
                            if let Some(port) = val.get("daemon_port").and_then(|v| v.as_i64()) {
                                if port > 0 {
                                    meta.configured_port = port as i32;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        "nzbget" => {
            for raw in [
                "/var/lib/nzbget/nzbget.conf",
                "/etc/nzbget.conf",
                "/opt/nzbget/nzbget.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(pw) = extract_ini_value(&text, &["ControlPassword"]) {
                            meta.api_key = pw;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(v) = extract_ini_value(&text, &["ControlPort"]) {
                            meta.configured_port = parse_valid_port(&v);
                        }
                    }
                }
            }
        }
        "znc" => {
            for raw in [
                "/var/lib/znc/.znc/configs/znc.conf",
                "/var/lib/znc/configs/znc.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["Port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "thelounge" => {
            for raw in [
                "/var/lib/thelounge/config.js",
                "/etc/thelounge/config.js",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["port"]) {
                        let clean = v.trim_end_matches(',').trim();
                        let port = parse_valid_port(clean);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "filebrowser" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/filebrowser.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                for raw in [
                    "/etc/filebrowser/filebrowser.json",
                    "/etc/filebrowser/config.json",
                    "/var/lib/filebrowser/filebrowser.json",
                    "/etc/filebrowser/.filebrowser.json",
                    "/opt/filebrowser/filebrowser.json",
                ] {
                    let p = resolve_config_path(raw);
                    if let Ok(text) = fs::read_to_string(&p) {
                        if let Ok(val) = serde_json::from_str::<Value>(&text) {
                            if let Some(port) = val.get("port").and_then(|v| v.as_i64()) {
                                if port > 0 {
                                    meta.configured_port = port as i32;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        "syncthing" => {
            for raw in [
                "/var/lib/syncthing/.config/syncthing/config.xml",
                "/var/lib/syncthing/config.xml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_xml_tag_text(&text, "apikey") {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(addr) = extract_xml_tag_text(&text, "address") {
                            let port = parse_port_from_host_port(&addr);
                            if port > 0 {
                                meta.configured_port = port;
                            }
                        }
                    }
                }
            }
        }
        "navidrome" => {
            for raw in [
                "/var/lib/navidrome/navidrome.toml",
                "/etc/navidrome/navidrome.toml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["Port", "ND_PORT"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "audiobookshelf" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/audiobookshelf.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                for raw in [
                    "/etc/default/audiobookshelf",
                    "/var/lib/audiobookshelf/config.env",
                    "/var/lib/audiobookshelf/config/.env",
                ] {
                    let p = resolve_config_path(raw);
                    if let Ok(text) = fs::read_to_string(&p) {
                        if let Some(v) = extract_ini_value(&text, &["PORT", "port"]) {
                            let port = parse_valid_port(&v);
                            if port > 0 {
                                meta.configured_port = port;
                                break;
                            }
                        }
                    }
                }
            }
        }
        "kavita" => {
            for raw in [
                "/var/lib/kavita/config/appsettings.json",
                "/opt/Kavita/config/appsettings.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val
                            .get("Port")
                            .or_else(|| val.get("port"))
                            .and_then(|v| v.as_i64())
                        {
                            if port > 0 {
                                meta.configured_port = port as i32;
                                break;
                            }
                        }
                    }
                }
            }
        }
        "komga" => {
            for raw in [
                "/var/lib/komga/application.yml",
                "/etc/komga/application.yml",
                "/etc/default/komga",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_yaml_section_value(&text, "server", "port")
                        .or_else(|| extract_ini_value(&text, &["KOMGA_SERVER_PORT", "SERVER_PORT", "port"]))
                    {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "calibre-web" => {
            for raw_db in [
                "/var/lib/calibre-web/app.db",
                "/opt/calibre-web/app.db",
            ] {
                let db_path = resolve_config_path(raw_db);
                if let Some(port_str) = query_sqlite_first_text(
                    &db_path,
                    &["SELECT CAST(config_port AS TEXT) FROM settings LIMIT 1"],
                    deadline,
                ) {
                    let port = parse_valid_port(&port_str);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "grafana" => {
            for raw in ["/etc/grafana/grafana.ini", "/var/lib/grafana/grafana.ini"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["http_port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "prometheus" => {
            for raw in [
                "/etc/systemd/system/prometheus.service",
                "/etc/default/prometheus",
                "/etc/sysconfig/prometheus",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(caps) = PROMETHEUS_LISTEN_PORT_RE.captures(&text) {
                        if let Some(m) = caps.get(1) {
                            let port = parse_valid_port(m.as_str());
                            if port > 0 {
                                meta.configured_port = port;
                                break;
                            }
                        }
                    }
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "uptime-kuma" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/uptime-kuma.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                for raw in [
                    "/var/lib/uptime-kuma/.env",
                    "/opt/uptime-kuma/.env",
                    "/etc/default/uptime-kuma",
                ] {
                    let p = resolve_config_path(raw);
                    if let Ok(text) = fs::read_to_string(&p) {
                        if let Some(v) = extract_ini_value(&text, &["UPTIME_KUMA_PORT", "PORT"]) {
                            let port = parse_valid_port(&v);
                            if port > 0 {
                                meta.configured_port = port;
                                break;
                            }
                        }
                    }
                }
            }
        }
        "vaultwarden" => {
            for raw in [
                "/etc/vaultwarden/vaultwarden.env",
                "/etc/vaultwarden.env",
                "/var/lib/vaultwarden/.env",
                "/etc/default/vaultwarden",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["ROCKET_PORT", "PORT"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "immich" => {
            for raw in [
                "/var/lib/immich/.env",
                "/opt/immich/.env",
                "/etc/default/immich",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["IMMICH_PORT", "PORT", "SERVER_PORT"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "dispatcharr" => {
            if let Ok(content) = fs::read_to_string(resolve_config_path("/etc/dispatcharr/dispatcharr.env")) {
                if let Some(port) = extract_ini_value(&content, &["DISPATCHARR_PORT"]) {
                    meta.configured_port = parse_valid_port(&port);
                }
            }
        }

        "paperless-ngx" => {
            for raw in [
                "/etc/paperless.conf",
                "/var/lib/paperless/paperless.conf",
                "/opt/paperless/paperless.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["PAPERLESS_PORT", "PORT"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "pihole" => {
            let toml_path = resolve_config_path("/etc/pihole/pihole.toml");
            if let Ok(text) = fs::read_to_string(&toml_path) {
                if let Some(v) = extract_ini_value(&text, &["port"]) {
                    for token in v.split(',') {
                        let port = parse_valid_port(token);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
            let setup_vars = resolve_config_path("/etc/pihole/setupVars.conf");
            if let Ok(text) = fs::read_to_string(&setup_vars) {
                if let Some(pw) = extract_ini_value(&text, &["WEBPASSWORD"]) {
                    meta.api_key = pw;
                }
            }
        }
        "plex" => {
            meta.configured_port = 32400;
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
            for raw_db in [
                "/var/lib/jellyfin/data/jellyfin.db",
                "/var/lib/jellyfin/jellyfin.db",
            ] {
                let db_path = resolve_config_path(raw_db);
                if let Some(tok) = query_sqlite_first_text(
                    &db_path,
                    &[
                        "SELECT AccessToken FROM ApiKeys ORDER BY DateCreated DESC LIMIT 1",
                        "SELECT AccessToken FROM Devices WHERE AccessToken IS NOT NULL AND AccessToken != '' ORDER BY DateLastActivity DESC LIMIT 1",
                    ],
                    deadline,
                ) {
                    meta.api_key = tok;
                    break;
                }
            }
        }
        "emby" => {
            for raw in ["/var/lib/emby/config/system.xml", "/etc/emby/system.xml"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_xml_tag_text(&text, "HttpServerPortNumber")
                        .or_else(|| extract_xml_tag_text(&text, "PublicPort"))
                        .map(|s| parse_valid_port(&s))
                        .unwrap_or(0);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            for raw_db in [
                "/var/lib/emby/data/authentication.db",
                "/var/lib/emby/authentication.db",
            ] {
                let db_path = resolve_config_path(raw_db);
                if let Some(tok) = query_sqlite_first_text(
                    &db_path,
                    &[
                        "SELECT AccessToken FROM Tokens ORDER BY DateCreated DESC LIMIT 1",
                        "SELECT AccessToken FROM ApiKeys ORDER BY DateCreated DESC LIMIT 1",
                    ],
                    deadline,
                ) {
                    meta.api_key = tok;
                    break;
                }
            }
        }
        "notifiarr" => {
            for raw in [
                "/etc/notifiarr/notifiarr.conf",
                "/var/lib/notifiarr/notifiarr.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if meta.api_key.is_empty() {
                        if let Some(k) = extract_ini_value(&text, &["api_key"]) {
                            meta.api_key = k;
                        }
                    }
                    if meta.configured_port <= 0 {
                        if let Some(v) = extract_ini_value(&text, &["bind_addr"]) {
                            meta.configured_port = parse_port_from_host_port(&v);
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
            for raw in [
                "/etc/apache2/conf-available/aetherflow-organizr-listen.conf",
                "/etc/apache2/sites-available/organizr.conf",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "requestrr" => {
            for raw in [
                "/var/lib/requestrr/config/settings.json",
                "/opt/requestrr/config/settings.json",
                "/var/lib/requestrr/settings.json",
                "/opt/requestrr/settings.json",
                "/opt/requestrr/Settings/settings.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val
                            .get("Port")
                            .or_else(|| val.get("port"))
                            .and_then(|v| v.as_i64())
                        {
                            if port > 0 {
                                meta.configured_port = port as i32;
                                break;
                            }
                        }
                    }
                }
            }
        }
        "seedcross" => {
            for raw in [
                "/opt/seedcross/start-seedcross.sh",
                "/etc/systemd/system/seedcross.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            for raw in [
                "/var/lib/seedcross/.env",
                "/opt/seedcross/.env",
                "/etc/seedcross/config.json",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if meta.api_key.is_empty() {
                            if let Some(k) = val.get("apiKey").or_else(|| val.get("api_key")).and_then(|v| v.as_str()) {
                                meta.api_key = k.trim().to_string();
                            }
                        }
                        if meta.configured_port <= 0 {
                            if let Some(port) = val.get("port").and_then(|v| v.as_i64()) {
                                meta.configured_port = port as i32;
                            }
                        }
                    } else {
                        if meta.api_key.is_empty() {
                            if let Some(k) = extract_ini_value(&text, &["API_KEY", "SEEDCROSS_API_KEY"]) {
                                meta.api_key = k;
                            }
                        }
                        if meta.configured_port <= 0 {
                            if let Some(v) = extract_ini_value(&text, &["PORT", "SEEDCROSS_PORT"]) {
                                meta.configured_port = parse_valid_port(&v);
                            }
                        }
                    }
                }
            }
        }
        "gitea" => {
            for raw in ["/etc/gitea/app.ini", "/var/lib/gitea/custom/conf/app.ini"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["HTTP_PORT"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "maintainerr" => {
            for raw in [
                "/etc/systemd/system/af-maintainerr.service",
                "/etc/systemd/system/maintainerr.service",
                "/var/lib/maintainerr/.env",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text)
                        .max(extract_ini_value(&text, &["UI_PORT", "PORT"]).map(|v| parse_valid_port(&v)).unwrap_or(0));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "flaresolverr" => {
            for raw in [
                "/etc/systemd/system/flaresolverr.service",
                "/opt/flaresolverr/.env",
                "/etc/default/flaresolverr",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text)
                        .max(extract_ini_value(&text, &["PORT"]).map(|v| parse_valid_port(&v)).unwrap_or(0));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "threadfin" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/threadfin.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                if let Ok(text) = fs::read_to_string(resolve_config_path("/var/lib/threadfin/conf/settings.json")) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val.get("port").or_else(|| val.get("Port")).and_then(|v| v.as_i64()) {
                            if port > 0 {
                                meta.configured_port = port as i32;
                            }
                        }
                    }
                }
            }
        }
        "flood" => {
            for raw in [
                "/etc/systemd/system/flood.service",
                "/etc/default/flood",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "nextcloud" | "rutorrent" => {
            let candidates = [
                format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
                format!("/etc/apache2/sites-available/{canonical}.conf"),
            ];
            for raw in candidates {
                let p = resolve_config_path(&raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "netdata" => {
            for raw in ["/etc/netdata/netdata.conf", "/etc/systemd/system/netdata.service"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["default port", "port"])
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "homeassistant" => {
            for raw in [
                "/home/homeassistant/.homeassistant/configuration.yaml",
                "/var/lib/homeassistant/configuration.yaml",
                "/etc/homeassistant/configuration.yaml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_yaml_section_value(&text, "http", "server_port")
                        .or_else(|| extract_ini_value(&text, &["server_port"]))
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "adguardhome" => {
            for raw in [
                "/opt/AdGuardHome/AdGuardHome.yaml",
                "/etc/AdGuardHome/AdGuardHome.yaml",
                "/var/lib/AdGuardHome/AdGuardHome.yaml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_yaml_section_value(&text, "http", "address")
                        .map(|v| parse_port_from_host_port(&v))
                        .filter(|&p| p > 0)
                        .or_else(|| {
                            extract_ini_value(&text, &["bind_port"])
                                .map(|v| parse_valid_port(&v))
                                .filter(|&p| p > 0)
                        })
                        .unwrap_or(0);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "rclone" => {
            for raw in [
                "/etc/systemd/system/rclone.service",
                "/etc/rclone/rclone.env",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text)
                        .max(extract_ini_value(&text, &["RCLONE_PORT", "PORT"]).map(|v| parse_valid_port(&v)).unwrap_or(0));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "autoscan" => {
            for raw in ["/etc/autoscan/config.yml", "/var/lib/autoscan/config.yml"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "librespeed" => {
            for raw in ["/opt/librespeed/settings.toml", "/etc/librespeed/settings.toml"] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["listen_port", "port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "scrutiny" => {
            for raw in [
                "/etc/scrutiny/scrutiny.yaml",
                "/opt/scrutiny/config/scrutiny.yaml",
                "/etc/systemd/system/scrutiny.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["port"])
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "n8n" => {
            for raw in [
                "/etc/systemd/system/n8n.service",
                "/var/lib/n8n/.env",
                "/etc/n8n/n8n.env",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text)
                        .max(extract_ini_value(&text, &["N8N_PORT", "PORT"]).map(|v| parse_valid_port(&v)).unwrap_or(0));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "palate" => {
            for raw in [
                "/etc/palate/palate.env",
                "/etc/systemd/system/af-palate.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["PORT", "PALATE_PORT"])
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "duplicati" => {
            for raw in [
                "/etc/duplicati/duplicati.env",
                "/etc/default/duplicati",
                "/etc/systemd/system/duplicati.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["DUPLICATI_PORT", "PORT"])
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "filebot" => {
            for raw in [
                "/var/lib/filebot/filebot-node.env",
                "/etc/default/filebot",
                "/etc/systemd/system/filebot.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["FILEBOT_NODE_HTTP_PORT", "PORT"])
                        .map(|v| parse_valid_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "novnc" => {
            if let Ok(text) = fs::read_to_string(resolve_config_path("/etc/systemd/system/novnc.service")) {
                let port = extract_port_from_systemd_or_apache_text(&text);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
        }
        "kasmvnc" => {
            for raw in [
                "/var/lib/kasmvnc/.vnc/kasmvnc.yaml",
                "/etc/kasmvnc/kasmvnc.yaml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["websocket_port", "port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        "mcvnc" => {
            for raw in [
                "/etc/mcvnc/mcvnc.env",
                "/etc/systemd/system/af-mcvnc.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["MCVNC_BIND", "MCVNC_PORT", "PORT"])
                        .map(|v| parse_port_from_host_port(&v))
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "pyload" => {
            for raw in [
                "/var/lib/pyload/settings/pyload.cfg",
                "/var/lib/pyload/.pyload/settings/pyload.cfg",
                "/etc/systemd/system/pyload.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_ini_value(&text, &["int port", "port"])
                        .map(|v| {
                            let rhs = v.rsplit('=').next().unwrap_or(&v).trim();
                            parse_valid_port(rhs)
                        })
                        .unwrap_or(0)
                        .max(extract_port_from_systemd_or_apache_text(&text));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "unmanic" => {
            for raw in [
                "/var/lib/unmanic/.unmanic/config/settings.json",
                "/etc/systemd/system/unmanic.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(port) = val.get("ui_port").or_else(|| val.get("port")).and_then(|v| v.as_i64()) {
                            if port > 0 {
                                meta.configured_port = port as i32;
                                break;
                            }
                        }
                    }
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "piped" => {
            for raw in [
                "/etc/piped/httpd.conf",
                "/etc/af-piped/httpd.conf",
                "/etc/systemd/system/af-piped.service",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    let port = extract_port_from_systemd_or_apache_text(&text);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }
        "invidious" => {
            for raw in [
                "/etc/invidious/config.yml",
                "/etc/af-invidious/config.yml",
                "/var/lib/invidious/config/config.yml",
            ] {
                let p = resolve_config_path(raw);
                if let Ok(text) = fs::read_to_string(&p) {
                    if let Some(v) = extract_ini_value(&text, &["port"]) {
                        let port = parse_valid_port(&v);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    if meta.configured_port <= 0 {
        let fallback_port = extract_fallback_unit_or_apache_port(&canonical);
        if fallback_port > 0 {
            meta.configured_port = fallback_port;
        }
    }

    let mut confirmed = !meta.api_key.is_empty() || meta.configured_port > 0;
    #[cfg(unix)]
    if meta.api_key.is_empty() && meta.configured_port <= 0 {
        if let Some(runner_meta) = query_runner_app_meta_unix(&canonical, deadline) {
            meta = runner_meta;
            confirmed = true;
        }
    }

    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if state.generation != generation {
        return AppRuntimeMeta::default();
    }
    let ttl = Duration::from_secs(if confirmed { 15 } else { 3 });
    state
        .cached
        .insert(canonical, (meta.clone(), Instant::now() + ttl));
    meta
}

// ─────────────────────────────────────────────────────────────────────────────
// Master Credentials & PBKDF2-HMAC-SHA512 Synchronizer (`master_credentials.go`)
// ─────────────────────────────────────────────────────────────────────────────

const MASTER_CREDS_SYSTEM_KEY: &str = "master_credentials";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MasterCreds {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ha1: String,
}

/// Pure-Rust RFC 1321 MD5 implementation (used for HTTP Digest HA1 = MD5(user:realm:pass)).
fn md5_hex(input: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in msg.as_chunks::<64>().0 {
        let mut words = [0u32; 16];
        for (word_idx, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            words[word_idx] = u32::from_le_bytes(*word);
        }
        let m = words;
        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    hex::encode(digest)
}

/// Pure-Rust RFC 2898 PBKDF2-HMAC-SHA512 (64-byte output) for qBittorrent `WebUI\Password_PBKDF2`.
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
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let dk = pbkdf2_hmac_sha512_block1(password.as_bytes(), &salt, 100_000);
    let salt_b64 = BASE64_STD.encode(salt);
    let dk_b64 = BASE64_STD.encode(dk);
    format!("\"@ByteArray({}:{})\"", salt_b64, dk_b64)
}

fn default_master_cred_paths() -> Vec<PathBuf> {
    vec![
        resolve_config_path("/var/lib/aetherflow/.master.creds"),
        resolve_config_path("/opt/AetherFlow/backend/data/.master.creds"),
        PathBuf::from("backend/data/.master.creds"),
    ]
}

fn master_cred_paths() -> Vec<PathBuf> {
    if let Ok(custom) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return vec![PathBuf::from(trimmed)];
        }
    }
    default_master_cred_paths()
}

fn finalized_ha1(creds: &MasterCreds) -> String {
    let expected = md5_hex(creds.password.as_bytes());
    if creds.ha1.is_empty() || creds.ha1 != expected {
        expected
    } else {
        creds.ha1.clone()
    }
}

/// Persists the master administrator username, password, and MD5(password) HA1
/// to the same JSON files Go SaveMasterCredentials and auth::save_master_credentials write.
pub fn save_master_credentials(username: &str, password: &str) -> Result<(), String> {
    let user_clean = username.trim();
    if user_clean.is_empty() || password.is_empty() {
        return Err("username and password are required".to_string());
    }
    let ha1 = md5_hex(password.as_bytes());
    let payload = serde_json::to_string(&MasterCreds {
        username: user_clean.to_string(),
        password: password.to_string(),
        ha1,
    })
    .map_err(|e| e.to_string())?;
    let mut raw = payload.into_bytes();
    raw.push(b'\n');

    let mut wrote = false;
    for path in master_cred_paths() {
        if path.as_os_str().is_empty() {
            continue;
        }
        if write_file_atomic_mode(&path, &raw, Some(0o600)).is_ok() {
            wrote = true;
        }
    }
    if let Ok(text) = std::str::from_utf8(&raw[..raw.len().saturating_sub(1)]) {
        if let Ok(encrypted) = af_db::encrypt_key(text) {
            if let Ok(conn) = af_db::get_conn() {
                let _ = conn.execute(
                    r#"INSERT INTO system_config (key, value, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP"#,
                    params![MASTER_CREDS_SYSTEM_KEY, encrypted],
                );
            }
        }
    }
    if !wrote {
        return Err("failed to persist master credentials file".to_string());
    }
    Ok(())
}

/// Loads `(username, password, ha1)` from the master credentials file, the installer
/// conf, or a previously encrypted `system_config` row.
pub fn load_master_credentials() -> (String, String, String) {
    for path in master_cred_paths() {
        if let Ok(data) = fs::read(&path) {
            if let Ok(creds) = serde_json::from_slice::<MasterCreds>(&data) {
                if !creds.username.is_empty() && !creds.password.is_empty() {
                    let ha1 = finalized_ha1(&creds);
                    return (creds.username, creds.password, ha1);
                }
            }
        }
    }
    if let Some(from_conf) = load_install_master_conf() {
        return from_conf;
    }
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(raw_val) = conn.query_row(
            "SELECT value FROM system_config WHERE key = ?1",
            params![MASTER_CREDS_SYSTEM_KEY],
            |r| r.get::<_, String>(0),
        ) {
            let decrypted = af_db::decrypt_key(&raw_val).unwrap_or(raw_val);
            if let Ok(creds) = serde_json::from_str::<MasterCreds>(&decrypted) {
                if !creds.username.is_empty() && !creds.password.is_empty() {
                    let ha1 = finalized_ha1(&creds);
                    return (creds.username, creds.password, ha1);
                }
            }
        }
    }
    (String::new(), String::new(), String::new())
}

fn load_install_master_conf() -> Option<(String, String, String)> {
    let text = fs::read_to_string(resolve_config_path("/install/.aetherflow.conf")).ok()?;
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
        let val = value.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
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
    if ha1.is_empty() {
        ha1 = md5_hex(password.as_bytes());
    }
    Some((username, password, ha1))
}

/// Propagates the master credentials to installed applications (qBittorrent PBKDF2, SABnzbd, Transmission).
pub fn sync_master_credentials_to_installed_apps(username: &str, password: &str) {
    if username.trim().is_empty() || password.is_empty() {
        return;
    }
    let qbit_hash = generate_qbittorrent_pbkdf2(password);
    let ha1_value = format!("@ByteArray({})", md5_hex(password.as_bytes()));
    for raw in [
        "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
        "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
    ] {
        let p = resolve_config_path(raw);
        if p.is_file() {
            let _ = mutate_ini_key(&p, "Preferences", r"WebUI\Username", username.trim());
            let _ = mutate_ini_key(&p, "Preferences", r"WebUI\Password_PBKDF2", &qbit_hash);
            let _ = mutate_ini_key(&p, "Preferences", r"WebUI\Password_ha1", &ha1_value);
        }
    }

    for raw in [
        "/var/lib/sabnzbd/sabnzbd.ini",
        "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
        "/etc/sabnzbd/sabnzbd.ini",
    ] {
        let p = resolve_config_path(raw);
        if p.is_file() {
            let _ = mutate_ini_key(&p, "misc", "username", username.trim());
            let _ = mutate_ini_key(&p, "misc", "password", password);
        }
    }

    for raw in [
        "/etc/transmission-daemon/settings.json",
        "/var/lib/transmission-daemon/info/settings.json",
    ] {
        let p = resolve_config_path(raw);
        if p.is_file() {
            let _ = mutate_json_key(&p, "rpc-username", json!(username.trim()));
            let _ = mutate_json_key(&p, "rpc-password", json!(password));
        }
    }

    #[cfg(unix)]
    if let Some(response) = request_runner_unix(
        "/v1/dispatcharr-credentials",
        json!({ "username": username.trim(), "password": password }),
        Duration::from_secs(25),
    ) {
        let success = serde_json::from_str::<Value>(&response)
            .ok()
            .and_then(|value| value.get("success").and_then(Value::as_bool));
        if success != Some(true) {
            tracing::warn!("Dispatcharr master credential sync failed");
        }
    }
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
        "dispatcharr" => NativeAppSpec {
            mutator_type: "ini",
            config_paths: vec!["/etc/dispatcharr/dispatcharr.env".to_string()],
            sqlite_db_path: None,
        },
        "gitea" => NativeAppSpec {
            mutator_type: "ini",
            config_paths: vec!["/etc/gitea/app.ini".to_string()],
            sqlite_db_path: None,
        },
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "listenarr" => {
            for candidate in [
                format!("/var/lib/{}/config.xml", canonical_app),
                format!("/var/lib/{}/config/config.xml", canonical_app),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
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
        "overseerr" | "jellyseerr" => {
            for candidate in [
                format!("/var/lib/{}/config/settings.json", canonical_app),
                format!("/var/lib/{}/settings.json", canonical_app),
            ] {
                if !paths.contains(&candidate) {
                    paths.push(candidate);
                }
            }
            NativeAppSpec {
                mutator_type: "json",
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

fn mutate_dispatcharr_port(file_path: &Path, port: i32) -> Result<bool, String> {
    let existing = fs::read_to_string(file_path).map_err(|error| error.to_string())?;
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
        pattern.replace_all(&existing, setting.as_str()).into_owned()
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

/// Applies an application's blueprint configuration:
/// 1. Looks up `crate::get_blueprint(app_name)`.
/// 2. If the app has a native config file (`config.xml`, `qBittorrent.conf`, `settings.json`, `network.xml`, etc.)
///    on disk, mutates its port/bind settings to match `listen_port` and injects master credentials where applicable.
/// 3. Synchronizes `<app_name>.aether.local` (and public domain) via `sync_local_dns_domains` and Apache2 vhosts.
/// 4. Returns a structured JSON summary of mutated files and synchronized DNS entries.
pub async fn apply_blueprint_app_config(app_name: &str, listen_port: i32) -> Result<Value, String> {
    with_blueprint_mutation(app_name, async {
        apply_blueprint_app_config_admitted(app_name, listen_port)
            .await
            .map_err(anyhow::Error::msg)
    })
    .await
    .map_err(|error| format!("{error:#}"))
}

async fn apply_blueprint_app_config_admitted(app_name: &str, listen_port: i32) -> Result<Value, String> {
    let canonical = normalize_app_key_name(app_name);
    let bp = crate::get_blueprint(&canonical)
        .or_else(|| crate::get_blueprint(app_name))
        .ok_or_else(|| format!("blueprint not found for {:?}", app_name))?;

    let effective_port = if listen_port > 0 {
        listen_port
    } else {
        bp.default_port
    };

    let app = bp.app_name.clone();
    let lifecycle_owned = !af_runner::current_package_job_id().is_empty();
    let existing_ingress = tokio::task::spawn_blocking(move || {
        if lifecycle_owned {
            // The enclosing blueprint admission has already verified the exact
            // package, active owner and install/update action. Materialize from
            // the same active-or-retained configuration as the durable callback.
            let connection = af_db::get_conn()?;
            af_db::load_lifecycle_ingress(&connection, &app)
        } else {
            af_db::get_app_ingress_config(&app)
        }
    })
    .await
    .map_err(|error| format!("cannot read blueprint ingress configuration: {error}"))?
    .map_err(|error| format!("cannot read blueprint ingress configuration: {error}"))?;

    let spec = native_app_spec(&canonical, &bp.config_file_path);
    let mut mutated_files: Vec<String> = Vec::new();
    let mut sqlite_routes_injected: usize = 0;
    let (master_user, master_pass, _master_ha1) = load_master_credentials();

    let handle_host_mutation = |res: Result<bool, String>| -> Result<bool, String> {
        match res {
            Ok(changed) => Ok(changed),
            Err(err) if is_unprivileged_host_write_error(&err) => {
                tracing::info!(
                    app = %canonical,
                    "skipping host config mutation in unprivileged API process (handled by privileged runner): {}",
                    err
                );
                Ok(false)
            }
            Err(err) => Err(err),
        }
    };

    for raw_path in &spec.config_paths {
        let resolved = resolve_config_path(raw_path);
        if !resolved.is_file() {
            continue;
        }

        let port_str = effective_port.to_string();
        match canonical.as_str() {
            "dispatcharr" => {
                if effective_port > 0
                    && handle_host_mutation(mutate_dispatcharr_port(&resolved, effective_port))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "gitea" => {
                if effective_port > 0
                    && handle_host_mutation(mutate_ini_key(&resolved, "server", "HTTP_PORT", &port_str))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "whisparr" | "listenarr" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "Port", &port_str))?;
                }
                let has_bind = read_xml_element(&resolved, "BindAddress")
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_bind {
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "BindAddress", "127.0.0.1"))?;
                }
                file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "AuthenticationMethod", "Forms"))?;
                file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "AnalyticsEnabled", "False"))?;
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "jellyfin" => {
                let mut file_changed = false;
                let existing_xml = fs::read_to_string(&resolved).unwrap_or_default();
                let has_remote_access = extract_xml_tag_text(&existing_xml, "EnableRemoteAccess")
                    .is_some_and(|v| !v.trim().is_empty());
                let has_known_proxies = Regex::new(r"(?is)<KnownProxies>\s*(.*?)\s*</KnownProxies>")
                    .ok()
                    .and_then(|re| re.captures(&existing_xml))
                    .and_then(|c| c.get(1))
                    .is_some_and(|m| !m.as_str().trim().is_empty());
                if effective_port > 0 {
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "InternalHttpPort", &port_str))?;
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "PublicHttpPort", &port_str))?;
                }
                file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "EnableIPV4", "true"))?;
                if !has_remote_access {
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "EnableRemoteAccess", "true"))?;
                }
                if !has_known_proxies {
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "KnownProxies", "127.0.0.1"))?;
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "emby" => {
                if effective_port > 0 {
                    let mut file_changed = false;
                    file_changed |=
                        handle_host_mutation(mutate_xml_element(&resolved, "HttpServerPortNumber", &port_str))?;
                    file_changed |= handle_host_mutation(mutate_xml_element(&resolved, "PublicPort", &port_str))?;
                    if file_changed {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
            }
            "qbittorrent" => {
                let mut file_changed = false;
                let existing_ini = fs::read_to_string(&resolved).unwrap_or_default();
                if effective_port > 0 {
                    file_changed |= handle_host_mutation(mutate_ini_key(
                        &resolved,
                        "Preferences",
                        r"WebUI\Port",
                        &port_str,
                    ))?;
                }
                let has_addr = extract_ini_value(&existing_ini, &[r"WebUI\Address"])
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_addr {
                    file_changed |= handle_host_mutation(mutate_ini_key(
                        &resolved,
                        "Preferences",
                        r"WebUI\Address",
                        "127.0.0.1",
                    ))?;
                }
                if !master_user.is_empty() && !master_pass.is_empty() {
                    let has_user = extract_ini_value(&existing_ini, &[r"WebUI\Username"])
                        .is_some_and(|v| !v.trim().is_empty());
                    let has_pass = extract_ini_value(
                        &existing_ini,
                        &[r"WebUI\Password_PBKDF2", r"WebUI\Password_ha1"],
                    )
                    .is_some_and(|v| !v.trim().is_empty());
                    if !has_user || !has_pass {
                        let qbit_hash = generate_qbittorrent_pbkdf2(&master_pass);
                        let ha1_value = format!("@ByteArray({})", md5_hex(master_pass.as_bytes()));
                        file_changed |= handle_host_mutation(mutate_ini_key(
                            &resolved,
                            "Preferences",
                            r"WebUI\Username",
                            &master_user,
                        ))?;
                        file_changed |= handle_host_mutation(mutate_ini_key(
                            &resolved,
                            "Preferences",
                            r"WebUI\Password_PBKDF2",
                            &qbit_hash,
                        ))?;
                        file_changed |= handle_host_mutation(mutate_ini_key(
                            &resolved,
                            "Preferences",
                            r"WebUI\Password_ha1",
                            &ha1_value,
                        ))?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "sabnzbd" => {
                let mut file_changed = false;
                let existing_ini = fs::read_to_string(&resolved).unwrap_or_default();
                if effective_port > 0 {
                    file_changed |= handle_host_mutation(mutate_ini_key(&resolved, "misc", "port", &port_str))?;
                }
                let has_host = extract_ini_value(&existing_ini, &["host"])
                    .is_some_and(|v| !v.trim().is_empty());
                if !has_host {
                    file_changed |= handle_host_mutation(mutate_ini_key(&resolved, "misc", "host", "127.0.0.1"))?;
                }
                let mut whitelist = "sabnzbd.aether.local, localhost, 127.0.0.1".to_string();
                let base_domain = crate::resolve_base_domain();
                if !base_domain.is_empty() {
                    let public_domain = crate::format_app_public_domain("sabnzbd", &base_domain);
                    if !public_domain.is_empty() {
                        whitelist = format!("{}, {}", public_domain, whitelist);
                    }
                }
                if let Some(ing) = existing_ingress.as_ref() {
                    if ing.external_access_enabled {
                        let custom = ing.public_domain.trim().to_ascii_lowercase();
                        if !custom.is_empty() && !whitelist.to_ascii_lowercase().contains(&custom) {
                            whitelist = format!("{}, {}", custom, whitelist);
                        }
                    }
                }
                file_changed |= handle_host_mutation(mutate_ini_key(
                    &resolved,
                    "misc",
                    "host_whitelist",
                    &whitelist,
                ))?;
                if !master_user.is_empty() && !master_pass.is_empty() {
                    let has_user = extract_ini_value(&existing_ini, &["username"])
                        .is_some_and(|v| !v.trim().is_empty());
                    let has_pass = extract_ini_value(&existing_ini, &["password"])
                        .is_some_and(|v| !v.trim().is_empty());
                    if !has_user || !has_pass {
                        file_changed |= handle_host_mutation(mutate_ini_key(&resolved, "misc", "username", &master_user))?;
                        file_changed |= handle_host_mutation(mutate_ini_key(&resolved, "misc", "password", &master_pass))?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "tautulli" => {
                if effective_port > 0
                    && handle_host_mutation(mutate_ini_key(&resolved, "General", "http_port", &port_str))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "transmission" => {
                let mut file_changed = false;
                if effective_port > 0 {
                    file_changed |=
                        handle_host_mutation(mutate_json_key(&resolved, "rpc-port", json!(effective_port)))?;
                }
                let existing_json: Value = fs::read_to_string(&resolved)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_else(|| json!({}));
                if existing_json.get("rpc-whitelist-enabled").is_none() {
                    file_changed |=
                        handle_host_mutation(mutate_json_key(&resolved, "rpc-whitelist-enabled", json!(false)))?;
                }
                if existing_json.get("rpc-host-whitelist-enabled").is_none() {
                    file_changed |=
                        handle_host_mutation(mutate_json_key(&resolved, "rpc-host-whitelist-enabled", json!(false)))?;
                }
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
                            handle_host_mutation(mutate_json_key(&resolved, "rpc-username", json!(master_user)))?;
                        file_changed |=
                            handle_host_mutation(mutate_json_key(&resolved, "rpc-password", json!(master_pass)))?;
                    }
                }
                if file_changed {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "overseerr" | "jellyseerr" => {
                if effective_port > 0
                    && handle_host_mutation(mutate_json_key(&resolved, "main.port", json!(effective_port)))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "jackett" => {
                if effective_port > 0
                    && handle_host_mutation(mutate_json_key(&resolved, "Port", json!(effective_port)))?
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            "pihole" => {
                if effective_port > 0 && handle_host_mutation(mutate_pihole_toml(&resolved, effective_port))? {
                    mutated_files.push(resolved.to_string_lossy().to_string());
                }
            }
            _ => match spec.mutator_type {
                "xml" if effective_port > 0 && !bp.port_config_key.is_empty() => {
                    if handle_host_mutation(mutate_xml_element(&resolved, &bp.port_config_key, &port_str))? {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
                "ini" if effective_port > 0 && !bp.port_config_key.is_empty() => {
                    if handle_host_mutation(mutate_ini_key(&resolved, "Preferences", &bp.port_config_key, &port_str))? {
                        mutated_files.push(resolved.to_string_lossy().to_string());
                    }
                }
                "json"
                    if effective_port > 0
                        && !bp.port_config_key.is_empty()
                        && handle_host_mutation(mutate_json_key(&resolved, &bp.port_config_key, json!(effective_port)))? =>
                {
                    mutated_files.push(resolved.to_string_lossy().to_string());
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
            let qbit_port = {
                let p = get_app_runtime_meta("qbittorrent").configured_port;
                if p > 0 {
                    p
                } else {
                    af_db::get_app_ingress_config("qbittorrent")
                        .ok()
                        .flatten()
                        .map(|c| c.listen_port)
                        .filter(|&p| p > 0)
                        .unwrap_or(8180)
                }
            };
            match inject_arr_download_client_routes(&db_path, &routes, qbit_port) {
                Ok(count) => {
                    sqlite_routes_injected = count;
                    if count > 0 {
                        mutated_files.push(db_path.to_string_lossy().to_string());
                    }
                }
                Err(err) if is_unprivileged_host_write_error(&err) => {
                    tracing::info!(
                        app = %canonical,
                        "skipping SQLite route injection in unprivileged API process: {}",
                        err
                    );
                }
                Err(err) => return Err(err),
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
    let mut public_domain = String::new();
    if effective_port > 0 {
        public_domain = existing_ingress
            .as_ref()
            .map(|config| config.public_domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| crate::format_app_public_domain(&bp.app_name, &base_domain));
        if !public_domain.is_empty() && !dns_domains.contains(&public_domain) {
            dns_domains.push(public_domain.clone());
        }
    }

    let external_access_enabled = existing_ingress
        .as_ref()
        .map(|c| c.external_access_enabled)
        .unwrap_or(false);
    sync_apache_app_vhost(
        &bp.app_name,
        effective_port,
        &internal_domain,
        &public_domain,
        external_access_enabled,
    )?;

    let dns_synced = match sync_local_dns_domains(&dns_domains).await {
        Ok(()) => true,
        Err(err) => {
            if is_unprivileged_host_write_error(&err) {
                tracing::info!(
                    app = %canonical,
                    "skipping local DNS hosts sync in unprivileged API process (handled by privileged runner): {}",
                    err
                );
                false
            } else {
                return Err(err);
            }
        }
    };
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

    #[test]
    fn test_write_file_atomic_rejects_symlink_parent_directory() {
        let dir = temp_test_dir("symlink_parent");
        let real_target_dir = dir.join("real_target");
        fs::create_dir_all(&real_target_dir).unwrap();
        let symlink_parent = dir.join("linked_parent");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real_target_dir, &symlink_parent).unwrap();
            let victim_file = symlink_parent.join("victim.conf");
            let err = write_file_atomic(&victim_file, b"pwned").unwrap_err();
            assert!(
                err.contains("symlink parent directory"),
                "expected symlink parent rejection, got: {}",
                err
            );
            assert!(!real_target_dir.join("victim.conf").exists());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_runner_app_meta_reads_response_payload() {
        let data = json!({"api_key": "runner-secret", "configured_port": 18989});
        for envelope in [
            json!({"id": "audit", "ok": true, "status": 200, "data": data.clone()}),
            json!({"success": true, "data": data.clone()}),
            json!({"success": true, "output": data.to_string()}),
        ] {
            let meta = parse_runner_app_meta(&envelope.to_string()).unwrap();
            assert_eq!(meta.api_key, "runner-secret");
            assert_eq!(meta.configured_port, 18989);
        }
    }

    #[test]
    fn test_runner_app_meta_rejects_failed_or_missing_payloads() {
        for envelope in [
            json!({"ok": false, "data": {"api_key": "not-trusted"}}),
            json!({"success": false, "output": "{}"}),
            json!({"ok": true}),
            json!({"ok": true, "data": null}),
            json!({"api_key": "not-an-envelope", "configured_port": 1234}),
        ] {
            assert!(parse_runner_app_meta(&envelope.to_string()).is_none());
        }
    }

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
    fn test_dispatcharr_blueprint_env_port_preserves_secrets_and_permissions() {
        let dir = temp_test_dir("dispatcharr");
        let path = dir.join("dispatcharr.env");
        let spec = native_app_spec("dispatcharr", "/stale/config");
        assert_eq!(spec.config_paths, vec!["/etc/dispatcharr/dispatcharr.env"]);
        for original in ["POSTGRES_PASSWORD=keep\nDISPATCHARR_PORT=9191\n", "POSTGRES_PASSWORD=keep", ""] {
            fs::write(&path, original).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            }
            assert!(mutate_dispatcharr_port(&path, 19200).unwrap());
            let text = fs::read_to_string(&path).unwrap();
            assert_eq!(extract_ini_value(&text, &["DISPATCHARR_PORT"]).as_deref(), Some("19200"));
            assert!(!text.contains("[Preferences]"));
            if original.contains("POSTGRES_PASSWORD") {
                assert!(text.contains("POSTGRES_PASSWORD=keep"));
            }
            assert!(!mutate_dispatcharr_port(&path, 19200).unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
            }
        }
        fs::remove_dir_all(dir).unwrap();
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

    #[test]
    fn test_md5_and_qbittorrent_pbkdf2() {
        // RFC 1321 test vectors
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");

        let hash_str = generate_qbittorrent_pbkdf2("correcthorsebatterystaple");
        assert!(hash_str.starts_with("\"@ByteArray("));
        assert!(hash_str.ends_with(")\""));
        let inner = &hash_str[12..hash_str.len() - 2];
        let (salt_b64, dk_b64) = inner.split_once(':').unwrap();
        let salt = BASE64_STD.decode(salt_b64).unwrap();
        let dk = BASE64_STD.decode(dk_b64).unwrap();
        assert_eq!(salt.len(), 16);
        assert_eq!(dk.len(), 64);
    }

    static TEST_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    #[tokio::test]
    async fn test_afmp004_service_jellyfin_blueprint_preserves_operator_remote_access_and_known_proxies(
    ) {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let dir = temp_test_dir("afmp004-jellyfin-service");
        for subdir in ["etc/jellyfin", "etc/apache2/sites-available", "var/lib/aetherflow"] {
            fs::create_dir_all(dir.join(subdir)).unwrap();
        }
        let net_xml = dir.join("etc/jellyfin/network.xml");
        let retained_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <InternalHttpPort>8096</InternalHttpPort>
  <PublicHttpPort>8096</PublicHttpPort>
  <EnableIPV4>true</EnableIPV4>
  <EnableRemoteAccess>false</EnableRemoteAccess>
  <KnownProxies><string>10.20.30.40</string></KnownProxies>
</NetworkConfiguration>
"#;
        fs::write(&net_xml, retained_xml).unwrap();
        fs::write(dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();
        let db_path = dir.join("var/lib/aetherflow/aetherflow.sqlite");

        let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        let prev_af_db = std::env::var_os("AF_DB_PATH");
        let prev_db = std::env::var_os("DB_PATH");
        let prev_aether_db = std::env::var_os("AETHERFLOW_DB_PATH");
        let prev_hosts = std::env::var_os("AETHERFLOW_HOSTS_FILE");
        let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");

        std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);
        std::env::set_var("AF_DB_PATH", &db_path);
        std::env::set_var("DB_PATH", &db_path);
        std::env::set_var("AETHERFLOW_DB_PATH", &db_path);
        std::env::set_var("AETHERFLOW_HOSTS_FILE", dir.join("hosts"));
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", dir.join("absent.sock"));

        af_db::init_db().unwrap();
        let res = apply_blueprint_app_config_admitted("jellyfin", 18096).await;

        for (key, prev) in [
            ("AETHERFLOW_FS_ROOT", prev_fs_root),
            ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
            ("AF_DB_PATH", prev_af_db),
            ("DB_PATH", prev_db),
            ("AETHERFLOW_DB_PATH", prev_aether_db),
            ("AETHERFLOW_HOSTS_FILE", prev_hosts),
            ("AETHERFLOW_RUNNER_SOCK", prev_sock),
        ] {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        res.unwrap();
        let updated = fs::read_to_string(&net_xml).unwrap();
        assert!(updated.contains("<InternalHttpPort>18096</InternalHttpPort>"));
        assert!(updated.contains("<PublicHttpPort>18096</PublicHttpPort>"));
        assert!(
            updated.contains("<EnableRemoteAccess>false</EnableRemoteAccess>"),
            "must preserve explicit EnableRemoteAccess=false, got:\n{updated}"
        );
        assert!(
            updated.contains("<KnownProxies><string>10.20.30.40</string></KnownProxies>"),
            "must preserve custom KnownProxies, got:\n{updated}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_afmp_sol_001_service_vhost_sync_preserves_apache_access_policy() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let dir = temp_test_dir("afmp-sol-001-service-apache");
        let sites_avail = dir.join("etc/apache2/sites-available");
        let sites_en = dir.join("etc/apache2/sites-enabled");
        fs::create_dir_all(&sites_avail).unwrap();
        fs::create_dir_all(&sites_en).unwrap();
        fs::create_dir_all(dir.join("var/lib/aetherflow")).unwrap();
        fs::write(dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();

        let int_conf = sites_avail.join("aetherflow-app-qui.conf");
        let ext_conf = sites_avail.join("aetherflow-ext-qui.conf");
        let en_ext_conf = sites_en.join("aetherflow-ext-qui.conf");

        let existing_int = "\
# Managed by AetherFlow v3.2.6
<VirtualHost *:80>
    ServerName qui.aether.local
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    RequestHeader set X-Forwarded-Proto \"http\"
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
        let existing_ext = "\
# Managed by AetherFlow v3.2.6 (External Ingress)
<VirtualHost *:80>
    ServerName qui.example.com
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
        fs::write(&int_conf, existing_int).unwrap();
        fs::write(&ext_conf, existing_ext).unwrap();
        fs::write(&en_ext_conf, existing_ext).unwrap();

        let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);

        let sync_res = sync_apache_app_vhost("qui", 18376, "qui.aether.local", "qui.example.com", true);

        for (key, prev) in [
            ("AETHERFLOW_FS_ROOT", prev_fs_root),
            ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
        ] {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        assert!(sync_res.unwrap());
        for path in [&int_conf, &ext_conf, &en_ext_conf] {
            let updated = fs::read_to_string(path).unwrap();
            assert!(
                updated.contains("ws://127.0.0.1:18376/$1"),
                "must update websocket RewriteRule port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("ProxyPass / http://127.0.0.1:18376/"),
                "must update ProxyPass port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("ProxyPassReverse / http://127.0.0.1:18376/"),
                "must update ProxyPassReverse port to 18376 in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("<Location /qui>"),
                "must preserve <Location /qui> block in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("AuthType Basic"),
                "must preserve AuthType Basic in {}: {updated}",
                path.display()
            );
            assert!(
                updated.contains("Require ip 192.0.2.0/24"),
                "must preserve Require ip 192.0.2.0/24 in {}: {updated}",
                path.display()
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_sync_local_dns_domains_preserves_multiple_apps() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-dns-sync-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());

        // Install App A -> syncs appa.aether.local
        sync_local_dns_domains(&["appa.aether.local".to_string()]).await.unwrap();
        let content_after_a = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_a.contains("appa.aether.local"));

        // Install App B -> syncs appb.aether.local without wiping appa
        sync_local_dns_domains(&["appb.aether.local".to_string()]).await.unwrap();
        let content_after_b = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_b.contains("appa.aether.local"), "App A must be preserved when installing App B: {content_after_b}");
        assert!(content_after_b.contains("appb.aether.local"), "App B must be present: {content_after_b}");

        env::remove_var("AF_HOSTS_FILE");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_reconcile_local_dns_domains_non_root_invokes_runner_and_propagates_error() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_HOSTS_FILE");

        let dummy_sock = env::temp_dir().join(format!("nonexistent-runner-{}.sock", uuid::Uuid::new_v4()));
        env::set_var("AETHERFLOW_RUNNER_SOCK", dummy_sock.to_string_lossy().as_ref());

        #[cfg(unix)]
        {
            extern "C" {
                fn geteuid() -> u32;
            }
            if unsafe { geteuid() != 0 } {
                let err = reconcile_local_dns_domains(&["testapp.aether.local".to_string()])
                    .await
                    .unwrap_err();
                assert!(
                    err.contains("runner hosts reconcile error") || err.contains("privileged runner hosts reconcile failed"),
                    "Expected runner error, got: {err}"
                );
            }
        }

        env::remove_var("AETHERFLOW_RUNNER_SOCK");
    }

    #[tokio::test]
    async fn test_reconcile_and_sync_dns_separates_hosts_loopback_and_provider_lan_ip() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-mutators-dns-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();

        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_DNSMASQ_DIR", dnsmasq_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_LAN_IP", "192.168.1.150");

        let domains = vec![
            "sonarr.aether.local".to_string(),
            "media.example.com".to_string(),
        ];

        // Run reconcile
        reconcile_local_dns_domains(&domains).await.unwrap();

        // 1. /etc/hosts must contain 127.0.0.1 and sonarr.aether.local, but NOT media.example.com or 192.168.1.150
        let hosts_content = fs::read_to_string(&hosts_file).unwrap();
        assert!(hosts_content.contains("127.0.0.1\tsonarr.aether.local"));
        assert!(!hosts_content.contains("media.example.com"));
        assert!(!hosts_content.contains("192.168.1.150"));

        // 2. dnsmasq must contain LAN IP 192.168.1.150 and both domains, but not 127.0.0.1
        let dnsmasq_conf = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
        assert!(dnsmasq_conf.contains("address=/sonarr.aether.local/192.168.1.150"));
        assert!(dnsmasq_conf.contains("address=/media.example.com/192.168.1.150"));
        assert!(!dnsmasq_conf.contains("127.0.0.1"));

        // 3. Pi-hole custom.list must contain LAN IP 192.168.1.150 and both domains
        let pihole_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(pihole_list.contains("192.168.1.150 sonarr.aether.local # aetherflow-managed"));
        assert!(pihole_list.contains("192.168.1.150 media.example.com # aetherflow-managed"));
        assert!(!pihole_list.contains("127.0.0.1"));

        // Test remove_dns_provider_domain
        remove_dns_provider_domain("sonarr.aether.local").unwrap();
        let pihole_after_rm = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(!pihole_after_rm.contains("sonarr.aether.local"));
        assert!(pihole_after_rm.contains("media.example.com"));

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        env::remove_var("AETHERFLOW_LAN_IP");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_untrimmed_or_invalid_lan_ip_fails_closed_without_modifications() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-mutators-invalid-lan-ip-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();

        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();
        let initial_custom_list = "192.168.1.10 existing.local # aetherflow-managed\n";
        fs::write(pihole_dir.join("custom.list"), initial_custom_list).unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_DNSMASQ_DIR", dnsmasq_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());

        let invalid_ips = [
            " 192.168.1.50 ",
            "192.168.1.50\nmalicious",
            "192.168.1.50\r\nmalicious",
            "192.168.1.50 ",
            " 192.168.1.50",
            "invalid-ip",
            "",
        ];

        let test_domains = vec!["app.aether.local".to_string()];

        for bad_ip in invalid_ips {
            env::set_var("AETHERFLOW_LAN_IP", bad_ip);

            assert!(detect_lan_ip_strict().is_err(), "detect_lan_ip_strict must fail for {bad_ip:?}");

            let sync_res = sync_local_dns_domains(&test_domains).await;
            assert!(sync_res.is_err(), "sync_local_dns_domains must fail closed for {bad_ip:?}");

            let rec_res = reconcile_local_dns_domains(&test_domains).await;
            assert!(rec_res.is_err(), "reconcile_local_dns_domains must fail closed for {bad_ip:?}");

            // Verify files were not modified
            let hosts_cur = fs::read_to_string(&hosts_file).unwrap();
            assert_eq!(hosts_cur, "127.0.0.1 localhost\n", "hosts file must remain untouched for {bad_ip:?}");

            assert!(!dnsmasq_dir.join("aetherflow.conf").exists(), "dnsmasq must not be created");
            assert!(!dnsmasq_dir.join("aetherflow-local.conf").exists(), "dnsmasq must not be created");

            let pihole_cur = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
            assert_eq!(pihole_cur, initial_custom_list, "custom.list must remain untouched for {bad_ip:?}");
        }

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        env::remove_var("AETHERFLOW_LAN_IP");
        let _ = fs::remove_dir_all(&scratch_dir);
    }
}
