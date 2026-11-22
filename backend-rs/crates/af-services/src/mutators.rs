use af_models::AppIngressConfig;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64_STD;
#[cfg(test)]
use base64::Engine as _;
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

static SAFE_SQL_IDENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$").unwrap());
pub use af_runner::blueprint::{
    backup_config_file, derive_app_webui_password, extract_ini_value, extract_xml_tag_text,
    generate_qbittorrent_pbkdf2, inject_arr_download_client_routes, load_master_credentials,
    mutate_ini_key, mutate_json_key, mutate_xml_element, read_xml_element, write_file_atomic,
    write_file_atomic_mode, MasterCreds,
};
use af_runner::blueprint::{master_cred_paths, master_ha1, read_metadata_config};
#[cfg(test)]
use af_runner::blueprint::{
    mutate_dispatcharr_port, mutate_pihole_toml, mutate_systemd_aspnetcore_urls,
    mutate_yaml_section_key, native_app_spec,
};

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
    is_host_permission_error(err)
}

fn is_host_permission_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("read-only file system")
        || lower.contains("readonly file system")
        || lower.contains("os error 13")
        || lower.contains("os error 1")
        || lower.contains("os error 30")
}

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
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("1.1.1.1:80").is_ok() {
            if let Ok(std::net::SocketAddr::V4(addr)) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Ok(ip.to_string());
                }
            }
        }
    }
    Ok("127.0.0.1".to_string())
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

    let existing = match af_runner::read_dns_provider_text(custom_list_path, true) {
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

    let content =
        af_runner::reconcile_pihole_custom_list_content(&existing, lan_ip, domains, false);
    if content == existing && custom_list_path.exists() {
        return Ok(());
    }
    af_runner::write_dns_provider_text(custom_list_path, &content, true)
        .map_err(|error| error.to_string())
}

pub fn update_dnsmasq_conf(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for dnsmasq config: {e}"))?;

    let existing = match af_runner::read_dns_provider_text(dnsmasq_conf_path, false) {
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
    af_runner::write_dns_provider_text(dnsmasq_conf_path, &content, false)
        .map_err(|error| error.to_string())
}

pub fn update_dnsmasq_config(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    update_dnsmasq_conf(dnsmasq_conf_path, lan_ip, domains)
}

pub fn update_pihole_toml_hosts(
    toml_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for Pi-hole pihole.toml: {e}"))?;
    if !toml_path.is_file() {
        return Ok(());
    }
    let existing = af_runner::read_dns_provider_text(toml_path, true)
        .map_err(|e| format!("failed to read {}: {}", toml_path.display(), e))?;

    let normalized_domains: BTreeSet<String> = domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    let lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
    let mut current_section = String::new();
    let mut dns_start: Option<usize> = None;
    let mut dns_end: usize = lines.len();
    let mut hosts_range: Option<(usize, usize)> = None;
    let mut in_multiline_hosts = false;
    let mut multiline_start = 0usize;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if in_multiline_hosts {
            if trimmed.contains(']') {
                hosts_range = Some((multiline_start, idx + 1));
                in_multiline_hosts = false;
            }
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if let Some(end) = trimmed.find(']') {
                let sec = trimmed[1..end].trim().to_string();
                if current_section == "dns" && dns_end == lines.len() {
                    dns_end = idx;
                }
                current_section = sec.clone();
                if sec == "dns" && dns_start.is_none() {
                    dns_start = Some(idx);
                }
                continue;
            }
        }
        if current_section == "dns" {
            if let Some(rest) = trimmed.strip_prefix("hosts") {
                let after = rest.trim_start();
                if after.starts_with('=') {
                    if after.contains('[') && after.contains(']') {
                        hosts_range = Some((idx, idx + 1));
                    } else if after.contains('[') {
                        multiline_start = idx;
                        in_multiline_hosts = true;
                    }
                }
            }
        }
    }

    let mut preserved_entries: Vec<String> = Vec::new();
    if let Some((start, end)) = hosts_range {
        let block = lines[start..end].join("\n");
        if let (Some(open), Some(close)) = (block.find('['), block.rfind(']')) {
            let inner = &block[open + 1..close];
            let re_entry = Regex::new(r#""([^"]*)""#).unwrap();
            for cap in re_entry.captures_iter(inner) {
                let entry = cap[1].trim();
                let mut parts = entry.split_whitespace();
                let _ip_part = parts.next();
                let dom_part = parts.next().map(|d| d.to_lowercase());
                if let Some(dom) = dom_part {
                    if !normalized_domains.contains(&dom) && !dom.ends_with(".aether.local") {
                        preserved_entries.push(entry.to_string());
                    }
                }
            }
        }
    }

    for dom in &normalized_domains {
        preserved_entries.push(format!("{lan_ip} {dom}"));
    }

    let rendered_hosts = if preserved_entries.is_empty() {
        "  hosts = []".to_string()
    } else {
        let items: Vec<String> = preserved_entries
            .iter()
            .map(|e| format!("    \"{}\"", e.replace('\"', "\\\"")))
            .collect();
        format!("  hosts = [\n{}\n  ]", items.join(",\n"))
    };

    let mut out_lines = lines.clone();
    if let Some((start, end)) = hosts_range {
        out_lines.splice(start..end, std::iter::once(rendered_hosts));
    } else if dns_start.is_some() {
        out_lines.insert(dns_end, rendered_hosts);
    } else {
        out_lines.push(String::new());
        out_lines.push("[dns]".to_string());
        out_lines.push(rendered_hosts);
    }

    let mut content = out_lines.join("\n");
    if existing.ends_with('\n') || !content.is_empty() {
        content.push('\n');
    }
    if content == existing {
        return Ok(());
    }
    af_runner::write_dns_provider_text(toml_path, &content, true).map_err(|error| error.to_string())
}

/// Synchronizes internal `.aether.local` (and configured public) domains into:
/// 1. `/etc/hosts` (via `af_runner::update_hosts_file_local` or atomic local fallback),
/// 2. `/etc/dnsmasq.d/05-aetherflow-dns.conf` if `/etc/dnsmasq.d` exists (cleaning up legacy duplicates),
/// 3. `/etc/pihole/custom.list` and `/etc/pihole/pihole.toml` (when present) if `/etc/pihole` exists.
pub async fn sync_local_dns_domains(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() {
        return Ok(());
    }

    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip).map_err(|e| format!("Invalid LAN IP: {e}"))?;

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
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            // 1. Update /etc/hosts for .aether.local domains locally
            if !aether_local_domains.is_empty() {
                af_runner::update_hosts_file(&aether_local_domains, "127.0.0.1")
                    .map_err(|e| format!("Local DNS synchronization failed: {e}"))?;
            }

            // 2. Consolidate onto canonical /etc/dnsmasq.d/05-aetherflow-dns.conf if directory exists
            let dnsmasq_dir = env::var("AETHERFLOW_DNSMASQ_DIR")
                .ok()
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| resolve_config_path("/etc/dnsmasq.d"));

            if af_runner::dns_provider_directory_exists(&dnsmasq_dir, false)
                .map_err(|error| error.to_string())?
            {
                let custom_dns_path = dnsmasq_dir.join("05-aetherflow-dns.conf");
                let mut consolidated_domains = validated.clone();
                for legacy_name in ["aetherflow-local.conf", "aetherflow-local-dns.conf"] {
                    let legacy_path = dnsmasq_dir.join(legacy_name);
                    if let Ok(legacy_raw) = af_runner::read_dns_provider_text(&legacy_path, false) {
                        for line in legacy_raw.lines() {
                            if let Some(rest) = line.trim().strip_prefix("address=/") {
                                if let Some((dom, _ip)) = rest.split_once('/') {
                                    let clean = dom.trim().to_lowercase();
                                    if !clean.is_empty() && !consolidated_domains.contains(&clean) {
                                        consolidated_domains.push(clean);
                                    }
                                }
                            }
                        }
                    }
                }
                update_dnsmasq_conf(&custom_dns_path, &lan_ip, &consolidated_domains)?;
                for legacy_name in ["aetherflow-local.conf", "aetherflow-local-dns.conf"] {
                    let legacy_path = dnsmasq_dir.join(legacy_name);
                    af_runner::remove_dns_provider_file(&legacy_path).map_err(|error| {
                        format!("cannot remove legacy dnsmasq configuration: {error}")
                    })?;
                }
            }

            // 3. Write Pi-hole custom.list and pihole.toml (v6) if /etc/pihole exists
            let pihole_dir = env::var("AETHERFLOW_PIHOLE_DIR")
                .ok()
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| resolve_config_path("/etc/pihole"));

            if af_runner::dns_provider_directory_exists(&pihole_dir, true)
                .map_err(|error| error.to_string())?
            {
                let custom_list = pihole_dir.join("custom.list");
                update_pihole_custom_list(&custom_list, &lan_ip, &validated)?;
                let pihole_toml = pihole_dir.join("pihole.toml");
                if pihole_toml.is_file() {
                    update_pihole_toml_hosts(&pihole_toml, &lan_ip, &validated)?;
                }
            }
            af_runner::sync_adguard_dns(&lan_ip, &validated, false)
                .map_err(|err| format!("AdGuard Home synchronization failed: {err}"))
        })
        .await
        .map_err(|err| err.to_string())??;
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
    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip).map_err(|e| format!("Invalid LAN IP: {e}"))?;

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
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            af_runner::reconcile_hosts_file(&aether_local_domains, "127.0.0.1")
                .map_err(|e| format!("Local DNS reconciliation failed: {e}"))?;
            af_runner::sync_dns_provider_files(&lan_ip, &validated_authoritative)
                .map_err(|e| format!("Local DNS provider synchronization failed: {e}"))
        })
        .await
        .map_err(|err| err.to_string())??;
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
        _ => af_runner::dispatch_hosts_update_with_provider(domains, provider_ip, provider_domains)
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
    let mut configured_public_apps: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    {
        for cfg in configs {
            let app_key = cfg.app_name.trim().to_ascii_lowercase();
            if !app_key.is_empty() {
                domain_set.insert(crate::resolve_app_internal_domain(&cfg.app_name));
            }
            if !cfg.public_domain.trim().is_empty() {
                if !app_key.is_empty() {
                    configured_public_apps.insert(app_key);
                }
                domain_set.insert(cfg.public_domain.trim().to_lowercase());
            } else if !base_domain.is_empty() && cfg.listen_port > 0 {
                let pub_dom = crate::format_app_public_domain(&cfg.app_name, &base_domain);
                if !pub_dom.is_empty() {
                    if !app_key.is_empty() {
                        configured_public_apps.insert(app_key);
                    }
                    domain_set.insert(pub_dom);
                }
            }
        }
    }

    let retained_apps: std::collections::HashSet<String> = af_db::list_retained_app_ingress_names()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|app| app.trim().to_ascii_lowercase())
        .collect();

    let pkgs = crate::get_packages().map_err(|error| error.to_string())?;
    {
        for p in pkgs {
            if p.status != "installed" {
                continue;
            }
            let app_key = p.name.trim().to_ascii_lowercase();
            if let Some(bp) = crate::get_blueprint(&p.name) {
                if !bp.internal_domain.trim().is_empty() {
                    domain_set.insert(bp.internal_domain.trim().to_lowercase());
                } else {
                    domain_set.insert(format!("{}.aether.local", p.name.to_lowercase()));
                }
                if !base_domain.is_empty()
                    && bp.default_port > 0
                    && !configured_public_apps.contains(&app_key)
                    && !retained_apps.contains(&app_key)
                {
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

/// Synchronous compatibility entry point for callers outside an async runtime.
pub fn sync_apache_app_vhost(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
) -> Result<bool, String> {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                runtime.block_on(sync_apache_app_vhost_async(
                    app_name,
                    listen_port,
                    internal_domain,
                    public_domain,
                    external_access,
                ))
            });
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| err.to_string())?
                    .block_on(sync_apache_app_vhost_async(
                        app_name,
                        listen_port,
                        internal_domain,
                        public_domain,
                        external_access,
                    ))
            })
            .join()
            .map_err(|_| "Apache vhost worker panicked".to_string())?
    })
}

pub async fn sync_apache_app_vhost_async(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
) -> Result<bool, String> {
    let app = app_name.to_owned();
    let ingress = tokio::task::spawn_blocking(move || af_db::get_app_ingress_config(&app))
        .await
        .map_err(|err| err.to_string())?;
    let tls_enabled = match ingress {
        Ok(ingress) => ingress.is_some_and(|ingress| ingress.tls_enabled),
        Err(_) if af_runner::blueprint::has_config_root() => false,
        Err(error) => return Err(error.to_string()),
    };
    if listen_port <= 0 {
        return Ok(false);
    }
    sync_apache_app_vhost_with_tls(
        app_name,
        listen_port,
        internal_domain,
        public_domain,
        external_access,
        tls_enabled,
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(true)
}

async fn sync_apache_app_vhost_with_tls(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
    tls_enabled: bool,
) -> anyhow::Result<()> {
    if listen_port <= 0 {
        return Ok(());
    }
    let apache_dir = resolve_config_path("/etc/apache2");
    let req = af_models::RunnerApacheVhostRequest {
        app_name: app_name.to_string(),
        listen_port,
        internal_domain: (!internal_domain.is_empty()).then(|| internal_domain.to_string()),
        public_domain: (!public_domain.is_empty()).then(|| public_domain.to_string()),
        external_access_enabled: external_access,
        tls_enabled,
        reload_apache: true,
        ..Default::default()
    };

    if apache_dir == Path::new("/etc/apache2")
        && (unsafe { libc::geteuid() } != 0 || af_runner::is_runner_available())
    {
        af_runner::sync_apache_vhost_via_runner(&req).await?;
    } else {
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(af_runner::sync_apache_vhost_local(&req, &apache_dir))
        })
        .await??;
    }
    Ok(())
}

/// Triggers certificate synchronization via the privileged runner `/v1/certbot-sync`,
/// falling back to `/usr/local/bin/af-certbot-sync` only when running directly as root.
pub async fn trigger_apache_cert_sync() {
    if af_runner::is_runner_available() {
        if let Err(err) = af_runner::trigger_certbot_sync_via_runner().await {
            tracing::warn!(error = %err, "runner certbot-sync failed");
        }
    } else if unsafe { libc::geteuid() } == 0 {
        if let Err(err) = af_runner::sync_certbot_and_managed_ingress().await {
            tracing::warn!(error = %err, "direct certbot-sync failed");
        }
    }
}

/// Reconciles installed app routes at startup using saved ingress settings.
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
    for package in pkgs
        .iter()
        .filter(|p| p.status == "installed" && p.default_port > 0)
    {
        let existing = existing_map.get(&package.name);
        let cfg = startup_app_ingress_config(package, &norm_base, existing);
        sync_apache_app_vhost_with_tls(
            &cfg.app_name,
            cfg.listen_port,
            &crate::resolve_app_internal_domain(&cfg.app_name),
            &cfg.public_domain,
            cfg.external_access_enabled,
            cfg.tls_enabled,
        )
        .await
        .map_err(|err| err.to_string())?;
        if existing != Some(&cfg) {
            af_db::set_app_ingress_config(&cfg).map_err(|error| error.to_string())?;
        }
        updated_count += 1;
    }

    sync_network_dns_providers().await?;
    trigger_apache_cert_sync().await;
    Ok(updated_count)
}

fn startup_app_ingress_config(
    package: &af_models::Package,
    base_domain: &str,
    existing: Option<&AppIngressConfig>,
) -> AppIngressConfig {
    let mut config = existing.cloned().unwrap_or_else(|| AppIngressConfig {
        app_name: package.name.clone(),
        ..Default::default()
    });
    if config.public_domain.trim().is_empty() && !base_domain.is_empty() {
        config.public_domain = crate::format_app_public_domain(&package.name, base_domain);
    }
    if config.listen_port <= 0 {
        config.listen_port = package.default_port;
    }
    config
}

// ─────────────────────────────────────────────────────────────────────────────
// App Credential & Runtime Metadata Discovery
// ─────────────────────────────────────────────────────────────────────────────

pub use af_models::AppRuntimeMeta;

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

pub(crate) fn qbittorrent_web_bind_address() -> Option<String> {
    for config in [
        "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
        "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
        "/var/lib/qbittorrent/qBittorrent.conf",
    ] {
        if let Ok(text) = read_metadata_config(resolve_config_path(config)) {
            if let Some(address) = extract_ini_value(&text, &[r"WebUI\Address"]) {
                return Some(address);
            }
        }
    }
    None
}

pub use af_models::app_metadata::normalize_app_slug as normalize_app_key_name;

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

    if ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"]
        .iter()
        .any(|key| {
            env::var(key)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
        })
    {
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
    let mut meta: AppRuntimeMeta = if let Some(data) = response.get("data") {
        serde_json::from_value(data.clone()).ok()?
    } else {
        serde_json::from_str(response.get("output")?.as_str()?).ok()?
    };
    meta.url_base =
        af_models::app_metadata::validate_app_web_path(&meta.url_base).unwrap_or_default();
    Some(meta)
}

/// Discovers runtime API key, configured port, and validated native URL base from an
/// application's native config files.
pub fn get_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    get_app_runtime_meta_until(app_name, Instant::now() + APP_META_BUDGET)
}

pub(super) fn collect_native_url_base_meta(
    app_names: &[String],
) -> HashMap<String, AppRuntimeMeta> {
    let mut targets: Vec<String> = app_names
        .iter()
        .map(|name| normalize_app_key_name(name))
        .filter(|name| af_models::app_metadata::supports_native_url_base(name))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return HashMap::new();
    }
    let deadline = Instant::now() + APP_META_BUDGET;
    if targets.len() == 1 {
        let app = targets.remove(0);
        let meta = get_app_runtime_meta_until(&app, deadline);
        return HashMap::from([(app, meta)]);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = Mutex::new(HashMap::with_capacity(targets.len()));
    let workers = MAX_APP_META_PROBES.min(targets.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(app) = targets.get(idx) else {
                    break;
                };
                if Instant::now() >= deadline {
                    break;
                }
                let meta = get_app_runtime_meta_until(app, deadline);
                results
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(app.clone(), meta);
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(|error| error.into_inner())
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

    let mut meta = af_runner::extract_app_runtime_meta_local_until(&canonical, deadline);

    let mut confirmed =
        !meta.api_key.is_empty() || meta.configured_port > 0 || !meta.url_base.is_empty();
    #[cfg(unix)]
    if meta.configured_port <= 0 {
        if let Some(runner_meta) = query_runner_app_meta_unix(&canonical, deadline) {
            if meta.api_key.is_empty() {
                meta.api_key = runner_meta.api_key;
            }
            if meta.url_base.is_empty() {
                meta.url_base = runner_meta.url_base;
            }
            meta.configured_port = runner_meta.configured_port;
            if meta.secondary_port <= 0 {
                meta.secondary_port = runner_meta.secondary_port;
            }
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
// Master Credentials & PBKDF2-HMAC-SHA512 Synchronizer
// ─────────────────────────────────────────────────────────────────────────────

use af_runner::blueprint::MASTER_CREDS_SYSTEM_KEY;

fn legacy_duplicate_master_cred_paths() -> Vec<PathBuf> {
    vec![
        resolve_config_path("/opt/AetherFlow/backend/data/.master.creds"),
        PathBuf::from("backend/data/.master.creds"),
    ]
}

/// Persists package-provisioning credentials (`username`, AES-256-GCM encrypted `password`
/// and `ha1` when `AES_MASTER_KEY` is configured) exclusively to `/var/lib/aetherflow/.master.creds`
/// (mode `0600`), unlinking any legacy duplicate `.master.creds` paths.
pub fn save_master_credentials(username: &str, password: &str) -> Result<(), String> {
    let user_clean = username.trim();
    if user_clean.is_empty() || password.is_empty() {
        return Err("username and password are required".to_string());
    }
    let ha1 = master_ha1(user_clean, password)?;
    let stored_password =
        af_db::encrypt_secret_if_configured(password).map_err(|e| e.to_string())?;
    let stored_ha1 = af_db::encrypt_secret_if_configured(&ha1).map_err(|e| e.to_string())?;
    let payload = serde_json::to_string(&MasterCreds {
        username: user_clean.to_string(),
        password: stored_password,
        ha1: stored_ha1,
    })
    .map_err(|e| e.to_string())?;
    let mut raw = payload.into_bytes();
    raw.push(b'\n');

    let mut wrote_any = false;
    let mut wrote_all = true;
    for path in master_cred_paths() {
        if path.as_os_str().is_empty() {
            continue;
        }
        if write_file_atomic_mode(&path, &raw, Some(0o600)).is_ok() {
            wrote_any = true;
        } else {
            wrote_all = false;
        }
    }
    if wrote_any
        && wrote_all
        && env::var("AETHERFLOW_MASTER_CREDS_FILE")
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
    {
        for legacy in legacy_duplicate_master_cred_paths() {
            let _ = fs::remove_file(legacy);
        }
    }
    let plain_record = serde_json::to_string(&MasterCreds {
        username: user_clean.to_string(),
        password: password.to_string(),
        ha1,
    })
    .map_err(|e| e.to_string())?;
    if let Ok(encrypted) = af_db::encrypt_secret_if_configured(&plain_record) {
        if let Ok(conn) = af_db::get_conn() {
            let _ = conn.execute(
                r#"INSERT INTO system_config (key, value, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP"#,
                params![MASTER_CREDS_SYSTEM_KEY, encrypted],
            );
        }
    }
    if !wrote_any {
        return Err("failed to persist master credentials file".to_string());
    }
    Ok(())
}

fn has_existing_encrypted_master_creds_file() -> bool {
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
        if let Ok(raw) = fs::read_to_string(&path) {
            if raw.contains("enc:v1:") {
                return true;
            }
        }
    }
    false
}

/// Ensures dedicated random package-provisioning credentials exist in `.master.creds`
/// without ever persisting the operator's control-plane password or overwriting an
/// existing encrypted `.master.creds` file on decryption failure.
pub fn ensure_provisioning_credentials(username: &str) {
    let user_clean = {
        let trimmed = username.trim();
        if trimmed.is_empty() {
            "admin"
        } else {
            trimmed
        }
    };
    let (existing_user, existing_pass, _) = load_master_credentials();
    if !existing_user.is_empty() && !existing_pass.is_empty() && existing_pass != "adminadmin" {
        let _ = save_master_credentials(&existing_user, &existing_pass);
        return;
    }
    if has_existing_encrypted_master_creds_file() {
        tracing::warn!(
            "Existing encrypted master credentials could not be decrypted; refusing to overwrite .master.creds"
        );
        return;
    }
    let mut random_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    let generated_secret = hex::encode(random_bytes);
    let _ = save_master_credentials(user_clean, &generated_secret);
}

/// Propagates the master credentials to installed applications (qBittorrent PBKDF2, SABnzbd derived secret, Transmission).
pub fn sync_master_credentials_to_installed_apps(username: &str, password: &str) {
    if username.trim().is_empty() || password.is_empty() {
        return;
    }
    let qbit_hash = generate_qbittorrent_pbkdf2(password);
    for raw in [
        "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
        "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
    ] {
        let p = resolve_config_path(raw);
        if p.is_file() {
            let _ = mutate_ini_key(&p, "Preferences", r"WebUI\Username", username.trim());
            let _ = mutate_ini_key(&p, "Preferences", r"WebUI\Password_PBKDF2", &qbit_hash);
        }
    }

    let sab_password = derive_app_webui_password("sabnzbd", password);
    for raw in [
        "/var/lib/sabnzbd/sabnzbd.ini",
        "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
        "/etc/sabnzbd/sabnzbd.ini",
    ] {
        let p = resolve_config_path(raw);
        if p.is_file() {
            let _ = mutate_ini_key(&p, "misc", "username", username.trim());
            let _ = mutate_ini_key(&p, "misc", "password", &sab_password);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
            }
        }
    }

    for raw in [
        "/etc/transmission-daemon/settings.json",
        "/var/lib/transmission-daemon/info/settings.json",
        "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlueprintConfigSummary {
    pub app_name: String,
    pub service_name: String,
    pub listen_port: i32,
    pub default_port: i32,
    pub port_reassigned: bool,
    pub internal_domain: String,
    pub config_applied: bool,
    pub mutated_files: Vec<String>,
    pub sqlite_routes_injected: usize,
    pub dns_domains: Vec<String>,
    pub dns_synced: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unprivileged_skips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Applies only an application's native blueprint configuration files under
/// blueprint mutation admission, leaving durable ingress, Apache publication,
/// and DNS synchronization to the caller.
pub async fn apply_blueprint_host_config(
    app_name: &str,
    port: u16,
) -> Result<BlueprintConfigSummary, String> {
    with_blueprint_mutation(app_name, async {
        let canonical = normalize_app_key_name(app_name);
        let bp = crate::get_blueprint(&canonical)
            .or_else(|| crate::get_blueprint(app_name))
            .ok_or_else(|| anyhow::anyhow!("blueprint not found for {:?}", app_name))?;
        let effective_port = if port > 0 {
            i32::from(port)
        } else {
            bp.default_port
        };
        let host_mutation = apply_blueprint_host_config_only(&bp.app_name, effective_port)
            .await
            .map_err(anyhow::Error::msg)?;
        clear_app_runtime_meta_cache();
        let internal_domain = if !bp.internal_domain.trim().is_empty() {
            bp.internal_domain.trim().to_lowercase()
        } else {
            format!("{}.aether.local", bp.app_name.trim().to_lowercase())
        };
        let mutated_files = host_mutation.mutated_files;
        Ok(BlueprintConfigSummary {
            app_name: bp.app_name,
            service_name: bp.service_name,
            listen_port: effective_port,
            default_port: bp.default_port,
            port_reassigned: effective_port > 0 && effective_port != bp.default_port,
            internal_domain,
            config_applied: !mutated_files.is_empty(),
            mutated_files,
            sqlite_routes_injected: host_mutation.sqlite_routes_injected,
            dns_domains: Vec::new(),
            dns_synced: false,
            unprivileged_skips: Vec::new(),
            warnings: Vec::new(),
        })
    })
    .await
    .map_err(|error| format!("{error:#}"))
}

async fn apply_blueprint_host_config_only(
    app_name: &str,
    effective_port: i32,
) -> Result<af_models::RunnerBlueprintApplyResponse, String> {
    let req = af_models::RunnerBlueprintApplyRequest {
        app_name: app_name.to_string(),
        listen_port: effective_port,
        lifecycle_job_id: af_runner::current_package_job_id(),
    };
    let config_root = af_runner::blueprint::has_config_root();
    let result = if unsafe { libc::geteuid() } != 0 && !config_root {
        af_runner::dispatch_blueprint_apply(&req).await
    } else {
        let admission = BLUEPRINT_ADMISSION.try_with(std::sync::Arc::clone).ok();
        let local_req = req.clone();
        let direct = tokio::task::spawn_blocking(move || {
            let _admission = admission;
            af_runner::blueprint::apply_host_config(&local_req)
        })
        .await
        .map_err(|err| format!("blueprint config task failed: {err}"))?;
        match direct {
            Err(err)
                if !config_root
                    && af_runner::is_runner_available()
                    && is_host_permission_error(&err.to_string()) =>
            {
                af_runner::dispatch_blueprint_apply(&req).await
            }
            result => result,
        }
    };
    result.map_err(|err| err.to_string())
}

/// Applies an application's blueprint configuration and returns a typed summary
/// (`BlueprintConfigSummary`) including `mutated_files` and `config_applied`.
pub async fn apply_blueprint_app_config_detailed(
    app_name: &str,
    port: u16,
) -> Result<BlueprintConfigSummary, String> {
    with_blueprint_mutation(app_name, async {
        apply_blueprint_app_config_detailed_admitted(app_name, port as i32)
            .await
            .map(|(summary, _)| summary)
            .map_err(anyhow::Error::msg)
    })
    .await
    .map_err(|error| format!("{error:#}"))
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

async fn apply_blueprint_app_config_admitted(
    app_name: &str,
    listen_port: i32,
) -> Result<Value, String> {
    let (summary, _) = apply_blueprint_app_config_detailed_admitted(app_name, listen_port).await?;
    serde_json::to_value(summary).map_err(|e| format!("failed to serialize blueprint summary: {e}"))
}

/// Apply the host blueprint under lifecycle admission and return the exact
/// ingress settings used, for the caller to commit after final verification.
pub async fn apply_lifecycle_blueprint_app_config(
    app_name: &str,
    listen_port: i32,
) -> Result<Option<AppIngressConfig>, String> {
    if af_runner::current_package_job_id().is_empty() {
        return Err("Blueprint lifecycle job identity is required".into());
    }
    with_blueprint_mutation(app_name, async {
        apply_blueprint_app_config_detailed_admitted(app_name, listen_port)
            .await
            .map(|(_, ingress)| ingress)
            .map_err(anyhow::Error::msg)
    })
    .await
    .map_err(|error| format!("{error:#}"))
}

async fn apply_blueprint_app_config_detailed_admitted(
    app_name: &str,
    listen_port: i32,
) -> Result<(BlueprintConfigSummary, Option<AppIngressConfig>), String> {
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

    let base_domain = crate::resolve_base_domain();
    let lifecycle_ingress = if lifecycle_owned {
        af_db::plan_lifecycle_ingress(
            &bp.app_name,
            effective_port,
            &base_domain,
            existing_ingress.as_ref(),
        )
        .map_err(|error| error.to_string())?
    } else {
        None
    };

    let host_mutation = apply_blueprint_host_config_only(&bp.app_name, effective_port).await?;
    let mutated_files = host_mutation.mutated_files;
    let sqlite_routes_injected = host_mutation.sqlite_routes_injected;

    let internal_domain = if !bp.internal_domain.trim().is_empty() {
        bp.internal_domain.trim().to_lowercase()
    } else {
        format!("{}.aether.local", bp.app_name.trim().to_lowercase())
    };

    let ingress = lifecycle_ingress.as_ref().or(existing_ingress.as_ref());
    let mut dns_domains = vec![internal_domain.clone()];
    let mut public_domain = String::new();
    if effective_port > 0 {
        public_domain = ingress
            .map(|config| config.public_domain.trim().to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| crate::format_app_public_domain(&bp.app_name, &base_domain));
        if !public_domain.is_empty() && !dns_domains.contains(&public_domain) {
            dns_domains.push(public_domain.clone());
        }
    }

    sync_apache_app_vhost_with_tls(
        &bp.app_name,
        effective_port,
        &internal_domain,
        &public_domain,
        ingress.is_some_and(|cfg| cfg.external_access_enabled),
        ingress.is_some_and(|cfg| cfg.tls_enabled),
    )
    .await
    .map_err(|err| err.to_string())?;
    sync_local_dns_domains(&dns_domains).await?;
    clear_app_runtime_meta_cache();

    let summary = BlueprintConfigSummary {
        app_name: bp.app_name,
        service_name: bp.service_name,
        listen_port: effective_port,
        default_port: bp.default_port,
        port_reassigned: effective_port > 0 && effective_port != bp.default_port,
        internal_domain,
        config_applied: !mutated_files.is_empty(),
        mutated_files,
        sqlite_routes_injected,
        dns_domains,
        dns_synced: true,
        unprivileged_skips: Vec::new(),
        warnings: Vec::new(),
    };
    Ok((summary, lifecycle_ingress))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_ingress_keeps_saved_hostname_port_and_exposure() {
        let package = af_models::Package {
            name: "sonarr".into(),
            default_port: 8989,
            ..Default::default()
        };
        let saved = AppIngressConfig {
            app_name: package.name.clone(),
            public_domain: "series.custom.example".into(),
            listen_port: 20001,
            external_access_enabled: true,
            tls_enabled: true,
            ..Default::default()
        };
        for base in ["", "new.example"] {
            assert_eq!(
                startup_app_ingress_config(&package, base, Some(&saved)),
                saved
            );
        }
        let seeded = startup_app_ingress_config(&package, "new.example", None);
        assert_eq!(seeded.public_domain, "sonarr.new.example");
        assert_eq!(seeded.listen_port, 8989);
        assert!(!seeded.external_access_enabled);
    }

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

        assert_eq!(read_xml_element(&xml_path, "Port").as_deref(), Some("8989"));
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
        for original in [
            "POSTGRES_PASSWORD=keep\nDISPATCHARR_PORT=9191\n",
            "POSTGRES_PASSWORD=keep",
            "",
        ] {
            fs::write(&path, original).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            }
            assert!(mutate_dispatcharr_port(&path, 19200).unwrap());
            let text = fs::read_to_string(&path).unwrap();
            assert_eq!(
                extract_ini_value(&text, &["DISPATCHARR_PORT"]).as_deref(),
                Some("19200")
            );
            assert!(!text.contains("[Preferences]"));
            if original.contains("POSTGRES_PASSWORD") {
                assert!(text.contains("POSTGRES_PASSWORD=keep"));
            }
            assert!(!mutate_dispatcharr_port(&path, 19200).unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o640
                );
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

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
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
        assert_eq!(
            master_ha1("alice", "secret").unwrap(),
            "6bd888770befc89c83a914b36f95b87f"
        );

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
        for subdir in [
            "etc/jellyfin",
            "etc/apache2/sites-available",
            "var/lib/aetherflow",
        ] {
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

        let sync_res =
            sync_apache_app_vhost("qui", 18376, "qui.aether.local", "qui.example.com", true);

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
        let scratch_dir =
            env::temp_dir().join(format!("af-dns-sync-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());

        // Install App A -> syncs appa.aether.local
        sync_local_dns_domains(&["appa.aether.local".to_string()])
            .await
            .unwrap();
        let content_after_a = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_a.contains("appa.aether.local"));

        // Install App B -> syncs appb.aether.local without wiping appa
        sync_local_dns_domains(&["appb.aether.local".to_string()])
            .await
            .unwrap();
        let content_after_b = fs::read_to_string(&hosts_file).unwrap();
        assert!(
            content_after_b.contains("appa.aether.local"),
            "App A must be preserved when installing App B: {content_after_b}"
        );
        assert!(
            content_after_b.contains("appb.aether.local"),
            "App B must be present: {content_after_b}"
        );

        env::remove_var("AF_HOSTS_FILE");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_reconcile_local_dns_domains_non_root_invokes_runner_and_propagates_error() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_HOSTS_FILE");

        let dummy_sock =
            env::temp_dir().join(format!("nonexistent-runner-{}.sock", uuid::Uuid::new_v4()));
        env::set_var(
            "AETHERFLOW_RUNNER_SOCK",
            dummy_sock.to_string_lossy().as_ref(),
        );

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
                    err.contains("runner hosts reconcile error")
                        || err.contains("privileged runner hosts reconcile failed"),
                    "Expected runner error, got: {err}"
                );
            }
        }

        env::remove_var("AETHERFLOW_RUNNER_SOCK");
    }

    #[tokio::test]
    async fn test_reconcile_and_sync_dns_separates_hosts_loopback_and_provider_lan_ip() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let scratch_dir =
            env::temp_dir().join(format!("af-mutators-dns-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();

        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var(
            "AETHERFLOW_DNSMASQ_DIR",
            dnsmasq_dir.to_string_lossy().as_ref(),
        );
        env::set_var(
            "AETHERFLOW_PIHOLE_DIR",
            pihole_dir.to_string_lossy().as_ref(),
        );
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
        let scratch_dir = env::temp_dir().join(format!(
            "af-mutators-invalid-lan-ip-{}",
            uuid::Uuid::new_v4()
        ));
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
        env::set_var(
            "AETHERFLOW_DNSMASQ_DIR",
            dnsmasq_dir.to_string_lossy().as_ref(),
        );
        env::set_var(
            "AETHERFLOW_PIHOLE_DIR",
            pihole_dir.to_string_lossy().as_ref(),
        );

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

            assert!(
                detect_lan_ip_strict().is_err(),
                "detect_lan_ip_strict must fail for {bad_ip:?}"
            );

            let sync_res = sync_local_dns_domains(&test_domains).await;
            assert!(
                sync_res.is_err(),
                "sync_local_dns_domains must fail closed for {bad_ip:?}"
            );

            let rec_res = reconcile_local_dns_domains(&test_domains).await;
            assert!(
                rec_res.is_err(),
                "reconcile_local_dns_domains must fail closed for {bad_ip:?}"
            );

            // Verify files were not modified
            let hosts_cur = fs::read_to_string(&hosts_file).unwrap();
            assert_eq!(
                hosts_cur, "127.0.0.1 localhost\n",
                "hosts file must remain untouched for {bad_ip:?}"
            );

            assert!(
                !dnsmasq_dir.join("aetherflow.conf").exists(),
                "dnsmasq must not be created"
            );
            assert!(
                !dnsmasq_dir.join("aetherflow-local.conf").exists(),
                "dnsmasq must not be created"
            );

            let pihole_cur = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
            assert_eq!(
                pihole_cur, initial_custom_list,
                "custom.list must remain untouched for {bad_ip:?}"
            );
        }

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        env::remove_var("AETHERFLOW_LAN_IP");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_round8_save_master_credentials_preserves_legacy_on_primary_write_failure() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let scratch_dir =
            env::temp_dir().join(format!("af_r8_master_creds_{}", uuid::Uuid::new_v4()));
        let legacy_file = scratch_dir.join("opt/AetherFlow/backend/data/.master.creds");
        fs::create_dir_all(legacy_file.parent().unwrap()).unwrap();
        fs::write(&legacy_file, b"legacy-must-survive\n").unwrap();

        // Block primary `/var/lib/aetherflow/.master.creds` by making parent `/var/lib/aetherflow` a regular file.
        let blocked_dir = scratch_dir.join("var/lib/aetherflow");
        fs::create_dir_all(blocked_dir.parent().unwrap()).unwrap();
        fs::write(&blocked_dir, b"blocking-regular-file").unwrap();

        env::set_var("AETHERFLOW_CONFIG_ROOT", &scratch_dir);
        env::remove_var("AETHERFLOW_MASTER_CREDS_FILE");
        env::set_var("AES_MASTER_KEY", "d".repeat(64));
        let _ = af_db::init_aes_key();

        let err_res = save_master_credentials("admin", "R8StrongPass!");
        assert!(err_res.is_err(), "primary write failure must return error");
        assert_eq!(
            fs::read_to_string(&legacy_file).unwrap(),
            "legacy-must-survive\n",
            "legacy .master.creds must NOT be unlinked when primary write fails"
        );

        // Fix `/var/lib/aetherflow` into a real directory and verify primary write + legacy unlink succeed.
        fs::remove_file(&blocked_dir).unwrap();
        fs::create_dir_all(&blocked_dir).unwrap();
        save_master_credentials("admin", "R8StrongPass!").expect("primary write should succeed");
        assert!(blocked_dir.join(".master.creds").is_file());
        assert!(
            !legacy_file.exists(),
            "legacy .master.creds must be unlinked once all primary writes succeed"
        );

        env::remove_var("AETHERFLOW_CONFIG_ROOT");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_librespeed_apache_vhost_pins_upstream_ca_and_dynamic_proto_on_ext_vhost() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        let dir = temp_test_dir("librespeed-tls-vhost");
        let sites_avail = dir.join("etc/apache2/sites-available");
        let sites_en = dir.join("etc/apache2/sites-enabled");
        let ls_dir = dir.join("opt/librespeed");
        fs::create_dir_all(&sites_avail).unwrap();
        fs::create_dir_all(&sites_en).unwrap();
        fs::create_dir_all(&ls_dir).unwrap();

        fs::write(
            ls_dir.join("cert.pem"),
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            ls_dir.join("settings.toml"),
            "enable_tls = true\ntls_cert_file = \"/opt/librespeed/cert.pem\"\n",
        )
        .unwrap();

        let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);

        let sync_res = sync_apache_app_vhost(
            "librespeed",
            8988,
            "librespeed.aether.local",
            "speed.example.com",
            true,
        );

        for (key, prev) in [
            ("AETHERFLOW_FS_ROOT", prev_fs_root.clone()),
            ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root.clone()),
        ] {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        assert!(sync_res.unwrap());
        let int_vhost =
            fs::read_to_string(sites_avail.join("aetherflow-app-librespeed.conf")).unwrap();
        let ext_vhost =
            fs::read_to_string(sites_avail.join("aetherflow-ext-librespeed.conf")).unwrap();
        for vhost in [&int_vhost, &ext_vhost] {
            assert!(vhost.contains("SSLProxyEngine On"));
            assert!(vhost.contains("SSLProxyVerify require"));
            assert!(vhost.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
            assert!(!vhost.contains("SSLProxyVerify none"));
            assert!(vhost.contains("https://127.0.0.1:8988/"));
            assert!(vhost.contains("IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf"));
        }
        assert!(int_vhost.contains("RequestHeader set X-Forwarded-Proto \"http\""));
        assert!(
            ext_vhost.contains("RequestHeader set X-Forwarded-Proto \"expr=%{REQUEST_SCHEME}\"")
        );

        // Missing/invalid tls_cert_file when enable_tls=true must fail closed and NEVER write SSLProxyVerify none
        fs::write(
            ls_dir.join("settings.toml"),
            "enable_tls = true\ntls_cert_file = \"relative/cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
        )
        .unwrap();
        std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);
        let invalid_res = sync_apache_app_vhost(
            "librespeed",
            8988,
            "librespeed.aether.local",
            "speed.example.com",
            true,
        );
        for (key, prev) in [
            ("AETHERFLOW_FS_ROOT", prev_fs_root),
            ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
        ] {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        assert!(
            invalid_res.is_err(),
            "enable_tls=true with unusable cert must fail closed"
        );
        let preserved_vhost =
            fs::read_to_string(sites_avail.join("aetherflow-app-librespeed.conf")).unwrap();
        assert!(preserved_vhost.contains("SSLProxyVerify require"));
        assert!(!preserved_vhost.contains("SSLProxyVerify none"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_normalize_app_key_name_matches_canonical_catalog_ids() {
        assert_eq!(normalize_app_key_name("calibre-web"), "calibreweb");
        assert_eq!(normalize_app_key_name("uptime-kuma"), "uptimekuma");
        assert_eq!(normalize_app_key_name("af-kasmvnc"), "kasmvnc");
        assert_eq!(normalize_app_key_name("af-palate"), "palate");
        assert_eq!(normalize_app_key_name("af-mcvnc"), "mcvnc");
        assert_eq!(normalize_app_key_name("af-maintainerr"), "maintainerr");
        assert_eq!(normalize_app_key_name("af-piped"), "piped");
        assert_eq!(normalize_app_key_name("af-invidious"), "invidious");
    }

    #[tokio::test]
    async fn test_detect_lan_ip_strict_and_dnsmasq_consolidation_with_pihole_v6() {
        let _env_guard = TEST_ENV_LOCK.lock().await;
        env::remove_var("AETHERFLOW_LAN_IP");
        let detected = detect_lan_ip_strict().expect("detect_lan_ip_strict succeeds when unset");
        assert!(detected.parse::<std::net::Ipv4Addr>().is_ok());

        let scratch_dir = temp_test_dir("dns-consolidate");
        let hosts_file = scratch_dir.join("hosts");
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        fs::create_dir_all(&pihole_dir).unwrap();
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        fs::write(
            dnsmasq_dir.join("aetherflow-local.conf"),
            "address=/legacy.aether.local/192.168.1.10\n",
        )
        .unwrap();
        fs::write(
            dnsmasq_dir.join("aetherflow-local-dns.conf"),
            "address=/legacy2.aether.local/192.168.1.10\n",
        )
        .unwrap();
        fs::write(
            pihole_dir.join("pihole.toml"),
            "[dns]\n  upstreams = [\"1.1.1.1\"]\n  hosts = [\n    \"192.168.1.20 manual.lan\"\n  ]\n",
        )
        .unwrap();

        env::set_var("AF_HOSTS_FILE", &hosts_file);
        env::set_var("AETHERFLOW_DNSMASQ_DIR", &dnsmasq_dir);
        env::set_var("AETHERFLOW_PIHOLE_DIR", &pihole_dir);
        env::set_var("AETHERFLOW_LAN_IP", "192.168.1.77");

        sync_local_dns_domains(&["radarr.aether.local".to_string()])
            .await
            .unwrap();

        assert!(!dnsmasq_dir.join("aetherflow-local.conf").exists());
        assert!(!dnsmasq_dir.join("aetherflow-local-dns.conf").exists());
        let canonical = fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
        assert!(canonical.contains("address=/radarr.aether.local/192.168.1.77"));
        assert!(canonical.contains("address=/legacy.aether.local/192.168.1.77"));
        assert!(canonical.contains("address=/legacy2.aether.local/192.168.1.77"));

        let custom_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(custom_list.contains("192.168.1.77 radarr.aether.local"));

        let pihole_toml = fs::read_to_string(pihole_dir.join("pihole.toml")).unwrap();
        assert!(pihole_toml.contains("\"192.168.1.20 manual.lan\""));
        assert!(pihole_toml.contains("\"192.168.1.77 radarr.aether.local\""));

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        env::remove_var("AETHERFLOW_LAN_IP");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[test]
    fn test_pihole_bazarr_and_listenarr_mutators() {
        let dir = temp_test_dir("mutators-v2");

        // 1. Pi-hole: mutates [webserver] port only and never duplicates [webserver]
        let pihole_toml = dir.join("pihole.toml");
        fs::write(
            &pihole_toml,
            "[dns]\n  port = 53\n[webserver]\n  threads = 4\n[webserver.api]\n  pwhash = \"hash\"\n[misc]\n  etc_dnsmasq_d = false\n",
        )
        .unwrap();
        assert!(mutate_pihole_toml(&pihole_toml, 18089).unwrap());
        let pihole_after_1 = fs::read_to_string(&pihole_toml).unwrap();
        assert_eq!(pihole_after_1.matches("[webserver]").count(), 1);
        assert!(pihole_after_1.contains("  port = \"18089o\""));
        assert!(pihole_after_1.contains("[dns]\n  port = 53"));
        assert!(pihole_after_1.contains("etc_dnsmasq_d = true"));

        assert!(mutate_pihole_toml(&pihole_toml, 18090).unwrap());
        let pihole_after_2 = fs::read_to_string(&pihole_toml).unwrap();
        assert_eq!(pihole_after_2.matches("[webserver]").count(), 1);
        assert!(pihole_after_2.contains("  port = \"18090o\""));
        assert!(pihole_after_2.contains("[dns]\n  port = 53"));

        // 2. Bazarr: YAML general.port mutator
        let bazarr_yaml = dir.join("config.yaml");
        fs::write(
            &bazarr_yaml,
            "auth:\n  type: form\ngeneral:\n  ip: 127.0.0.1\n  port: 6767\n",
        )
        .unwrap();
        assert!(mutate_yaml_section_key(&bazarr_yaml, "general", "port", "16767").unwrap());
        let bazarr_after = fs::read_to_string(&bazarr_yaml).unwrap();
        assert!(bazarr_after.contains("  port: 16767"));
        assert!(bazarr_after.contains("  type: form"));

        // 3. Listenarr: ASPNETCORE_URLS mutator in systemd unit
        let listenarr_unit = dir.join("listenarr.service");
        fs::write(
            &listenarr_unit,
            "[Service]\nEnvironment=\"ASPNETCORE_URLS=http://127.0.0.1:4546\"\n",
        )
        .unwrap();
        assert!(mutate_systemd_aspnetcore_urls(&listenarr_unit, 14546).unwrap());
        let listenarr_after = fs::read_to_string(&listenarr_unit).unwrap();
        assert!(listenarr_after.contains("ASPNETCORE_URLS=http://127.0.0.1:14546"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_trigger_apache_cert_sync_uses_runner_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let _env_guard = TEST_ENV_LOCK.lock().await;
        let sock_path =
            PathBuf::from("/tmp").join(format!("af-cert-sync-test-{}.sock", std::process::id()));
        let _ = fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();

        let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
        env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"success":true,"output":"synced","error":""}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        trigger_apache_cert_sync().await;
        let received = server.await.unwrap();
        assert!(received.starts_with("POST /v1/certbot-sync "));

        match prev_sock {
            Some(v) => env::set_var("AETHERFLOW_RUNNER_SOCK", v),
            None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
        }
        let _ = fs::remove_file(&sock_path);
    }
}
