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

mod blueprint_apply;
mod network_vhost;
mod runtime_meta;
#[cfg(test)]
mod tests;

#[cfg(test)]
use blueprint_apply::apply_blueprint_app_config_admitted;
pub use blueprint_apply::{
    apply_blueprint_app_config, apply_blueprint_app_config_detailed, apply_blueprint_host_config,
    apply_lifecycle_blueprint_app_config, ensure_provisioning_credentials, save_master_credentials,
    sync_master_credentials_to_installed_apps, BlueprintConfigSummary,
};

#[cfg(test)]
use network_vhost::startup_app_ingress_config;
use network_vhost::sync_apache_app_vhost_with_tls;
pub use network_vhost::{
    detect_lan_ip, detect_lan_ip_strict, provision_all_installed_app_subdomains,
    reconcile_local_dns_domains, remove_dns_provider_domain, run_privileged_hosts_command,
    run_privileged_hosts_command_with_provider, sync_apache_app_vhost, sync_apache_app_vhost_async,
    sync_local_dns_domains, sync_network_dns_providers, trigger_apache_cert_sync,
    update_dnsmasq_conf, update_dnsmasq_config, update_pihole_custom_list,
    update_pihole_toml_hosts,
};

#[cfg(test)]
use runtime_meta::parse_runner_app_meta;
use runtime_meta::request_runner_unix;
pub(crate) use runtime_meta::{
    app_runtime_meta_epoch, cached_app_runtime_meta, collect_native_url_base_meta,
    get_app_runtime_meta_until, qbittorrent_web_bind_address,
};
pub use runtime_meta::{
    clear_app_runtime_meta_cache, get_app_runtime_meta, normalize_app_key_name, AppRuntimeMeta,
};
