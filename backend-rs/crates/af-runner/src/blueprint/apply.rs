use super::fs_mutators::{
    extract_ini_value, extract_xml_tag_text, mutate_dispatcharr_port, mutate_ini_key,
    mutate_json_key, mutate_pihole_toml, mutate_systemd_aspnetcore_urls, mutate_systemd_port,
    mutate_transmission_whitelist, mutate_xml_element, mutate_yaml_section_key, read_mutation_text,
    read_xml_element, validate_no_symlink_parents,
};
use super::master_creds::{
    database_master_credentials, derive_app_webui_password, generate_qbittorrent_pbkdf2,
    load_master_credentials, load_master_credentials_with,
};
use super::native_specs::{
    inject_arr_download_client_routes, native_app_spec, NativeAppSpec, TRANSMISSION_CONFIG_PATHS,
};
use crate::resolve_runner_fs_path as resolve_config_path;
use af_models::{RunnerBlueprintApplyRequest, RunnerBlueprintApplyResponse};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

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
