use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Master Credentials & PBKDF2-HMAC-SHA512 Synchronizer
// ─────────────────────────────────────────────────────────────────────────────

use af_runner::blueprint::MASTER_CREDS_SYSTEM_KEY;

pub(super) fn legacy_duplicate_master_cred_paths() -> Vec<PathBuf> {
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

pub(super) fn has_existing_encrypted_master_creds_file() -> bool {
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

pub(super) async fn apply_blueprint_host_config_only(
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

pub(super) async fn apply_blueprint_app_config_admitted(
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

pub(super) async fn apply_blueprint_app_config_detailed_admitted(
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
