use super::*;

pub(crate) fn normalize_systemd_unit(unit: &str) -> String {
    let trimmed = unit.trim();
    if trimmed.ends_with(".service")
        || trimmed.ends_with(".timer")
        || trimmed.ends_with(".socket")
        || trimmed.ends_with(".mount")
    {
        trimmed.to_string()
    } else {
        format!("{}.service", trimmed)
    }
}

pub(crate) fn is_exempt_sandbox_unit(unit: &str) -> bool {
    let unit = unit.trim();
    unit.ends_with(".timer")
        || unit.ends_with(".socket")
        || matches!(
            unit,
            "aetherflow-api"
                | "aetherflow-runner"
                | "aetherflow-api.service"
                | "aetherflow-runner.service"
                | "af-transcode-worker"
                | "af-transcode-worker.service"
                | "fail2ban.service"
                | "pihole-FTL.service"
                | "netdata.service"
                | "node_exporter.service"
                | "apache2.service"
                | "mariadb.service"
                | "mysql.service"
                | "nfs-server"
                | "nfs-server.service"
                | "tailscale"
                | "tailscaled"
                | "tailscale.service"
                | "tailscaled.service"
        )
        || unit.starts_with("wg-quick@")
        || unit.starts_with("wireguard")
        || unit.starts_with(r"mnt-af\x2dpeers-")
        || unit.starts_with("tailscale")
        || unit.starts_with("tailscaled")
        || unit.starts_with("mergerfs")
        || unit.starts_with("rclone-vfs")
        || unit.starts_with("scrutiny-collector")
        || unit.starts_with("x2goserver")
        || unit.starts_with("novnc-xvnc")
        || unit.starts_with("novnc-session")
}

pub(crate) fn sandbox_master_user(credentials: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(credentials) {
        let username = value.get("username")?.as_str()?;
        return SAFE_USERNAME
            .is_match(username)
            .then(|| username.to_string());
    }
    let first = credentials.lines().next()?.trim();
    let username = first
        .strip_prefix("username=")
        .or_else(|| first.split_once(':').map(|(username, _)| username))?;
    SAFE_USERNAME
        .is_match(username)
        .then(|| username.to_string())
}

pub(crate) fn expand_sandbox_path(
    raw: &str,
    service_user: &str,
    service_home: &str,
    master_user: &str,
) -> String {
    let clean = raw
        .trim_start_matches('-')
        .replace("{{SERVICE_USER}}", service_user)
        .replace("{{SERVICE_HOME}}", service_home)
        .replace("{{MASTER_USER}}", master_user);
    let prefixed = if raw.starts_with('-') || !Path::new(&clean).exists() {
        format!("-{}", clean)
    } else {
        clean
    };
    if prefixed.contains(char::is_whitespace) {
        format!("\"{}\"", prefixed)
    } else {
        prefixed
    }
}

fn read_unit_service_user(unit_path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(unit_path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 256 * 1024 {
        return None;
    }
    let content = fs::read_to_string(unit_path).ok()?;
    let mut in_service = false;
    let mut found = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_service = trimmed.eq_ignore_ascii_case("[Service]");
            continue;
        }
        if in_service {
            if let Some(raw_user) = trimmed.strip_prefix("User=") {
                let candidate = raw_user.trim().trim_matches(['"', '\'']);
                if SAFE_USERNAME.is_match(candidate) {
                    found = Some(candidate.to_string());
                }
            }
        }
    }
    found
}

pub fn render_systemd_sandbox_dropin(profile: &str, unit: &str, rw_paths: &[String]) -> String {
    render_systemd_sandbox_dropin_in_root(profile, unit, rw_paths, None, None)
}

pub(crate) fn render_systemd_sandbox_dropin_in_root(
    profile: &str,
    unit: &str,
    rw_paths: &[String],
    systemd_root: Option<&Path>,
    fs_root: Option<&Path>,
) -> String {
    let norm_unit = normalize_systemd_unit(unit);
    if is_exempt_sandbox_unit(&norm_unit) {
        return String::new();
    }
    let private_devices = if norm_unit.starts_with("jellyfin")
        || norm_unit.starts_with("plex")
        || norm_unit.starts_with("emby")
        || norm_unit.starts_with("tdarr")
        || norm_unit.starts_with("threadfin")
        || norm_unit.starts_with("scrutiny")
        || norm_unit.starts_with("dispatcharr")
        || norm_unit.starts_with("unmanic")
    {
        "no"
    } else {
        "yes"
    };
    let restrict_namespaces = if norm_unit.starts_with("flaresolverr") {
        "no"
    } else {
        "yes"
    };

    let protect_home = if norm_unit == "librespeed.service" {
        "yes"
    } else {
        "read-only"
    };

    let mut lines = vec![
        "[Service]".to_string(),
        "NoNewPrivileges=yes".to_string(),
        "PrivateTmp=yes".to_string(),
        format!("PrivateDevices={}", private_devices),
        "ProtectSystem=strict".to_string(),
        format!("ProtectHome={}", protect_home),
        "ProtectClock=yes".to_string(),
        "ProtectControlGroups=yes".to_string(),
        "ProtectKernelLogs=yes".to_string(),
        "ProtectKernelModules=yes".to_string(),
        "ProtectKernelTunables=yes".to_string(),
        "ProtectProc=invisible".to_string(),
        "ProcSubset=pid".to_string(),
        "LockPersonality=yes".to_string(),
        format!("RestrictNamespaces={}", restrict_namespaces),
        "RestrictRealtime=yes".to_string(),
        "RestrictSUIDSGID=yes".to_string(),
        "SystemCallArchitectures=native".to_string(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK".to_string(),
        "CapabilityBoundingSet=".to_string(),
        "AmbientCapabilities=".to_string(),
        "UMask=0077".to_string(),
    ];

    if !matches!(profile, "node" | "mono" | "dotnet" | "java" | "python") {
        lines.push("MemoryDenyWriteExecute=yes".to_string());
    }

    if !rw_paths.is_empty() {
        let needs_identity = rw_paths.iter().any(|raw| raw.contains("{{"));
        let unit_file = systemd_root
            .map(|dir| dir.join(&norm_unit))
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system").join(&norm_unit));
        let service_user = if needs_identity {
            let from_systemctl = if fs_root.is_none() && cfg!(target_os = "linux") {
                let mut cmd = Command::new("systemctl");
                cmd.args(["show", &norm_unit, "-p", "User", "--value"]);
                bounded_command::output_blocking(cmd, None, Duration::from_secs(5), 16 * 1024)
                    .ok()
                    .filter(|output| output.status.success())
                    .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                    .filter(|username| SAFE_USERNAME.is_match(username))
            } else {
                None
            };
            from_systemctl
                .or_else(|| read_unit_service_user(&unit_file))
                .unwrap_or_else(|| "root".to_string())
        } else {
            "root".to_string()
        };
        let passwd_candidates: Vec<PathBuf> = match fs_root {
            Some(root) => vec![root.join("etc/passwd"), PathBuf::from("/etc/passwd")],
            None => vec![PathBuf::from("/etc/passwd")],
        };
        let service_home = passwd_candidates
            .iter()
            .find_map(|passwd_path| {
                fs::read_to_string(passwd_path).ok().and_then(|passwd| {
                    passwd.lines().find_map(|entry| {
                        let fields: Vec<_> = entry.split(':').collect();
                        (fields.len() >= 7 && fields[0] == service_user)
                            .then(|| fields[5].to_string())
                    })
                })
            })
            .unwrap_or_else(|| format!("/home/{}", service_user));
        let master_creds_paths = [
            "/var/lib/aetherflow/.master.creds",
            "/etc/aetherflow/.master.creds",
            "/root/.master.creds",
        ];
        let master_user = master_creds_paths
            .iter()
            .find_map(|path| {
                let candidate = match fs_root {
                    Some(root) => root.join(path.trim_start_matches('/')),
                    None => PathBuf::from(path),
                };
                af_release::fs_security::read_regular_file_bounded_nofollow(&candidate, 64 * 1024)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|credentials| sandbox_master_user(&credentials))
            })
            .unwrap_or_else(|| service_user.clone());
        let mut expanded = Vec::with_capacity(rw_paths.len());
        for raw in rw_paths {
            let entry = expand_sandbox_path(raw, &service_user, &service_home, &master_user);
            if !expanded.contains(&entry) {
                expanded.push(entry);
            }
        }
        lines.push(format!("ReadWritePaths={}", expanded.join(" ")));
    }

    format!("{}\n", lines.join("\n"))
}

pub async fn apply_package_sandbox_local(pkg_id: &str) -> anyhow::Result<String> {
    if !SAFE_PKG_ID.is_match(pkg_id) {
        anyhow::bail!("invalid package identifier");
    }

    let target = if matches!(pkg_id, "aetherflow-api" | "aetherflow-runner") {
        af_release::lifecycle::ReservationTarget::System
    } else {
        af_release::lifecycle::ReservationTarget::Package(pkg_id)
    };
    let guard = acquire_package_maintenance_guard(
        PackageExecutionEnv::default().fs_root.as_deref(),
        target,
        &current_package_job_id(),
        None,
    )
    .await?;
    apply_package_sandbox_reserved(pkg_id, &guard).await
}

pub(crate) fn write_file_atomically_with_mode(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let temp_path = parent.join(format!(".{}.tmp.{}", file_name, uuid::Uuid::new_v4()));
    let write_res = (|| -> anyhow::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut temp_file = opts.open(&temp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp_file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }
    Ok(())
}

pub(crate) fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub(crate) fn apply_sandbox_dropins_in_dir(
    sys_dir: &Path,
    units: &[String],
    sandbox_profile: &str,
    sandbox_read_write: &[String],
) -> anyhow::Result<()> {
    for raw_unit in units {
        let norm_unit = normalize_systemd_unit(raw_unit);
        let dropin_dir = sys_dir.join(format!("{}.d", norm_unit));
        let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
        let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
        if !norm_unit.ends_with(".service")
            || sandbox_profile == "privileged"
            || sandbox_profile == "none"
            || is_exempt_sandbox_unit(&norm_unit)
        {
            remove_file_if_exists(&dropin_aether)?;
            remove_file_if_exists(&dropin_10)?;
            continue;
        }
        fs::create_dir_all(&dropin_dir)?;
        let content =
            render_systemd_sandbox_dropin(sandbox_profile, &norm_unit, sandbox_read_write);
        write_file_atomically_with_mode(&dropin_10, content.as_bytes(), 0o644)?;
        remove_file_if_exists(&dropin_aether)?;
    }
    Ok(())
}

pub(crate) async fn apply_package_sandbox_reserved(
    pkg_id: &str,
    guard: &af_release::ReleaseLockGuard,
) -> anyhow::Result<String> {
    let pkg = get_runner_package_definition(pkg_id)
        .ok_or_else(|| anyhow::anyhow!("Sandbox target is not a managed package: {pkg_id}"))?;

    if !pkg.service_type.is_empty() && pkg.service_type != "systemd" {
        return Ok("sandbox skipped (non-systemd service)".to_string());
    }
    if pkg.sandbox_profile.is_empty() {
        return Ok("sandbox skipped (no profile configured)".to_string());
    }
    if pkg.sandbox_read_write.is_empty()
        && pkg.sandbox_profile != "privileged"
        && pkg.sandbox_profile != "none"
    {
        return Ok("sandbox skipped (no read-write paths)".to_string());
    }

    let mut units = pkg.sandbox_service_ids.clone();
    if units.is_empty() && !pkg.service_name.is_empty() {
        units.push(pkg.service_name.clone());
    }
    if units.is_empty() {
        units.push(pkg_id.to_string());
    }

    let dry_run = env::var("AETHERFLOW_SANDBOX_DRY_RUN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let systemd_root_override = env::var("AETHERFLOW_SYSTEMD_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            env::var("AETHERFLOW_INSTALL_ROOT")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "/")
                .map(|root| {
                    Path::new(&root)
                        .join("etc/systemd/system")
                        .to_string_lossy()
                        .into_owned()
                })
        });

    // 1. If systemd root override is set, write canonical 10-aetherflow-sandbox.conf drop-in files
    if let Some(ref sys_root) = systemd_root_override {
        apply_sandbox_dropins_in_dir(
            Path::new(sys_root),
            &units,
            &pkg.sandbox_profile,
            &pkg.sandbox_read_write,
        )?;
        return Ok("sandbox applied".to_string());
    }

    if dry_run || !cfg!(target_os = "linux") {
        return Ok("sandbox applied".to_string());
    }

    // 2. On Linux, prefer executing `af-systemd-sandbox` script if available
    if let Some(script_path) = resolve_sandbox_script_path() {
        let mut args = vec![
            script_path.to_string_lossy().to_string(),
            "apply".to_string(),
            "--profile".to_string(),
            pkg.sandbox_profile.clone(),
        ];
        for rw in &pkg.sandbox_read_write {
            args.push("--rw".to_string());
            args.push(rw.clone());
        }
        for u in &units {
            args.push(u.clone());
        }

        let mut command = Command::new("bash");
        command.args(&args);
        #[cfg(unix)]
        guard.preserve_in_child(command.as_std_mut())?;
        let out = bounded_command::output(command, Duration::from_secs(30), 256 * 1024)
            .await
            .map_err(|err| anyhow::anyhow!("failed to execute {}: {err}", script_path.display()))?;
        if out.status.success() {
            return Ok("sandbox applied".to_string());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        anyhow::bail!(
            "af-systemd-sandbox apply failed for {pkg_id} (exit {:?}): {detail}",
            out.status.code()
        );
    }

    // 3. Direct drop-in fallback in /etc/systemd/system/<unit>.service.d/10-aetherflow-sandbox.conf
    let sys_dir = Path::new("/etc/systemd/system");
    if sys_dir.exists() {
        apply_sandbox_dropins_in_dir(
            sys_dir,
            &units,
            &pkg.sandbox_profile,
            &pkg.sandbox_read_write,
        )?;
        let mut command = Command::new("systemctl");
        command.arg("daemon-reload");
        #[cfg(unix)]
        guard.preserve_in_child(command.as_std_mut())?;
        let out = bounded_command::output(command, Duration::from_secs(30), 64 * 1024)
            .await
            .map_err(|err| anyhow::anyhow!("failed to execute systemctl daemon-reload: {err}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("systemctl daemon-reload failed: {}", stderr.trim());
        }
    }

    Ok("sandbox applied".to_string())
}

pub(crate) async fn handle_sandbox(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let identity = req.lifecycle_job_id.clone();
    PACKAGE_JOB_ID
        .scope(
            identity,
            handle_sandbox_with(
                req,
                |pkg| async move { apply_package_sandbox_local(&pkg).await },
            ),
        )
        .await
}

pub(crate) async fn handle_sandbox_with<F, Fut>(
    req: SandboxRunnerRequest,
    apply: F,
) -> (StatusCode, Json<RunnerResponse>)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let pkg = if !req.package.trim().is_empty() {
        req.package.trim().to_string()
    } else {
        req.package_id.trim().to_string()
    };
    if !SAFE_PKG_ID.is_match(&pkg) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }

    match apply(pkg).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: if out.is_empty() {
                    "sandbox applied".to_string()
                } else {
                    out
                },
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}

pub(crate) fn open_runner_state_database(
    root: Option<&Path>,
) -> anyhow::Result<af_release::fs_security::IsolatedSqliteReplica> {
    let env_root = resolve_self_update_isolated_root_from_env().map_err(anyhow::Error::msg)?;
    let root = root.or(env_root.as_deref());
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let config = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let path = af_release::config::try_resolve_db_path(&config, None)?.path;
    let conn = af_release::fs_security::open_sqlite_isolated_readonly(&path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

pub(crate) async fn handle_blueprint_apply(
    Json(req): Json<af_models::RunnerBlueprintApplyRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_PKG_ID.is_match(&req.app_name) || !(0..=65535).contains(&req.listen_port) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid blueprint app or port".into(),
            }),
        );
    }
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let package = if req.app_name == "transmission-daemon" {
            "transmission"
        } else {
            &req.app_name
        };
        anyhow::ensure!(
            get_runner_package_definition(package).is_some(),
            "unknown blueprint package"
        );
        let units = package_lifecycle::package_service_units(package)?;
        let conn = open_runner_state_database(None)?;
        af_release::lifecycle::check_package_reservation(
            &conn,
            package,
            &units,
            &req.lifecycle_job_id,
            None,
        )
        .map_err(|err| err.context(LifecycleBusy))?;
        if !req.lifecycle_job_id.is_empty() {
            let action: String = conn.query_row(
                "SELECT action FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                rusqlite::params![package, req.lifecycle_job_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                matches!(action.as_str(), "install" | "reinstall" | "update"),
                "removal cannot own blueprint configuration mutations"
            );
        }
        Ok(serde_json::to_string(
            &blueprint::apply_host_config_with_state(&req, Some(&conn))?,
        )?)
    })
    .await;
    match result {
        Ok(Ok(output)) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Ok(Err(err)) => {
            let status = if is_lifecycle_busy(&err) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: af_models::secret_redaction::redact_diagnostic(&err.to_string())
                        .into_owned(),
                }),
            )
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "blueprint config worker failed".into(),
            }),
        ),
    }
}

pub async fn dispatch_blueprint_apply(
    req: &af_models::RunnerBlueprintApplyRequest,
) -> anyhow::Result<af_models::RunnerBlueprintApplyResponse> {
    let response = post_runner_json("/v1/blueprint/apply", req, Duration::from_secs(45)).await?;
    anyhow::ensure!(
        response.success,
        "runner blueprint apply failed: {}",
        response.error
    );
    Ok(serde_json::from_str(&response.output)?)
}
