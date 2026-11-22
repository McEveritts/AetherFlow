use super::*;

static SAFE_INGRESS_APP_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,47}$").unwrap());

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PrevEnabledVhostState {
    Missing,
    Symlink(PathBuf),
    RegularFile(Vec<u8>, u32),
}

fn ensure_non_symlink_dir(dir: &Path, create_if_missing: bool) -> anyhow::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                anyhow::bail!("refusing non-directory or symlinked path {}", dir.display());
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if create_if_missing {
                fs::create_dir_all(dir)?;
                let meta = fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    anyhow::bail!("refusing non-directory or symlinked path {}", dir.display());
                }
            }
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn read_regular_file_nofollow(path: &Path) -> anyhow::Result<Option<(Vec<u8>, u32)>> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    const LIMIT: u64 = 1024 * 1024;
    let file = match open_confined_file(path, &[]) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "unsafe Apache vhost {}: {err}",
                path.display()
            ))
        }
    };
    let mode = file.metadata()?.permissions().mode() & 0o777;
    let mut buf = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut buf)?;
    anyhow::ensure!(buf.len() as u64 <= LIMIT, "Apache vhost exceeds 1 MiB");
    Ok(Some((buf, mode)))
}

fn snapshot_enabled_vhost(path: &Path) -> anyhow::Result<PrevEnabledVhostState> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(PrevEnabledVhostState::Missing)
        }
        Err(err) => Err(err.into()),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                Ok(PrevEnabledVhostState::Symlink(fs::read_link(path)?))
            } else if meta.is_file() {
                let (bytes, mode) = read_regular_file_nofollow(path)?
                    .ok_or_else(|| anyhow::anyhow!("vhost disappeared during snapshot"))?;
                Ok(PrevEnabledVhostState::RegularFile(bytes, mode))
            } else {
                anyhow::bail!("refusing non-regular enabled vhost path {}", path.display());
            }
        }
    }
}

fn rollback_ingress_vhost(
    avail_path: &Path,
    enabled_path: &Path,
    prev_avail: &Option<(Vec<u8>, u32)>,
    prev_enabled: &PrevEnabledVhostState,
) -> anyhow::Result<()> {
    match prev_enabled {
        PrevEnabledVhostState::Missing => remove_file_if_exists(enabled_path)?,
        PrevEnabledVhostState::Symlink(target) => {
            remove_file_if_exists(enabled_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, enabled_path)?;
            #[cfg(not(unix))]
            let _ = target;
        }
        PrevEnabledVhostState::RegularFile(bytes, mode) => {
            remove_file_if_exists(enabled_path)?;
            write_file_atomically_with_mode(enabled_path, bytes, *mode)?;
        }
    }
    match prev_avail {
        Some((bytes, mode)) => write_file_atomically_with_mode(avail_path, bytes, *mode)?,
        None => remove_file_if_exists(avail_path)?,
    }
    Ok(())
}

pub(crate) fn enable_managed_apache_modules(downstream_tls: bool) -> anyhow::Result<()> {
    let mut modules = vec![
        "proxy",
        "proxy_http",
        "proxy_wstunnel",
        "rewrite",
        "headers",
        "alias",
    ];
    if downstream_tls {
        modules.push("ssl");
    }
    let apache = Path::new("/etc/apache2");
    if !apache.join("mods-available").is_dir() {
        return Ok(());
    }
    modules.retain(|module| {
        !apache
            .join("mods-enabled")
            .join(format!("{module}.load"))
            .is_file()
    });
    if !modules.is_empty() {
        let output = std::process::Command::new("/usr/sbin/a2enmod")
            .args(modules)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "a2enmod failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn run_apache_configtest_if_present() -> anyhow::Result<()> {
    for bin in [
        "/usr/sbin/apache2ctl",
        "/usr/sbin/apachectl",
        "apache2ctl",
        "apachectl",
    ] {
        let mut cmd = Command::new(bin);
        cmd.arg("-t").kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
            Ok(Ok(out)) => {
                if out.status.success() {
                    return Ok(());
                }
                let combined = format!(
                    "{} {}",
                    String::from_utf8_lossy(&out.stderr).trim(),
                    String::from_utf8_lossy(&out.stdout).trim()
                );
                anyhow::bail!("apache2ctl -t failed: {}", combined.trim());
            }
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(Err(err)) => anyhow::bail!("failed to execute {} -t: {}", bin, err),
            Err(_) => anyhow::bail!("{} -t timed out", bin),
        }
    }
    Ok(())
}

async fn reload_apache_if_active() -> anyhow::Result<()> {
    let active_out = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("systemctl")
            .args(["is-active", "--quiet", "apache2"])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let is_active = match active_out {
        Ok(Ok(out)) => out.status.success(),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(Err(err)) => anyhow::bail!("failed to check apache2 status: {}", err),
        Err(_) => anyhow::bail!("systemctl is-active apache2 timed out"),
    };
    if !is_active {
        return Ok(());
    }
    let reload_out = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new("systemctl")
            .args(["reload", "apache2"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("systemctl reload apache2 timed out"))?
    .map_err(|err| anyhow::anyhow!("failed to execute systemctl reload apache2: {}", err))?;
    if !reload_out.status.success() {
        let combined = format!(
            "{} {}",
            String::from_utf8_lossy(&reload_out.stderr).trim(),
            String::from_utf8_lossy(&reload_out.stdout).trim()
        );
        anyhow::bail!("systemctl reload apache2 failed: {}", combined.trim());
    }
    Ok(())
}

pub(crate) fn validate_ingress_vhost_request(req: &RunnerApacheVhostRequest) -> Result<(), String> {
    if !SAFE_INGRESS_APP_NAME.is_match(&req.app_name) {
        return Err("invalid app_name: must match ^[a-z0-9][a-z0-9-]{0,47}$".to_string());
    }
    if get_runner_package_definition(&req.app_name).is_none() {
        return Err("app_name is not in the package catalog".to_string());
    }
    if !req.remove_only && !(1..=65535).contains(&req.listen_port) {
        return Err("listen_port must be in 1..=65535".to_string());
    }
    if let Some(domain) = &req.internal_domain {
        if !domain.eq_ignore_ascii_case(&format!("{}.aether.local", req.app_name)) {
            return Err("invalid internal_domain: expected <app_name>.aether.local".to_string());
        }
    }
    if let Some(domain) = &req.public_domain {
        if !af_models::valid_ingress_hostname(domain)
            || domain.eq_ignore_ascii_case("aether.local")
            || domain.to_ascii_lowercase().ends_with(".aether.local")
        {
            return Err("invalid public_domain".to_string());
        }
    }
    if !req.remove_only && req.external_access_enabled && req.public_domain.is_none() {
        return Err("public_domain is required for external access".to_string());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct VhostBackup {
    avail_path: PathBuf,
    enabled_path: PathBuf,
    prev_avail: Option<(Vec<u8>, u32)>,
    prev_enabled: PrevEnabledVhostState,
}

fn resolve_lifecycle_apache_dir(fs_root: Option<&Path>) -> PathBuf {
    if let Ok(explicit) = env::var("AETHERFLOW_APACHE_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Some(root) = fs_root {
        root.join("etc/apache2")
    } else {
        PathBuf::from("/etc/apache2")
    }
}

pub(crate) fn snapshot_app_vhost_backups(
    app_name: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<Vec<VhostBackup>> {
    if !SAFE_INGRESS_APP_NAME.is_match(app_name) {
        return Ok(Vec::new());
    }
    let apache_dir = resolve_lifecycle_apache_dir(fs_root);
    let avail_dir = apache_dir.join("sites-available");
    let enabled_dir = apache_dir.join("sites-enabled");
    if apache_dir.exists() {
        ensure_non_symlink_dir(&apache_dir, false)?;
    }
    if avail_dir.exists() {
        ensure_non_symlink_dir(&avail_dir, false)?;
    }
    if enabled_dir.exists() {
        ensure_non_symlink_dir(&enabled_dir, false)?;
    }
    let names = [
        format!("aetherflow-app-{app_name}.conf"),
        format!("aetherflow-ext-{app_name}.conf"),
        format!("aetherflow-ext-{app_name}-le-ssl.conf"),
        format!("{app_name}.conf"),
    ];
    let mut backups = Vec::with_capacity(names.len());
    for name in names {
        let avail_path = avail_dir.join(&name);
        let enabled_path = enabled_dir.join(&name);
        let prev_avail = if avail_dir.exists() {
            read_regular_file_nofollow(&avail_path)?
        } else {
            None
        };
        let prev_enabled = if enabled_dir.exists() {
            snapshot_enabled_vhost(&enabled_path)?
        } else {
            PrevEnabledVhostState::Missing
        };
        backups.push(VhostBackup {
            avail_path,
            enabled_path,
            prev_avail,
            prev_enabled,
        });
    }
    Ok(backups)
}

pub(crate) fn restore_app_vhost_backups(backups: &[VhostBackup]) -> anyhow::Result<bool> {
    if backups.is_empty() {
        return Ok(false);
    }
    let mut changed = false;
    for backup in backups {
        let curr_avail = if backup.avail_path.parent().is_some_and(Path::exists) {
            read_regular_file_nofollow(&backup.avail_path)?
        } else {
            None
        };
        let curr_enabled = if backup.enabled_path.parent().is_some_and(Path::exists) {
            snapshot_enabled_vhost(&backup.enabled_path)?
        } else {
            PrevEnabledVhostState::Missing
        };
        if curr_avail != backup.prev_avail || curr_enabled != backup.prev_enabled {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }
    rollback_vhost_backups(backups)?;
    Ok(true)
}

pub(crate) async fn reload_apache_after_rollback_if_live(fs_root: Option<&Path>) {
    if fs_root.is_none()
        && env::var_os("AETHERFLOW_APACHE_DIR").is_none()
        && env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none()
    {
        let _ = reload_apache_if_active().await;
    }
}

fn apply_single_ingress_vhost(
    enabled: bool,
    content: Option<&str>,
    conf_name: &str,
    avail_path: &Path,
    enabled_path: &Path,
) -> anyhow::Result<()> {
    if enabled {
        let body = content.unwrap_or_default();
        write_file_atomically_with_mode(avail_path, body.as_bytes(), 0o644)?;
        remove_file_if_exists(enabled_path)?;
        #[cfg(unix)]
        {
            let target = format!("../sites-available/{conf_name}");
            std::os::unix::fs::symlink(target, enabled_path)?;
        }
    } else {
        remove_file_if_exists(enabled_path)?;
        remove_file_if_exists(avail_path)?;
    }
    Ok(())
}

fn rollback_vhost_backups(backups: &[VhostBackup]) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for backup in backups {
        if let Err(err) = rollback_ingress_vhost(
            &backup.avail_path,
            &backup.enabled_path,
            &backup.prev_avail,
            &backup.prev_enabled,
        ) {
            errors.push(format!("{}: {err}", backup.avail_path.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("; "))
    }
}

pub(crate) async fn apply_ingress_vhost_with_hooks<FTest, FutTest, FReload, FutReload>(
    req: &RunnerApacheVhostRequest,
    apache_dir: &Path,
    configtest_fn: FTest,
    reload_fn: FReload,
) -> anyhow::Result<String>
where
    FTest: FnOnce() -> FutTest,
    FutTest: std::future::Future<Output = anyhow::Result<()>>,
    FReload: FnOnce() -> FutReload,
    FutReload: std::future::Future<Output = anyhow::Result<()>>,
{
    if let Err(msg) = validate_ingress_vhost_request(req) {
        anyhow::bail!("{msg}");
    }

    let internal = req.internal_domain.as_deref().filter(|_| !req.remove_only);
    let external = req
        .public_domain
        .as_deref()
        .filter(|_| !req.remove_only && req.external_access_enabled);
    let any_enabled = internal.is_some() || external.is_some();
    let fs_root = if apache_dir.ends_with("etc/apache2") && apache_dir != Path::new("/etc/apache2")
    {
        apache_dir.parent().and_then(Path::parent)
    } else {
        None
    };
    let upstream = if any_enabled {
        package_executor::apache_upstream_tls(&req.app_name, fs_root)?
    } else {
        Default::default()
    };
    let avail_dir = apache_dir.join("sites-available");
    let enabled_dir = apache_dir.join("sites-enabled");

    if any_enabled {
        ensure_non_symlink_dir(apache_dir, true)?;
        ensure_non_symlink_dir(&avail_dir, true)?;
        ensure_non_symlink_dir(&enabled_dir, true)?;
    } else {
        if apache_dir.exists() {
            ensure_non_symlink_dir(apache_dir, false)?;
        }
        if avail_dir.exists() {
            ensure_non_symlink_dir(&avail_dir, false)?;
        }
        if enabled_dir.exists() {
            ensure_non_symlink_dir(&enabled_dir, false)?;
        }
    }

    let int_conf_name = format!("aetherflow-app-{}.conf", req.app_name);
    let ext_conf_name = format!("aetherflow-ext-{}.conf", req.app_name);
    let ssl_conf_name = format!("aetherflow-ext-{}-le-ssl.conf", req.app_name);
    let legacy_conf_name = format!("{}.conf", req.app_name);
    let targets = [
        &int_conf_name,
        &ext_conf_name,
        &ssl_conf_name,
        &legacy_conf_name,
    ];
    let mut backups = Vec::with_capacity(targets.len());
    for name in targets {
        let avail_path = avail_dir.join(name);
        let enabled_path = enabled_dir.join(name);
        let prev_avail = read_regular_file_nofollow(&avail_path)?;
        let prev_enabled = snapshot_enabled_vhost(&enabled_path)?;
        backups.push(VhostBackup {
            avail_path,
            enabled_path,
            prev_avail,
            prev_enabled,
        });
    }

    let contents = |index: usize| -> anyhow::Result<Vec<&str>> {
        let backup = &backups[index];
        let available = backup.prev_avail.iter().map(|(bytes, _)| bytes);
        let enabled = match &backup.prev_enabled {
            PrevEnabledVhostState::RegularFile(bytes, _) => Some(bytes),
            _ => None,
        };
        available
            .chain(enabled)
            .map(|bytes| Ok(std::str::from_utf8(bytes)?))
            .collect()
    };
    let legacy = if any_enabled {
        contents(3)?
    } else {
        Vec::new()
    };
    let int_existing = if internal.is_some() {
        contents(0)?
    } else {
        Vec::new()
    };
    let mut ext_existing = Vec::new();
    if external.is_some() {
        ext_existing.extend(contents(1)?);
        ext_existing.extend(contents(2)?);
    }
    let int_body = internal
        .map(|domain| {
            package_executor::render_managed_apache_vhost(
                req,
                domain,
                true,
                &upstream,
                fs_root,
                &int_existing,
                &legacy,
            )
        })
        .transpose()?;
    let ext_body = external
        .map(|domain| {
            package_executor::render_managed_apache_vhost(
                req,
                domain,
                false,
                &upstream,
                fs_root,
                &ext_existing,
                &legacy,
            )
        })
        .transpose()?;

    let write_result = (|| -> anyhow::Result<()> {
        for ((name, body), backup) in targets
            .into_iter()
            .zip([int_body.as_deref(), ext_body.as_deref(), None])
            .zip(&backups)
        {
            apply_single_ingress_vhost(
                body.is_some(),
                body,
                name,
                &backup.avail_path,
                &backup.enabled_path,
            )?;
        }
        if any_enabled {
            let backup = &backups[3];
            let update = |bytes: &[u8]| -> anyhow::Result<String> {
                package_executor::update_legacy_apache_vhost(
                    std::str::from_utf8(bytes)?,
                    req,
                    &upstream,
                    fs_root,
                    false,
                )
            };
            if let Some((bytes, mode)) = &backup.prev_avail {
                let body = update(bytes)?;
                if body.as_bytes() != bytes {
                    write_file_atomically_with_mode(&backup.avail_path, body.as_bytes(), *mode)?;
                }
            }
            if let PrevEnabledVhostState::RegularFile(bytes, mode) = &backup.prev_enabled {
                let body = update(bytes)?;
                if body.as_bytes() != bytes {
                    write_file_atomically_with_mode(&backup.enabled_path, body.as_bytes(), *mode)?;
                }
            }
        }
        Ok(())
    })();
    if let Err(err) = write_result {
        if let Err(rb_err) = rollback_vhost_backups(&backups) {
            anyhow::bail!("{err}; rollback failed: {rb_err}");
        }
        return Err(err);
    }

    if let Err(test_err) = configtest_fn().await {
        if let Err(rb_err) = rollback_vhost_backups(&backups) {
            anyhow::bail!("{test_err}; rollback failed: {rb_err}");
        }
        return Err(test_err);
    }

    if req.reload_apache {
        if let Err(reload_err) = reload_fn().await {
            if let Err(rb_err) = rollback_vhost_backups(&backups) {
                anyhow::bail!("{reload_err}; rollback failed: {rb_err}");
            }
            return Err(reload_err);
        }
    }

    Ok(format!(
        "synced apache vhosts ({}={}, {}={})",
        int_conf_name,
        if internal.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        ext_conf_name,
        if external.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    ))
}

pub(crate) async fn handle_ingress_vhost(
    Json(req): Json<RunnerApacheVhostRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if let Err(msg) = validate_ingress_vhost_request(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: msg,
            }),
        );
    }

    let apache_dir = resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2");
    let res = sync_apache_vhost_local(&req, &apache_dir).await;

    match res {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            }),
        ),
    }
}

pub async fn sync_apache_vhost_local(
    req: &RunnerApacheVhostRequest,
    apache_dir: &Path,
) -> anyhow::Result<String> {
    validate_ingress_vhost_request(req).map_err(anyhow::Error::msg)?;
    static VHOST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = VHOST_LOCK.lock().await;
    let live = apache_dir == Path::new("/etc/apache2");
    if live && !req.remove_only && unsafe { libc::geteuid() } == 0 {
        let tls = req.tls_enabled || matches!(req.app_name.as_str(), "kasmvnc" | "librespeed");
        tokio::task::spawn_blocking(move || enable_managed_apache_modules(tls)).await??;
    }
    apply_ingress_vhost_with_hooks(
        req,
        apache_dir,
        || async {
            if live {
                run_apache_configtest_if_present().await
            } else {
                Ok(())
            }
        },
        || async {
            if live {
                reload_apache_if_active().await
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn sync_apache_vhost_via_runner(
    req: &RunnerApacheVhostRequest,
) -> anyhow::Result<RunnerResponse> {
    if let Err(msg) = validate_ingress_vhost_request(req) {
        anyhow::bail!("{msg}");
    }
    let result = post_runner_json("/v1/ingress/vhost", req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!("runner ingress vhost error: {}", result.error);
    }
    Ok(result)
}

pub(crate) async fn execute_certbot_sync_with_candidates(
    candidates: &[&Path],
    require_root_owner: bool,
    timeout: Duration,
) -> anyhow::Result<String> {
    let mut selected: Option<&Path> = None;
    for candidate in candidates {
        match fs::symlink_metadata(candidate) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing symlinked certbot-sync executable: {}",
                        candidate.display()
                    );
                }
                if !meta.is_file() {
                    anyhow::bail!(
                        "refusing non-regular certbot-sync path: {}",
                        candidate.display()
                    );
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if require_root_owner && meta.uid() != 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} must be owned by root",
                            candidate.display()
                        );
                    }
                    let mode = meta.mode();
                    if (mode & 0o022) != 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} must not be group/world writable",
                            candidate.display()
                        );
                    }
                    if (mode & 0o111) == 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} is not executable",
                            candidate.display()
                        );
                    }
                }
                #[cfg(not(unix))]
                let _ = require_root_owner;
                selected = Some(candidate);
                break;
            }
        }
    }

    let bin = selected.ok_or_else(|| {
        anyhow::anyhow!("af-certbot-sync executable not found in /usr/local/bin or /usr/bin")
    })?;

    let mut cmd = Command::new(bin);
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("af-certbot-sync timed out after {}s", timeout.as_secs()))?
        .map_err(|err| anyhow::anyhow!("failed to execute {}: {}", bin.display(), err))?;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        let combined = [stdout, stderr]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        anyhow::bail!(
            "af-certbot-sync exited with {:?}: {}",
            out.status.code(),
            combined
        );
    }
    Ok(if stdout.is_empty() {
        "certbot-sync completed".to_string()
    } else {
        stdout
    })
}

pub async fn sync_certbot_and_managed_ingress() -> anyhow::Result<String> {
    static CERTBOT_SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _lock = CERTBOT_SYNC_LOCK.lock().await;
    let candidates = [
        Path::new("/usr/local/bin/af-certbot-sync"),
        Path::new("/usr/bin/af-certbot-sync"),
    ];
    let output =
        execute_certbot_sync_with_candidates(&candidates, true, Duration::from_secs(120)).await?;
    let apache_dir = resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2");
    let active = apache_dir.join("sites-enabled");
    if !active.is_dir() {
        return Ok(output);
    }
    let configs = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<(String, String, i32)>> {
        let conn = open_runner_state_database(None)?;
        let mut stmt = conn.prepare(
            "SELECT app_name, public_domain, listen_port FROM app_ingress_configs \
             WHERE external_access_enabled = 1 AND tls_enabled = 1 AND public_domain <> '' AND listen_port > 0",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }).await??;
    for (app_name, domain, listen_port) in configs {
        if !SAFE_INGRESS_APP_NAME.is_match(&app_name)
            || !active
                .join(format!("aetherflow-ext-{app_name}.conf"))
                .is_file()
        {
            continue;
        }
        let req = RunnerApacheVhostRequest {
            internal_domain: active
                .join(format!("aetherflow-app-{app_name}.conf"))
                .is_file()
                .then(|| format!("{app_name}.aether.local")),
            app_name,
            public_domain: Some(domain),
            listen_port,
            external_access_enabled: true,
            tls_enabled: true,
            reload_apache: true,
            ..Default::default()
        };
        validate_ingress_vhost_request(&req).map_err(anyhow::Error::msg)?;
        sync_apache_vhost_local(&req, &apache_dir).await?;
    }
    Ok(output)
}

pub(crate) async fn handle_certbot_sync() -> (StatusCode, Json<RunnerResponse>) {
    match sync_certbot_and_managed_ingress().await {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            }),
        ),
    }
}

pub async fn trigger_certbot_sync_via_runner() -> anyhow::Result<RunnerResponse> {
    let result = post_runner_json("/v1/certbot-sync", &json!({}), Duration::from_secs(130)).await?;
    if !result.success {
        anyhow::bail!("runner certbot-sync error: {}", result.error);
    }
    Ok(result)
}
