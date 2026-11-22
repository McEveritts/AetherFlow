use std::path::{Path as StdPath, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DeploySnapshotPrior {
    /// Confirmed absent prior to deploy (`symlink_metadata` returned `NotFound`).
    ConfirmedAbsent,
    /// Regular file captured with prior contents and POSIX permission mode.
    RegularFile { bytes: Vec<u8>, mode: u32 },
    /// Symbolic link captured with its target path.
    Symlink { target: PathBuf },
    /// Path existed or could not be confirmed absent (e.g., `EACCES` on a 0600 config file).
    /// Must never be deleted or overwritten by unprivileged rollback.
    Unreadable { reason: String },
}

#[derive(Clone, Debug)]
pub(super) struct DeployFileSnapshot {
    pub(super) path: PathBuf,
    pub(super) prior: DeploySnapshotPrior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeployStage {
    BeforeHostMutation,
    HostConfigMutated { target_port: i32 },
    IngressPersisted { target_port: i32 },
}

#[derive(Clone, Debug)]
struct DeployRestoreFailure {
    path: PathBuf,
    was_confirmed_absent: bool,
    error: String,
}

#[derive(Debug, Default)]
struct RestoreFilesOutcome {
    apache_restored: bool,
    systemd_unit_restored: bool,
    apache_failures: Vec<DeployRestoreFailure>,
    native_failures: Vec<DeployRestoreFailure>,
    unreadable_apache: Vec<(PathBuf, String)>,
    unreadable_native: Vec<(PathBuf, String)>,
    systemd_units_touched: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct DeployRollbackReport {
    pub(super) apache_restored: bool,
    pub(super) systemd_unit_restored: bool,
    pub(super) unrestored_paths: Vec<String>,
    pub(super) errors: Vec<String>,
    pub(super) warnings: Vec<String>,
    pub(super) fully_reverted: bool,
}

impl DeployRollbackReport {
    pub(super) fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.unrestored_paths.is_empty() {
            parts.push(format!(
                "unrestored paths: {}",
                self.unrestored_paths.join(", ")
            ));
        }
        if !self.errors.is_empty() {
            parts.push(self.errors.join("; "));
        }
        if !self.warnings.is_empty() {
            parts.push(format!("warnings: {}", self.warnings.join("; ")));
        }
        if parts.is_empty() {
            "rollback status unknown".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

/// Captures a pre-deploy snapshot while distinguishing confirmed `NotFound`
/// from permission/metadata/read errors (`EACCES`, non-regular files, TOCTOU races).
pub(super) fn read_deploy_snapshot(path: &StdPath) -> DeploySnapshotPrior {
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return DeploySnapshotPrior::ConfirmedAbsent;
        }
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("metadata lookup failed: {err}"),
            };
        }
    };
    if lmeta.file_type().is_symlink() {
        return match std::fs::read_link(path) {
            Ok(target) => DeploySnapshotPrior::Symlink { target },
            Err(err) => DeploySnapshotPrior::Unreadable {
                reason: format!("read_link failed: {err}"),
            },
        };
    }
    if !lmeta.is_file() {
        return DeploySnapshotPrior::Unreadable {
            reason: "non-regular file".to_string(),
        };
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match opts.open(path) {
        Ok(file) => file,
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("open failed: {err}"),
            };
        }
    };
    let fmeta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => {
            return DeploySnapshotPrior::Unreadable {
                reason: format!("fstat failed: {err}"),
            };
        }
    };
    if !fmeta.is_file() {
        return DeploySnapshotPrior::Unreadable {
            reason: "non-regular file after open".to_string(),
        };
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if lmeta.dev() != fmeta.dev() || lmeta.ino() != fmeta.ino() {
            return DeploySnapshotPrior::Unreadable {
                reason: "file identity changed during snapshot".to_string(),
            };
        }
        fmeta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600u32;

    let mut bytes = Vec::new();
    if let Err(err) = std::io::Read::read_to_end(&mut file, &mut bytes) {
        return DeploySnapshotPrior::Unreadable {
            reason: format!("read failed: {err}"),
        };
    }
    DeploySnapshotPrior::RegularFile {
        bytes,
        mode: if mode == 0 { 0o600 } else { mode },
    }
}

fn prepare_restore_parent_and_tmp(path: &StdPath) -> std::io::Result<PathBuf> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "missing parent directory",
        ));
    };
    if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
        if pmeta.file_type().is_symlink() || !pmeta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing symlink parent directory",
            ));
        }
    } else {
        std::fs::create_dir_all(parent)?;
    }
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deploy");
    Ok(parent.join(format!(
        ".{fname}.restore.{}.tmp",
        uuid::Uuid::new_v4().simple()
    )))
}

fn write_atomic_nofollow_mode(path: &StdPath, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let tmp_path = prepare_restore_parent_and_tmp(path)?;
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if existing.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to overwrite symlink target",
            ));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut tmp_file = opts.open(&tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let effective_mode = if mode == 0 { 0o600 } else { mode & 0o777 };
        if let Err(err) = tmp_file.set_permissions(std::fs::Permissions::from_mode(effective_mode))
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
    }
    if let Err(err) = tmp_file.write_all(bytes).and_then(|()| tmp_file.sync_all()) {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    drop(tmp_file);
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(unix)]
fn restore_symlink_nofollow(path: &StdPath, target: &StdPath) -> std::io::Result<()> {
    let tmp_path = prepare_restore_parent_and_tmp(path)?;
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if existing.is_dir() && !existing.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to replace directory with symlink",
            ));
        }
    }
    std::os::unix::fs::symlink(target, &tmp_path)?;
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(not(unix))]
fn restore_symlink_nofollow(_path: &StdPath, _target: &StdPath) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink restoration unsupported on this platform",
    ))
}

pub(super) fn snapshot_deploy_files(bp: &af_services::AppBlueprint) -> Vec<DeployFileSnapshot> {
    let mut snapshots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push_rel = |rel: &str| {
        if rel.trim().is_empty() {
            return;
        }
        let resolved = af_services::mutators::resolve_config_path(rel);
        if !resolved.as_os_str().is_empty() && seen.insert(resolved.clone()) {
            let prior = read_deploy_snapshot(&resolved);
            snapshots.push(DeployFileSnapshot {
                path: resolved,
                prior,
            });
        }
    };

    push_rel(&bp.config_file_path);
    for native_path in
        af_runner::blueprint::native_app_spec(&bp.app_name, &bp.config_file_path).config_paths
    {
        push_rel(&native_path);
    }
    match bp.app_name.as_str() {
        "transmission" => {
            push_rel("/var/lib/transmission-daemon/info/settings.json");
            push_rel("/var/lib/transmission-daemon/.config/transmission-daemon/settings.json");
        }
        "overseerr" | "jellyseerr" => {
            push_rel(&format!("/var/lib/{}/config/settings.json", bp.app_name));
            push_rel(&format!("/var/lib/{}/settings.json", bp.app_name));
        }
        "listenarr" => {
            push_rel("/var/lib/listenarr/config.xml");
            push_rel("/var/lib/listenarr/config/config.xml");
        }
        _ => {}
    }

    for vhost_rel in [
        format!(
            "/etc/apache2/sites-available/aetherflow-app-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-app-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-available/aetherflow-ext-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-ext-{}.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-available/aetherflow-ext-{}-le-ssl.conf",
            bp.app_name
        ),
        format!(
            "/etc/apache2/sites-enabled/aetherflow-ext-{}-le-ssl.conf",
            bp.app_name
        ),
        format!("/etc/apache2/sites-available/{}.conf", bp.app_name),
        format!("/etc/apache2/sites-enabled/{}.conf", bp.app_name),
    ] {
        push_rel(&vhost_rel);
    }
    snapshots
}

fn is_apache2_deploy_path(path: &StdPath) -> bool {
    let apache_root = af_services::mutators::resolve_config_path("/etc/apache2");
    (!apache_root.as_os_str().is_empty() && path.starts_with(&apache_root))
        || path.starts_with("/etc/apache2")
        || path.to_string_lossy().contains("/etc/apache2/")
}

fn is_systemd_unit_deploy_path(path: &StdPath) -> bool {
    let unit_root = af_services::mutators::resolve_config_path("/etc/systemd/system");
    let in_systemd_dir = (!unit_root.as_os_str().is_empty() && path.starts_with(&unit_root))
        || path.starts_with("/etc/systemd/system")
        || path.to_string_lossy().contains("/etc/systemd/system/");
    in_systemd_dir
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("service"))
}

fn record_restored_path(outcome: &mut RestoreFilesOutcome, path: &StdPath) {
    if is_apache2_deploy_path(path) {
        outcome.apache_restored = true;
    }
    if is_systemd_unit_deploy_path(path) {
        outcome.systemd_unit_restored = true;
        outcome.systemd_units_touched.push(path.to_path_buf());
    }
}

fn record_restore_failure(
    outcome: &mut RestoreFilesOutcome,
    path: &StdPath,
    was_confirmed_absent: bool,
    error: String,
) {
    let failure = DeployRestoreFailure {
        path: path.to_path_buf(),
        was_confirmed_absent,
        error,
    };
    if is_apache2_deploy_path(path) {
        outcome.apache_failures.push(failure);
    } else {
        outcome.native_failures.push(failure);
    }
}

fn restore_deploy_files(snapshots: &[DeployFileSnapshot]) -> RestoreFilesOutcome {
    let mut outcome = RestoreFilesOutcome::default();
    for snap in snapshots {
        match &snap.prior {
            DeploySnapshotPrior::RegularFile { bytes, mode } => {
                let unchanged = match read_deploy_snapshot(&snap.path) {
                    DeploySnapshotPrior::RegularFile {
                        bytes: cur_bytes,
                        mode: cur_mode,
                    } => &cur_bytes == bytes && cur_mode == *mode,
                    _ => false,
                };
                if unchanged {
                    continue;
                }
                match write_atomic_nofollow_mode(&snap.path, bytes, *mode) {
                    Ok(()) => record_restored_path(&mut outcome, &snap.path),
                    Err(err) => record_restore_failure(
                        &mut outcome,
                        &snap.path,
                        false,
                        format!("failed to restore {}: {err}", snap.path.display()),
                    ),
                }
            }
            DeploySnapshotPrior::Symlink { target } => {
                let unchanged = match std::fs::symlink_metadata(&snap.path) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        std::fs::read_link(&snap.path).ok().as_ref() == Some(target)
                    }
                    _ => false,
                };
                if unchanged {
                    continue;
                }
                match restore_symlink_nofollow(&snap.path, target) {
                    Ok(()) => record_restored_path(&mut outcome, &snap.path),
                    Err(err) => record_restore_failure(
                        &mut outcome,
                        &snap.path,
                        false,
                        format!("failed to restore symlink {}: {err}", snap.path.display()),
                    ),
                }
            }
            DeploySnapshotPrior::ConfirmedAbsent => match std::fs::symlink_metadata(&snap.path) {
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => record_restore_failure(
                    &mut outcome,
                    &snap.path,
                    true,
                    format!(
                        "failed to verify absence of {} during rollback: {err}",
                        snap.path.display()
                    ),
                ),
                Ok(meta) if meta.is_file() || meta.file_type().is_symlink() => {
                    match std::fs::remove_file(&snap.path) {
                        Ok(()) => record_restored_path(&mut outcome, &snap.path),
                        Err(err) => record_restore_failure(
                            &mut outcome,
                            &snap.path,
                            true,
                            format!("failed to remove new file {}: {err}", snap.path.display()),
                        ),
                    }
                }
                Ok(_) => record_restore_failure(
                    &mut outcome,
                    &snap.path,
                    true,
                    format!(
                        "refusing to remove non-regular path {} created during deploy",
                        snap.path.display()
                    ),
                ),
            },
            DeploySnapshotPrior::Unreadable { reason } => {
                // Never delete or overwrite a file that existed (or could not be confirmed
                // absent) before deploy; record it for privileged fallback / operator report.
                if is_apache2_deploy_path(&snap.path) {
                    outcome
                        .unreadable_apache
                        .push((snap.path.clone(), reason.clone()));
                } else {
                    outcome
                        .unreadable_native
                        .push((snap.path.clone(), reason.clone()));
                }
            }
        }
    }
    outcome
}

fn push_unique_string(target: &mut Vec<String>, item: String) {
    if !target.contains(&item) {
        target.push(item);
    }
}

async fn reload_systemd_units_after_rollback(
    touched_units: &[PathBuf],
    is_real_host: bool,
) -> Result<(), String> {
    if touched_units.is_empty() || !is_real_host {
        return Ok(());
    }
    if unsafe { libc::geteuid() } == 0 {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::process::Command::new("systemctl")
                .arg("daemon-reload")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| "systemctl daemon-reload timed out after 15s".to_string())?
        .map_err(|err| format!("failed to execute systemctl daemon-reload: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(());
    }
    let unit_list = touched_units
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "reverted systemd unit(s) [{unit_list}] require 'systemctl daemon-reload', which cannot be executed by unprivileged af-api (runner /v1/systemctl does not expose daemon-reload)"
    ))
}

pub(super) async fn rollback_deploy_files_inner(
    snapshots: &[DeployFileSnapshot],
    bp: Option<&af_services::AppBlueprint>,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    mutated_target_port: Option<i32>,
    host_mutation_attempted: bool,
    is_real_host: bool,
) -> DeployRollbackReport {
    if !host_mutation_attempted {
        return DeployRollbackReport {
            fully_reverted: true,
            ..Default::default()
        };
    }

    let outcome = restore_deploy_files(snapshots);
    let mut report = DeployRollbackReport {
        apache_restored: outcome.apache_restored,
        systemd_unit_restored: outcome.systemd_unit_restored,
        fully_reverted: true,
        ..Default::default()
    };
    let mut apache_reloaded_by_runner = false;
    let apache_live_runner = af_services::mutators::resolve_config_path("/etc/apache2")
        == StdPath::new("/etc/apache2")
        && af_runner::is_runner_available();

    if !outcome.apache_failures.is_empty() || !outcome.unreadable_apache.is_empty() {
        let mut fallback_handled = false;
        if let (Some(bp), Some(target_port)) = (bp, mutated_target_port.filter(|p| *p > 0)) {
            if apache_live_runner {
                if let Some(prior) = prior_ingress.filter(|cfg| cfg.listen_port > 0) {
                    let internal_domain = (!bp.internal_domain.trim().is_empty())
                        .then(|| bp.internal_domain.trim().to_ascii_lowercase());
                    let base_domain = af_services::resolve_base_domain();
                    let public_domain = {
                        let candidate = prior.public_domain.trim().to_ascii_lowercase();
                        if !candidate.is_empty() {
                            Some(candidate)
                        } else {
                            let fallback =
                                af_services::format_app_public_domain(&bp.app_name, &base_domain);
                            (!fallback.is_empty()).then_some(fallback)
                        }
                    };
                    let req = af_models::RunnerApacheVhostRequest {
                        app_name: bp.app_name.clone(),
                        listen_port: prior.listen_port,
                        internal_domain,
                        public_domain,
                        external_access_enabled: prior.external_access_enabled,
                        tls_enabled: prior.tls_enabled,
                        remove_only: false,
                        reload_apache: true,
                    };
                    match af_runner::sync_apache_vhost_via_runner(&req).await {
                        Ok(_) => {
                            fallback_handled = true;
                            apache_reloaded_by_runner = true;
                            report.apache_restored = true;
                            if !outcome.unreadable_apache.is_empty() {
                                report.warnings.push(format!(
                                    "unreadable Apache vhost(s) re-synchronized to prior port {} via runner /v1/ingress/vhost",
                                    prior.listen_port
                                ));
                            }
                        }
                        Err(err) => {
                            report.fully_reverted = false;
                            report.errors.push(format!(
                                "privileged Apache vhost rollback to port {} failed (after deploy target port {target_port}): {err}",
                                prior.listen_port
                            ));
                        }
                    }
                } else if prior_ingress.is_none()
                    && outcome.unreadable_apache.is_empty()
                    && outcome
                        .apache_failures
                        .iter()
                        .all(|f| f.was_confirmed_absent)
                {
                    let req = af_models::RunnerApacheVhostRequest {
                        app_name: bp.app_name.clone(),
                        remove_only: true,
                        reload_apache: true,
                        ..Default::default()
                    };
                    match af_runner::sync_apache_vhost_via_runner(&req).await {
                        Ok(_) => {
                            fallback_handled = true;
                            apache_reloaded_by_runner = true;
                            report.apache_restored = true;
                        }
                        Err(err) => {
                            report.fully_reverted = false;
                            report.errors.push(format!(
                                "privileged Apache vhost removal via runner failed: {err}"
                            ));
                        }
                    }
                }
            }
        }
        if !fallback_handled {
            report.fully_reverted = false;
            for failure in &outcome.apache_failures {
                push_unique_string(
                    &mut report.unrestored_paths,
                    failure.path.display().to_string(),
                );
                report.errors.push(failure.error.clone());
            }
            for (path, reason) in &outcome.unreadable_apache {
                push_unique_string(&mut report.unrestored_paths, path.display().to_string());
                report.errors.push(format!(
                    "prior Apache vhost {} could not be read before deploy ({reason}); preserved untouched without removal",
                    path.display()
                ));
            }
        }
    }

    if report.apache_restored && !apache_reloaded_by_runner {
        if let Err(err) = af_services::runner_systemctl("reload", "apache2").await {
            tracing::warn!(
                error = %err,
                "deploy rollback restored Apache vhost files but reloading apache2 failed"
            );
            report.fully_reverted = false;
            report.errors.push(format!(
                "restored Apache vhost files, but reloading apache2 failed: {err}"
            ));
        }
    }

    let mut runner_reloaded_systemd = false;
    if !outcome.native_failures.is_empty() || !outcome.unreadable_native.is_empty() {
        let mut fallback_attempted = false;
        let mut fallback_succeeded = false;
        if let (Some(bp), Some(prior), Some(target_port)) = (
            bp,
            prior_ingress.filter(|cfg| cfg.listen_port > 0),
            mutated_target_port.filter(|p| *p > 0),
        ) {
            if prior.listen_port != target_port
                && !af_runner::blueprint::has_config_root()
                && af_runner::is_runner_available()
            {
                fallback_attempted = true;
                let req = af_models::RunnerBlueprintApplyRequest {
                    app_name: bp.app_name.clone(),
                    listen_port: prior.listen_port,
                    lifecycle_job_id: String::new(),
                };
                match af_runner::dispatch_blueprint_apply(&req).await {
                    Ok(_) => {
                        fallback_succeeded = true;
                        let touched_systemd = outcome
                            .native_failures
                            .iter()
                            .any(|f| is_systemd_unit_deploy_path(&f.path))
                            || outcome
                                .unreadable_native
                                .iter()
                                .any(|(p, _)| is_systemd_unit_deploy_path(p));
                        if touched_systemd {
                            runner_reloaded_systemd = true;
                            report.systemd_unit_restored = true;
                        }
                        for failure in &outcome.native_failures {
                            let verified = snapshots
                                .iter()
                                .find(|s| s.path == failure.path)
                                .is_some_and(|snap| match &snap.prior {
                                    DeploySnapshotPrior::RegularFile { .. }
                                    | DeploySnapshotPrior::Symlink { .. }
                                    | DeploySnapshotPrior::ConfirmedAbsent => {
                                        read_deploy_snapshot(&failure.path) == snap.prior
                                    }
                                    DeploySnapshotPrior::Unreadable { .. } => false,
                                });
                            if !verified {
                                report.fully_reverted = false;
                                push_unique_string(
                                    &mut report.unrestored_paths,
                                    failure.path.display().to_string(),
                                );
                                report.errors.push(format!(
                                    "{}; privileged blueprint fallback did not restore exact prior contents",
                                    failure.error
                                ));
                            }
                        }
                        for (path, _) in &outcome.unreadable_native {
                            report.warnings.push(format!(
                                "unreadable prior file {} was preserved and re-applied to prior port {} via runner /v1/blueprint/apply (non-port fields cannot be byte-verified without runner snapshot)",
                                path.display(),
                                prior.listen_port
                            ));
                        }
                    }
                    Err(err) => {
                        report.fully_reverted = false;
                        report.errors.push(format!(
                            "privileged blueprint rollback to port {} via runner failed: {err}",
                            prior.listen_port
                        ));
                    }
                }
            }
        }
        if !fallback_attempted || !fallback_succeeded {
            report.fully_reverted = false;
            for failure in &outcome.native_failures {
                push_unique_string(
                    &mut report.unrestored_paths,
                    failure.path.display().to_string(),
                );
                report.errors.push(failure.error.clone());
            }
            for (path, reason) in &outcome.unreadable_native {
                push_unique_string(&mut report.unrestored_paths, path.display().to_string());
                report.errors.push(format!(
                    "prior file {} could not be read before deploy ({reason}); preserved untouched without removal and cannot be auto-reverted by unprivileged API",
                    path.display()
                ));
            }
        }
    }

    if !outcome.systemd_units_touched.is_empty() && !runner_reloaded_systemd {
        if let Err(err) =
            reload_systemd_units_after_rollback(&outcome.systemd_units_touched, is_real_host).await
        {
            report.fully_reverted = false;
            report.errors.push(err);
        }
    }

    report
}

async fn rollback_deploy_files_with_context(
    snapshots: &[DeployFileSnapshot],
    bp: Option<&af_services::AppBlueprint>,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    mutated_target_port: Option<i32>,
    host_mutation_attempted: bool,
) -> DeployRollbackReport {
    let is_real_host = !af_runner::blueprint::has_config_root() && cfg!(target_os = "linux");
    rollback_deploy_files_inner(
        snapshots,
        bp,
        prior_ingress,
        mutated_target_port,
        host_mutation_attempted,
        is_real_host,
    )
    .await
}

#[cfg(test)]
pub(super) async fn rollback_deploy_files(snapshots: &[DeployFileSnapshot]) -> bool {
    let report = rollback_deploy_files_with_context(snapshots, None, None, None, true).await;
    report.apache_restored && report.fully_reverted
}

pub(super) async fn finalize_failed_deploy_rollback(
    bp: &af_services::AppBlueprint,
    service_unit: &str,
    transmission_stopped: bool,
    stage: DeployStage,
    prior_ingress: Option<&af_models::AppIngressConfig>,
    file_snapshots: &[DeployFileSnapshot],
) -> DeployRollbackReport {
    let (host_mutation_attempted, mutated_target_port) = match stage {
        DeployStage::BeforeHostMutation => (false, None),
        DeployStage::HostConfigMutated { target_port }
        | DeployStage::IngressPersisted { target_port } => (true, Some(target_port)),
    };

    let mut report = rollback_deploy_files_with_context(
        file_snapshots,
        Some(bp),
        prior_ingress,
        mutated_target_port,
        host_mutation_attempted,
    )
    .await;

    if transmission_stopped {
        if report.fully_reverted {
            if let Err(start_err) = af_services::control_service(service_unit, "start").await {
                report.fully_reverted = false;
                report.errors.push(format!(
                    "failed to restart {service_unit} after rollback: {start_err}"
                ));
            }
        } else {
            report.errors.push(format!(
                "{service_unit} was not restarted because configuration rollback did not complete cleanly"
            ));
        }
    }

    if matches!(stage, DeployStage::IngressPersisted { .. }) {
        if report.fully_reverted {
            let db_revert = match prior_ingress {
                Some(prior) => af_db::set_app_ingress_config(prior),
                None => af_db::delete_app_ingress_config(&bp.app_name),
            };
            if let Err(db_err) = db_revert {
                report.fully_reverted = false;
                report.errors.push(format!(
                    "host state reverted, but failed to revert SQLite ingress configuration: {db_err}"
                ));
            }
        } else {
            report.errors.push(
                "SQLite ingress configuration was NOT reverted because host rollback failed; keeping persisted ingress in sync with host state".to_string(),
            );
        }
    } else if host_mutation_attempted && !report.fully_reverted {
        report.warnings.push(
            "SQLite ingress was not modified before failure, but host files may remain partially mutated".to_string(),
        );
    }

    report
}

pub(super) fn is_transmission_deploy_unit(app_name: &str, service_unit: &str) -> bool {
    let unit_clean = service_unit.trim().trim_end_matches(".service");
    app_name.eq_ignore_ascii_case("transmission")
        || unit_clean.eq_ignore_ascii_case("transmission-daemon")
        || unit_clean.eq_ignore_ascii_case("transmission")
}
