use crate::cli::{BackupCliCommand, BackupCreateKind, GlobalOptions};
use crate::error::{CliError, CliResponseEnvelope, CliResult};
use crate::provision::is_effective_root_user;
use af_host::{
    assemble_verified_chunks, create_host_archive_backup, create_sqlite_snapshot_backup,
    delete_backup_artifacts, execute_destructive_restore, list_backup_inventory,
    maintenance_helper_ownership_registry, plan_restore_from_manifest_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid, prune_backup_inventory,
    safe_backup_file_path, split_backup_into_chunks, verify_backup_artifact_with_trusted_uid,
    BackupManifest, HostBackupConfig, RestorePlan, RestorePreflightOptions,
};
use serde_json::json;
use std::path::{Path, PathBuf};

/// Resolves the running host version from `af_release::runtime::runtime_version_for_root`
/// (honoring `<root>/opt/AetherFlow/current/.version` when `--root` is supplied), validates it
/// as a semver triplet via `af_host::parse_semver_triplet`, and falls back to
/// `concat!("v", env!("CARGO_PKG_VERSION"))` for non-semver or empty stamps.
pub(crate) fn resolve_runtime_host_version(isolated_root: Option<&Path>) -> String {
    let candidate = af_release::runtime::runtime_version_for_root(isolated_root);
    if af_host::parse_semver_triplet(&candidate).is_ok() {
        candidate
    } else {
        concat!("v", env!("CARGO_PKG_VERSION")).to_string()
    }
}

pub(crate) fn target_requires_live_quiescence(
    global: &GlobalOptions,
    resolved_target: &Path,
    active_db_path: Option<&Path>,
) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    if global.root.is_some() && resolved_target != Path::new("/") {
        return false;
    }
    let target_contains_active_db =
        af_models::resolve_contained_sqlite_restore_override(resolved_target, active_db_path)
            .is_some();
    resolved_target == Path::new("/")
        || is_system_scoped_backup_path(resolved_target)
        || target_contains_active_db
}

pub(crate) fn resolve_backup_config(
    global: &GlobalOptions,
    explicit_backup_dir: Option<&Path>,
    explicit_db_path: Option<&Path>,
    app_version: &str,
) -> CliResult<HostBackupConfig> {
    let active_db = af_models::try_resolve_active_db_path_from_env(
        global.root.as_deref(),
        "/var/lib/aetherflow/aetherflow.sqlite",
    )
    .map_err(CliError::Validation)?;
    let active_backup_dir = af_models::try_resolve_active_backup_dir_from_env(
        global.root.as_deref(),
        Some(&active_db),
        "/var/lib/aetherflow/backups",
    )
    .map_err(CliError::Validation)?;
    let (env_trusted_uid, _) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(global.root.as_deref())
            .map_err(CliError::Validation)?;

    let mut cfg = if let Some(ref root) = global.root {
        let mut isolated_cfg = HostBackupConfig::for_isolated_root(root, app_version);
        isolated_cfg.backup_dir = active_backup_dir;
        isolated_cfg.sqlite_db_path = Some(active_db);
        isolated_cfg
    } else {
        let mut base = HostBackupConfig::for_isolated_root(Path::new("/"), app_version);
        base.backup_dir = active_backup_dir;
        base.sqlite_db_path = Some(active_db);
        base
    };
    cfg.snapshot_options.trusted_source_uid = env_trusted_uid;
    if let Some(bdir) = explicit_backup_dir {
        if let Some(ref root) = global.root {
            let validated_bdir =
                af_models::validate_path_within_isolated_root(bdir, root, "--backup-dir")
                    .map_err(CliError::Validation)?;
            cfg.backup_dir = validated_bdir;
        } else {
            cfg.backup_dir = bdir.to_path_buf();
        }
    }
    if let Some(db) = explicit_db_path {
        if let Some(ref root) = global.root {
            let validated_db = af_models::validate_path_within_isolated_root(db, root, "--db-path")
                .map_err(CliError::Validation)?;
            cfg.sqlite_db_path = Some(validated_db);
        } else {
            cfg.sqlite_db_path = Some(db.to_path_buf());
        }
    }
    Ok(cfg)
}

fn require_backup_write_privilege(
    global: &GlobalOptions,
    backup_dir: &Path,
    operator_privileged: bool,
    operation: &str,
) -> CliResult<()> {
    if global.dry_run || global.root.is_some() || operator_privileged || is_effective_root_user() {
        return Ok(());
    }
    let is_system_path = backup_dir.starts_with("/var/lib/aetherflow")
        || backup_dir.starts_with("/etc")
        || backup_dir.starts_with("/opt");
    if is_system_path {
        return Err(CliError::PrivilegeRequired(format!(
            "local backup operation '{}' on system path '{}' requires root privileges (UID 0), '--operator-privileged', or an isolated '--root <dir>'",
            operation,
            backup_dir.display()
        )));
    }
    Ok(())
}

fn is_system_scoped_backup_path(path: &Path) -> bool {
    path == Path::new("/")
        || path.starts_with("/var/lib/aetherflow")
        || path.starts_with("/run/aetherflow")
        || path.starts_with("/etc")
        || path.starts_with("/opt")
}

pub(crate) fn resolve_backup_maintenance_lock_path(
    global: &GlobalOptions,
    cmd: &BackupCliCommand,
    cfg: &HostBackupConfig,
) -> CliResult<PathBuf> {
    let (
        explicit_backup_dir,
        explicit_db_path,
        explicit_target_root,
        targets_db,
        defaults_target_to_root,
    ) = match cmd {
        BackupCliCommand::Create {
            backup_dir,
            db_path,
            ..
        } => (backup_dir.as_deref(), db_path.as_deref(), None, true, false),
        BackupCliCommand::RestoreDestructive {
            backup_dir,
            target_root,
            ..
        } => (
            backup_dir.as_deref(),
            None,
            target_root.as_deref(),
            false,
            false,
        ),
        BackupCliCommand::RecoverInterrupted {
            backup_dir,
            target_root,
            ..
        } => (
            backup_dir.as_deref(),
            None,
            target_root.as_deref(),
            false,
            true,
        ),
        BackupCliCommand::Delete { backup_dir, .. }
        | BackupCliCommand::Prune { backup_dir, .. }
        | BackupCliCommand::Chunk { backup_dir, .. }
        | BackupCliCommand::Assemble { backup_dir, .. } => {
            (backup_dir.as_deref(), None, None, false, false)
        }
        _ => (None, None, None, false, false),
    };

    let resolved_target = explicit_target_root
        .or(global.root.as_deref())
        .or_else(|| defaults_target_to_root.then_some(Path::new("/")));
    let target_contains_active_db = resolved_target.is_some_and(|target| {
        af_models::resolve_contained_sqlite_restore_override(target, cfg.sqlite_db_path.as_deref())
            .is_some()
    });
    let target_is_system_scoped =
        resolved_target.is_some_and(is_system_scoped_backup_path) || target_contains_active_db;
    let backup_dir_is_system_scoped =
        explicit_backup_dir.is_none() || is_system_scoped_backup_path(&cfg.backup_dir);
    let db_is_system_scoped = targets_db
        && (explicit_db_path.is_none()
            || cfg
                .sqlite_db_path
                .as_deref()
                .is_some_and(is_system_scoped_backup_path));

    let use_canonical_lock = global.root.is_some()
        || backup_dir_is_system_scoped
        || db_is_system_scoped
        || target_is_system_scoped;

    if use_canonical_lock {
        let canonical_db_arg = if global.root.is_some()
            || cfg
                .sqlite_db_path
                .as_deref()
                .is_some_and(is_system_scoped_backup_path)
            || (targets_db && explicit_db_path.is_none())
            || target_contains_active_db
        {
            cfg.sqlite_db_path.as_deref()
        } else {
            None
        };
        af_models::try_resolve_canonical_maintenance_lock_path_from_env(
            global.root.as_deref(),
            canonical_db_arg,
            Some(&cfg.backup_dir),
        )
        .map_err(CliError::Validation)
    } else {
        Ok(af_host::resolve_maintenance_lock_path(Some(
            &cfg.backup_dir,
        )))
    }
}

pub(crate) fn execute_backup_command(
    global: &GlobalOptions,
    cmd: &BackupCliCommand,
) -> CliResult<CliResponseEnvelope> {
    let (env_trusted_uid, env_trusted_gid) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(global.root.as_deref())
            .map_err(CliError::Validation)?;
    let mutating_backup_target = match cmd {
        BackupCliCommand::RestoreDestructive {
            confirm_destructive_restore: false,
            ..
        } => None,
        BackupCliCommand::Create {
            backup_dir,
            db_path,
            operator_privileged,
            ..
        } => Some((
            backup_dir.as_deref(),
            db_path.as_deref(),
            *operator_privileged,
        )),
        BackupCliCommand::RestoreDestructive {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::RecoverInterrupted {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Delete {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Prune {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Chunk {
            backup_dir,
            operator_privileged,
            ..
        }
        | BackupCliCommand::Assemble {
            backup_dir,
            operator_privileged,
            ..
        } => Some((backup_dir.as_deref(), None, *operator_privileged)),
        _ => None,
    };
    let runtime_host_version = resolve_runtime_host_version(global.root.as_deref());
    let _maintenance_lock = if global.dry_run {
        None
    } else if let Some((backup_dir, explicit_db_path, operator_privileged)) = mutating_backup_target
    {
        let cfg =
            resolve_backup_config(global, backup_dir, explicit_db_path, &runtime_host_version)?;
        require_backup_write_privilege(
            global,
            &cfg.backup_dir,
            operator_privileged,
            cmd.action_name(),
        )?;
        let timeout = std::time::Duration::from_secs(30);
        let lock_path = resolve_backup_maintenance_lock_path(global, cmd, &cfg)?;
        Some(af_host::HostMaintenanceLockGuard::acquire(
            lock_path, timeout,
        )?)
    } else {
        None
    };
    match cmd {
        BackupCliCommand::Create {
            kind,
            backup_dir,
            db_path,
            app_version,
            chunk_size_bytes,
            timestamp_slug,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid: _,
        } => {
            let mut cfg = resolve_backup_config(
                global,
                backup_dir.as_deref(),
                db_path.as_deref(),
                app_version,
            )?;
            cfg.chunk_size_bytes = *chunk_size_bytes;
            cfg.snapshot_options.trusted_source_uid = (*trusted_sqlite_uid).or(env_trusted_uid);

            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup create",
            )?;

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "create",
                    format!(
                        "[DRY-RUN] Would create {:?} backup in {}",
                        kind,
                        cfg.backup_dir.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "kind": kind,
                        "config": cfg,
                    })),
                ));
            }

            let receipt = match kind {
                BackupCreateKind::Sqlite => {
                    create_sqlite_snapshot_backup(&cfg, timestamp_slug.as_deref())?
                }
                BackupCreateKind::Archive => {
                    create_host_archive_backup(&cfg, timestamp_slug.as_deref())?
                }
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "create",
                format!(
                    "Created verified backup '{}' (manifest: {}, chunks: {})",
                    receipt.primary_artifact_path.display(),
                    receipt.manifest_path.display(),
                    receipt.chunk_paths.len()
                ),
                Some(serde_json::to_value(&receipt).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::List { backup_dir } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            let items = list_backup_inventory(&cfg.backup_dir)?;
            let mut lines = vec![format!(
                "Backups in {} ({} total):",
                cfg.backup_dir.display(),
                items.len()
            )];
            for item in &items {
                lines.push(format!(
                    "  {} ({} bytes, sha256={}, manifest={}, chunks={})",
                    item.filename,
                    item.size_bytes,
                    item.checksum_present,
                    item.manifest_present,
                    item.chunk_count
                ));
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "list",
                lines.join("\n"),
                Some(json!({
                    "backup_dir": cfg.backup_dir,
                    "count": items.len(),
                    "items": items,
                })),
            ))
        }
        BackupCliCommand::Verify {
            filename,
            backup_dir,
            trusted_sqlite_uid,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            let effective_trusted_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            let (verification, manifest_opt) = verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                effective_trusted_uid,
            )?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "verify",
                format!(
                    "Verified backup '{}' (sha256={}, size={} bytes, manifest_loaded={})",
                    filename,
                    verification.actual_sha256,
                    verification.size_bytes,
                    manifest_opt.is_some()
                ),
                Some(json!({
                    "verification": verification,
                    "manifest": manifest_opt,
                })),
            ))
        }
        BackupCliCommand::RestorePreflight {
            filename,
            backup_dir,
            target_root,
            host_version,
            max_sqlite_user_version,
            overwrite_policy,
            trusted_sqlite_uid,
        } => {
            let cfg = resolve_backup_config(global, backup_dir.as_deref(), None, host_version)?;
            let effective_trusted_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            let artifact_path = safe_backup_file_path(&cfg.backup_dir, filename)?;
            let manifest_path = cfg.backup_dir.join(format!("{}.manifest.json", filename));

            if !manifest_path.is_file() {
                return Err(CliError::PreflightOrIntegrity(format!(
                    "missing required backup manifest '{}' for non-destructive restore preflight",
                    manifest_path.display()
                )));
            }
            let manifest = BackupManifest::load_from_path(&manifest_path, true)?;
            let opts = RestorePreflightOptions {
                host_app_version: host_version.clone(),
                max_supported_sqlite_user_version: *max_sqlite_user_version,
                overwrite_policy: *overwrite_policy,
                require_artifact_sidecar: true,
            };

            let sqlite_override_buf =
                if global.root.is_none() || global.root.as_deref() == Some(target_root.as_path()) {
                    af_models::resolve_contained_sqlite_restore_override(
                        target_root,
                        cfg.sqlite_db_path.as_deref(),
                    )
                } else {
                    None
                };
            let sqlite_override = sqlite_override_buf.as_deref();
            let sqlite_target_rel = sqlite_override
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(target_root, db_p));
            let plan: RestorePlan = if filename.ends_with(".tar.gz") {
                preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
                    &artifact_path,
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    effective_trusted_uid,
                )?
            } else if filename.ends_with(".sqlite") {
                preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
                    &cfg.backup_dir,
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    effective_trusted_uid,
                )?
            } else {
                plan_restore_from_manifest_with_sqlite_overrides(
                    &manifest,
                    target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "restore-preflight",
                format!(
                    "Non-destructive restore preflight PASSED for '{}' -> staging '{}' ({} entries, {} bytes, non_destructive_only={})",
                    filename,
                    plan.target_root.display(),
                    plan.items.len(),
                    plan.total_bytes,
                    plan.non_destructive_only
                ),
                Some(serde_json::to_value(&plan).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::RestoreDestructive {
            filename,
            backup_dir,
            target_root,
            confirm_destructive_restore,
            allow_overwrite,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            if global.dry_run {
                let artifact_path = safe_backup_file_path(&cfg.backup_dir, filename)?;
                if !std::fs::symlink_metadata(&artifact_path)
                    .map(|meta| meta.file_type().is_file())
                    .unwrap_or(false)
                {
                    return Err(CliError::PreflightOrIntegrity(format!(
                        "missing backup artifact '{}' at '{}'",
                        filename,
                        artifact_path.display()
                    )));
                }
                let manifest_path = cfg.backup_dir.join(format!("{}.manifest.json", filename));
                af_host::reject_symlink_chain(&cfg.backup_dir, &manifest_path)?;
                if !std::fs::symlink_metadata(&manifest_path)
                    .map(|meta| meta.file_type().is_file())
                    .unwrap_or(false)
                {
                    return Err(CliError::PreflightOrIntegrity(format!(
                        "missing required backup manifest '{}'",
                        manifest_path.display()
                    )));
                }
                let resolved_target = target_root
                    .clone()
                    .or_else(|| global.root.clone())
                    .ok_or_else(|| {
                        CliError::Usage(
                            "restore requires '--target-root <dir>' or '--root <dir>'".to_string(),
                        )
                    })?;
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "restore",
                    format!(
                        "[DRY-RUN] Would execute staged restore of '{}' into '{}'",
                        filename,
                        resolved_target.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "filename": filename,
                        "artifact_path": artifact_path,
                        "manifest_path": manifest_path,
                        "backup_dir": cfg.backup_dir,
                        "target_root": resolved_target,
                        "confirm_destructive_restore": confirm_destructive_restore,
                    })),
                ));
            }
            if !*confirm_destructive_restore {
                let dummy_manifest =
                    BackupManifest::new(&runtime_host_version, "aetherflow_placeholder.sqlite")?;
                let dummy_stage = target_root
                    .clone()
                    .unwrap_or_else(|| cfg.backup_dir.join("restore-stage"));
                let dummy_plan = RestorePlan {
                    backup_id: dummy_manifest.backup_id,
                    target_root: dummy_stage,
                    overwrite_policy: af_host::OverwritePolicy::RejectExisting,
                    compatibility: af_host::CompatibilityReport {
                        compatible: true,
                        manifest_schema_version: 1,
                        backup_app_version: runtime_host_version.clone(),
                        host_app_version: runtime_host_version.clone(),
                        entry_count: 0,
                        has_sqlite_snapshot: false,
                        warnings: vec![format!("requested artifact: {}", filename)],
                    },
                    items: Vec::new(),
                    total_bytes: 0,
                    sqlite_integrity_verified: false,
                    non_destructive_only: true,
                };
                execute_destructive_restore(&dummy_plan)?;
                unreachable!("execute_destructive_restore always fails closed")
            }

            let resolved_target = target_root
                .clone()
                .or_else(|| global.root.clone())
                .ok_or_else(|| {
                    CliError::Usage(
                        "confirmed restore requires '--target-root <dir>' or '--root <dir>'"
                            .to_string(),
                    )
                })?;

            require_backup_write_privilege(
                global,
                &resolved_target,
                *operator_privileged,
                "backup restore",
            )?;

            let trusted_sqlite_db_path = if global.root.is_none()
                || global.root.as_deref() == Some(resolved_target.as_path())
            {
                af_models::resolve_contained_sqlite_restore_override(
                    &resolved_target,
                    cfg.sqlite_db_path.as_deref(),
                )
            } else {
                None
            };
            let exec_opts = af_host::RestoreExecutionOptions {
                host_app_version: runtime_host_version.clone(),
                max_supported_sqlite_user_version: None,
                allow_overwrite: *allow_overwrite,
                confirm_destructive_restore: true,
                quiesce_services: Vec::new(),
                sqlite_target_rel_path: trusted_sqlite_db_path.as_deref().and_then(|db_p| {
                    af_models::derive_sqlite_target_rel_path(&resolved_target, db_p)
                }),
                trusted_sqlite_db_path,
                trusted_sqlite_uid: (*trusted_sqlite_uid).or(env_trusted_uid),
                trusted_sqlite_gid: (*trusted_sqlite_gid).or(env_trusted_gid),
                ..Default::default()
            };

            let live_quiescence = target_requires_live_quiescence(
                global,
                &resolved_target,
                cfg.sqlite_db_path.as_deref(),
            );
            let report = if !live_quiescence {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &resolved_target,
                    &exec_opts,
                    &af_host::NoopQuiescenceController,
                )?
            } else {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &resolved_target,
                    &exec_opts,
                    &af_host::CommandQuiescenceController::default(),
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "restore",
                format!(
                    "Executed verified restore of '{}' into '{}' ({} file(s) restored)",
                    filename,
                    resolved_target.display(),
                    report.restored_files.len()
                ),
                Some(serde_json::to_value(&report).unwrap_or(json!({}))),
            ))
        }
        BackupCliCommand::RecoverInterrupted {
            backup_dir,
            target_root,
            operator_privileged,
            trusted_sqlite_uid,
            trusted_sqlite_gid,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            let resolved_target = target_root
                .clone()
                .or_else(|| global.root.clone())
                .unwrap_or_else(|| PathBuf::from("/"));

            require_backup_write_privilege(
                global,
                &resolved_target,
                *operator_privileged,
                "backup recover",
            )?;

            let trusted_sqlite_db_path = if global.root.is_none()
                || global.root.as_deref() == Some(resolved_target.as_path())
            {
                af_models::resolve_contained_sqlite_restore_override(
                    &resolved_target,
                    cfg.sqlite_db_path.as_deref(),
                )
            } else {
                None
            };
            let mut recovery_context = if resolved_target == Path::new("/") {
                af_host::RecoveryContext::for_canonical_host(trusted_sqlite_db_path)
            } else {
                af_host::RecoveryContext::for_target_root(
                    resolved_target.clone(),
                    trusted_sqlite_db_path,
                )
            };
            recovery_context.trusted_sqlite_uid = (*trusted_sqlite_uid).or(env_trusted_uid);
            recovery_context.trusted_sqlite_gid = (*trusted_sqlite_gid).or(env_trusted_gid);

            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "recover-interrupted",
                    format!(
                        "[DRY-RUN] Would recover interrupted restores in '{}' for target '{}'",
                        cfg.backup_dir.display(),
                        resolved_target.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "backup_dir": cfg.backup_dir,
                        "target_root": resolved_target,
                    })),
                ));
            }

            let live_quiescence = target_requires_live_quiescence(
                global,
                &resolved_target,
                cfg.sqlite_db_path.as_deref(),
            );
            let recovered_directories = if !live_quiescence {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::NoopQuiescenceController,
                )?
            } else {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::CommandQuiescenceController::default(),
                )?
            };

            Ok(CliResponseEnvelope::success(
                "backup",
                "recover-interrupted",
                format!(
                    "Recovered {} interrupted restore directory(s) in '{}'",
                    recovered_directories.len(),
                    cfg.backup_dir.display()
                ),
                Some(json!({
                    "backup_dir": cfg.backup_dir,
                    "target_root": resolved_target,
                    "recovered_directories": recovered_directories,
                })),
            ))
        }
        BackupCliCommand::Delete {
            filename,
            backup_dir,
            operator_privileged,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup delete",
            )?;
            if global.dry_run {
                let target = safe_backup_file_path(&cfg.backup_dir, filename)?;
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "delete",
                    format!(
                        "[DRY-RUN] Would delete backup artifacts for {}",
                        target.display()
                    ),
                    Some(json!({ "dry_run": true, "artifact": target })),
                ));
            }
            let removed = delete_backup_artifacts(&cfg.backup_dir, filename)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "delete",
                format!(
                    "Deleted {} file(s) for backup '{}'",
                    removed.len(),
                    filename
                ),
                Some(json!({ "filename": filename, "removed_paths": removed })),
            ))
        }
        BackupCliCommand::Prune {
            backup_dir,
            max_retained,
            retention_days,
            operator_privileged,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup prune",
            )?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "prune",
                    format!(
                        "[DRY-RUN] Would prune backups in {} (max_retained={}, retention_days={})",
                        cfg.backup_dir.display(),
                        max_retained,
                        retention_days
                    ),
                    Some(json!({
                        "dry_run": true,
                        "backup_dir": cfg.backup_dir,
                        "max_retained": max_retained,
                        "retention_days": retention_days,
                    })),
                ));
            }
            let pruned = prune_backup_inventory(&cfg.backup_dir, *max_retained, *retention_days)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "prune",
                format!("Pruned {} backup(s)", pruned.len()),
                Some(json!({ "pruned": pruned })),
            ))
        }
        BackupCliCommand::Chunk {
            filename,
            chunk_size_bytes,
            backup_dir,
            operator_privileged,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup chunk",
            )?;
            let target = safe_backup_file_path(&cfg.backup_dir, filename)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "chunk",
                    format!(
                        "[DRY-RUN] Would split {} into {}-byte chunks",
                        target.display(),
                        chunk_size_bytes
                    ),
                    Some(json!({
                        "dry_run": true,
                        "artifact": target,
                        "chunk_size_bytes": chunk_size_bytes,
                    })),
                ));
            }
            let chunks = split_backup_into_chunks(&target, *chunk_size_bytes)?;
            let manifest_path = PathBuf::from(format!("{}.manifest.json", target.display()));
            if manifest_path.exists() {
                let mut manifest = BackupManifest::load_from_path(&manifest_path, true)?;
                manifest.chunk_count = chunks.len();
                manifest.chunk_size_bytes = Some(*chunk_size_bytes);
                manifest.save_atomic(&manifest_path)?;
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "chunk",
                format!("Split '{}' into {} chunk(s)", filename, chunks.len()),
                Some(json!({
                    "filename": filename,
                    "chunk_size_bytes": chunk_size_bytes,
                    "chunks": chunks,
                })),
            ))
        }
        BackupCliCommand::Assemble {
            output_filename,
            expected_sha256,
            chunks,
            backup_dir,
            operator_privileged,
        } => {
            let cfg =
                resolve_backup_config(global, backup_dir.as_deref(), None, &runtime_host_version)?;
            require_backup_write_privilege(
                global,
                &cfg.backup_dir,
                *operator_privileged,
                "backup assemble",
            )?;
            let output_path = safe_backup_file_path(&cfg.backup_dir, output_filename)?;
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "backup",
                    "assemble",
                    format!(
                        "[DRY-RUN] Would assemble {} chunk(s) into {}",
                        chunks.len(),
                        output_path.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "output_path": output_path,
                        "expected_sha256": expected_sha256,
                        "chunks": chunks,
                    })),
                ));
            }
            let verification = assemble_verified_chunks(chunks, &output_path, expected_sha256)?;
            Ok(CliResponseEnvelope::success(
                "backup",
                "assemble",
                format!(
                    "Assembled and verified '{}' ({} bytes, sha256={})",
                    output_path.display(),
                    verification.size_bytes,
                    verification.actual_sha256
                ),
                Some(json!({ "verification": verification })),
            ))
        }
        BackupCliCommand::OwnershipRegistry => {
            let registry = maintenance_helper_ownership_registry();
            let mut lines = vec![format!(
                "Host Maintenance Script Ownership Registry ({} entries):",
                registry.len()
            )];
            for item in registry {
                lines.push(format!(
                    "  {} -> {:?} ({})",
                    item.script_path, item.owner, item.rust_replacement_or_entry
                ));
            }
            Ok(CliResponseEnvelope::success(
                "backup",
                "ownership",
                lines.join("\n"),
                Some(serde_json::to_value(registry).unwrap_or(json!([]))),
            ))
        }
    }
}
