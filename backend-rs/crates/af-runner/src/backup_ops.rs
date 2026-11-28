use super::*;

type RunnerResolvedBackupConfig = (
    af_host::HostBackupConfig,
    Option<PathBuf>,
    Option<u32>,
    Option<u32>,
);

fn resolve_server_owned_backup_config(
    isolated_root: Option<PathBuf>,
    app_version: &str,
) -> Result<RunnerResolvedBackupConfig, (StatusCode, String)> {
    let active_db = af_models::try_resolve_active_db_path_from_env(
        isolated_root.as_deref(),
        "/var/lib/aetherflow/aetherflow.sqlite",
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let active_backup_dir = af_models::try_resolve_active_backup_dir_from_env(
        isolated_root.as_deref(),
        Some(&active_db),
        "/var/lib/aetherflow/backups",
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let (env_sqlite_uid, env_sqlite_gid) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(isolated_root.as_deref())
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    if let Some(root_path) = isolated_root {
        let mut cfg = af_host::HostBackupConfig::for_isolated_root(&root_path, app_version);
        cfg.backup_dir = active_backup_dir;
        cfg.sqlite_db_path = Some(active_db);
        cfg.snapshot_options.trusted_source_uid = env_sqlite_uid;
        return Ok((cfg, Some(root_path), env_sqlite_uid, env_sqlite_gid));
    }

    let mut cfg = af_host::HostBackupConfig {
        app_version: app_version.to_string(),
        backup_dir: active_backup_dir,
        sqlite_db_path: Some(active_db),
        ..Default::default()
    };
    cfg.snapshot_options.trusted_source_uid = env_sqlite_uid;
    Ok((cfg, None, env_sqlite_uid, env_sqlite_gid))
}

fn format_runner_backup_app_version(raw: &str) -> String {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if !body.is_empty() {
        let candidate = format!("v{body}");
        if af_host::parse_semver_triplet(&candidate).is_ok() {
            return candidate;
        }
    }
    concat!("v", env!("CARGO_PKG_VERSION")).to_string()
}

fn default_runner_backup_app_version_for_root(isolated_root: Option<&Path>) -> String {
    format_runner_backup_app_version(&af_release::runtime::runtime_version_for_root(
        isolated_root,
    ))
}

fn build_runner_backup_config(
    req: &BackupRunnerRequest,
) -> Result<RunnerResolvedBackupConfig, (StatusCode, String)> {
    let isolated_root = af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let fallback_version;
    let app_version = if req.app_version.trim().is_empty() {
        fallback_version = default_runner_backup_app_version_for_root(isolated_root.as_deref());
        fallback_version.as_str()
    } else {
        req.app_version.trim()
    };

    let (mut cfg, isolated_root, mut trusted_sqlite_uid, mut trusted_sqlite_gid) =
        resolve_server_owned_backup_config(isolated_root, app_version)?;

    if let Some(req_uid) = req.trusted_sqlite_uid {
        if let Some(existing_uid) = trusted_sqlite_uid {
            if existing_uid != req_uid {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "untrusted trusted_sqlite_uid override '{}' rejected: runner enforces configured UID {}",
                        req_uid, existing_uid
                    ),
                ));
            }
        } else if isolated_root.is_some() {
            trusted_sqlite_uid = Some(req_uid);
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted trusted_sqlite_uid override '{}' rejected without server-side configuration",
                    req_uid
                ),
            ));
        }
    }
    if let Some(req_gid) = req.trusted_sqlite_gid {
        if let Some(existing_gid) = trusted_sqlite_gid {
            if existing_gid != req_gid {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "untrusted trusted_sqlite_gid override '{}' rejected: runner enforces configured GID {}",
                        req_gid, existing_gid
                    ),
                ));
            }
        } else if isolated_root.is_some() {
            trusted_sqlite_gid = Some(req_gid);
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted trusted_sqlite_gid override '{}' rejected without server-side configuration",
                    req_gid
                ),
            ));
        }
    }
    cfg.snapshot_options.trusted_source_uid = trusted_sqlite_uid;

    if !req.backup_dir.trim().is_empty() {
        let req_bdir = PathBuf::from(req.backup_dir.trim());
        af_host::validate_no_parent_traversal(&req_bdir, "backup_dir")
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let allowed = req_bdir == cfg.backup_dir
            || isolated_root
                .as_ref()
                .map(|iso| req_bdir.starts_with(iso))
                .unwrap_or(false);
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted backup_dir override '{}' rejected: runner enforces server-owned backup root '{}'",
                    req_bdir.display(),
                    cfg.backup_dir.display()
                ),
            ));
        }
        cfg.backup_dir = req_bdir;
    }

    if !req.db_path.trim().is_empty() {
        let req_db = PathBuf::from(req.db_path.trim());
        af_host::validate_no_parent_traversal(&req_db, "db_path")
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let allowed = cfg.sqlite_db_path.as_ref() == Some(&req_db)
            || isolated_root
                .as_ref()
                .map(|iso| req_db.starts_with(iso))
                .unwrap_or(false);
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted db_path override '{}' rejected: runner enforces server-owned database path",
                    req_db.display()
                ),
            ));
        }
        cfg.sqlite_db_path = Some(req_db);
    }

    if let Some(chunk_sz) = req.chunk_size_bytes {
        cfg.chunk_size_bytes = if chunk_sz > 0 { Some(chunk_sz) } else { None };
    }
    if let Some(days) = req.retention_days {
        cfg.retention_days = days;
    }
    if let Some(max_keep) = req.max_retained {
        cfg.max_retained_backups = max_keep;
    }
    Ok((cfg, isolated_root, trusted_sqlite_uid, trusted_sqlite_gid))
}

fn validate_runner_restore_target_root(raw_target: &str) -> Result<PathBuf, (StatusCode, String)> {
    let trimmed = raw_target.trim();
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "target_root must not be empty".to_string(),
        ));
    }
    let target = PathBuf::from(trimmed);
    if target == Path::new("/") {
        return Ok(target);
    }
    af_host::validate_no_parent_traversal(&target, "target_root")
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if target.starts_with("/var/lib/aetherflow/restore-staging") {
        return Ok(target);
    }
    if let Ok(staging_env) = env::var("AETHERFLOW_RESTORE_STAGING_ROOT") {
        let st = staging_env.trim();
        if !st.is_empty() && target.starts_with(Path::new(st)) {
            return Ok(target);
        }
    }
    if let Ok(Some(iso_path)) =
        af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
    {
        if target.starts_with(&iso_path)
            || iso_path
                .parent()
                .map(|p| target.starts_with(p))
                .unwrap_or(false)
        {
            return Ok(target);
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        format!(
            "untrusted target_root '{}' rejected: runner only permits '/' (canonical FHS mapping) or configured restore-staging roots",
            target.display()
        ),
    ))
}

/// Executes a validated `BackupRunnerRequest` using `af-host` with serialized write locking.
pub async fn execute_backup_local(
    req: &BackupRunnerRequest,
) -> Result<BackupRunnerResponse, (StatusCode, String)> {
    let action = req.action.trim();
    if !ALLOWED_BACKUP_ACTIONS.contains(action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("disallowed backup action: {:?}", action),
        ));
    }

    let _guard = BACKUP_MUTEX.lock().await;
    let (cfg, isolated_root, trusted_sqlite_uid, trusted_sqlite_gid) =
        build_runner_backup_config(req)?;
    let canonical_lock_path = af_models::try_resolve_canonical_maintenance_lock_path_from_env(
        isolated_root.as_deref(),
        cfg.sqlite_db_path.as_deref(),
        Some(&cfg.backup_dir),
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let _maint_lock =
        af_host::HostMaintenanceLockGuard::acquire(&canonical_lock_path, Duration::from_secs(30))
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    let slug_opt = if req.timestamp_slug.trim().is_empty() {
        None
    } else {
        Some(req.timestamp_slug.trim())
    };

    let effective_action = if action == "create" {
        if req.kind.eq_ignore_ascii_case("archive") || req.kind.eq_ignore_ascii_case("full") {
            "create_archive"
        } else {
            "create_sqlite"
        }
    } else {
        action
    };

    match effective_action {
        "create_sqlite" => {
            let receipt = af_host::create_sqlite_snapshot_backup(&cfg, slug_opt)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let filename = receipt
                .primary_artifact_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let sha256 = receipt
                .manifest
                .sqlite_snapshot
                .as_ref()
                .map(|s| s.sha256.clone())
                .unwrap_or_default();
            let size_bytes = receipt
                .manifest
                .sqlite_snapshot
                .as_ref()
                .map(|s| s.size_bytes)
                .unwrap_or(0);
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: receipt.manifest.backup_id.clone(),
                filename,
                artifact_path: receipt.primary_artifact_path.to_string_lossy().into_owned(),
                manifest_path: receipt.manifest_path.to_string_lossy().into_owned(),
                sha256,
                size_bytes,
                chunk_count: receipt.chunk_paths.len(),
                verified: true,
                restored_files: 0,
                rolled_back: false,
                details: serde_json::to_value(&receipt.manifest).unwrap_or(Value::Null),
            })
        }
        "create_archive" => {
            let receipt = af_host::create_host_archive_backup(&cfg, slug_opt)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let filename = receipt
                .primary_artifact_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let primary_entry = receipt.manifest.entries.first();
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: receipt.manifest.backup_id.clone(),
                filename,
                artifact_path: receipt.primary_artifact_path.to_string_lossy().into_owned(),
                manifest_path: receipt.manifest_path.to_string_lossy().into_owned(),
                sha256: primary_entry.map(|e| e.sha256.clone()).unwrap_or_default(),
                size_bytes: fs::metadata(&receipt.primary_artifact_path)
                    .map(|m| m.len())
                    .unwrap_or(0),
                chunk_count: receipt.chunk_paths.len(),
                verified: true,
                restored_files: 0,
                rolled_back: false,
                details: serde_json::to_value(&receipt.manifest).unwrap_or(Value::Null),
            })
        }
        "list" => {
            let inv = af_host::list_backup_inventory(&cfg.backup_dir)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                details: serde_json::to_value(&inv).unwrap_or(Value::Array(Vec::new())),
                ..Default::default()
            })
        }
        "verify" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let (ver, manifest) = af_host::verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                trusted_sqlite_uid,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: manifest
                    .as_ref()
                    .map(|m| m.backup_id.clone())
                    .unwrap_or_default(),
                filename: filename.to_string(),
                artifact_path: ver.artifact_path.to_string_lossy().into_owned(),
                manifest_path: manifest
                    .as_ref()
                    .map(|_| format!("{}.manifest.json", ver.artifact_path.display()))
                    .unwrap_or_default(),
                sha256: ver.actual_sha256,
                size_bytes: ver.size_bytes,
                verified: ver.verified,
                details: serde_json::to_value(&manifest).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "delete" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let removed = af_host::delete_backup_artifacts(&cfg.backup_dir, filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                filename: filename.to_string(),
                verified: true,
                details: json!({
                    "removed_files": removed.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                }),
                ..Default::default()
            })
        }
        "prune" => {
            let removed = af_host::prune_backup_inventory(
                &cfg.backup_dir,
                cfg.max_retained_backups,
                cfg.retention_days,
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                details: json!({
                    "removed_files": removed,
                }),
                ..Default::default()
            })
        }
        "restore_preflight" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let target_root = validate_runner_restore_target_root(&req.target_root)?;
            let (ver, maybe_manifest) = af_host::verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                trusted_sqlite_uid,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let manifest = maybe_manifest.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("backup '{}' is missing a .manifest.json sidecar", filename),
                )
            })?;
            let opts = af_host::RestorePreflightOptions {
                host_app_version: cfg.app_version.clone(),
                max_supported_sqlite_user_version: req.max_sqlite_user_version,
                overwrite_policy: if req.allow_overwrite {
                    af_host::OverwritePolicy::AllowRegularFilesInStaging
                } else {
                    af_host::OverwritePolicy::RejectExisting
                },
                require_artifact_sidecar: true,
            };
            let sqlite_override_buf = af_models::resolve_contained_sqlite_restore_override(
                &target_root,
                cfg.sqlite_db_path.as_deref(),
            );
            let sqlite_override = sqlite_override_buf.as_deref();
            let sqlite_target_rel = sqlite_override
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(&target_root, db_p));
            let plan = if filename.ends_with(".tar.gz") {
                af_host::preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
                    &ver.artifact_path,
                    &manifest,
                    &target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    trusted_sqlite_uid,
                )
            } else {
                af_host::preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
                    &cfg.backup_dir,
                    &manifest,
                    &target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    trusted_sqlite_uid,
                )
            }
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: manifest.backup_id,
                filename: filename.to_string(),
                artifact_path: ver.artifact_path.to_string_lossy().into_owned(),
                manifest_path: format!("{}.manifest.json", ver.artifact_path.display()),
                sha256: ver.actual_sha256,
                size_bytes: ver.size_bytes,
                verified: true,
                restored_files: plan.items.len(),
                rolled_back: false,
                details: serde_json::to_value(&plan).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "restore_execute" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let validated_quiesce =
                af_host::validate_quiesce_service_entries(&req.quiesce_services)
                    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            for svc in &validated_quiesce {
                if !SAFE_SERVICE_NAME.is_match(svc) || svc.contains("..") {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("invalid quiesce service unit name: {:?}", svc),
                    ));
                }
            }
            let target_root = validate_runner_restore_target_root(&req.target_root)?;
            let trusted_sqlite_db_path = af_models::resolve_contained_sqlite_restore_override(
                &target_root,
                cfg.sqlite_db_path.as_deref(),
            );
            let sqlite_target_rel_path = trusted_sqlite_db_path
                .as_deref()
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(&target_root, db_p));
            let exec_opts = af_host::RestoreExecutionOptions {
                host_app_version: cfg.app_version.clone(),
                max_supported_sqlite_user_version: req.max_sqlite_user_version,
                confirm_destructive_restore: req.confirm_destructive_restore,
                allow_overwrite: req.allow_overwrite,
                quiesce_services: af_host::resolve_effective_quiesce_services(&validated_quiesce),
                sqlite_target_rel_path,
                trusted_sqlite_db_path,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
                ..Default::default()
            };

            let dry_quiesce = env::var("AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE")
                .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
                || af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
                    .ok()
                    .flatten()
                    .is_some()
                || !cfg!(target_os = "linux");

            let report = if dry_quiesce {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &target_root,
                    &exec_opts,
                    &af_host::NoopQuiescenceController,
                )
            } else {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &target_root,
                    &exec_opts,
                    &af_host::CommandQuiescenceController::default(),
                )
            }
            .map_err(|err| {
                let code = match err {
                    af_host::HostBackupError::DestructiveRestoreUnsupported { .. }
                    | af_host::HostBackupError::UnsafeOverwriteRejected { .. }
                    | af_host::HostBackupError::TraversalRejected { .. }
                    | af_host::HostBackupError::SymlinkRejected { .. }
                    | af_host::HostBackupError::ChecksumMismatch { .. }
                    | af_host::HostBackupError::InvalidManifest(_)
                    | af_host::HostBackupError::InvalidConfig(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, err.to_string())
            })?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: report.backup_id.clone(),
                filename: filename.to_string(),
                verified: true,
                restored_files: report.restored_files.len(),
                rolled_back: report.rolled_back,
                details: serde_json::to_value(&report).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "recover_interrupted" => {
            let mut recovery_context = if !req.target_root.trim().is_empty() {
                let target_root = validate_runner_restore_target_root(&req.target_root)?;
                let trusted_sqlite_db_path = af_models::resolve_contained_sqlite_restore_override(
                    &target_root,
                    cfg.sqlite_db_path.as_deref(),
                );
                if target_root == Path::new("/") {
                    af_host::RecoveryContext::for_canonical_host(trusted_sqlite_db_path)
                } else {
                    af_host::RecoveryContext::for_target_root(target_root, trusted_sqlite_db_path)
                }
            } else {
                let trusted_sqlite_db_path = match isolated_root.as_deref() {
                    Some(iso_root) => af_models::resolve_contained_sqlite_restore_override(
                        iso_root,
                        cfg.sqlite_db_path.as_deref(),
                    ),
                    None => cfg.sqlite_db_path.clone(),
                };
                af_host::RecoveryContext::from_host_config(
                    isolated_root.as_deref(),
                    trusted_sqlite_db_path,
                )
            };
            recovery_context.trusted_sqlite_uid = trusted_sqlite_uid;
            recovery_context.trusted_sqlite_gid = trusted_sqlite_gid;

            let dry_quiesce = env::var("AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
                || af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
                    .ok()
                    .flatten()
                    .is_some()
                || !cfg!(target_os = "linux");

            let recovered_directories = if dry_quiesce {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::NoopQuiescenceController,
                )
            } else {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::CommandQuiescenceController::default(),
                )
            }
            .map_err(|err| {
                let code = match err {
                    af_host::HostBackupError::DestructiveRestoreUnsupported { .. }
                    | af_host::HostBackupError::UnsafeOverwriteRejected { .. }
                    | af_host::HostBackupError::TraversalRejected { .. }
                    | af_host::HostBackupError::SymlinkRejected { .. }
                    | af_host::HostBackupError::ChecksumMismatch { .. }
                    | af_host::HostBackupError::PathValidation { .. }
                    | af_host::HostBackupError::InvalidManifest(_)
                    | af_host::HostBackupError::InvalidConfig(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, err.to_string())
            })?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                rolled_back: !recovered_directories.is_empty(),
                details: json!({"recovered_directories": recovered_directories}),
                ..Default::default()
            })
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "unsupported backup action".to_string(),
        )),
    }
}

pub(crate) async fn handle_backup(
    Json(req): Json<BackupRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match execute_backup_local(&req).await {
        Ok(resp) => {
            let output = serde_json::to_string(&resp).unwrap_or_default();
            (
                StatusCode::OK,
                Json(RunnerResponse {
                    success: true,
                    output,
                    error: String::new(),
                }),
            )
        }
        Err((code, err_msg)) => (
            code,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err_msg,
            }),
        ),
    }
}

pub async fn dispatch_backup_request(
    req: &BackupRunnerRequest,
) -> anyhow::Result<BackupRunnerResponse> {
    if is_runner_available() {
        let resp = post_runner_json("/v1/backup", req, Duration::from_secs(300)).await?;
        if !resp.success {
            anyhow::bail!("runner backup error: {}", resp.error);
        }
        let parsed: BackupRunnerResponse = serde_json::from_str(&resp.output)?;
        return Ok(parsed);
    }
    execute_backup_local(req)
        .await
        .map_err(|(_, msg)| anyhow::anyhow!(msg))
}

#[cfg(test)]
mod backup_version_tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn default_runner_backup_app_version_formats_runtime_identity_with_v_prefix() {
        assert_eq!(format_runner_backup_app_version("4.0.1"), "v4.0.1");
        assert_eq!(format_runner_backup_app_version("v4.0.1"), "v4.0.1");
        assert_eq!(format_runner_backup_app_version("V4.0.1"), "v4.0.1");
        assert_eq!(
            format_runner_backup_app_version("v4.1.0-nightly.12.1"),
            "v4.1.0-nightly.12.1"
        );
        let fallback = concat!("v", env!("CARGO_PKG_VERSION"));
        assert_eq!(
            format_runner_backup_app_version("source-1764270000"),
            fallback
        );
        assert_eq!(
            format_runner_backup_app_version("vsource-1764270000"),
            fallback
        );
        assert_eq!(format_runner_backup_app_version(""), fallback);
        assert_eq!(format_runner_backup_app_version("   "), fallback);
        assert_eq!(format_runner_backup_app_version("not-a-semver"), fallback);

        let resolved = default_runner_backup_app_version_for_root(None);
        assert!(resolved.starts_with('v'), "expected v prefix: {resolved}");
        assert!(
            af_host::parse_semver_triplet(&resolved).is_ok(),
            "expected valid semver: {resolved}"
        );
    }

    #[test]
    fn default_runner_backup_app_version_honors_isolated_root_version_and_rejects_non_semver() {
        let root = std::env::temp_dir().join(format!("af-backup-ver-{}", Uuid::new_v4()));
        let current_dir = root.join("opt/AetherFlow/current");
        fs::create_dir_all(&current_dir).unwrap();
        let version_file = current_dir.join(".version");

        fs::write(&version_file, "4.9.2\n").unwrap();
        assert_eq!(
            default_runner_backup_app_version_for_root(Some(&root)),
            "v4.9.2"
        );

        fs::write(&version_file, "v4.9.3\n").unwrap();
        assert_eq!(
            default_runner_backup_app_version_for_root(Some(&root)),
            "v4.9.3"
        );

        // Non-semver --from-source stamps must fall back cleanly to Cargo package version
        fs::write(&version_file, "source-1764270000\n").unwrap();
        assert_eq!(
            default_runner_backup_app_version_for_root(Some(&root)),
            concat!("v", env!("CARGO_PKG_VERSION"))
        );

        // Verify full build_runner_backup_config resolves isolated_root first and honors .version
        let _lock = crate::ENV_TEST_MUTEX.blocking_lock();
        fs::write(&version_file, "v4.8.7\n").unwrap();
        let prev_iso = env::var_os("AETHERFLOW_BACKUP_ISOLATED_ROOT");
        let prev_rel = env::var_os("AETHERFLOW_RELEASE_ROOT");
        let prev_db = env::var_os("AETHERFLOW_DB_PATH");
        let prev_bdir = env::var_os("AETHERFLOW_BACKUP_DIR");
        env::set_var("AETHERFLOW_BACKUP_ISOLATED_ROOT", &root);
        env::remove_var("AETHERFLOW_RELEASE_ROOT");
        env::remove_var("AETHERFLOW_DB_PATH");
        env::remove_var("AETHERFLOW_BACKUP_DIR");

        let req = BackupRunnerRequest {
            action: "list".to_string(),
            ..Default::default()
        };
        let cfg_res = build_runner_backup_config(&req);

        match prev_iso {
            Some(v) => env::set_var("AETHERFLOW_BACKUP_ISOLATED_ROOT", v),
            None => env::remove_var("AETHERFLOW_BACKUP_ISOLATED_ROOT"),
        }
        match prev_rel {
            Some(v) => env::set_var("AETHERFLOW_RELEASE_ROOT", v),
            None => env::remove_var("AETHERFLOW_RELEASE_ROOT"),
        }
        match prev_db {
            Some(v) => env::set_var("AETHERFLOW_DB_PATH", v),
            None => env::remove_var("AETHERFLOW_DB_PATH"),
        }
        match prev_bdir {
            Some(v) => env::set_var("AETHERFLOW_BACKUP_DIR", v),
            None => env::remove_var("AETHERFLOW_BACKUP_DIR"),
        }

        let (cfg, iso_resolved, _, _) = cfg_res.expect("build_runner_backup_config should succeed");
        assert_eq!(iso_resolved.as_deref(), Some(root.as_path()));
        assert_eq!(cfg.app_version, "v4.8.7");

        let _ = fs::remove_dir_all(&root);
    }
}
