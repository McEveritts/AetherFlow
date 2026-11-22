use super::*;

const EMBEDDED_AUTOMATION_FOR_EXECUTOR: &str = crate::EMBEDDED_AUTOMATION_JSON;

pub(super) fn resolve_package_lock_name(pkg_id: &str) -> &str {
    af_models::resolve_package_lock_name(pkg_id)
}

/// Returns whether `config/package_automation.json` configures `require_download_sha256: true`
/// for `pkg_id`. Fails closed (`true`) if a config candidate is a symlink or unreadable.
pub fn package_requires_download_sha256(pkg_id: &str) -> bool {
    let raw = match crate::try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_FOR_EXECUTOR,
    ) {
        Ok(s) => s,
        Err(_) => return true,
    };

    let Ok(map) = serde_json::from_str::<HashMap<String, af_models::PackageAutomation>>(&raw)
    else {
        return true;
    };
    let clean = resolve_package_lock_name(pkg_id);
    map.get(clean)
        .or_else(|| map.get(pkg_id.trim()))
        .map(|a| a.require_download_sha256)
        .unwrap_or(false)
}

/// Resolves the effective listen port for `install` / `reinstall` / `update` when `req.app_port`
/// was not explicitly supplied (`<= 0`), checking persisted SQLite ingress (`app_ingress_configs`
/// and `retained_app_ingress_configs`), native runtime config, lockfile, and catalog `default_port`.
pub fn resolve_effective_runner_app_port(action: &str, pkg_id: &str, requested_port: i32) -> i32 {
    let action_lower = action.trim().to_ascii_lowercase();
    if action_lower == "remove" || action_lower == "uninstall" {
        return 0;
    }
    if (1024..=65535).contains(&requested_port) {
        return requested_port;
    }

    let clean_id = resolve_package_lock_name(pkg_id);
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(Some(cfg)) = af_db::load_lifecycle_ingress(&conn, clean_id)
            .or_else(|_| af_db::load_lifecycle_ingress(&conn, pkg_id.trim()))
        {
            if (1024..=65535).contains(&cfg.listen_port) {
                return cfg.listen_port;
            }
        }
    }

    let env_cfg = PackageExecutionEnv::default();
    if env_cfg.fs_root.is_none() {
        let meta = crate::extract_app_runtime_meta_local(clean_id);
        if (1024..=65535).contains(&meta.configured_port) {
            return meta.configured_port;
        }
    }

    let pkg_def = crate::get_runner_package_definition(clean_id)
        .or_else(|| crate::get_runner_package_definition(pkg_id.trim()));
    if let Ok(Some(p)) = af_models::read_package_receipt_port(
        clean_id,
        pkg_def
            .as_ref()
            .map(|p| p.lock_file.as_str())
            .filter(|s| !s.trim().is_empty()),
        env_cfg.fs_root.as_deref(),
    ) {
        return p;
    }

    pkg_def
        .map(|p| p.default_port)
        .filter(|p| (1024..=65535).contains(p))
        .unwrap_or(0)
}

fn legacy_sandbox_units(pkg_id: &str) -> Vec<String> {
    let Some(pkg) = crate::get_runner_package_definition(pkg_id) else {
        return Vec::new();
    };
    if (!pkg.service_type.is_empty() && pkg.service_type != "systemd")
        || matches!(pkg.sandbox_profile.as_str(), "" | "privileged" | "none")
    {
        return Vec::new();
    }
    let mut units = pkg.sandbox_service_ids;
    if units.is_empty() {
        units.push(if pkg.service_name.is_empty() {
            pkg_id.to_string()
        } else {
            pkg.service_name
        });
    }
    let mut out = Vec::new();
    for raw in units {
        let norm = normalize_unit_filename(&raw);
        if norm.ends_with(".service")
            && !crate::is_exempt_sandbox_unit(&norm)
            && !out.contains(&norm)
        {
            out.push(norm);
        }
    }
    out
}

fn legacy_unit_snapshot_in_root(
    unit: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<Vec<Option<fs::Metadata>>> {
    [
        "etc/systemd/system",
        "usr/local/lib/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ]
    .iter()
    .map(|rel| {
        let path = match fs_root {
            Some(root) => root.join(rel).join(unit),
            None => Path::new("/").join(rel).join(unit),
        };
        match fs::metadata(&path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    })
    .collect()
}

fn legacy_unit_changed(before: &[Option<fs::Metadata>], after: &[Option<fs::Metadata>]) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.iter().zip(after).any(|(before, after)| {
        let identity =
            |stat: &fs::Metadata| (stat.dev(), stat.ino(), stat.ctime(), stat.ctime_nsec());
        before.as_ref().map(identity) != after.as_ref().map(identity)
    })
}

async fn rollback_legacy_sandbox_with_lease(
    guard: &Arc<af_release::ReleaseLockGuard>,
    sandbox_journal: &mut RollbackJournal,
    sandbox_units: &[String],
    systemd_root: &Path,
    live_sandbox: bool,
) -> Result<bool, String> {
    let runner = TokioCommandRunner {
        respect_dry_run_env: false,
    };
    crate::PACKAGE_MAINTENANCE_LEASE
        .scope(
            guard.clone(),
            rollback_legacy_sandbox(
                sandbox_journal,
                sandbox_units,
                systemd_root,
                live_sandbox,
                &runner,
            ),
        )
        .await
}

fn format_error_with_sandbox_rollback(base: String, rollback_res: Result<bool, String>) -> String {
    match rollback_res {
        Err(rb) => format!("__RUNNER_EXIT_ERROR__:{base}; incomplete rollback: {rb}\n"),
        Ok(_) => format!("__RUNNER_EXIT_ERROR__:{base}\n"),
    }
}

fn format_post_commit_sandbox_error(base: String, rollback_res: Result<bool, String>) -> String {
    match rollback_res {
        Ok(true) => format!(
            "__RUNNER_EXIT_ERROR__:{base}; managed sandbox drop-in changes restored (package installer had already committed)\n"
        ),
        Ok(false) => format!("__RUNNER_EXIT_ERROR__:{base}\n"),
        Err(rb) => format!(
            "__RUNNER_EXIT_ERROR__:{base}; incomplete rollback: failed to restore managed sandbox drop-in changes ({rb})\n"
        ),
    }
}

/// Sets the lifecycle contract environment for a legacy Bash package script.
/// `DELETE_DATA` is always set explicitly so an inherited runner value can
/// never turn an ordinary removal into a purge.
pub(crate) fn apply_legacy_package_environment(cmd: &mut Command, req: &PackageRunnerRequest) {
    let default_env = PackageExecutionEnv::default();
    let action_lower = req.action.trim().to_ascii_lowercase();
    let keep_existing_secrets = if action_lower == "remove" || action_lower == "uninstall" {
        false
    } else if action_lower == "update" || action_lower == "reinstall" {
        true
    } else {
        default_env.keep_existing_secrets
    };
    cmd.env("DEBIAN_FRONTEND", "noninteractive")
        .env("AF_PACKAGE_ACTION", req.action.as_str())
        .env("AF_LIFECYCLE_ACTION", req.action.as_str())
        .env(
            "DELETE_DATA",
            if package_request_deletes_data(req) {
                "true"
            } else {
                "false"
            },
        )
        .env(
            "AF_KEEP_EXISTING_SECRETS",
            if keep_existing_secrets { "1" } else { "0" },
        )
        .env("DPKG_LOCK_TIMEOUT", "120");
    if package_requires_download_sha256(&req.package_id) {
        cmd.env("AF_REQUIRE_DOWNLOAD_SHA256", "1");
    }
    cmd.env_remove("AF_CONFIG_PASS");
    cmd.env_remove("AF_CONFIG_USER");
    if keep_existing_secrets {
        cmd.env_remove("AF_PASS");
    }
    let effective_port =
        resolve_effective_runner_app_port(&req.action, &req.package_id, req.app_port);
    if (1024..=65535).contains(&effective_port) {
        cmd.env("AF_APP_PORT", effective_port.to_string());
        cmd.env("AETHERFLOW_APP_PORT", effective_port.to_string());
    } else {
        cmd.env_remove("AF_APP_PORT");
        cmd.env_remove("AETHERFLOW_APP_PORT");
    }
    cmd.env_remove("AF_RCLONE_API_PORT");
    cmd.env_remove("AF_RCLONE_API_PORT_ERROR");
    if req.package_id == "rclone"
        && matches!(action_lower.as_str(), "install" | "reinstall" | "update")
        && (1..=65535).contains(&req.secondary_port)
    {
        cmd.env("RCLONE_API_PORT", req.secondary_port.to_string());
    } else if req.package_id != "rclone" || action_lower == "remove" || action_lower == "uninstall"
    {
        cmd.env_remove("RCLONE_API_PORT");
    }
    if let Some(target) = req
        .expected_target_version
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        cmd.env("AF_TARGET_VERSION", target.trim());
    } else {
        cmd.env_remove("AF_TARGET_VERSION");
    }
    let recovery_root = default_env
        .recovery_root
        .clone()
        .or_else(|| {
            default_env
                .fs_root
                .as_ref()
                .map(|root| root.join("var/backups/aetherflow-recovery"))
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PRIVILEGED_RECOVERY_ROOT));
    cmd.env("AF_RECOVERY_ROOT", &recovery_root);
    cmd.env("AF_TRANSACTION_ROOT", &recovery_root);
    if default_env.fs_root.is_none() {
        cmd.env_remove("AF_FIXTURE_ROOT");
        cmd.env_remove("TEST_ROOT");
    }
    cmd.env("AF_JOB_SCRATCH_ROOT", "/var/tmp/aetherflow-scratch");
}

pub(crate) fn configure_legacy_rclone_api_port_env(
    cmd: &mut Command,
    req: &PackageRunnerRequest,
    fs_root: Option<&Path>,
    effective_app_port: i32,
) {
    let gui_port = if (1..=65535).contains(&effective_app_port) {
        effective_app_port as u16
    } else {
        5572
    };
    let explicit_rc_port = if (1..=65535).contains(&req.secondary_port) {
        Some(req.secondary_port.to_string())
    } else {
        env::var("RCLONE_API_PORT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    match declarative_recipes::resolve_and_reserve_rclone_api_port(
        fs_root,
        gui_port,
        explicit_rc_port.as_deref(),
        &req.lifecycle_job_id,
        Some(&req.action),
    ) {
        Ok(api_port) => {
            cmd.env("AF_RCLONE_API_PORT", api_port.to_string());
            cmd.env_remove("AF_RCLONE_API_PORT_ERROR");
            if explicit_rc_port.is_some() {
                cmd.env("RCLONE_API_PORT", api_port.to_string());
            } else {
                cmd.env_remove("RCLONE_API_PORT");
            }
        }
        Err(err) => {
            cmd.env_remove("AF_RCLONE_API_PORT");
            cmd.env_remove("RCLONE_API_PORT");
            cmd.env("AF_RCLONE_API_PORT_ERROR", err.to_string());
        }
    }
}

#[cfg(unix)]
pub fn check_disk_space(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut check_path = path.to_path_buf();
    while !check_path.exists() {
        if let Some(parent) = check_path.parent() {
            check_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    let c_path = match CString::new(check_path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Failed to inspect filesystem capacity on {}: {}",
            check_path.display(),
            std::io::Error::last_os_error()
        )));
    }

    let block_size = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    let avail_bytes = (stat.f_bavail as u64).saturating_mul(block_size);
    let avail_inodes = stat.f_favail as u64;

    // Inspect filesystem type via statfs (for magic number) and df -PT
    let mut statfs_buf = unsafe { std::mem::zeroed::<libc::statfs>() };
    let _ = unsafe { libc::statfs(c_path.as_ptr(), &mut statfs_buf) };
    let f_type_u64 = statfs_buf.f_type as u64;
    let is_magic_tmpfs = f_type_u64 == 0x01021994;
    let is_magic_ramfs = f_type_u64 == 0x858458f6 || (f_type_u64 as u32) == 0x858458f6;

    let df_out = std::process::Command::new("df")
        .args(["-PT", &check_path.to_string_lossy()])
        .output();

    let fs_type = match df_out {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.lines()
                .nth(1)
                .and_then(|line| line.split_whitespace().nth(1))
                .map(|t| t.to_ascii_lowercase())
                .unwrap_or_default()
        }
        _ => String::new(),
    };

    if fs_type.is_empty() {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Staging directory {} is on tmpfs filesystem or filesystem type is unknown (unknown)",
            check_path.display()
        )));
    }

    let orig_str = path.to_string_lossy();
    let check_str = check_path.to_string_lossy();
    let is_var_tmp = |s: &str| {
        s == "/var/tmp"
            || s.starts_with("/var/tmp/")
            || s.ends_with("/var/tmp")
            || s.contains("/var/tmp/")
            || s.ends_with("var/tmp")
            || s.contains("var/tmp/")
    };

    let reject_tmpfs = is_var_tmp(&orig_str)
        || is_var_tmp(&check_str)
        || std::env::var("AF_REJECT_TMPFS_STAGING").as_deref() == Ok("1");

    if reject_tmpfs
        && (fs_type == "tmpfs" || fs_type == "ramfs" || is_magic_tmpfs || is_magic_ramfs)
    {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Staging directory {} is on tmpfs filesystem or filesystem type is unknown ({})",
            check_path.display(),
            if !fs_type.is_empty() {
                &fs_type
            } else {
                "tmpfs"
            }
        )));
    }

    if avail_bytes < min_free_bytes {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Insufficient free disk space on {}: {} MB available, {} MB required",
            path.display(),
            avail_bytes / (1024 * 1024),
            min_free_bytes / (1024 * 1024)
        )));
    }

    if avail_inodes < min_free_inodes {
        return Err(PackageExecutorError::ExecutionError(format!(
            "Insufficient free inodes on {}: {} available, {} required",
            path.display(),
            avail_inodes,
            min_free_inodes
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn check_disk_space(
    _path: &Path,
    _min_free_bytes: u64,
    _min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    Ok(())
}

pub fn ensure_sufficient_disk_space(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), PackageExecutorError> {
    check_disk_space(path, min_free_bytes, min_free_inodes)
}

pub fn check_filesystem_capacity_and_inodes(
    path: &Path,
    min_free_bytes: u64,
    min_free_inodes: u64,
) -> Result<(), String> {
    check_disk_space(path, min_free_bytes, min_free_inodes).map_err(|e| match e {
        PackageExecutorError::ExecutionError(msg) => msg,
        other => other.to_string(),
    })
}

pub fn preflight_check_disk_and_inodes(fs_root: Option<&Path>) -> Result<(), String> {
    const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;
    const MIN_FREE_INODES: u64 = 4096;

    for target in ["/var/tmp", "/var/backups", "/opt"] {
        let p = if let Some(root) = fs_root {
            root.join(target.trim_start_matches('/'))
        } else {
            PathBuf::from(target)
        };
        check_filesystem_capacity_and_inodes(&p, MIN_FREE_BYTES, MIN_FREE_INODES)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let scratch_path = if let Some(root) = fs_root {
            root.join("var/tmp/aetherflow-scratch")
        } else {
            PathBuf::from("/var/tmp/aetherflow-scratch")
        };

        let is_root = unsafe { libc::geteuid() == 0 };
        let mut check_capacity = false;

        match std::fs::symlink_metadata(&scratch_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Scratch root {} must not be a symlink",
                        scratch_path.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "Scratch root {} is not a directory",
                        scratch_path.display()
                    ));
                }
                let mode = meta.mode() & 0o777;
                if mode != 0o700 {
                    return Err(format!(
                        "Scratch root {} has permissions 0o{:o}, expected 0o700",
                        scratch_path.display(),
                        mode
                    ));
                }
                if is_root && meta.uid() != 0 {
                    return Err(format!(
                        "Scratch root {} is owned by uid {}, expected 0 (root)",
                        scratch_path.display(),
                        meta.uid()
                    ));
                }
                check_capacity = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                if let Some(parent) = scratch_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&scratch_path) {
                    Ok(()) => {
                        check_capacity = true;
                    }
                    Err(create_err) => {
                        if !is_root && create_err.kind() == std::io::ErrorKind::PermissionDenied {
                            // Unprivileged test runs fallback to checking /var/tmp
                        } else {
                            return Err(format!(
                                "Failed to create scratch root {}: {}",
                                scratch_path.display(),
                                create_err
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read metadata for scratch root {}: {}",
                    scratch_path.display(),
                    e
                ));
            }
        }

        if check_capacity && scratch_path.exists() {
            check_filesystem_capacity_and_inodes(&scratch_path, MIN_FREE_BYTES, MIN_FREE_INODES)?;
        }
    }

    Ok(())
}

pub(crate) fn format_exit_failure_diagnostics(
    code: i32,
    diag_failure: Option<&serde_json::Value>,
    saw_incomplete_rollback_line: Option<&str>,
) -> Option<String> {
    if let Some(diag) = diag_failure {
        let mut stage = diag
            .get("stage")
            .or_else(|| diag.get("failed_stage"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut category = diag
            .get("category")
            .or_else(|| diag.get("failure_category"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut summary = diag
            .get("summary")
            .or_else(|| diag.get("sanitized_summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut updated_diag = diag.clone();
        if let Some(inc_line) = saw_incomplete_rollback_line {
            if !summary.contains("incomplete-rollback") && !summary.contains("incomplete rollback")
            {
                if !summary.is_empty() {
                    summary.push_str("; ");
                }
                summary.push_str(inc_line);
            }
        }
        let is_incomplete = saw_incomplete_rollback_line.is_some()
            || category.contains("incomplete_rollback")
            || category.contains("incomplete-rollback");
        if is_incomplete {
            stage = "rollback";
            if !category.contains("incomplete_rollback")
                && !category.contains("incomplete-rollback")
            {
                category = "incomplete_rollback".to_string();
            }
            if let Some(obj) = updated_diag.as_object_mut() {
                obj.insert(
                    "stage".to_string(),
                    serde_json::Value::String("rollback".to_string()),
                );
                obj.insert(
                    "category".to_string(),
                    serde_json::Value::String("incomplete_rollback".to_string()),
                );
                obj.insert(
                    "summary".to_string(),
                    serde_json::Value::String(summary.clone()),
                );
            }
        }
        let diag_json = serde_json::to_string(&updated_diag).unwrap_or_default();
        Some(format!(
            "__RUNNER_EXIT_ERROR__:exit status {} [STAGE:{}] [CATEGORY:{}] [SUMMARY:{}] | AF_DIAG_FAILURE={}\n",
            code, stage, category, summary, diag_json
        ))
    } else {
        saw_incomplete_rollback_line.map(|inc_line| format!(
            "__RUNNER_EXIT_ERROR__:exit status {} [STAGE:rollback] [CATEGORY:incomplete_rollback] [SUMMARY:{}] | incomplete-rollback\n",
            code, inc_line
        ))
    }
}

/// Streams a package lifecycle operation (`install`, `remove`, or `update`) as newline-delimited
/// progress/log lines, dispatching to [`DeclarativePackageExecutor`] for migrated recipes and
/// automatically falling back to the legacy Bash script for unported recipes.
pub fn execute_package_request_stream(
    req: PackageRunnerRequest,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> + Send {
    async_stream::stream! {
        let Some(action) = PackageAction::parse(&req.action) else {
            yield Ok("__RUNNER_EXIT_ERROR__:disallowed package action\n".to_string());
            return;
        };
        if !script_matches_package_identity(&req.action, &req.package_id, &req.script_name) {
            yield Ok(format!(
                "__RUNNER_EXIT_ERROR__:validation failed: script '{}' does not match package '{}' for action '{}'\n",
                req.script_name, req.package_id, req.action
            ));
            return;
        };

        let effective_expected_target = req
            .expected_target_version
            .clone()
            .or_else(|| env::var("AF_TARGET_VERSION").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if let Some(pkg_def) = crate::get_runner_package_definition(&req.package_id) {
            if let Err(reason) = validate_package_target_policy(
                &req.package_id,
                &pkg_def.update_source,
                &pkg_def.update_package,
                &req.action,
                effective_expected_target.as_deref(),
            ) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", reason));
                return;
            }
        } else if req.package_id.eq_ignore_ascii_case("threadfin") {
            if let Err(reason) = validate_package_target_policy(
                &req.package_id,
                "pinned",
                THREADFIN_PINNED_VERSION,
                &req.action,
                effective_expected_target.as_deref(),
            ) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", reason));
                return;
            }
        }

        let declarative_recipe =
            if select_package_engine(&req.package_id) == PackageEngineMode::DeclarativeRust {
                get_declarative_recipe(&req.package_id)
            } else {
                None
            };
        let legacy_script_path = if declarative_recipe.is_none() {
            let Some(p) = resolve_package_script_path(&req.action, &req.script_name) else {
                yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
                return;
            };
            Some(p)
        } else {
            None
        };

        let cancel = CancellationToken::new();
        let _cancel_guard = match register_package_cancellation(&req.package_id, cancel.clone()) {
            Ok(g) => g,
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };

        let _proc_lock = match acquire_package_mutex_with_cancel(&req.package_id, &cancel).await {
            Ok(g) => g,
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };
        let default_env = PackageExecutionEnv::default();
        let _flock_guard =
            match CrossProcessLockGuard::acquire_with_cancel(&default_env, &req.package_id, &cancel)
                .await
            {
                Ok(g) => g,
                Err(e) => {
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                    return;
                }
            };

        let maintenance_guard = match crate::acquire_package_maintenance_guard(
            default_env.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&req.package_id),
            &req.lifecycle_job_id,
            Some(&req.action),
        )
        .await
        {
            Ok(guard) => Arc::new(guard),
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                return;
            }
        };

        let effective_app_port =
            resolve_effective_runner_app_port(&req.action, &req.package_id, req.app_port);

        if let Some(recipe) = declarative_recipe {
            if let Err(err) = recipe.validate() {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                return;
            }
            if let Err(err) = cancel.check(&recipe.package_id) {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                return;
            }
            let fs_root_clone = default_env.fs_root.clone();
            let keep_existing_secrets = if matches!(action, PackageAction::Remove) {
                false
            } else if matches!(action, PackageAction::Update | PackageAction::Reinstall) {
                true
            } else {
                default_env.keep_existing_secrets
            };
            let env_cfg = PackageExecutionEnv {
                app_port: effective_app_port,
                rclone_api_port: (req.package_id == "rclone"
                    && (1..=65535).contains(&req.secondary_port))
                .then_some(req.secondary_port as u16),
                lifecycle_job_id: req.lifecycle_job_id.clone(),
                // Purge is an explicit request property, never ambient
                // runner environment.
                delete_data: package_request_deletes_data(&req),
                keep_existing_secrets,
                expected_target_version: req.expected_target_version.clone().or_else(|| {
                    env::var("AF_TARGET_VERSION").ok().filter(|s| !s.trim().is_empty())
                }),
                scratch_root: Some(PathBuf::from("/var/tmp/aetherflow-scratch")),
                ..default_env
            };
            let executor = Arc::new(DeclarativePackageExecutor::new(env_cfg));
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let lease_for_task = maintenance_guard.clone();
            let cancel_for_task = cancel.clone();
            let exec_handle = tokio::spawn(async move {
                crate::PACKAGE_MAINTENANCE_LEASE
                    .scope(
                        lease_for_task,
                        executor.execute_reserved_recipe(&recipe, action, cancel_for_task, move |ev| {
                            let _ = tx.send(format!("{}\n", ev.to_wire_line()));
                        }),
                    )
                    .await
            });

            let mut saw_error = false;
            while let Some(line) = rx.recv().await {
                if line.starts_with("__RUNNER_EXIT_ERROR__:") {
                    saw_error = true;
                }
                yield Ok(line);
            }

            match exec_handle.await {
                Ok(Ok(_outcome)) => {}
                Ok(Err(err)) => {
                    saw_error = true;
                    yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
                }
                Err(join_err) => {
                    saw_error = true;
                    yield Ok(format!(
                        "__RUNNER_EXIT_ERROR__:declarative task failed: {}\n",
                        join_err
                    ));
                }
            }

            if !saw_error
                && matches!(
                    action,
                    PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
                )
            {
                let defer_blueprint = std::env::var("AETHERFLOW_DEFER_BLUEPRINT_SYNC")
                    .map(|v| v == "1")
                    .unwrap_or(false)
                    || req.expected_target_version.is_some()
                    || !req.lifecycle_job_id.is_empty();

                if !defer_blueprint {
                    if let Err(err) = crate::PACKAGE_MAINTENANCE_LEASE.scope(
                        maintenance_guard.clone(),
                        apply_runner_blueprint_in_background(fs_root_clone, req.package_id.clone(), effective_app_port),
                    ).await {
                        yield Ok(format!(
                            "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                            err
                        ));
                        return;
                    }
                }
            }
            return;
        }

        // Legacy Bash fallback for unported recipes
        let Some(script_path) = legacy_script_path else {
            yield Ok("__RUNNER_EXIT_ERROR__:package script not found\n".to_string());
            return;
        };
        let env_cfg = default_env;

        let installs = matches!(action, PackageAction::Install | PackageAction::Reinstall | PackageAction::Update);
        let sandbox_units = legacy_sandbox_units(&req.package_id);
        let test_live_sandbox = {
            #[cfg(test)]
            {
                env::var("AETHERFLOW_TEST_LIVE_SANDBOX")
                    .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        let live_sandbox = ((env_cfg.fs_root.is_none()
            && env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none())
            || test_live_sandbox)
            && !env::var("AETHERFLOW_SANDBOX_DRY_RUN").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            && cfg!(target_os = "linux");
        let (sandbox_effective_root, sandbox_systemd_root) =
            resolve_package_sandbox_roots(env_cfg.fs_root.as_deref());
        let mut sandbox_journal = RollbackJournal::new(sandbox_effective_root);
        let sandbox_runner = TokioCommandRunner {
            respect_dry_run_env: false,
        };
        let readiness_config = {
            #[cfg(test)]
            {
                LegacyReadinessConfig::from_test_env_for_package(&req.package_id)
            }
            #[cfg(not(test))]
            {
                LegacyReadinessConfig::for_package(&req.package_id)
            }
        };
        let mut unit_snapshots = Vec::new();
        if installs && !sandbox_units.is_empty() {
            if let Err(error) = ensure_package_sandbox_dropin_under_root_with_journal(
                env_cfg.fs_root.as_deref(),
                &req.package_id,
                &req.action,
                Some(&mut sandbox_journal),
            ) {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(
                    format!("pre-install sandbox failed: {error}"),
                    rb,
                ));
                return;
            }
            if live_sandbox {
                for unit in &sandbox_units {
                    match legacy_unit_snapshot_in_root(unit, env_cfg.fs_root.as_deref()) {
                        Ok(snapshot) => unit_snapshots.push((unit, snapshot)),
                        Err(error) => {
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(
                                format!("cannot snapshot {unit}: {error}"),
                                rb,
                            ));
                            return;
                        }
                    }
                }
                if let Err(error) = crate::PACKAGE_MAINTENANCE_LEASE
                    .scope(
                        maintenance_guard.clone(),
                        run_systemctl_bounded(
                            &sandbox_runner,
                            &["daemon-reload"],
                            &cancel,
                            readiness_config.systemctl_timeout,
                        ),
                    )
                    .await
                {
                    let rb = rollback_legacy_sandbox_with_lease(
                        &maintenance_guard,
                        &mut sandbox_journal,
                        &sandbox_units,
                        &sandbox_systemd_root,
                        live_sandbox,
                    )
                    .await;
                    let base = match error {
                        PackageExecutorError::Cancelled(_) => {
                            format!("operation cancelled for package '{}'", req.package_id)
                        }
                        other => format!("pre-install sandbox failed: {other}"),
                    };
                    yield Ok(format_error_with_sandbox_rollback(base, rb));
                    return;
                }
            }
        }

        let mut cmd = Command::new("bash");
        cmd.arg(&script_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        apply_legacy_package_environment(&mut cmd, &req);
        if req.package_id == "rclone" && installs {
            configure_legacy_rclone_api_port_env(
                &mut cmd,
                &req,
                env_cfg.fs_root.as_deref(),
                effective_app_port,
            );
        }
        let verify_sandbox = installs && live_sandbox && !sandbox_units.is_empty();
        if verify_sandbox {
            cmd.env("AF_EMIT_READINESS_RECORD", "1");
        } else {
            cmd.env_remove("AF_EMIT_READINESS_RECORD");
        }
        match try_resolve_master_credentials(env_cfg.fs_root.as_deref()) {
            Ok((master_user, master_pass)) => {
                cmd.env("MASTER_USER", master_user)
                    .env("MASTER_PASS", master_pass);
            }
            Err(error) => {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                return;
            }
        }

        #[cfg(unix)]
        if let Err(error) = maintenance_guard.preserve_in_child(cmd.as_std_mut()) {
            let rb = rollback_legacy_sandbox_with_lease(
                &maintenance_guard,
                &mut sandbox_journal,
                &sandbox_units,
                &sandbox_systemd_root,
                live_sandbox,
            )
            .await;
            yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
            return;
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let mut stdout = BoundedLines::new(child.stdout.take().unwrap());
                let mut stderr = BoundedLines::new(child.stderr.take().unwrap());
                let mut stdout_open = true;
                let mut stderr_open = true;
                let mut diag_failure: Option<serde_json::Value> = None;
                let mut saw_incomplete_rollback_line: Option<String> = None;
                let mut recorded_readiness_probes: HashMap<String, Vec<RecordedReadinessProbe>> =
                    HashMap::new();
                while stdout_open || stderr_open {
                    if cancel.is_cancelled() {
                        terminate_child_process_group(&mut child).await;
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(
                            format!("operation cancelled for package '{}'", req.package_id),
                            rb,
                        ));
                        return;
                    }
                    let (is_stdout, result) = tokio::select! {
                        _ = wait_for_cancellation(&cancel) => {
                            terminate_child_process_group(&mut child).await;
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(
                                format!("operation cancelled for package '{}'", req.package_id),
                                rb,
                            ));
                            return;
                        }
                        result = stdout.next_line(), if stdout_open => (true, result),
                        result = stderr.next_line(), if stderr_open => (false, result),
                    };
                    match result {
                        Ok(Some(line)) => {
                            if line.trim_start().starts_with(AF_READINESS_PROBE_PREFIX) {
                                if verify_sandbox && !is_stdout {
                                    if let Some(probe) =
                                        parse_readiness_probe_record(&line, &sandbox_units)
                                    {
                                        record_readiness_probe(
                                            &mut recorded_readiness_probes,
                                            probe,
                                        );
                                    }
                                }
                                continue;
                            }
                            if let Some(pos) = line.find("AF_DIAG_FAILURE=") {
                                let json_slice = &line[pos + "AF_DIAG_FAILURE=".len()..];
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_slice.trim()) {
                                    diag_failure = Some(v);
                                }
                            }
                            let lower = line.to_ascii_lowercase();
                            if crate::package_lifecycle::is_incomplete_rollback_error(&line)
                                || lower.contains("incomplete-rollback")
                                || lower.contains("incomplete rollback")
                                || lower.contains("recovery backup preserved")
                            {
                                saw_incomplete_rollback_line = Some(crate::package_lifecycle::sanitize_lifecycle_field(line.trim()));
                            }
                            yield Ok(format!("{}\n", line));
                        }
                        Ok(None) if is_stdout => stdout_open = false,
                        Ok(None) => stderr_open = false,
                        Err(error) => {
                            terminate_child_process_group(&mut child).await;
                            let rb = rollback_legacy_sandbox_with_lease(
                                &maintenance_guard,
                                &mut sandbox_journal,
                                &sandbox_units,
                                &sandbox_systemd_root,
                                live_sandbox,
                            )
                            .await;
                            yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                            return;
                        }
                    }
                }
                let status = tokio::select! {
                    biased;
                    _ = wait_for_cancellation(&cancel) => {
                        terminate_child_process_group(&mut child).await;
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(
                            format!("operation cancelled for package '{}'", req.package_id),
                            rb,
                        ));
                        return;
                    }
                    status = child.wait() => status,
                };
                match status {
                    Ok(status) if !status.success() => {
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        if let Err(rb_err) = rb {
                            let combined = match saw_incomplete_rollback_line.take() {
                                Some(existing) => format!("{existing}; {rb_err}"),
                                None => format!("incomplete rollback: {rb_err}"),
                            };
                            saw_incomplete_rollback_line = Some(
                                crate::package_lifecycle::sanitize_lifecycle_field(&combined),
                            );
                        }
                        let code = status.code().unwrap_or(1);
                        if let Some(formatted) = format_exit_failure_diagnostics(
                            code,
                            diag_failure.as_ref(),
                            saw_incomplete_rollback_line.as_deref(),
                        ) {
                            yield Ok(formatted);
                        } else {
                            yield Ok(format!("__RUNNER_EXIT_ERROR__:exit status {}\n", status));
                        }
                    }
                    Err(error) => {
                        let rb = rollback_legacy_sandbox_with_lease(
                            &maintenance_guard,
                            &mut sandbox_journal,
                            &sandbox_units,
                            &sandbox_systemd_root,
                            live_sandbox,
                        )
                        .await;
                        yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
                    }
                    Ok(_) => {
                        let activation = async {
                            let post_script_dropins = verify_sandbox
                                .then(|| snapshot_sandbox_dropin_bytes(&sandbox_systemd_root, &sandbox_units))
                                .transpose()?;
                            ensure_package_sandbox_dropin_under_root_with_journal(
                                env_cfg.fs_root.as_deref(),
                                &req.package_id,
                                &req.action,
                                Some(&mut sandbox_journal),
                            )?;
                            let Some(post_script_dropins) = post_script_dropins else {
                                return Ok(Vec::new());
                            };
                            let final_dropins =
                                snapshot_sandbox_dropin_bytes(&sandbox_systemd_root, &sandbox_units)?;
                            let mut units_needing_restart = Vec::new();
                            for (unit, before) in &unit_snapshots {
                                let after = legacy_unit_snapshot_in_root(
                                    unit,
                                    env_cfg.fs_root.as_deref(),
                                )
                                .map_err(|err| {
                                        PackageExecutorError::ExecutionError(format!(
                                            "cannot inspect {unit}: {err}"
                                        ))
                                })?;
                                let dropin_changed =
                                    post_script_dropins.get(*unit) != final_dropins.get(*unit);
                                if legacy_unit_changed(before, &after) || dropin_changed {
                                    units_needing_restart.push((*unit).clone());
                                }
                            }
                            crate::PACKAGE_MAINTENANCE_LEASE
                                .scope(
                                    maintenance_guard.clone(),
                                    activate_and_verify_legacy_sandbox(
                                        &req.package_id,
                                        &units_needing_restart,
                                        &recorded_readiness_probes,
                                        &sandbox_runner,
                                        &cancel,
                                        &readiness_config,
                                    ),
                                )
                                .await
                        }.await;
                        match activation {
                            Ok(notes) => {
                                for note in notes {
                                    yield Ok(format!("{note}\n"));
                                }
                            }
                            Err(error) => {
                                let rollback = rollback_legacy_sandbox_with_lease(
                                    &maintenance_guard,
                                    &mut sandbox_journal,
                                    &sandbox_units,
                                    &sandbox_systemd_root,
                                    live_sandbox,
                                )
                                .await;
                                let message = match error {
                                    PackageExecutorError::Cancelled(_) => format!(
                                        "operation cancelled for package '{}'",
                                        req.package_id
                                    ),
                                    other => format!("post-install sandbox failed: {other}"),
                                };
                                yield Ok(format_post_commit_sandbox_error(message, rollback));
                                return;
                            }
                        }
                        sandbox_journal.commit();
                        let defer_blueprint = std::env::var("AETHERFLOW_DEFER_BLUEPRINT_SYNC")
                            .map(|v| v == "1")
                            .unwrap_or(false)
                            || req.expected_target_version.is_some()
                            || !req.lifecycle_job_id.is_empty();

                        if !defer_blueprint
                            && matches!(
                                action,
                                PackageAction::Install
                                    | PackageAction::Reinstall
                                    | PackageAction::Update
                            )
                        {
                            if let Err(err) = crate::PACKAGE_MAINTENANCE_LEASE.scope(
                                maintenance_guard.clone(),
                                apply_runner_blueprint_in_background(env_cfg.fs_root.clone(), req.package_id.clone(), effective_app_port),
                            ).await {
                                yield Ok(format!(
                                    "__RUNNER_EXIT_ERROR__:blueprint configuration failed: {}\n",
                                    err
                                ));
                                return;
                            }
                        }

                    }
                }
            }
            Err(error) => {
                let rb = rollback_legacy_sandbox_with_lease(
                    &maintenance_guard,
                    &mut sandbox_journal,
                    &sandbox_units,
                    &sandbox_systemd_root,
                    live_sandbox,
                )
                .await;
                yield Ok(format_error_with_sandbox_rollback(error.to_string(), rb));
            }
        }
    }
}
