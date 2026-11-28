use super::*;

pub(crate) fn build_self_update_transient_unit_name(command: &str, channel: &str) -> String {
    let cmd_slug: String = command
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect();
    let chan_slug: String = channel
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect();
    let raw_uuid = uuid::Uuid::new_v4().simple().to_string();
    let short_id = &raw_uuid[..8];
    format!(
        "aetherflow-self-update-{}-{}-{}.service",
        cmd_slug, chan_slug, short_id
    )
}

static SAFE_SELF_UPDATE_UNIT_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^aetherflow-self-update-[a-z0-9-]+-[a-z0-9-]+-[a-f0-9]{8,32}\.service$").unwrap()
});

pub fn validate_self_update_job_unit_name(unit_name: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = unit_name.trim();
    if trimmed.is_empty()
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || !SAFE_SELF_UPDATE_UNIT_NAME.is_match(trimmed)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid self-update job_unit identifier: {:?}", unit_name),
        ));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn resolve_self_update_isolated_root_from_env() -> Result<Option<PathBuf>, String> {
    if let Ok(raw) = env::var("AETHERFLOW_RELEASE_ROOT") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if !p.is_absolute()
                || p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "AETHERFLOW_RELEASE_ROOT '{}' must be an absolute path without '..'",
                    trimmed
                ));
            }
            return Ok(Some(p));
        }
    }
    af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
        .map_err(|e| e.to_string())
}

pub(crate) fn resolve_self_update_lock_path_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::resolve_maintenance_lock_path_for_config(cfg)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

pub(crate) fn resolve_self_update_db_path_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::try_resolve_db_path(cfg, None)
        .map(|resolved| resolved.path)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

pub(crate) fn resolve_self_update_backup_dir_for_cfg(cfg: &af_release::ReleaseConfig) -> PathBuf {
    cfg.data_dir.join("backups")
}

pub(crate) fn resolve_self_update_jobs_dir_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::resolve_self_update_jobs_dir_for_config(cfg)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

pub(crate) fn resolve_self_update_jobs_dir_from_env() -> Result<PathBuf, (StatusCode, String)> {
    let explicit_root = resolve_self_update_isolated_root_from_env()
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let conf_path = af_release::resolve_release_manager_conf_for_root(explicit_root.as_deref());
    af_release::resolve_self_update_jobs_dir_from_process_env(
        explicit_root.as_deref(),
        conf_path.as_deref(),
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

pub fn write_self_update_job_status_atomic(
    status_path: &Path,
    status: &SelfUpdateJobStatus,
) -> std::io::Result<()> {
    job_receipts::write(status_path, status)
}

pub fn claim_self_update_job(status_path: &Path, unit: &str) -> std::io::Result<()> {
    job_receipts::claim(status_path, unit)
}

type ValidatedSelfUpdateConfig = (af_release::ReleaseConfig, Option<PathBuf>, Option<PathBuf>);

pub(crate) fn resolve_validated_self_update_config(
    channel: af_release::ReleaseChannel,
) -> Result<ValidatedSelfUpdateConfig, (StatusCode, String)> {
    let explicit_root =
        resolve_self_update_isolated_root_from_env().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conf_path = af_release::resolve_release_manager_conf_for_root(explicit_root.as_deref());
    let mut cfg = af_release::ReleaseConfig::load_for_root_from_process_env(
        explicit_root.as_deref(),
        conf_path.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    cfg.release_channel = channel;
    af_release::ensure_interoperable_maintenance_lock_file(&cfg)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok((cfg, explicit_root, conf_path))
}

pub(crate) async fn spawn_self_update_transient_unit(
    unit_name: &str,
    program: &Path,
    args: &[String],
    extra_envs: &[(&str, String)],
) -> Result<String, (StatusCode, String)> {
    let Some(systemd_run) = resolve_systemd_run_binary() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "systemd-run binary not found for out-of-cgroup self-update handoff".to_string(),
        ));
    };

    let mut cmd = Command::new(&systemd_run);
    cmd.arg(format!("--unit={}", unit_name))
        .arg("--collect")
        .arg("--no-block")
        .arg("--property=Type=exec")
        .arg("--property=KillMode=control-group");

    let preserved_envs = [
        "AETHERFLOW_ENABLE_RUST_RELEASE",
        "AETHERFLOW_USE_RUST_RELEASE",
        "AETHERFLOW_RELEASE_ENGINE",
        "AETHERFLOW_FORCE_BASH_RELEASE",
        "AETHERFLOW_RELEASE_ROOT",
        "AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE",
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_MAINTENANCE_LOCK_PATH",
        "AF_DB_PATH",
        "DB_PATH",
        "AETHERFLOW_DB_PATH",
        "AETHERFLOW_BACKUP_DIR",
        "AF_BACKUP_DIR",
        "BACKUP_DIR",
        "AF_OFFLINE",
        "DRY_RUN_ROOT",
    ];
    for env_key in &preserved_envs {
        if extra_envs.iter().any(|(k, _)| k == env_key) {
            continue;
        }
        if let Ok(env_val) = env::var(env_key) {
            let trimmed = env_val.trim();
            if !trimmed.is_empty() {
                cmd.arg(format!("--setenv={}={}", env_key, trimmed));
            }
        }
    }
    for (env_key, env_val) in extra_envs {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("--setenv={}={}", env_key, trimmed));
        }
    }

    cmd.arg("--").arg(program);
    for arg_val in args {
        cmd.arg(arg_val);
    }

    match bounded_command::output(cmd, Duration::from_secs(15), 256 * 1024).await {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .trim()
            .to_string();
            if out.status.success() {
                Ok(combined)
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "transient systemd unit '{}' failed to start ({}): {}",
                        unit_name, out.status, combined
                    ),
                ))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => Err((
            StatusCode::GATEWAY_TIMEOUT,
            format!(
                "systemd-run timed out while launching transient unit '{}'",
                unit_name
            ),
        )),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to launch transient systemd unit '{}': {}",
                unit_name, err
            ),
        )),
    }
}

/// A successful launch request may already have a terminal worker receipt.
/// `RunnerResponse::success` reports that the request was handled; the payload
/// carries the actual operation result, including a fast failure.
fn self_update_launch_response(
    engine: &str,
    command: &str,
    channel: &str,
    observed: &SelfUpdateJobStatus,
) -> RunnerResponse {
    RunnerResponse {
        success: true,
        output: json!({
            "status": if observed.completed { observed.status.as_str() } else { "initiated" },
            "completed": observed.completed,
            "success": observed.success,
            "error": observed.error,
            "exit_code": observed.exit_code,
            "engine": engine,
            "command": command,
            "channel": channel,
            "job_unit": observed.job_unit,
        })
        .to_string(),
        error: String::new(),
    }
}

/// Validates and executes a `SelfUpdateRequest` using either the native Rust `af-release`
/// engine (the default, unless `AETHERFLOW_FORCE_BASH_RELEASE=1` or
/// `AETHERFLOW_RELEASE_ENGINE=bash` is set) or the legacy `deploy/release-manager.sh` script.
///
/// Experimental channel safety: `af_release::validate_self_update_request` validates
/// `stable`, `nightly`, and `experimental` channels.
pub async fn execute_self_update_request(
    req: &SelfUpdateRequest,
    background: bool,
) -> (StatusCode, RunnerResponse) {
    let validated = match af_release::validate_self_update_request(req) {
        Ok(val) => val,
        Err(err_resp) => return (StatusCode::BAD_REQUEST, err_resp),
    };

    let (cfg, explicit_root, _resolved_conf) =
        match resolve_validated_self_update_config(validated.channel) {
            Ok(tuple) => tuple,
            Err((code, err_msg)) => {
                return (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err_msg,
                    },
                );
            }
        };

    let cfg_lock_path = match resolve_self_update_lock_path_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };
    let cfg_db_path = match resolve_self_update_db_path_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };
    let cfg_backup_dir = resolve_self_update_backup_dir_for_cfg(&cfg);
    let cfg_jobs_dir = match resolve_self_update_jobs_dir_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };

    let _admission_guard = if background {
        let guard = match af_release::ReleaseLockGuard::acquire(&cfg_lock_path, Duration::ZERO) {
            Ok(guard) => guard,
            Err(err) => {
                return (
                    StatusCode::CONFLICT,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Application or system lifecycle work is active: {}", err),
                    },
                )
            }
        };
        if let Err(error) =
            af_release::admin::ensure_no_active_package_lifecycle_jobs(&cfg, validated.command)
        {
            return (
                StatusCode::CONFLICT,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                },
            );
        }
        match discover_system_update(&cfg).await {
            Ok(status) if update_status_allows_launch(&status, validated.command) => {}
            Ok(status) => {
                return (
                    StatusCode::CONFLICT,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!(
                            "System update in progress or recovery required: {}",
                            status.error
                        ),
                    },
                )
            }
            Err((code, error)) => {
                return (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    },
                )
            }
        }
        Some(guard)
    } else {
        None
    };

    let engine = select_release_engine();
    if engine == ReleaseEngineMode::NativeRustRelease {
        if background {
            let Some(af_bin) = resolve_af_cli_binary() else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: "af CLI binary not found for transient systemd release unit"
                            .to_string(),
                    },
                );
            };
            let unit_name = build_self_update_transient_unit_name(
                validated.command.as_str(),
                validated.channel.as_str(),
            );
            let job_status_path = cfg_jobs_dir.join(format!("{}.json", unit_name));
            let job_conf_name = format!("{}.conf", unit_name);
            let job_conf_path = cfg_jobs_dir.join(&job_conf_name);
            let _launch_owner = match job_receipts::begin_launch(&job_status_path) {
                Ok(owner) => owner,
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: format!("Cannot reserve updater launch: {error}"),
                        },
                    )
                }
            };

            if let Err(err) = _launch_owner
                .write_protected_config_file(std::ffi::OsStr::new(&job_conf_name), &cfg)
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("failed to persist self-update job config: {}", err),
                    },
                );
            }
            let initial_status = SelfUpdateJobStatus {
                status: "launching".to_string(),
                completed: false,
                success: false,
                job_unit: unit_name.clone(),
                error: String::new(),
                exit_code: None,
            };
            if let Err(err) = write_self_update_job_status_atomic(&job_status_path, &initial_status)
            {
                let _ = _launch_owner
                    .remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("failed to persist initial self-update job status: {}", err),
                    },
                );
            }

            let mut unit_args = Vec::new();
            if let Some(ref root) = explicit_root {
                unit_args.push("--root".to_string());
                unit_args.push(root.to_string_lossy().into_owned());
            }
            unit_args.extend([
                "release".to_string(),
                validated.command.as_str().to_string(),
                "--channel".to_string(),
                validated.channel.as_str().to_string(),
                "--local".to_string(),
                "--config".to_string(),
                job_conf_path.to_string_lossy().into_owned(),
                "--job-status-file".to_string(),
                job_status_path.to_string_lossy().into_owned(),
                "--job-unit".to_string(),
                unit_name.clone(),
            ]);

            let (dir_dev, dir_ino) = match _launch_owner.directory_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = _launch_owner
                        .remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: format!(
                                "Cannot pin self-update receipt directory identity: {error}"
                            ),
                        },
                    );
                }
            };
            let mut extra_envs = vec![
                (
                    "AETHERFLOW_SELF_UPDATE_STATUS_FILE",
                    job_status_path.to_string_lossy().into_owned(),
                ),
                ("AETHERFLOW_SELF_UPDATE_JOB_UNIT", unit_name.clone()),
                ("AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV", dir_dev.to_string()),
                ("AETHERFLOW_SELF_UPDATE_DIRECTORY_INO", dir_ino.to_string()),
                (
                    "AETHERFLOW_RELEASE_CONF",
                    job_conf_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                    cfg_lock_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_DB_PATH",
                    cfg_db_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_BACKUP_DIR",
                    cfg_backup_dir.to_string_lossy().into_owned(),
                ),
            ];
            if let Some(ref root) = explicit_root {
                extra_envs.push((
                    "AETHERFLOW_RELEASE_ROOT",
                    root.to_string_lossy().into_owned(),
                ));
            }

            match spawn_self_update_transient_unit(&unit_name, &af_bin, &unit_args, &extra_envs)
                .await
            {
                Ok(_) => {
                    let mut admitted = initial_status.clone();
                    admitted.status = "running".into();
                    let observed = match job_receipts::compare_exchange_pinned(
                        &job_status_path,
                        &initial_status,
                        &admitted,
                        Some((dir_dev, dir_ino)),
                    ) {
                        Ok(observed) => observed,
                        Err(error) => {
                            return (StatusCode::INTERNAL_SERVER_ERROR, RunnerResponse {
                                success: false, output: String::new(), error: format!("Unit admitted but launch acknowledgment could not be persisted: {error}"),
                            });
                        }
                    };
                    return (
                        StatusCode::OK,
                        self_update_launch_response(
                            "native_rust_release",
                            validated.command.as_str(),
                            validated.channel.as_str(),
                            &observed,
                        ),
                    );
                }
                Err((code, err_msg)) => {
                    if code != StatusCode::GATEWAY_TIMEOUT {
                        let failed_receipt = SelfUpdateJobStatus {
                            status: "failed".to_string(),
                            completed: true,
                            success: false,
                            job_unit: unit_name.clone(),
                            error: err_msg.clone(),
                            exit_code: Some(1),
                        };
                        let _ = job_receipts::compare_exchange_pinned(
                            &job_status_path,
                            &initial_status,
                            &failed_receipt,
                            Some((dir_dev, dir_ino)),
                        );
                        let _ = _launch_owner
                            .remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
                    }
                    return (
                        code,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: err_msg,
                        },
                    );
                }
            }
        } else {
            let req_clone = validated.clone();
            let (_exit_code, resp) = tokio::task::spawn_blocking(move || {
                af_release::execute_self_update_sync(&req_clone, cfg)
            })
            .await
            .unwrap_or_else(|err| {
                (
                    af_release::ExitCode::ConfigurationOrUsageError,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err.to_string(),
                    },
                )
            });
            let status = if resp.success {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (status, resp);
        }
    }

    let Some(script_path) = resolve_release_manager_script() else {
        return (
            StatusCode::NOT_FOUND,
            RunnerResponse {
                success: false,
                output: String::new(),
                error: "release-manager.sh not found".to_string(),
            },
        );
    };

    let cmd_name = validated.command.as_str().to_string();
    let channel_str = validated.channel.as_str().to_string();
    if background {
        let unit_name = build_self_update_transient_unit_name(&cmd_name, &channel_str);
        let job_status_path = cfg_jobs_dir.join(format!("{}.json", unit_name));
        let job_conf_name = format!("{}.conf", unit_name);
        let job_conf_path = cfg_jobs_dir.join(&job_conf_name);
        let _launch_owner = match job_receipts::begin_launch(&job_status_path) {
            Ok(owner) => owner,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Cannot reserve updater launch: {error}"),
                    },
                )
            }
        };

        if let Err(err) =
            _launch_owner.write_protected_config_file(std::ffi::OsStr::new(&job_conf_name), &cfg)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist self-update job config: {}", err),
                },
            );
        }
        let initial_status = SelfUpdateJobStatus {
            status: "launching".to_string(),
            completed: false,
            success: false,
            job_unit: unit_name.clone(),
            error: String::new(),
            exit_code: None,
        };
        if let Err(err) = write_self_update_job_status_atomic(&job_status_path, &initial_status) {
            let _ =
                _launch_owner.remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist initial self-update job status: {}", err),
                },
            );
        }

        let receipt_directory_identity = match _launch_owner.directory_identity() {
            Ok(identity) => identity,
            Err(error) => {
                let _ = _launch_owner
                    .remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Cannot bind updater receipt directory: {error}"),
                    },
                );
            }
        };
        let mut unit_args = vec![
            script_path.to_string_lossy().into_owned(),
            cmd_name.clone(),
            "--channel".to_string(),
            channel_str.clone(),
        ];
        if let Some(ref root) = explicit_root {
            unit_args.push("--root".to_string());
            unit_args.push(root.to_string_lossy().into_owned());
        }
        unit_args.extend([
            "--config".to_string(),
            job_conf_path.to_string_lossy().into_owned(),
            "--job-status-file".to_string(),
            job_status_path.to_string_lossy().into_owned(),
            "--job-unit".to_string(),
            unit_name.clone(),
        ]);

        let mut extra_envs = vec![
            (
                "AETHERFLOW_SELF_UPDATE_STATUS_FILE",
                job_status_path.to_string_lossy().into_owned(),
            ),
            ("AETHERFLOW_SELF_UPDATE_JOB_UNIT", unit_name.clone()),
            (
                "AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV",
                receipt_directory_identity.0.to_string(),
            ),
            (
                "AETHERFLOW_SELF_UPDATE_DIRECTORY_INO",
                receipt_directory_identity.1.to_string(),
            ),
            (
                "AETHERFLOW_RELEASE_CONF",
                job_conf_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                cfg_lock_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_DB_PATH",
                cfg_db_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_BACKUP_DIR",
                cfg_backup_dir.to_string_lossy().into_owned(),
            ),
        ];
        if let Some(ref root) = explicit_root {
            extra_envs.push((
                "AETHERFLOW_RELEASE_ROOT",
                root.to_string_lossy().into_owned(),
            ));
        }

        match spawn_self_update_transient_unit(
            &unit_name,
            Path::new("/bin/bash"),
            &unit_args,
            &extra_envs,
        )
        .await
        {
            Ok(_) => {
                let mut admitted = initial_status.clone();
                admitted.status = "running".into();
                let observed = match job_receipts::compare_exchange_pinned(
                    &job_status_path,
                    &initial_status,
                    &admitted,
                    Some(receipt_directory_identity),
                ) {
                    Ok(observed) => observed,
                    Err(error) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, RunnerResponse {
                            success: false, output: String::new(), error: format!("Unit admitted but launch acknowledgment could not be persisted: {error}"),
                        });
                    }
                };
                (
                    StatusCode::OK,
                    self_update_launch_response(
                        "legacy_bash_release",
                        &cmd_name,
                        &channel_str,
                        &observed,
                    ),
                )
            }
            Err((code, err_msg)) => {
                if code != StatusCode::GATEWAY_TIMEOUT {
                    let failed_receipt = SelfUpdateJobStatus {
                        status: "failed".to_string(),
                        completed: true,
                        success: false,
                        job_unit: unit_name.clone(),
                        error: err_msg.clone(),
                        exit_code: Some(1),
                    };
                    let _ = job_receipts::compare_exchange_pinned(
                        &job_status_path,
                        &initial_status,
                        &failed_receipt,
                        Some(receipt_directory_identity),
                    );
                    let _ = _launch_owner
                        .remove_regular_file_if_present(std::ffi::OsStr::new(&job_conf_name));
                }
                (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err_msg,
                    },
                )
            }
        }
    } else {
        let _guard = BACKUP_MUTEX.lock().await;
        let sync_dir =
            match job_receipts::ReceiptDirectory::open_confined(&cfg_jobs_dir, true, 0o700)
                .and_then(|dir| {
                    dir.verify_root_owner()?;
                    Ok(dir)
                }) {
                Ok(dir) => dir,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: format!(
                                "failed to open confined self-update jobs directory: {}",
                                err
                            ),
                        },
                    );
                }
            };
        let sync_conf_name = format!("sync-{}.conf", std::process::id());
        let sync_conf_path = cfg_jobs_dir.join(&sync_conf_name);
        if let Err(err) =
            sync_dir.write_protected_config_file(std::ffi::OsStr::new(&sync_conf_name), &cfg)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist sync self-update config: {}", err),
                },
            );
        }
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(&script_path)
            .arg(&cmd_name)
            .arg("--channel")
            .arg(&channel_str);
        if let Some(ref root) = explicit_root {
            cmd.arg("--root").arg(root);
            cmd.env("AETHERFLOW_RELEASE_ROOT", root);
        }
        cmd.arg("--config").arg(&sync_conf_path);
        cmd.env("AETHERFLOW_RELEASE_CONF", &sync_conf_path);
        cmd.env("AETHERFLOW_MAINTENANCE_LOCK_PATH", &cfg_lock_path);
        cmd.env("AETHERFLOW_DB_PATH", &cfg_db_path);
        cmd.env("AETHERFLOW_BACKUP_DIR", &cfg_backup_dir);

        let res = bounded_command::output(cmd, Duration::from_secs(900), 4 * 1024 * 1024).await;
        let _ = sync_dir.remove_regular_file_if_present(std::ffi::OsStr::new(&sync_conf_name));
        match res {
            Ok(out) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if out.status.success() {
                    (
                        StatusCode::OK,
                        RunnerResponse {
                            success: true,
                            output: combined,
                            error: String::new(),
                        },
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: combined,
                            error: format!("exit status: {}", out.status),
                        },
                    )
                }
            }
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err.to_string(),
                },
            ),
        }
    }
}

/// Empty job identity discovers all persisted receipts, even after API/runner
/// restart. Missing directories mean no jobs; unreadable/corrupt state fails closed.
pub async fn query_self_update_status_local(
    job_unit: &str,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    if !job_unit.trim().is_empty() {
        return query_self_update_job_status_local(job_unit).await;
    }
    let root =
        resolve_self_update_isolated_root_from_env().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conf = af_release::resolve_release_manager_conf_for_root(root.as_deref());
    let cfg =
        af_release::ReleaseConfig::load_for_root_from_process_env(root.as_deref(), conf.as_deref())
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    discover_system_update(&cfg).await
}

pub(crate) fn update_status_allows_launch(
    status: &SelfUpdateJobStatus,
    command: af_release::ReleaseCommand,
) -> bool {
    status.completed
        || (status.status == "recovery_required" && command == af_release::ReleaseCommand::Rollback)
}

pub(crate) async fn discover_system_update(
    cfg: &af_release::ReleaseConfig,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let dir = resolve_self_update_jobs_dir_for_cfg(cfg)?;
    match job_receipts::ReceiptDirectory::open_existing(&dir) {
        Ok(Some(directory)) => {
            directory
                .verify_root_owner()
                .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
            let names = directory
                .names()
                .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
            for name in names {
                let path = dir.join(name);
                if path.extension().and_then(|p| p.to_str()) != Some("json") {
                    continue;
                }
                let unit = path
                    .file_stem()
                    .and_then(|p| p.to_str())
                    .unwrap_or_default();
                validate_self_update_job_unit_name(unit)
                    .map_err(|(_, error)| (StatusCode::SERVICE_UNAVAILABLE, error))?;
                let status = query_self_update_job_in(unit, &path, &directory).await?;
                if !status.completed {
                    return Ok(status);
                }
            }
        }
        Ok(None) => {}
        Err(e) => return Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string())),
    }
    let recovery = af_release::RecoveryState::load(&cfg.releases_dir)
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    if recovery
        .is_some_and(|r| r.is_unfinished() || r.has_unhealthy_or_interrupted_post_swap_deploy())
    {
        return Ok(SelfUpdateJobStatus {
            status: "recovery_required".into(),
            completed: false,
            success: false,
            job_unit: String::new(),
            error: "System update recovery is required before application work".into(),
            exit_code: None,
        });
    }
    Ok(SelfUpdateJobStatus {
        status: "succeeded".into(),
        completed: true,
        success: true,
        job_unit: String::new(),
        error: String::new(),
        exit_code: Some(0),
    })
}

/// API admission holds this only while checking updater receipts and persisting
/// its job. Updaters inspect that durable row under the same lock before launch.
pub fn acquire_lifecycle_admission_lock(
    root: Option<&Path>,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    let env_root = resolve_self_update_isolated_root_from_env().map_err(|e| anyhow::anyhow!(e))?;
    let root = root.or(env_root.as_deref());
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let cfg = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    Ok(af_release::ReleaseLockGuard::acquire(path, Duration::ZERO)?)
}

/// Same cross-process lock used by local releases. Order: package process lock,
/// package flock, maintenance lock. Updater launch takes only maintenance.
pub(crate) async fn acquire_package_maintenance_guard(
    root: Option<&Path>,
    target: af_release::lifecycle::ReservationTarget<'_>,
    job_id: &str,
    action: Option<&str>,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    let conf = af_release::resolve_release_manager_conf_for_root(root).filter(|conf_path| {
        root.map(|explicit_root| conf_path.starts_with(explicit_root))
            .unwrap_or(true)
    });
    let cfg = if let Some(explicit_root) = root {
        let mut env_map: HashMap<String, String> = env::vars().collect();
        env_map.remove("AETHERFLOW_RELEASE_ROOT");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = env_map.get(key) {
                if !Path::new(val.trim()).starts_with(explicit_root) {
                    env_map.remove(key);
                }
            }
        }
        af_release::ReleaseConfig::load_for_root_with_env(
            Some(explicit_root),
            conf.as_deref(),
            &env_map,
        )?
    } else {
        af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?
    };
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    let owned_restore = !job_id.is_empty()
        && matches!(target, af_release::lifecycle::ReservationTarget::Service(_));
    let guard = if owned_restore {
        tokio::task::spawn_blocking(move || {
            af_release::ReleaseLockGuard::acquire(path, Duration::from_secs(30))
        })
        .await??
    } else {
        af_release::ReleaseLockGuard::acquire(path, Duration::ZERO)?
    };
    let status = discover_system_update(&cfg)
        .await
        .map_err(|(_, e)| anyhow::anyhow!(e))?;
    anyhow::ensure!(status.completed, LifecycleBusy);
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    if af_release::fs_security::validate_sqlite_file_and_sidecars_nofollow(&database)?.is_some() {
        let (conn, is_scratch) =
            af_release::fs_security::open_sqlite_isolated_for_reconcile(&database)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        af_release::lifecycle::reconcile_jobs_with_options(&conn, &database, !is_scratch)?;
        match target {
            af_release::lifecycle::ReservationTarget::Package(package) => {
                let units = package_lifecycle::package_service_units(package)?;
                af_release::lifecycle::check_package_reservation(
                    &conn, package, &units, job_id, action,
                )
            }
            _ => af_release::lifecycle::check_reservation(&conn, target, job_id, action),
        }
        .map_err(|error| error.context(LifecycleBusy))?;
    } else {
        anyhow::ensure!(
            job_id.is_empty(),
            "Lifecycle reservation database is missing"
        );
    }
    Ok(guard)
}

pub(crate) async fn acquire_owned_lifecycle_snapshot_guard(
    root: Option<&Path>,
    package: &str,
    job_id: &str,
) -> anyhow::Result<(af_release::ReleaseLockGuard, PathBuf)> {
    anyhow::ensure!(!job_id.trim().is_empty(), "lifecycle_job_id is required");
    let conf = af_release::resolve_release_manager_conf_for_root(root).filter(|conf_path| {
        root.map(|explicit_root| conf_path.starts_with(explicit_root))
            .unwrap_or(true)
    });
    let cfg = if let Some(explicit_root) = root {
        let mut env_map: HashMap<String, String> = env::vars().collect();
        env_map.remove("AETHERFLOW_RELEASE_ROOT");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = env_map.get(key) {
                if !Path::new(val.trim()).starts_with(explicit_root) {
                    env_map.remove(key);
                }
            }
        }
        af_release::ReleaseConfig::load_for_root_with_env(
            Some(explicit_root),
            conf.as_deref(),
            &env_map,
        )?
    } else {
        af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?
    };
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    let guard = tokio::task::spawn_blocking(move || {
        af_release::ReleaseLockGuard::acquire(path, Duration::from_secs(10))
    })
    .await??;
    let status = discover_system_update(&cfg)
        .await
        .map_err(|(_, e)| anyhow::anyhow!(e))?;
    anyhow::ensure!(status.completed, LifecycleBusy);
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    anyhow::ensure!(
        af_release::fs_security::validate_sqlite_file_and_sidecars_nofollow(&database)?.is_some(),
        "Lifecycle reservation database is missing"
    );
    let (conn, is_scratch) =
        af_release::fs_security::open_sqlite_isolated_for_reconcile(&database)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    af_release::lifecycle::reconcile_jobs_with_options(&conn, &database, !is_scratch)?;
    let units = package_lifecycle::package_service_units(package)?;
    af_release::lifecycle::check_package_reservation(&conn, package, &units, job_id, None)
        .map_err(|error| error.context(LifecycleBusy))?;
    let action: String = conn.query_row(
        "SELECT action FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
        rusqlite::params![package, job_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        matches!(action.as_str(), "install" | "reinstall" | "update"),
        "removal cannot own lifecycle runtime snapshots"
    );
    Ok((guard, database))
}

pub(crate) fn service_reservation_target<'a>(
    service: &'a str,
    action: &str,
) -> af_release::lifecycle::ReservationTarget<'a> {
    if matches!(
        service.trim_end_matches(".service"),
        "aetherflow-api" | "aetherflow-runner"
    ) && matches!(action, "stop" | "restart" | "restart-deferred")
    {
        af_release::lifecycle::ReservationTarget::System
    } else {
        af_release::lifecycle::ReservationTarget::Service(service)
    }
}

pub async fn acquire_service_maintenance_guard(
    service: &str,
    action: &str,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    acquire_package_maintenance_guard(
        PackageExecutionEnv::default().fs_root.as_deref(),
        service_reservation_target(service, action),
        &current_package_job_id(),
        None,
    )
    .await
}

pub(crate) async fn query_self_update_job_status_local(
    job_unit: &str,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let valid_unit = validate_self_update_job_unit_name(job_unit)?;
    let jobs_dir = resolve_self_update_jobs_dir_from_env()?;
    let status_path = jobs_dir.join(format!("{}.json", valid_unit));
    query_self_update_job_at(&valid_unit, &status_path).await
}

pub(crate) async fn query_self_update_job_at(
    valid_unit: &str,
    status_path: &Path,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let directory = job_receipts::ReceiptDirectory::open_existing(
        status_path.parent().unwrap_or(Path::new(".")),
    )
    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("self-update job '{valid_unit}' not found"),
        )
    })?;
    directory
        .verify_root_owner()
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    query_self_update_job_in(valid_unit, status_path, &directory).await
}

pub(crate) async fn query_self_update_job_in(
    valid_unit: &str,
    status_path: &Path,
    directory: &job_receipts::ReceiptDirectory,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let name = status_path.file_name().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Missing receipt filename".into(),
        )
    })?;
    if let Some(mut parsed) = directory.read_status(name, valid_unit).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("corrupt self-update status file: {error}"),
            )
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Cannot read confined self-update status: {error}"),
            )
        }
    })? {
        if parsed.completed {
            return Ok(parsed);
        }
        if directory
            .launch_is_alive(name, parsed.status == "launching")
            .map_err(|error| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Cannot verify launch owner: {error}"),
                )
            })?
        {
            return Ok(parsed);
        }

        let custom_systemd_run = env::var("AETHERFLOW_SYSTEMD_RUN_BIN")
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false);
        let systemctl_bin = env::var("AETHERFLOW_SYSTEMCTL_BIN")
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty());
        if cfg!(target_os = "linux") && (!custom_systemd_run || systemctl_bin.is_some()) {
            let ctl_prog = systemctl_bin.as_deref().unwrap_or("systemctl");
            let mut ctl_cmd = Command::new(ctl_prog);
            ctl_cmd.args([
                "show",
                "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus",
                valid_unit,
            ]);
            if let Ok(out) =
                bounded_command::output(ctl_cmd, Duration::from_secs(5), 64 * 1024).await
            {
                {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let mut load_state = "";
                    let mut active_state = "";
                    let mut sub_state = "";
                    let mut result_prop = "";
                    let mut exec_status: Option<i32> = None;
                    for line in stdout.lines() {
                        if let Some(val) = line.strip_prefix("LoadState=") {
                            load_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("ActiveState=") {
                            active_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("SubState=") {
                            sub_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("Result=") {
                            result_prop = val.trim();
                        } else if let Some(val) = line.strip_prefix("ExecMainStatus=") {
                            exec_status = val.trim().parse::<i32>().ok();
                        }
                    }
                    let unit_no_longer_running =
                        matches!(load_state, "loaded" | "not-found" | "error" | "masked")
                            && matches!(active_state, "failed" | "inactive");
                    if unit_no_longer_running {
                        if valid_unit.contains("-restart-")
                            && core_restart_timer_pending(ctl_prog, valid_unit).await?
                        {
                            return Ok(parsed);
                        }
                        let expected = parsed.clone();
                        let reread_status = directory
                            .read_status(name, valid_unit)
                            .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
                            .ok_or_else(|| {
                                (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Receipt disappeared during reconciliation".into(),
                                )
                            })?;
                        if reread_status.completed {
                            return Ok(reread_status);
                        }
                        parsed.status = "failed".to_string();
                        parsed.completed = true;
                        parsed.success = false;
                        parsed.exit_code = exec_status.filter(|code| *code != 0).or(Some(1));
                        if parsed.error.is_empty() {
                            parsed.error = format!(
                                "transient systemd unit '{}' terminated without writing completion receipt (LoadState={}, ActiveState={}, SubState={}, Result={}, exit_code={:?})",
                                valid_unit,
                                load_state,
                                active_state,
                                sub_state,
                                result_prop,
                                parsed.exit_code
                            );
                        }
                        return directory
                            .compare_exchange(name, &expected, &parsed)
                            .map_err(|error| {
                                (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    format!("Cannot persist reconciled updater status: {error}"),
                                )
                            });
                    }
                    if load_state == "loaded"
                        && matches!(
                            active_state,
                            "active" | "activating" | "deactivating" | "reloading"
                        )
                    {
                        if parsed.status == "launching" {
                            let mut admitted = parsed.clone();
                            admitted.status = "running".into();
                            return directory
                                .compare_exchange(name, &parsed, &admitted)
                                .map_err(|error| {
                                    (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
                                });
                        }
                        return Ok(parsed);
                    }
                }
            }
            return Err((StatusCode::SERVICE_UNAVAILABLE,
                format!("Cannot determine authoritative systemd state for '{valid_unit}'; receipt retained as unresolved. Retry status after restoring systemd access.")));
        }
        return Ok(parsed);
    }

    Err((
        StatusCode::NOT_FOUND,
        format!("self-update job '{}' not found", valid_unit),
    ))
}

pub(crate) async fn core_restart_timer_pending(
    program: &str,
    unit: &str,
) -> Result<bool, (StatusCode, String)> {
    let timer = format!("{}.timer", unit.trim_end_matches(".service"));
    let mut timer_cmd = Command::new(program);
    timer_cmd.args(["show", "--property=LoadState,ActiveState,SubState", &timer]);
    let output = bounded_command::output(timer_cmd, Duration::from_secs(5), 64 * 1024)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Core restart timer query timed out".into(),
                )
            } else {
                (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
            }
        })?;
    let text = String::from_utf8_lossy(&output.stdout);
    let load = text
        .lines()
        .find_map(|line| line.strip_prefix("LoadState="))
        .unwrap_or("");
    let active = text
        .lines()
        .find_map(|line| line.strip_prefix("ActiveState="))
        .unwrap_or("");
    let phase = text
        .lines()
        .find_map(|line| line.strip_prefix("SubState="))
        .unwrap_or("");
    if load == "loaded"
        && matches!(active, "active" | "activating" | "deactivating")
        && matches!(phase, "waiting" | "running")
    {
        return Ok(true);
    }
    if load == "loaded" && active == "active" && phase == "elapsed" {
        return Ok(false);
    }
    if matches!(load, "loaded" | "not-found" | "error" | "masked")
        && matches!(active, "inactive" | "failed")
    {
        return Ok(false);
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "Core restart timer state is unknown; admission remains reserved".into(),
    ))
}

pub(crate) async fn handle_self_update(
    Json(req): Json<SelfUpdateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let (status, resp) = execute_self_update_request(&req, true).await;
    (status, Json(resp))
}

pub(crate) async fn handle_self_update_status(
    Json(req): Json<SelfUpdateStatusRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match query_self_update_status_local(&req.job_unit).await {
        Ok(status_payload) => {
            let output = serde_json::to_string(&status_payload).unwrap_or_default();
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
