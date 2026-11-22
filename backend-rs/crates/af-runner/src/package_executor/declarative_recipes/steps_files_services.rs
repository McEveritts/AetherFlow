use super::*;

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub(super) async fn execute_files_and_services_step(
        &self,
        recipe: &DeclarativePackageRecipe,
        step: &DeclarativeStep,
        vars: &mut HashMap<String, String>,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        match step {
            DeclarativeStep::EnsureThreadfinConfig { .. } => {
                let resolved = self
                    .env_cfg
                    .resolve_path("/var/lib/threadfin/conf/settings.json")?;
                let mut settings = serde_json::Map::new();
                if resolved.exists() {
                    let mut contents = Vec::new();
                    File::open(&resolved)?
                        .take(1024 * 1024 + 1)
                        .read_to_end(&mut contents)?;
                    if contents.len() > 1024 * 1024 {
                        return Err(PackageExecutorError::Validation(
                            "Threadfin settings exceed 1 MiB".to_string(),
                        ));
                    }
                    settings = serde_json::from_slice::<serde_json::Value>(&contents)
                        .map_err(|error| {
                            PackageExecutorError::Validation(format!(
                                "invalid Threadfin settings: {}",
                                error
                            ))
                        })?
                        .as_object()
                        .cloned()
                        .ok_or_else(|| {
                            PackageExecutorError::Validation(
                                "Threadfin settings must be a JSON object".to_string(),
                            )
                        })?;
                }
                if settings.is_empty() {
                    settings.insert(
                        "version".to_string(),
                        serde_json::Value::String("0.5.0".to_string()),
                    );
                } else if !matches!(settings.get("version"), Some(serde_json::Value::String(version)) if !version.is_empty())
                {
                    return Err(PackageExecutorError::Validation(
                        "existing Threadfin settings require a version string".to_string(),
                    ));
                }
                match settings.get("bindIpAddress") {
                    Some(serde_json::Value::String(address)) if !address.is_empty() => {
                        journal.stage_file_mutation(&resolved)?;
                        self.apply_file_metadata(
                            &resolved,
                            0o600,
                            Some("threadfin"),
                            Some("threadfin"),
                            cancel,
                        )
                        .await?;
                        return Ok("preserved explicit Threadfin bindIpAddress".to_string());
                    }
                    Some(serde_json::Value::String(_) | serde_json::Value::Null) | None => {}
                    Some(_) => {
                        return Err(PackageExecutorError::Validation(
                            "Threadfin bindIpAddress must be a string".to_string(),
                        ))
                    }
                }
                settings.insert(
                    "bindIpAddress".to_string(),
                    serde_json::Value::String("127.0.0.1".to_string()),
                );
                journal.stage_file_mutation(&resolved)?;
                let contents = serde_json::to_vec_pretty(&settings)
                    .map_err(|error| PackageExecutorError::Validation(error.to_string()))?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    &contents,
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                self.apply_file_metadata(
                    &resolved,
                    0o600,
                    Some("threadfin"),
                    Some("threadfin"),
                    cancel,
                )
                .await?;
                Ok("defaulted Threadfin bindIpAddress to 127.0.0.1 while preserving other settings".to_string())
            }

            DeclarativeStep::ResolveGitHubReleaseTag {
                repo,
                fallback_version,
                strip_v_prefix,
                ..
            } => {
                let tag = self
                    .resolve_github_tag(repo, fallback_version, *strip_v_prefix)
                    .await;
                let clean_ver = tag.trim_start_matches('v').to_string();
                if !is_downgrade_allowed() {
                    let ver_marker_logical = format!("/var/lib/{}/.af-version", recipe.package_id);
                    if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical) {
                        if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            if is_semver_strictly_greater(existing_ver, &clean_ver) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                }
                let raw_tag = if tag.starts_with('v') {
                    tag.clone()
                } else {
                    format!("v{}", tag)
                };
                vars.insert("VERSION".to_string(), clean_ver.clone());
                vars.insert(
                    "TAG".to_string(),
                    if *strip_v_prefix {
                        clean_ver.clone()
                    } else {
                        raw_tag
                    },
                );
                Ok(format!(
                    "resolved release version {} for {}",
                    clean_ver, repo
                ))
            }

            DeclarativeStep::DownloadBinary {
                url_template,
                arch_map,
                dest_path,
                mode,
                verification,
                ..
            } => {
                if !is_downgrade_allowed() {
                    if let Some(target_ver) = vars.get("VERSION").cloned() {
                        let clean_ver = target_ver.trim().trim_start_matches('v');
                        let ver_marker_logical =
                            format!("/var/lib/{}/.af-version", recipe.package_id);
                        if let Ok(ver_marker_path) = self.env_cfg.resolve_path(&ver_marker_logical)
                        {
                            if let Ok(existing_raw) = fs::read_to_string(&ver_marker_path) {
                                let existing_ver = existing_raw.trim().trim_start_matches('v');
                                if is_semver_strictly_greater(existing_ver, clean_ver) {
                                    return Err(PackageExecutorError::Validation(format!(
                                        "refusing to downgrade {} from installed version {} to {}",
                                        recipe.package_id, existing_ver, clean_ver
                                    )));
                                }
                            }
                        }
                    }
                }
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS binary download URL: {}",
                        resolved_url
                    )));
                }
                let (tmp_artifact, cached_candidate) = self
                    .fetch_artifact_to_temp_with_source(
                        &recipe.package_id,
                        &resolved_url,
                        arch_asset,
                        journal,
                        cancel,
                    )
                    .await?;
                cancel.check(&recipe.package_id)?;
                let mut effective_verification = verification.clone();
                if recipe.package_id == "threadfin" {
                    let (_, sha_override) = validate_threadfin_target_policy(
                        self.env_cfg.expected_target_version.as_deref(),
                    )?;
                    if let Some(sha_override) = sha_override {
                        effective_verification.expected_sha256 = Some(sha_override);
                        effective_verification.arch_sha256 = None;
                    } else if effective_verification.expected_sha256.is_none()
                        && arch == "amd64"
                        && cached_candidate.as_deref() == Some("Threadfin_linux_amd64")
                        && effective_verification
                            .arch_sha256
                            .as_ref()
                            .is_some_and(|map| map.amd64 == THREADFIN_AMD64_COMPAT_SHA256)
                    {
                        // Legacy offline cache bridge: if a cache supplies plain `Threadfin_linux_amd64`,
                        // bind verification strictly to its verified upstream SHA-256 rather than accepting
                        // cross-asset digests on remote compat downloads.
                        effective_verification.expected_sha256 =
                            Some(THREADFIN_AMD64_PLAIN_SHA256.to_string());
                    }
                }
                let sha256 = verify_artifact_file_for_arch(
                    &tmp_artifact,
                    &effective_verification,
                    Some(&arch),
                )?;

                let dest_resolved = self.env_cfg.resolve_path(dest_path)?;
                journal.stage_file_mutation(&dest_resolved)?;
                let bytes = fs::read(&tmp_artifact)?;
                write_file_atomic_with_mode_bounded(
                    &dest_resolved,
                    &bytes,
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                let _ = fs::remove_file(&tmp_artifact);

                Ok(format!(
                    "installed verified binary {} (sha256={})",
                    dest_path,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::DownloadAndExtractTarGz {
                url_template,
                arch_map,
                dest_dir,
                extract_binaries,
                binary_mode,
                verification,
                ..
            } => {
                let arch = self.env_cfg.effective_arch();
                let arch_asset = arch_map.resolve(&arch).ok_or_else(|| {
                    PackageExecutorError::Validation(format!(
                        "unsupported architecture '{}' for package '{}'",
                        arch, recipe.package_id
                    ))
                })?;
                vars.insert("ARCH_ASSET".to_string(), arch_asset.to_string());
                let resolved_url = interpolate_template(url_template, vars);
                if !resolved_url.starts_with("https://") && !resolved_url.starts_with("file://") {
                    return Err(PackageExecutorError::SecurityViolation(format!(
                        "refusing non-HTTPS archive download URL: {}",
                        resolved_url
                    )));
                }
                let tmp_archive = self
                    .fetch_artifact_to_temp(
                        &recipe.package_id,
                        &resolved_url,
                        arch_asset,
                        journal,
                        cancel,
                    )
                    .await?;
                cancel.check(&recipe.package_id)?;

                let mut gz_policy = verification.clone();
                gz_policy.require_gzip_magic = true;
                let sha256 = verify_artifact_file_for_arch(&tmp_archive, &gz_policy, Some(&arch))?;

                let dest_dir_resolved = self.env_cfg.resolve_path(dest_dir)?;
                create_dir_all_0755(&dest_dir_resolved)?;
                validate_filesystem_path(&dest_dir_resolved, self.env_cfg.fs_root.as_deref())?;

                extract_binaries_from_targz(
                    &tmp_archive,
                    &dest_dir_resolved,
                    extract_binaries,
                    *binary_mode,
                    verification.require_elf_magic,
                    journal,
                )?;
                let _ = fs::remove_file(&tmp_archive);

                Ok(format!(
                    "extracted verified archive binaries {:?} to {} (sha256={})",
                    extract_binaries,
                    dest_dir,
                    &sha256[..12]
                ))
            }

            DeclarativeStep::MergeIniSettings {
                path,
                section,
                settings,
                mode,
                ..
            } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                journal.stage_file_mutation(&resolved)?;
                let original = match fs::read_to_string(&resolved) {
                    Ok(contents) => contents,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.into()),
                };
                let rendered_settings = settings
                    .iter()
                    .map(|(key, value)| (key.clone(), interpolate_template(value, vars)))
                    .collect::<Vec<_>>();
                let rendered = merge_ini_settings(&original, section, &rendered_settings);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("merged managed INI settings in {}", path))
            }
            DeclarativeStep::WriteTemplateFile {
                path,
                content_template,
                mode,
                overwrite,
                owner,
                group,
                ..
            } => {
                let resolved = self.env_cfg.resolve_path(path)?;
                let rendered = if path.ends_with(".env") || path.starts_with("/etc/default/") {
                    let mut escaped_vars = vars.clone();
                    if let Some(u) = escaped_vars.get("MASTER_USER").cloned() {
                        escaped_vars
                            .insert("MASTER_USER".to_string(), escape_systemd_env_quoted(&u));
                    }
                    if let Some(p) = escaped_vars.get("MASTER_PASS").cloned() {
                        escaped_vars
                            .insert("MASTER_PASS".to_string(), escape_systemd_env_quoted(&p));
                    }
                    if let Some(p) = escaped_vars.get("RCLONE_PASS").cloned() {
                        escaped_vars
                            .insert("RCLONE_PASS".to_string(), escape_systemd_env_quoted(&p));
                    }
                    interpolate_template(content_template, &escaped_vars)
                } else if path == "/var/lib/znc/configs/znc.conf" {
                    let mut znc_vars = vars.clone();
                    if let Some(ver) = znc_vars.get("VERSION").cloned() {
                        let mm = format_znc_major_minor(&ver);
                        znc_vars.insert("VERSION".to_string(), mm.clone());
                        znc_vars.insert("ZNC_CONF_VERSION".to_string(), mm);
                    }
                    interpolate_template(content_template, &znc_vars)
                } else {
                    interpolate_template(content_template, vars)
                };

                if path == RCLONE_ENV {
                    let existing = read_rclone_env(&resolved)?;
                    let source = match existing {
                        Some(ref content) => Some(content.clone()),
                        None => read_rclone_env(&self.env_cfg.resolve_path(RCLONE_LEGACY_ENV)?)?,
                    };
                    let content = if let Some(source) = source {
                        let lifecycle_action = vars.get("LIFECYCLE_ACTION").map(String::as_str);
                        let keep_secrets = self.env_cfg.keep_existing_secrets
                            || env::var("AF_KEEP_EXISTING_SECRETS")
                                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                            || (matches!(lifecycle_action, Some("update" | "reinstall"))
                                && env::var("AF_KEEP_EXISTING_SECRETS")
                                    .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                                    .unwrap_or(true));
                        if let Some(pass) =
                            self.resolve_explicit_password().filter(|_| !keep_secrets)
                        {
                            update_preserved_rclone_env_pass(&source, &pass)
                        } else {
                            source
                        }
                    } else {
                        rendered
                    };
                    let content = add_missing_rclone_env_aliases(content);
                    #[cfg(unix)]
                    if existing.as_ref() == Some(&content) {
                        use std::os::unix::fs::PermissionsExt;
                        if fs::metadata(&resolved)?.permissions().mode() & 0o777 == *mode {
                            return Ok(format!("preserved configuration file {}", path));
                        }
                    }
                    journal.stage_file_mutation(&resolved)?;
                    write_file_atomic_with_mode_bounded(
                        &resolved,
                        content.as_bytes(),
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    self.apply_file_metadata(
                        &resolved,
                        *mode,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                    return Ok(format!("wrote configuration file {}", path));
                }

                if !*overwrite && resolved.is_file() {
                    let port_var = if path == "/etc/default/quasselcore" {
                        vars.get("LISTEN_PORT").or_else(|| vars.get("APP_PORT"))
                    } else {
                        vars.get("APP_PORT")
                    };
                    if let Some(app_port) = port_var {
                        if let Ok(existing) = fs::read_to_string(&resolved) {
                            if let Some(updated) =
                                update_preserved_template_port(path, &existing, &rendered, app_port)
                            {
                                if updated != existing {
                                    journal.stage_file_mutation(&resolved)?;
                                    write_file_atomic_with_mode_bounded(
                                        &resolved,
                                        updated.as_bytes(),
                                        *mode,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    self.apply_file_metadata(
                                        &resolved,
                                        *mode,
                                        owner.as_deref(),
                                        group.as_deref(),
                                        cancel,
                                    )
                                    .await?;
                                    return Ok(format!("updated port in existing file {}", path));
                                }
                            }
                        }
                    }
                    return Ok(format!("preserved existing file {}", path));
                }
                journal.stage_file_mutation(&resolved)?;
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    *mode,
                    self.env_cfg.fs_root.as_deref(),
                )?;

                if let Some(ref o) = owner {
                    let grp = group.as_deref().unwrap_or(o.as_str());
                    if self.env_cfg.fs_root.is_none() {
                        let out = self
                            .runner
                            .run_command(
                                "chown",
                                &[
                                    "-h".to_string(),
                                    format!("{}:{}", o, grp),
                                    resolved.to_string_lossy().to_string(),
                                ],
                                &[],
                                cancel,
                            )
                            .await?;
                        if !out.success() {
                            return Err(PackageExecutorError::StepFailed {
                                step: "write_template_file".to_string(),
                                reason: format!(
                                    "chown -h {}:{} {} exited with {}: {}",
                                    o,
                                    grp,
                                    resolved.display(),
                                    out.exit_code,
                                    out.combined_output()
                                ),
                            });
                        }
                    }
                }
                Ok(format!("wrote configuration file {}", path))
            }

            DeclarativeStep::WriteSystemdUnit {
                unit_name,
                content_template,
                ..
            } => {
                let norm = normalize_unit_filename(unit_name);
                let logical_path = format!("/etc/systemd/system/{}", norm);
                let resolved = self.env_cfg.resolve_path(&logical_path)?;
                let existed = resolved.is_file();
                journal.stage_file_mutation(&resolved)?;
                if existed {
                    if !matches!(norm.as_str(), "rclone.service" | "rclone-vfs.service")
                        || self
                            .runner
                            .run_command(
                                "systemctl",
                                &["is-active".into(), "--quiet".into(), norm.clone()],
                                &[],
                                cancel,
                            )
                            .await?
                            .success()
                    {
                        journal.record_restorable_systemd_service(&norm);
                    }
                } else {
                    journal.record_created_systemd_unit(&norm, &resolved);
                }
                let mut content = content_template.clone();
                if norm == "rclone.service" {
                    let effective_root = self.env_cfg.fs_root.as_deref().unwrap_or(Path::new("/"));
                    let detected_exec = detect_rclone_exec_start_for_root(effective_root);
                    content = content.replace("{{RCLONE_EXEC_START}}", &detected_exec);
                    if detected_exec.contains("{{RCLONE_API_PORT}}") {
                        let app_port = vars
                            .get("APP_PORT")
                            .and_then(|value| value.parse::<u16>().ok())
                            .unwrap_or(5572);
                        let explicit_api = vars.get("RCLONE_API_PORT").map(String::as_str);
                        let lifecycle_action = vars.get("LIFECYCLE_ACTION").map(String::as_str);
                        let api_port = resolve_and_reserve_rclone_api_port(
                            self.env_cfg.fs_root.as_deref(),
                            app_port,
                            explicit_api,
                            &self.env_cfg.lifecycle_job_id,
                            lifecycle_action,
                        )?;
                        vars.insert("RCLONE_API_PORT".to_string(), api_port.to_string());
                        vars.insert("RCLONE_MODE".to_string(), "gui".to_string());
                    } else {
                        vars.remove("RCLONE_API_PORT");
                        vars.insert("RCLONE_MODE".to_string(), "rcd".to_string());
                    }
                }
                let rendered = interpolate_template(&content, vars);
                write_file_atomic_with_mode_bounded(
                    &resolved,
                    rendered.as_bytes(),
                    0o644,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                Ok(format!("wrote systemd unit {}", logical_path))
            }

            DeclarativeStep::Systemctl {
                unit,
                operation,
                ignore_errors,
                ..
            } => {
                if matches!(
                    operation,
                    SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed
                ) {
                    let norm_unit = normalize_unit_filename(unit.as_deref().unwrap_or_default());
                    if matches!(operation, SystemctlOp::Stop | SystemctlOp::Disable)
                        && !norm_unit.is_empty()
                    {
                        let unit_logical = format!("/etc/systemd/system/{}", norm_unit);
                        if self
                            .env_cfg
                            .resolve_path(&unit_logical)
                            .map(|p| p.is_file())
                            .unwrap_or(false)
                        {
                            journal.record_restorable_systemd_service(&norm_unit);
                        }
                    }
                    let operation_name = match operation {
                        SystemctlOp::Stop => "stop",
                        SystemctlOp::Disable => "disable",
                        _ => "reset-failed",
                    };
                    self.teardown_systemctl(operation_name, &norm_unit, cancel)
                        .await?;
                    return Ok(format!("systemctl {operation_name} completed"));
                }
                let args: Vec<String> = match operation {
                    SystemctlOp::DaemonReload => vec!["daemon-reload".to_string()],
                    SystemctlOp::EnableNow => vec![
                        "enable".to_string(),
                        "--now".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Enable => vec![
                        "enable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Start => vec![
                        "start".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Restart | SystemctlOp::TryRestart => vec![
                        if *operation == SystemctlOp::TryRestart {
                            "try-restart"
                        } else {
                            "restart"
                        }
                        .to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Stop => vec![
                        "stop".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::Disable => vec![
                        "disable".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                    SystemctlOp::ResetFailed => vec![
                        "reset-failed".to_string(),
                        "--".to_string(),
                        unit.clone().unwrap_or_default(),
                    ],
                };
                let out = self
                    .runner
                    .run_command("systemctl", &args, &[], cancel)
                    .await?;
                if !out.success()
                    && (!*ignore_errors || matches!(operation, SystemctlOp::DaemonReload))
                {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("systemctl {:?}", operation),
                        reason: format!(
                            "systemctl {} exited with {}: {}",
                            args.join(" "),
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if out.success()
                    && matches!(
                        operation,
                        SystemctlOp::EnableNow
                            | SystemctlOp::Start
                            | SystemctlOp::Restart
                            | SystemctlOp::TryRestart
                    )
                {
                    if let Some(unit_name) = unit.as_ref().filter(|u| !u.is_empty()) {
                        journal.record_touched_service(unit_name);
                        let verify_args = vec![
                            "is-active".to_string(),
                            "--quiet".to_string(),
                            "--".to_string(),
                            unit_name.clone(),
                        ];
                        let active_out = self
                            .runner
                            .run_command("systemctl", &verify_args, &[], cancel)
                            .await?;
                        if !active_out.success() && !*ignore_errors {
                            return Err(PackageExecutorError::StepFailed {
                                step: format!("systemctl is-active {}", unit_name),
                                reason: format!(
                                    "service {} failed post-activation readiness check (systemctl is-active exited with {}): {}",
                                    unit_name,
                                    active_out.exit_code,
                                    active_out.combined_output()
                                ),
                            });
                        }
                    }
                }
                Ok(format!("systemctl {} completed", args.join(" ")))
            }

            DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                let norm = normalize_unit_filename(unit_name);
                for op in ["stop", "disable", "reset-failed"] {
                    cancel.check(&recipe.package_id)?;
                    self.teardown_systemctl(op, &norm, cancel).await?;
                }
                let unit_logical = format!("/etc/systemd/system/{}", norm);
                let dropin_logical = format!("/etc/systemd/system/{}.d", norm);
                let unit_path = self.env_cfg.resolve_path(&unit_logical)?;
                let dropin_path = self.env_cfg.resolve_path(&dropin_logical)?;
                match fs::remove_file(&unit_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                match fs::remove_dir_all(&dropin_path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let reload = self
                    .runner
                    .run_command("systemctl", &["daemon-reload".to_string()], &[], cancel)
                    .await?;
                if !reload.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "systemctl_daemon_reload".to_string(),
                        reason: reload.combined_output(),
                    });
                }
                Ok(format!("purged systemd unit {}", norm))
            }

            DeclarativeStep::UnmountPaths { paths, .. } => {
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    validate_managed_path(logical)?;
                    let resolved = self.env_cfg.resolve_path(logical)?;
                    if !self.is_active_mountpoint(logical, &resolved) {
                        continue;
                    }
                    let fuse_args = vec!["-u".to_string(), logical.clone()];
                    let fuse_succeeded = match self
                        .runner
                        .run_command("fusermount", &fuse_args, &[], cancel)
                        .await
                    {
                        Ok(out) => out.success(),
                        Err(PackageExecutorError::Io(ref err))
                            if err.kind() == std::io::ErrorKind::NotFound =>
                        {
                            false
                        }
                        Err(err) => return Err(err),
                    };
                    if !fuse_succeeded {
                        match self
                            .runner
                            .run_command("umount", std::slice::from_ref(logical), &[], cancel)
                            .await
                        {
                            Ok(_) => {}
                            Err(PackageExecutorError::Io(ref err))
                                if err.kind() == std::io::ErrorKind::NotFound => {}
                            Err(err) => return Err(err),
                        }
                    }
                    if self.is_active_mountpoint(logical, &resolved) {
                        return Err(PackageExecutorError::StepFailed {
                            step: format!("unmount {}", logical),
                            reason: format!(
                                "Cannot confirm {} is unmounted (still an active mountpoint); refusing package removal",
                                logical
                            ),
                        });
                    }
                }
                Ok(format!("unmounted paths: {}", paths.join(", ")))
            }

            DeclarativeStep::RemovePaths {
                paths,
                only_if_delete_data,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped data directory removal (DELETE_DATA=false)".to_string());
                }
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    validate_managed_path(logical)?;
                    let resolved = if let Some(ref root) = self.env_cfg.fs_root {
                        let rel = logical.trim_start_matches(['/', '\\']);
                        root.join(rel)
                    } else {
                        PathBuf::from(logical)
                    };
                    if let Some(parent) = resolved.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                    match fs::symlink_metadata(&resolved) {
                        Ok(meta) => {
                            if meta.file_type().is_symlink() {
                                fs::remove_file(&resolved)?;
                                continue;
                            }
                            if meta.is_dir() {
                                if self.is_active_mountpoint(logical, &resolved) {
                                    return Err(PackageExecutorError::SecurityViolation(format!(
                                        "refusing to remove active mountpoint directory: {}",
                                        resolved.display()
                                    )));
                                }
                                fs::remove_dir_all(&resolved)?;
                            } else {
                                fs::remove_file(&resolved)?;
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(PackageExecutorError::Io(err)),
                    }
                }
                Ok(format!("removed paths: {}", paths.join(", ")))
            }

            DeclarativeStep::RunCommand {
                program,
                args,
                only_if_delete_data,
                ignore_errors,
                ..
            } => {
                if *only_if_delete_data && !self.env_cfg.delete_data {
                    return Ok("skipped command (DELETE_DATA=false)".to_string());
                }
                let mut cmd_envs: Vec<(String, String)> = Vec::new();
                cmd_envs.push((
                    "AF_JOB_SCRATCH_ROOT".to_string(),
                    "/var/tmp/aetherflow-scratch".to_string(),
                ));
                if let Some(ref target) = self.env_cfg.expected_target_version {
                    cmd_envs.push(("AF_TARGET_VERSION".to_string(), target.clone()));
                }
                let out = self
                    .runner
                    .run_command(program, args, &cmd_envs, cancel)
                    .await?;
                if !out.success() && !*ignore_errors {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("run_command {}", program),
                        reason: format!(
                            "{} {:?} exited with {}: {}",
                            program,
                            args,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok(format!("executed command {}", program))
            }

            _ => unreachable!("step handled by primary dispatcher"),
        }
    }
}
