use super::*;

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    async fn apply_recipe_sandbox(
        &self,
        package_id: &str,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        let systemd_root = self
            .env_cfg
            .fs_root
            .as_ref()
            .map(|root| root.join("etc/systemd/system"))
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
        let status = apply_sandbox_in_root_with_journal(
            package_id,
            &systemd_root,
            Some(journal),
            self.env_cfg.fs_root.as_deref(),
        )?;
        let output = self
            .runner
            .run_command("systemctl", &["daemon-reload".to_string()], &[], cancel)
            .await?;
        if !output.success() {
            return Err(PackageExecutorError::StepFailed {
                step: "apply_systemd_sandbox".to_string(),
                reason: output.combined_output(),
            });
        }
        Ok(status)
    }

    pub(super) async fn apply_file_metadata(
        &self,
        path: &Path,
        mode: u32,
        owner: Option<&str>,
        group: Option<&str>,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        validate_filesystem_path(path, self.env_cfg.fs_root.as_deref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        if let (None, Some(owner_name)) = (self.env_cfg.fs_root.as_ref(), owner) {
            let group_name = group.unwrap_or(owner_name);
            let output = self
                .runner
                .run_command(
                    "chown",
                    &[
                        "-h".to_string(),
                        format!("{}:{}", owner_name, group_name),
                        path.to_string_lossy().to_string(),
                    ],
                    &[],
                    cancel,
                )
                .await?;
            if !output.success() {
                return Err(PackageExecutorError::StepFailed {
                    step: "apply_file_metadata".to_string(),
                    reason: output.combined_output(),
                });
            }
        }
        Ok(())
    }

    /// Executes a declarative package recipe for `action` (`Install`, `Update`, or `Remove`),
    /// emitting structured [`PackageProgressEvent`] notifications to `on_progress`.
    pub async fn execute_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        recipe.validate()?;
        cancel.check(&recipe.package_id)?;

        // Register in-flight cancellation guard BEFORE waiting on process/file locks
        // (rejects duplicate concurrent action on the same package ID immediately).
        let _cancel_guard = register_package_cancellation(&recipe.package_id, cancel.clone())?;

        // Acquire process-wide mutex + cross-process flock with cancellation awareness
        let _proc_lock = acquire_package_mutex_with_cancel(&recipe.package_id, &cancel).await?;
        let _flock_guard =
            CrossProcessLockGuard::acquire_with_cancel(&self.env_cfg, &recipe.package_id, &cancel)
                .await?;

        let _maintenance_guard = crate::acquire_package_maintenance_guard(
            self.env_cfg.fs_root.as_deref(),
            af_release::lifecycle::ReservationTarget::Package(&recipe.package_id),
            &self.env_cfg.lifecycle_job_id,
            Some(action.as_str()),
        )
        .await
        .map_err(|e| PackageExecutorError::LockConflict(e.to_string()))?;

        crate::PACKAGE_MAINTENANCE_LEASE
            .scope(
                Arc::new(_maintenance_guard),
                self.execute_reserved_recipe(recipe, action, cancel, on_progress),
            )
            .await
    }

    pub(in crate::package_executor) async fn execute_reserved_recipe<F>(
        &self,
        recipe: &DeclarativePackageRecipe,
        action: PackageAction,
        cancel: CancellationToken,
        mut on_progress: F,
    ) -> Result<PackageExecutionOutcome, PackageExecutorError>
    where
        F: FnMut(PackageProgressEvent) + Send,
    {
        let steps = recipe.steps_for_action(action);
        let total_steps = steps.len();
        let lock_file_path = self.env_cfg.resolve_lock_file(recipe)?;
        let log_file_path = self.env_cfg.resolve_log_file(action, &recipe.package_id)?;
        if let Some(parent) = log_file_path.parent() {
            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
            crate::create_package_lock_directory(parent)?;
        }

        let mut logs = Vec::new();
        let mut journal = RollbackJournal::new(self.env_cfg.fs_root.clone());

        if matches!(
            action,
            PackageAction::Install | PackageAction::Update | PackageAction::Reinstall
        ) {
            let mut pre_existing_ver = None;
            if let Some(vf_logical) = recipe_version_file_logical_path(recipe) {
                if let Ok(vf_resolved) = self.env_cfg.resolve_path(&vf_logical) {
                    if let Ok(raw) = fs::read_to_string(&vf_resolved) {
                        let trimmed = raw.trim().to_string();
                        if !trimmed.is_empty() {
                            pre_existing_ver = Some(trimmed);
                        }
                    }
                }
            }
            let mut state_dirs = Vec::new();
            for state_dir in recipe_mutable_state_dirs(recipe) {
                if let Ok(resolved_dir) = self.env_cfg.resolve_path(&state_dir) {
                    if fs::symlink_metadata(&resolved_dir).is_ok() {
                        state_dirs.push(resolved_dir);
                    }
                }
            }
            journal.stage_directory_snapshots_with_cancel(
                &state_dirs,
                Some((&cancel, &recipe.package_id)),
            )?;
            journal.has_existing_installation = pre_existing_ver.is_some()
                || af_models::inspect_receipt_file(
                    &lock_file_path,
                    self.env_cfg.fs_root.as_deref(),
                )
                .unwrap_or(false)
                || (matches!(action, PackageAction::Update | PackageAction::Reinstall)
                    && !journal.dir_snapshots.is_empty());
            journal.pre_existing_version = pre_existing_ver;

            if self.env_cfg.fs_root.is_none()
                || std::env::var("AF_REJECT_TMPFS_STAGING").as_deref() == Ok("1")
            {
                let staging_target = self.env_cfg.resolve_readonly_path("/var/tmp");
                validate_filesystem_path(&staging_target, self.env_cfg.fs_root.as_deref())?;
                ensure_sufficient_disk_space(&staging_target, 512 * 1024 * 1024, 1024)?;
            }
        }

        let effective_port = if (1024..=65535).contains(&self.env_cfg.app_port) {
            self.env_cfg.app_port
        } else {
            recipe.default_port
        };
        let listen_port = if (1024..=65535).contains(&effective_port) {
            effective_port
        } else if recipe.package_id == "quassel" {
            env::var("AF_QUASSEL_PORT")
                .or_else(|_| env::var("AF_APP_PORT"))
                .or_else(|_| env::var("AETHERFLOW_APP_PORT"))
                .ok()
                .and_then(|v| v.trim().parse::<i32>().ok())
                .filter(|p| (1024..=65535).contains(p))
                .unwrap_or(QUASSEL_DEFAULT_LISTEN_PORT)
        } else {
            effective_port
        };
        let initial_version = if recipe.package_id == "threadfin" {
            if matches!(action, PackageAction::Remove) {
                resolve_threadfin_target_version()
            } else {
                let (resolved_ver, _) = validate_threadfin_target_policy(
                    self.env_cfg.expected_target_version.as_deref(),
                )?;
                resolved_ver
            }
        } else {
            "unknown".to_string()
        };

        let (master_user, mut master_pass) =
            try_resolve_master_credentials(self.env_cfg.fs_root.as_deref())
                .map_err(|e| PackageExecutorError::SecurityViolation(e.to_string()))?;
        if let Some(explicit_pass) = self.resolve_explicit_password() {
            master_pass = explicit_pass;
        }
        let znc_salt = uuid::Uuid::new_v4().simple().to_string();
        let znc_hash = hex::encode(Sha256::digest(
            format!("{}{}", master_pass, znc_salt).as_bytes(),
        ));

        let bind_address = resolve_bind_address(env::var("AF_BIND_ADDRESS").ok().as_deref())?;

        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert("PACKAGE_ID".to_string(), recipe.package_id.clone());
        vars.insert("APP_NAME".to_string(), recipe.package_id.clone());
        vars.insert("APP_LABEL".to_string(), recipe.label.clone());
        vars.insert("APP_PORT".to_string(), effective_port.to_string());
        vars.insert("LISTEN_PORT".to_string(), listen_port.to_string());
        vars.insert("BIND_ADDRESS".to_string(), bind_address);
        vars.insert("SSH_PORT".to_string(), "ssh".to_string());
        vars.insert("MASTER_USER".to_string(), master_user);
        vars.insert("MASTER_PASS".to_string(), master_pass);
        vars.insert("ZNC_SALT".to_string(), znc_salt);
        vars.insert("ZNC_PASS_HASH".to_string(), znc_hash);
        vars.insert("VERSION".to_string(), initial_version.clone());
        vars.insert(
            "ZNC_CONF_VERSION".to_string(),
            format_znc_major_minor(&initial_version),
        );
        vars.insert(
            "TAG".to_string(),
            if initial_version == "unknown" {
                "unknown".to_string()
            } else {
                format!("v{}", initial_version)
            },
        );
        vars.insert("ARCH".to_string(), self.env_cfg.effective_arch());
        vars.insert("LIFECYCLE_ACTION".to_string(), action.as_str().to_string());
        if recipe.package_id == "rclone" {
            vars.insert("RCLONE_BIN".to_string(), RCLONE_BIN.to_string());
            vars.insert(
                "RCLONE_PASS".to_string(),
                format!(
                    "{}{}",
                    uuid::Uuid::new_v4().simple(),
                    uuid::Uuid::new_v4().simple()
                ),
            );
            if let Some(explicit_api) = self.env_cfg.rclone_api_port {
                vars.insert("RCLONE_API_PORT".to_string(), explicit_api.to_string());
            } else if let Ok(raw) = env::var("RCLONE_API_PORT") {
                if !raw.trim().is_empty() {
                    vars.insert("RCLONE_API_PORT".to_string(), raw.trim().to_string());
                }
            }
        }
        if let Some(target) = self
            .env_cfg
            .expected_target_version
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            vars.insert("AF_TARGET_VERSION".to_string(), target.trim().to_string());
            vars.insert("TARGET_VERSION".to_string(), target.trim().to_string());
        }
        vars.insert(
            "AF_JOB_SCRATCH_ROOT".to_string(),
            "/var/tmp/aetherflow-scratch".to_string(),
        );

        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::LockAcquire,
            0,
            total_steps,
            5,
            format!(
                "Starting declarative {} for {} ({})",
                action.as_str(),
                recipe.label,
                recipe.package_id
            ),
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        let mut completed_steps = 0usize;
        let mut exec_err: Option<PackageExecutorError> = None;
        let mut sandbox_status = None;
        let should_apply_sandbox = matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && recipe.apply_systemd_sandbox;
        let mut sandbox_applied = false;
        let mut sandbox_needs_refresh = false;

        if action == PackageAction::Remove {
            let mut units = vec![normalize_unit_filename(&recipe.service_name)];
            for step in steps {
                match step {
                    DeclarativeStep::PurgeSystemdUnit { unit_name, .. } => {
                        units.push(normalize_unit_filename(unit_name));
                    }
                    DeclarativeStep::Systemctl {
                        unit: Some(unit),
                        operation:
                            SystemctlOp::Stop | SystemctlOp::Disable | SystemctlOp::ResetFailed,
                        ..
                    } => units.push(normalize_unit_filename(unit)),
                    _ => {}
                }
            }
            units.sort_by_key(|unit| {
                (
                    af_release::lifecycle::unit_stop_order_key(unit),
                    unit.clone(),
                )
            });
            units.dedup();
            for unit in &units {
                if let Err(error) = self.teardown_systemctl("stop", unit, &cancel).await {
                    exec_err = Some(error);
                    break;
                }
            }
            if exec_err.is_none() {
                for unit in &units {
                    if let Err(error) = self.teardown_systemctl("disable", unit, &cancel).await {
                        exec_err = Some(error);
                        break;
                    }
                }
            }
        }

        for (idx, step) in steps.iter().enumerate() {
            if exec_err.is_some() {
                break;
            }
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
                break;
            }

            // Apply systemd sandbox drop-in BEFORE systemctl reloads/enables/starts/restarts
            // the native service so the service never runs unsandboxed.
            if should_apply_sandbox
                && !sandbox_applied
                && matches!(
                    step,
                    DeclarativeStep::AptInstall { .. }
                        | DeclarativeStep::Systemctl {
                            operation: SystemctlOp::DaemonReload
                                | SystemctlOp::EnableNow
                                | SystemctlOp::Enable
                                | SystemctlOp::Start
                                | SystemctlOp::Restart
                                | SystemctlOp::TryRestart,
                            ..
                        }
                )
            {
                let (step_pct, _) = step_progress_meta(step);
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    step_pct.saturating_sub(1).max(5),
                    format!(
                        "Applying systemd security sandbox profile for {} before service activation...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => {
                        sandbox_status = Some(st);
                        sandbox_applied = true;
                    }
                    Err(err) => {
                        exec_err = Some(err);
                        break;
                    }
                }
            } else if should_apply_sandbox
                && sandbox_needs_refresh
                && matches!(
                    step,
                    DeclarativeStep::Systemctl {
                        operation: SystemctlOp::DaemonReload
                            | SystemctlOp::EnableNow
                            | SystemctlOp::Enable
                            | SystemctlOp::Start
                            | SystemctlOp::Restart
                            | SystemctlOp::TryRestart,
                        ..
                    }
                )
            {
                let needs_reload = !matches!(
                    step,
                    DeclarativeStep::Systemctl {
                        operation: SystemctlOp::DaemonReload,
                        ..
                    }
                );
                let sb_res = if needs_reload {
                    self.apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                        .await
                } else {
                    let systemd_root = self
                        .env_cfg
                        .fs_root
                        .as_ref()
                        .map(|root| root.join("etc/systemd/system"))
                        .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
                    apply_sandbox_in_root_with_journal(
                        &recipe.package_id,
                        &systemd_root,
                        Some(&mut journal),
                        self.env_cfg.fs_root.as_deref(),
                    )
                };
                match sb_res {
                    Ok(st) => {
                        sandbox_status = Some(st);
                        sandbox_needs_refresh = false;
                    }
                    Err(err) => {
                        exec_err = Some(err);
                        break;
                    }
                }
            }

            let (pct, desc) = step_progress_meta(step);
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::ExecuteStep,
                idx + 1,
                total_steps,
                pct,
                desc.to_string(),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );

            match self
                .run_single_step(recipe, step, &mut vars, &mut journal, &cancel)
                .await
            {
                Ok(step_note) => {
                    if !step_note.is_empty() {
                        append_log_line(&log_file_path, &format!("[INFO] {}", step_note));
                        logs.push(format!("[INFO] {}", step_note));
                    }
                    if sandbox_applied && matches!(step, DeclarativeStep::WriteSystemdUnit { .. }) {
                        sandbox_needs_refresh = true;
                    }
                    completed_steps += 1;
                }
                Err(err) => {
                    exec_err = Some(err);
                    break;
                }
            }
        }

        // Fallback: if no systemctl activation step was present in the recipe, apply sandbox after steps
        if exec_err.is_none() && should_apply_sandbox && !sandbox_applied {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            } else {
                self.emit_event(
                    &recipe.package_id,
                    action,
                    ExecutionPhase::SandboxApply,
                    completed_steps,
                    total_steps,
                    97,
                    format!(
                        "Applying systemd security sandbox profile for {}...",
                        recipe.package_id
                    ),
                    &log_file_path,
                    &mut logs,
                    &mut on_progress,
                );
                let sb_res = self
                    .apply_recipe_sandbox(&recipe.package_id, &mut journal, &cancel)
                    .await;
                match sb_res {
                    Ok(st) => sandbox_status = Some(st),
                    Err(err) => {
                        exec_err = Some(err);
                    }
                }
            }
        }

        if exec_err.is_none() {
            if let Err(e) = cancel.check(&recipe.package_id) {
                exec_err = Some(e);
            }
        }

        // Persist or remove completion receipt BEFORE committing the rollback journal so any
        // receipt write/remove failure triggers compensating rollback of prior config/service mutations.
        if exec_err.is_none() {
            let resolved_locks = af_models::resolve_package_lock_paths(
                &recipe.package_id,
                (!recipe.lock_file.trim().is_empty()).then_some(recipe.lock_file.as_str()),
                self.env_cfg.fs_root.as_deref(),
            );
            let retained_lock_path =
                af_models::retained_receipt_path_for_canonical(&lock_file_path);
            let legacy_lock_path = resolved_locks.legacy_swizzin;
            let finalize_res: Result<(), PackageExecutorError> = (|| {
                match action {
                    PackageAction::Install | PackageAction::Reinstall | PackageAction::Update => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        if let Some(parent) = lock_file_path.parent() {
                            validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                            crate::create_package_lock_directory(parent)?;
                        }
                        journal.stage_file_mutation(&lock_file_path)?;
                        let lock_payload = format!(
                            "package={}\nversion={}\nupdated_at={}\nengine=declarative_rust\n",
                            recipe.package_id,
                            vars.get("VERSION").cloned().unwrap_or_default(),
                            Utc::now().to_rfc3339()
                        );
                        write_file_atomic_with_mode_bounded(
                            &lock_file_path,
                            lock_payload.as_bytes(),
                            0o644,
                            self.env_cfg.fs_root.as_deref(),
                        )?;
                        if !retained_lock_path.as_os_str().is_empty() {
                            let retained_present = af_models::inspect_receipt_file(
                                &retained_lock_path,
                                self.env_cfg.fs_root.as_deref(),
                            )
                            .map_err(PackageExecutorError::SecurityViolation)?;
                            if retained_present {
                                validate_filesystem_path(
                                    &retained_lock_path,
                                    self.env_cfg.fs_root.as_deref(),
                                )?;
                                journal.stage_file_mutation(&retained_lock_path)?;
                                match fs::remove_file(&retained_lock_path) {
                                    Ok(()) => {}
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        }
                        if let Some(ref legacy_path) = legacy_lock_path {
                            let legacy_present = af_models::inspect_receipt_file(
                                legacy_path,
                                self.env_cfg.fs_root.as_deref(),
                            )
                            .map_err(PackageExecutorError::SecurityViolation)?;
                            if legacy_present {
                                validate_filesystem_path(
                                    legacy_path,
                                    self.env_cfg.fs_root.as_deref(),
                                )?;
                                journal.stage_file_mutation(legacy_path)?;
                                match fs::remove_file(legacy_path) {
                                    Ok(()) => {}
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        }
                    }
                    PackageAction::Remove => {
                        validate_filesystem_path(&lock_file_path, self.env_cfg.fs_root.as_deref())?;
                        let had_canonical = af_models::inspect_receipt_file(
                            &lock_file_path,
                            self.env_cfg.fs_root.as_deref(),
                        )
                        .map_err(PackageExecutorError::SecurityViolation)?;
                        let had_legacy = match &legacy_lock_path {
                            Some(legacy_path) => af_models::inspect_receipt_file(
                                legacy_path,
                                self.env_cfg.fs_root.as_deref(),
                            )
                            .map_err(PackageExecutorError::SecurityViolation)?,
                            None => false,
                        };
                        let had_retained = if !retained_lock_path.as_os_str().is_empty() {
                            af_models::inspect_receipt_file(
                                &retained_lock_path,
                                self.env_cfg.fs_root.as_deref(),
                            )
                            .map_err(PackageExecutorError::SecurityViolation)?
                        } else {
                            false
                        };

                        if !self.env_cfg.delete_data {
                            if (had_canonical || had_legacy || had_retained)
                                && !retained_lock_path.as_os_str().is_empty()
                            {
                                validate_filesystem_path(
                                    &retained_lock_path,
                                    self.env_cfg.fs_root.as_deref(),
                                )?;
                                if let Some(parent) = retained_lock_path.parent() {
                                    validate_filesystem_path(
                                        parent,
                                        self.env_cfg.fs_root.as_deref(),
                                    )?;
                                    crate::create_package_lock_directory(parent)?;
                                }
                                journal.stage_file_mutation(&retained_lock_path)?;
                                let retained_payload = af_models::format_retained_package_receipt(
                                    &recipe.package_id,
                                    &Utc::now().to_rfc3339(),
                                );
                                write_file_atomic_with_mode_bounded(
                                    &retained_lock_path,
                                    retained_payload.as_bytes(),
                                    0o644,
                                    self.env_cfg.fs_root.as_deref(),
                                )?;
                            }
                        } else if had_retained {
                            validate_filesystem_path(
                                &retained_lock_path,
                                self.env_cfg.fs_root.as_deref(),
                            )?;
                            journal.stage_file_mutation(&retained_lock_path)?;
                            match fs::remove_file(&retained_lock_path) {
                                Ok(()) => {}
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                Err(error) => return Err(error.into()),
                            }
                        }

                        journal.stage_file_mutation(&lock_file_path)?;
                        match fs::remove_file(&lock_file_path) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error.into()),
                        }
                        if let Some(ref legacy_path) = legacy_lock_path {
                            if had_legacy {
                                validate_filesystem_path(
                                    legacy_path,
                                    self.env_cfg.fs_root.as_deref(),
                                )?;
                                journal.stage_file_mutation(legacy_path)?;
                                match fs::remove_file(legacy_path) {
                                    Ok(()) => {}
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        }
                    }
                }
                Ok(())
            })();
            if let Err(err) = finalize_res {
                exec_err = Some(err);
            }
        }

        // Handle failure or cancellation -> run compensating rollback
        if let Some(err) = exec_err {
            let phase = match err {
                PackageExecutorError::Cancelled(_) => ExecutionPhase::Cancelled,
                _ => ExecutionPhase::Failed,
            };
            self.emit_event(
                &recipe.package_id,
                action,
                ExecutionPhase::Rollback,
                completed_steps,
                total_steps,
                98,
                format!(
                    "Rolling back partial {} state for {}: {}",
                    action.as_str(),
                    recipe.package_id,
                    err
                ),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            let rb_notes = journal.rollback(&self.runner).await;
            for note in rb_notes {
                append_log_line(&log_file_path, &format!("[WARN] [rollback] {}", note));
                logs.push(format!("[WARN] [rollback] {}", note));
            }
            if action == PackageAction::Remove {
                append_log_line(&log_file_path, "[WARN] Removal incomplete; installed marker retained. Retry removal to reconcile package state.");
            }
            let final_err =
                if let Some(incomplete_reason) = journal.incomplete_rollback_error.take() {
                    match err {
                        PackageExecutorError::StepFailed { step, reason } => {
                            PackageExecutorError::StepFailed {
                                step,
                                reason: format!(
                                    "{reason}; incomplete rollback/recovery: {incomplete_reason}"
                                ),
                            }
                        }
                        other => PackageExecutorError::StepFailed {
                            step: "rollback_journal".to_string(),
                            reason: format!(
                                "{other}; incomplete rollback/recovery: {incomplete_reason}"
                            ),
                        },
                    }
                } else {
                    err
                };
            self.emit_event(
                &recipe.package_id,
                action,
                phase,
                completed_steps,
                total_steps,
                99,
                format!(
                    "Package {} {} failed: {}",
                    recipe.package_id,
                    action.as_str(),
                    final_err
                ),
                &log_file_path,
                &mut logs,
                &mut on_progress,
            );
            return Err(final_err);
        }

        // Commit rollback journal ONLY after all steps, sandboxing, and lockfile persistence succeeded
        journal.commit();
        if matches!(
            action,
            PackageAction::Install | PackageAction::Reinstall | PackageAction::Update
        ) && self.env_cfg.fs_root.is_none()
        {
            trigger_certbot_sync_best_effort();
        }

        let done_msg = match action {
            PackageAction::Install => format!("{} installed successfully.", recipe.label),
            PackageAction::Reinstall => format!("{} reinstalled successfully.", recipe.label),
            PackageAction::Update => format!("{} updated successfully.", recipe.label),
            PackageAction::Remove => format!("{} completely removed.", recipe.label),
        };
        self.emit_event(
            &recipe.package_id,
            action,
            ExecutionPhase::Complete,
            completed_steps,
            total_steps,
            100,
            done_msg,
            &log_file_path,
            &mut logs,
            &mut on_progress,
        );

        Ok(PackageExecutionOutcome {
            package_id: recipe.package_id.clone(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            completed_steps,
            total_steps,
            lock_present: af_models::inspect_receipt_file(
                &lock_file_path,
                self.env_cfg.fs_root.as_deref(),
            )
            .unwrap_or(false),
            lock_file_path,
            resolved_version: vars.get("VERSION").cloned(),
            sandbox_status,
            rollback_performed: false,
            logs,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_event<F>(
        &self,
        pkg_id: &str,
        action: PackageAction,
        phase: ExecutionPhase,
        step_index: usize,
        total_steps: usize,
        progress_pct: u8,
        message: String,
        log_file_path: &Path,
        logs: &mut Vec<String>,
        on_progress: &mut F,
    ) where
        F: FnMut(PackageProgressEvent),
    {
        let event = PackageProgressEvent {
            package_id: pkg_id.to_string(),
            action,
            engine: PackageEngineMode::DeclarativeRust,
            phase,
            step_index,
            total_steps,
            progress_pct: progress_pct.min(100),
            message,
            timestamp: Utc::now().to_rfc3339(),
        };
        let wire_line = event.to_wire_line();
        append_log_line(log_file_path, &wire_line);
        logs.push(wire_line);
        on_progress(event);
    }

    pub(super) async fn teardown_systemctl(
        &self,
        operation: &str,
        unit: &str,
        cancel: &CancellationToken,
    ) -> Result<(), PackageExecutorError> {
        let output = self
            .runner
            .run_command(
                "systemctl",
                &[operation.to_string(), "--".to_string(), unit.to_string()],
                &[],
                cancel,
            )
            .await?;
        if output.success() {
            return Ok(());
        }
        let state = self
            .runner
            .run_command(
                "systemctl",
                &[
                    "show".to_string(),
                    "--property=LoadState".to_string(),
                    "--property=ActiveState".to_string(),
                    "--property=UnitFileState".to_string(),
                    "--".to_string(),
                    unit.to_string(),
                ],
                &[],
                cancel,
            )
            .await?;
        let load_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("LoadState="));
        let active_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("ActiveState="));
        let unit_file_state = state
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("UnitFileState="));
        let known_inactive = state.success()
            && active_state == Some("inactive")
            && matches!(load_state, Some("loaded" | "masked" | "not-found"));
        let disable_or_reset_ok = matches!(load_state, Some("not-found" | "masked"))
            || matches!(
                unit_file_state,
                Some("disabled" | "static" | "indirect" | "masked")
            );
        if known_inactive && (operation == "stop" || disable_or_reset_ok) {
            return Ok(());
        }
        Err(PackageExecutorError::StepFailed {
            step: format!("systemctl_{operation}"),
            reason: format!(
                "systemctl {operation} {unit} exited with {}: {}; teardown state unproven: {}",
                output.exit_code,
                output.combined_output(),
                state.combined_output()
            ),
        })
    }
}
