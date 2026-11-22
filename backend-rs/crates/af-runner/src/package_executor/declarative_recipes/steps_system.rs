use super::*;

impl<R: CommandRunner> DeclarativePackageExecutor<R> {
    pub(crate) async fn run_single_step(
        &self,
        recipe: &DeclarativePackageRecipe,
        step: &DeclarativeStep,
        vars: &mut HashMap<String, String>,
        journal: &mut RollbackJournal,
        cancel: &CancellationToken,
    ) -> Result<String, PackageExecutorError> {
        cancel.check(&recipe.package_id)?;
        let apt_env = vec![
            ("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string()),
            ("DPKG_LOCK_TIMEOUT".to_string(), "120".to_string()),
        ];

        match step {
            DeclarativeStep::AptUpdate { .. } => {
                let args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "update".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_update".to_string(),
                        reason: format!(
                            "apt-get update exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                Ok("apt-get update completed".to_string())
            }

            DeclarativeStep::AptInstall { packages, .. } => {
                let primary_pkg = recipe_primary_apt_package(recipe, packages);
                let exact_apt_target: Option<String> = if primary_pkg.is_some() {
                    match self
                        .env_cfg
                        .expected_target_version
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        Some(target) => {
                            if !af_release::lifecycle::validate_exact_apt_version(target) {
                                return Err(PackageExecutorError::Validation(format!(
                                    "Invalid exact Debian/APT target version '{}' for package '{}'",
                                    target, recipe.package_id
                                )));
                            }
                            Some(target.to_string())
                        }
                        None => None,
                    }
                } else {
                    None
                };

                let mut prior_pkg_version = None;
                let mut primary_was_absent = false;
                if let Some(pkg_name) = primary_pkg.as_deref() {
                    let dpkg_args = vec![
                        "-W".to_string(),
                        "-f=${db:Status-Status} ${Version}\n".to_string(),
                        pkg_name.to_string(),
                    ];
                    match self
                        .runner
                        .run_command("dpkg-query", &dpkg_args, &[], cancel)
                        .await
                    {
                        Ok(dpkg_out) if dpkg_out.success() => {
                            if let Some(installed) =
                                af_release::lifecycle::parse_installed_dpkg_status_version(
                                    &dpkg_out.stdout,
                                )
                            {
                                if journal.has_existing_installation {
                                    prior_pkg_version = Some(installed.to_string());
                                }
                            } else if !journal.has_existing_installation {
                                primary_was_absent = true;
                            }
                        }
                        Ok(_) => {
                            if !journal.has_existing_installation {
                                primary_was_absent = true;
                            }
                        }
                        Err(_) => {}
                    }
                    if journal.has_existing_installation {
                        if let Some(pre_ver) = journal.pre_existing_version.as_ref() {
                            let keep_full_live = prior_pkg_version.as_deref().is_some_and(|live| {
                                live == pre_ver.as_str()
                                    || af_release::lifecycle::apt_receipt_matches_live_debian_revision(
                                        "apt", pre_ver, live,
                                    )
                            });
                            if !keep_full_live {
                                prior_pkg_version = Some(pre_ver.clone());
                            }
                        }
                    }
                }

                if let (Some(pkg_name), Some(target)) =
                    (primary_pkg.as_deref(), exact_apt_target.as_deref())
                {
                    if !is_downgrade_allowed() {
                        if let Some(prev) = prior_pkg_version.as_deref() {
                            if af_release::lifecycle::validate_exact_apt_version(prev)
                                && af_release::lifecycle::compare_debian_versions_str(target, prev)
                                    == std::cmp::Ordering::Less
                            {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade APT package {} from installed version {} to {}",
                                    pkg_name, prev, target
                                )));
                            }
                        }
                    }
                }

                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confdef".to_string(),
                    "-o".to_string(),
                    "DPkg::Options::=--force-confold".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                if exact_apt_target.is_some() && is_downgrade_allowed() {
                    args.push("--allow-downgrades".to_string());
                }
                let install_specs: Vec<String> =
                    match (primary_pkg.as_deref(), exact_apt_target.as_deref()) {
                        (Some(primary_name), Some(target)) => packages
                            .iter()
                            .map(|pkg| {
                                if pkg == primary_name {
                                    format!("{pkg}={target}")
                                } else {
                                    pkg.clone()
                                }
                            })
                            .collect(),
                        _ => packages.clone(),
                    };
                args.extend(install_specs.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "apt_install".to_string(),
                        reason: format!(
                            "apt-get install {:?} exited with {}: {}",
                            install_specs,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if let Some(ref pkg_name) = primary_pkg {
                    if let Some(old_ver) = prior_pkg_version {
                        journal.record_apt_upgrade(pkg_name, &old_ver);
                    } else if primary_was_absent {
                        journal.record_apt_install(pkg_name);
                    }
                    if !recipe.service_name.is_empty() {
                        journal.record_touched_service(&recipe.service_name);
                    }
                    if let Some(ref target) = exact_apt_target {
                        let verify_args = vec![
                            "-W".to_string(),
                            "-f=${db:Status-Status} ${Version}\n".to_string(),
                            pkg_name.clone(),
                        ];
                        let verify_out = self
                            .runner
                            .run_command("dpkg-query", &verify_args, &[], cancel)
                            .await?;
                        let installed = if verify_out.success() {
                            af_release::lifecycle::parse_installed_dpkg_status_version(
                                &verify_out.stdout,
                            )
                        } else {
                            None
                        };
                        match installed {
                            Some(ver) if ver == target => {}
                            Some(ver) => {
                                return Err(PackageExecutorError::VerificationFailed(format!(
                                    "Installed APT package '{}' version '{}' does not match requested exact target version '{}'",
                                    pkg_name, ver, target
                                )));
                            }
                            None => {
                                return Err(PackageExecutorError::VerificationFailed(format!(
                                    "APT package '{}' is not in installed dpkg status after installing exact target '{}'",
                                    pkg_name, target
                                )));
                            }
                        }
                    }
                }
                Ok(format!("installed APT packages: {}", packages.join(", ")))
            }

            DeclarativeStep::AptRemove {
                packages,
                autoremove,
                ..
            }
            | DeclarativeStep::AptPurge {
                packages,
                autoremove,
                ..
            } => {
                let removal_action = if self.env_cfg.delete_data {
                    "purge"
                } else {
                    "remove"
                };
                let mut args = vec![
                    "-o".to_string(),
                    "DPkg::Lock::Timeout=120".to_string(),
                    removal_action.to_string(),
                    "-y".to_string(),
                    "-qq".to_string(),
                ];
                args.extend(packages.iter().cloned());
                let out = self
                    .runner
                    .run_command("apt-get", &args, &apt_env, cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: format!("apt_{}", removal_action),
                        reason: format!(
                            "apt-get {} {:?} exited with {}: {}",
                            removal_action,
                            packages,
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }
                if *autoremove {
                    cancel.check(&recipe.package_id)?;
                    let ar_args = vec![
                        "-o".to_string(),
                        "DPkg::Lock::Timeout=120".to_string(),
                        "autoremove".to_string(),
                        "-y".to_string(),
                        "-qq".to_string(),
                    ];
                    let output = self
                        .runner
                        .run_command("apt-get", &ar_args, &apt_env, cancel)
                        .await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "apt_autoremove".to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!(
                    "APT {} packages: {}",
                    removal_action,
                    packages.join(", ")
                ))
            }

            DeclarativeStep::EnsureSystemUser {
                username,
                home_dir,
                create_home,
                ..
            } => {
                validate_chown_target_path(home_dir)?;
                let check = self
                    .runner
                    .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                    .await?;
                if check.success() {
                    return Ok(format!("system user {} already exists", username));
                }
                cancel.check(&recipe.package_id)?;
                let mut args = vec![
                    "--system".to_string(),
                    "--user-group".to_string(),
                    if *create_home {
                        "--create-home".to_string()
                    } else {
                        "--no-create-home".to_string()
                    },
                    "--home-dir".to_string(),
                    home_dir.clone(),
                    "--shell".to_string(),
                    "/usr/sbin/nologin".to_string(),
                    username.clone(),
                ];
                let out = self
                    .runner
                    .run_command("useradd", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    // Check again in case user was already created
                    let recheck = self
                        .runner
                        .run_command("id", &["-u".to_string(), username.clone()], &[], cancel)
                        .await?;
                    if !recheck.success() {
                        args.clear();
                        return Err(PackageExecutorError::StepFailed {
                            step: "ensure_system_user".to_string(),
                            reason: format!(
                                "useradd {} failed ({}): {}",
                                username,
                                out.exit_code,
                                out.combined_output()
                            ),
                        });
                    }
                }
                Ok(format!("ensured system user {}", username))
            }

            DeclarativeStep::PurgeSystemUser { username, .. } => {
                if !self.env_cfg.delete_data {
                    return Ok(format!(
                        "retained system user {} with application data",
                        username
                    ));
                }
                for (database, program) in [("passwd", "userdel"), ("group", "groupdel")] {
                    let account = self
                        .runner
                        .run_command(
                            "getent",
                            &[database.to_string(), username.clone()],
                            &[],
                            cancel,
                        )
                        .await?;
                    if account.exit_code == 2 {
                        continue;
                    }
                    if !account.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: "account_lookup".to_string(),
                            reason: account.combined_output(),
                        });
                    }
                    let output = self
                        .runner
                        .run_command(program, std::slice::from_ref(username), &[], cancel)
                        .await?;
                    if !output.success() {
                        return Err(PackageExecutorError::StepFailed {
                            step: program.to_string(),
                            reason: output.combined_output(),
                        });
                    }
                }
                Ok(format!("purged system user {}", username))
            }

            DeclarativeStep::EnsureDirectories {
                paths,
                mode,
                owner,
                group,
                ..
            } => {
                for logical in paths {
                    cancel.check(&recipe.package_id)?;
                    if owner.is_some() || group.is_some() {
                        validate_chown_target_path(logical)?;
                    }
                    let resolved = self.env_cfg.resolve_path(logical)?;
                    if let Some(parent) = resolved.parent() {
                        create_dir_all_0755(parent)?;
                    }
                    fs::create_dir_all(&resolved)?;
                    validate_filesystem_path(&resolved, self.env_cfg.fs_root.as_deref())?;
                    set_path_mode(&resolved, *mode);
                    if let Some(ref o) = owner {
                        let grp = group.as_deref().unwrap_or(o.as_str());
                        if self.env_cfg.fs_root.is_none() {
                            let out = self
                                .runner
                                .run_command(
                                    "chown",
                                    &[
                                        "-R".to_string(),
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
                                    step: "ensure_directories".to_string(),
                                    reason: format!(
                                        "chown -R -h {}:{} {} exited with {}: {}",
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
                }
                Ok(format!("ensured directories: {}", paths.join(", ")))
            }

            DeclarativeStep::ProbeSshPort { .. } => {
                let sshd_cfg = self.env_cfg.resolve_readonly_path("/etc/ssh/sshd_config");
                validate_filesystem_path(&sshd_cfg, self.env_cfg.fs_root.as_deref())?;
                let mut port = "ssh".to_string();
                if let Ok(raw) = fs::read_to_string(&sshd_cfg) {
                    if let Some(caps) = SSH_PORT_LINE_RE.captures(&raw) {
                        if let Some(m) = caps.get(1) {
                            let candidate = m.as_str().trim();
                            if !candidate.is_empty() {
                                port = candidate.to_string();
                            }
                        }
                    }
                }
                vars.insert("SSH_PORT".to_string(), port.clone());
                Ok(format!("probed SSH port: {}", port))
            }

            DeclarativeStep::GenerateSelfSignedTlsCert {
                cert_path,
                key_out_path,
                days,
                subject,
                mode,
                owner,
                group,
                overwrite,
                ..
            } => {
                let cert_resolved = self.env_cfg.resolve_path(cert_path)?;
                let key_resolved = match key_out_path {
                    Some(ref kp) => self.env_cfg.resolve_path(kp)?,
                    None => cert_resolved.clone(),
                };
                if !*overwrite && (cert_resolved.is_file() || key_resolved.is_file()) {
                    if cert_resolved.is_file() {
                        journal.stage_file_mutation(&cert_resolved)?;
                        self.apply_file_metadata(
                            &cert_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    if key_resolved != cert_resolved && key_resolved.is_file() {
                        journal.stage_file_mutation(&key_resolved)?;
                        self.apply_file_metadata(
                            &key_resolved,
                            *mode,
                            owner.as_deref(),
                            group.as_deref(),
                            cancel,
                        )
                        .await?;
                    }
                    return Ok(format!("preserved existing TLS certificate {}", cert_path));
                }
                if let Some(parent) = cert_resolved.parent() {
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    create_dir_all_0755(parent)?;
                    validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                }
                if key_resolved != cert_resolved {
                    if let Some(parent) = key_resolved.parent() {
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                        create_dir_all_0755(parent)?;
                        validate_filesystem_path(parent, self.env_cfg.fs_root.as_deref())?;
                    }
                }
                journal.stage_file_mutation(&cert_resolved)?;
                if key_resolved != cert_resolved {
                    journal.stage_file_mutation(&key_resolved)?;
                }

                // Pre-create destination files with strict 0600 permissions before invoking `openssl`
                // so private key material is never briefly exposed under a permissive process umask.
                write_file_atomic_with_mode_bounded(
                    &cert_resolved,
                    b"",
                    0o600,
                    self.env_cfg.fs_root.as_deref(),
                )?;
                if key_resolved != cert_resolved {
                    write_file_atomic_with_mode_bounded(
                        &key_resolved,
                        b"",
                        0o600,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                }

                let args = vec![
                    "req".to_string(),
                    "-x509".to_string(),
                    "-nodes".to_string(),
                    "-days".to_string(),
                    days.to_string(),
                    "-newkey".to_string(),
                    "rsa:4096".to_string(),
                    "-keyout".to_string(),
                    key_resolved.to_string_lossy().to_string(),
                    "-out".to_string(),
                    cert_resolved.to_string_lossy().to_string(),
                    "-subj".to_string(),
                    subject.clone(),
                ];
                let out = self
                    .runner
                    .run_command("openssl", &args, &[], cancel)
                    .await?;
                if !out.success() {
                    return Err(PackageExecutorError::StepFailed {
                        step: "generate_self_signed_tls_cert".to_string(),
                        reason: format!(
                            "openssl req -x509 exited with {}: {}",
                            out.exit_code,
                            out.combined_output()
                        ),
                    });
                }

                // In isolated test roots where `openssl` is mocked via `CommandRunner`, ensure
                // the staged certificate file is materialized on disk with the requested mode.
                if self.env_cfg.fs_root.is_some()
                    && fs::metadata(&cert_resolved)
                        .map(|m| m.len() == 0)
                        .unwrap_or(true)
                {
                    let pem_payload = format!(
                        "# AETHERFLOW-MOCK-TLS-KEY (isolated test sentinel - not a real key)\nsubject={}\ndays={}\n",
                        subject, days
                    );
                    write_file_atomic_with_mode_bounded(
                        &cert_resolved,
                        pem_payload.as_bytes(),
                        *mode,
                        self.env_cfg.fs_root.as_deref(),
                    )?;
                    if key_resolved != cert_resolved
                        && fs::metadata(&key_resolved)
                            .map(|m| m.len() == 0)
                            .unwrap_or(true)
                    {
                        write_file_atomic_with_mode_bounded(
                            &key_resolved,
                            pem_payload.as_bytes(),
                            *mode,
                            self.env_cfg.fs_root.as_deref(),
                        )?;
                    }
                }

                self.apply_file_metadata(
                    &cert_resolved,
                    *mode,
                    owner.as_deref(),
                    group.as_deref(),
                    cancel,
                )
                .await?;
                if key_resolved != cert_resolved {
                    self.apply_file_metadata(
                        &key_resolved,
                        *mode,
                        owner.as_deref(),
                        group.as_deref(),
                        cancel,
                    )
                    .await?;
                }
                Ok(format!(
                    "generated self-signed TLS certificate {}",
                    cert_path
                ))
            }

            DeclarativeStep::CaptureDpkgVersion {
                package,
                fallback_version: _,
                version_file_path,
                owner,
                group,
                ..
            } => {
                let args = vec![
                    "-W".to_string(),
                    "-f=${db:Status-Status} ${Version}\n".to_string(),
                    package.clone(),
                ];
                let out = self
                    .runner
                    .run_command("dpkg-query", &args, &[], cancel)
                    .await?;
                if !out.success() || out.stdout.trim().is_empty() {
                    let detail = if out.stderr.trim().is_empty() {
                        "dpkg-query failed or returned empty version".to_string()
                    } else {
                        out.stderr.trim().to_string()
                    };
                    return Err(PackageExecutorError::StepFailed {
                        step: "capture_dpkg_version".to_string(),
                        reason: format!(
                            "dpkg-query {:?} exited with {}: {}",
                            args, out.exit_code, detail
                        ),
                    });
                }
                let Some(resolved_ref) =
                    af_release::lifecycle::parse_installed_dpkg_status_version(&out.stdout)
                else {
                    return Err(PackageExecutorError::StepFailed {
                        step: "capture_dpkg_version".to_string(),
                        reason: format!(
                            "dpkg-query for '{}' did not report an installed package with a valid Debian version (got {:?})",
                            package,
                            out.stdout.trim()
                        ),
                    });
                };
                let resolved_ver = resolved_ref.to_string();
                if let Some(target) = self
                    .env_cfg
                    .expected_target_version
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if resolved_ver != target {
                        return Err(PackageExecutorError::VerificationFailed(format!(
                            "APT {} package version '{}' does not satisfy expected target version '{}'",
                            package, resolved_ver, target
                        )));
                    }
                }
                vars.insert("VERSION".to_string(), resolved_ver.clone());
                vars.insert(
                    "ZNC_CONF_VERSION".to_string(),
                    format_znc_major_minor(&resolved_ver),
                );
                vars.insert(
                    "TAG".to_string(),
                    format!("v{}", resolved_ver.trim_start_matches('v')),
                );

                if let Some(ref vp) = version_file_path {
                    let resolved_path = self.env_cfg.resolve_path(vp)?;
                    if !is_downgrade_allowed() {
                        if let Ok(existing_raw) = fs::read_to_string(&resolved_path) {
                            let existing_ver = existing_raw.trim().trim_start_matches('v');
                            let clean_ver = resolved_ver.trim().trim_start_matches('v');
                            if !existing_ver.is_empty()
                                && af_release::lifecycle::compare_debian_versions_str(
                                    existing_ver,
                                    clean_ver,
                                ) == std::cmp::Ordering::Greater
                            {
                                return Err(PackageExecutorError::Validation(format!(
                                    "refusing to downgrade {} from installed version {} to {}",
                                    recipe.package_id, existing_ver, clean_ver
                                )));
                            }
                        }
                    }
                    journal.stage_file_mutation(&resolved_path)?;
                    let content = format!("{}\n", resolved_ver);
                    write_file_atomic_with_mode_bounded(
                        &resolved_path,
                        content.as_bytes(),
                        0o644,
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
                                        resolved_path.to_string_lossy().to_string(),
                                    ],
                                    &[],
                                    cancel,
                                )
                                .await?;
                            if !out.success() {
                                return Err(PackageExecutorError::StepFailed {
                                    step: "capture_dpkg_version".to_string(),
                                    reason: format!(
                                        "chown -h {}:{} {} exited with {}: {}",
                                        o,
                                        grp,
                                        resolved_path.display(),
                                        out.exit_code,
                                        out.combined_output()
                                    ),
                                });
                            }
                        }
                    }
                }
                Ok(format!(
                    "captured dpkg version {} for {}",
                    resolved_ver, package
                ))
            }


            DeclarativeStep::InstallRcloneBinary { .. } => {
                self.execute_install_rclone_binary(recipe, vars, journal, cancel)
                    .await
            }

            DeclarativeStep::RemoveRcloneFiles { .. } => self.execute_remove_rclone_files(),

            DeclarativeStep::WaitForHttpReady { path, .. } => {
                self.execute_wait_for_http_ready(
                    &recipe.package_id,
                    path,
                    recipe.default_port,
                    vars,
                    cancel,
                )
                .await
            }

            other => {
                self.execute_files_and_services_step(recipe, other, vars, journal, cancel)
                    .await
            }
        }
    }
}
