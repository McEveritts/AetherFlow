use super::*;

#[tokio::test]
async fn test_quassel_install_update_remove_and_cert_data_preservation() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("quassel-lifecycle");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    // Verify custom app_port propagates to /etc/default/quasselcore
    env_cfg.app_port = 4249;

    // Custom runner that simulates openssl writing a cert file when invoked
    #[derive(Clone, Default)]
    struct QuasselMockRunner {
        recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
        fail_systemctl_restart: bool,
    }

    impl CommandRunner for QuasselMockRunner {
        fn run_command<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
            env_vars: &'a [(String, String)],
            cancel: &'a CancellationToken,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                if cancel.is_cancelled() {
                    return Err(PackageExecutorError::Cancelled(program.to_string()));
                }
                self.recorded.lock().unwrap().push(RecordedCommand {
                    program: program.to_string(),
                    args: args.to_vec(),
                    env: env_vars.to_vec(),
                });

                if program == "id" {
                    return Ok(CommandOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "no such user".to_string(),
                    });
                }
                if program == "dpkg-query" {
                    let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                    let stdout = if wants_status {
                        "installed 1:0.14.0-1ubuntu2\n".to_string()
                    } else {
                        "1:0.14.0-1ubuntu2\n".to_string()
                    };
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout,
                        stderr: String::new(),
                    });
                }
                if program == "openssl" {
                    // Find `-out` and `-keyout` argument and write synthetic PEM payload
                    if let Some(pos) = args.iter().position(|a| a == "-out") {
                        if let Some(out_path) = args.get(pos + 1) {
                            fs::write(
                                    out_path,
                                    b"-----BEGIN PRIVATE KEY-----\nNEWKEY\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nNEWCERT\n-----END CERTIFICATE-----\n",
                                )
                                .unwrap();
                        }
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "Certificate generated".to_string(),
                        stderr: String::new(),
                    });
                }
                if self.fail_systemctl_restart
                    && program == "systemctl"
                    && args.iter().any(|a| a == "restart")
                {
                    return Ok(CommandOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "simulated systemctl restart failure".to_string(),
                    });
                }
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("ok: {} {}", program, args.join(" ")),
                    stderr: String::new(),
                })
            })
        }
    }

    let runner = QuasselMockRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
    let recipe = get_declarative_recipe("quassel").unwrap();

    let mut install_events = Vec::new();
    let outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |ev| install_events.push(ev),
        )
        .await
        .expect("quassel install should succeed");

    assert!(outcome.lock_present);
    assert!(root.join("install/.quassel.lock").is_file());
    assert_eq!(
        outcome.resolved_version.as_deref(),
        Some("1:0.14.0-1ubuntu2")
    );
    let install_commands = runner.recorded.lock().unwrap().clone();
    let certificate_command = install_commands
        .iter()
        .position(|command| command.program == "openssl")
        .expect("TLS credentials must be provisioned");
    let quassel_install_command = install_commands
        .iter()
        .position(|command| {
            command.program == "apt-get"
                && command.args.contains(&"install".to_string())
                && command.args.contains(&"quassel-core".to_string())
        })
        .expect("quassel-core must be installed");
    assert!(certificate_command < quassel_install_command);
    assert!(install_commands[quassel_install_command]
        .args
        .contains(&"DPkg::Options::=--force-confold".to_string()));
    let defaults_step = recipe.install_steps.iter().position(|step| matches!(
            step, DeclarativeStep::WriteTemplateFile { path, .. } if path == "/etc/default/quasselcore"
        )).unwrap();
    let package_step = recipe.install_steps.iter().position(|step| matches!(
            step, DeclarativeStep::AptInstall { packages, .. } if packages.iter().any(|package| package == "quassel-core")
        )).unwrap();
    assert!(defaults_step < package_step);
    let sandbox_event = install_events
        .iter()
        .position(|event| event.phase == ExecutionPhase::SandboxApply)
        .unwrap();
    let first_install_event = install_events
        .iter()
        .position(|event| {
            event.phase == ExecutionPhase::ExecuteStep && event.message.contains("Installing")
        })
        .unwrap();
    assert!(sandbox_event < first_install_event);

    // Verify dependencies, config, sandbox drop-in, cert, and version metadata
    let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
    assert!(default_cfg.contains("LISTEN=\"0.0.0.0\""));
    assert!(default_cfg.contains("PORT=\"4249\""));
    assert!(default_cfg.contains("CONFIGDIR=\"/var/lib/quassel\""));
    assert!(default_cfg.contains("LOGFILE=\"/var/log/quassel/quasselcore.log\""));

    let sandbox_cfg = fs::read_to_string(
        root.join("etc/systemd/system/quasselcore.service.d/aetherflow-sandbox.conf"),
    )
    .unwrap();
    assert!(sandbox_cfg.contains("ReadWritePaths=-/var/lib/quassel -/var/log/quassel"));

    let cert_path = root.join("var/lib/quassel/quasselCert.pem");
    assert!(cert_path.is_file());

    let version_marker = fs::read_to_string(root.join("var/lib/quassel/.af-version")).unwrap();
    assert_eq!(version_marker.trim(), "1:0.14.0-1ubuntu2");

    // Verify bounded monotonic progress
    assert!(!install_events.is_empty());
    for pair in install_events.windows(2) {
        assert!(pair[1].progress_pct >= pair[0].progress_pct);
    }
    assert_eq!(install_events.last().unwrap().progress_pct, 100);

    // Verify apt-get installed quassel-core and openssl
    let cmds = runner.recorded.lock().unwrap().clone();
    for dependency in ["quassel-core", "openssl"] {
        assert!(cmds.iter().any(|command| {
            command.program == "apt-get"
                && command.args.contains(&"install".to_string())
                && command.args.contains(&dependency.to_string())
        }));
    }
    assert!(cmds.iter().any(|c| c.program == "openssl"));

    // Seed custom certificate, SQLite database, and custom /etc/default/quasselcore settings
    // to verify preservation across reinstall/update/remove while updating PORT in-place.
    let custom_cert = b"-----BEGIN CERTIFICATE-----\nEXISTING_USER_CERT_DO_NOT_OVERWRITE\n-----END CERTIFICATE-----\n";
    fs::write(&cert_path, custom_cert).unwrap();
    let sqlite_db = root.join("var/lib/quassel/quassel-storage.sqlite");
    fs::write(&sqlite_db, b"SQLite format 3 user backlog data").unwrap();
    let defaults_file = root.join("etc/default/quasselcore");
    fs::write(
            &defaults_file,
            "# Custom operator Quassel settings\nSTART=\"true\"\nUSER=\"quasselcore\"\nLOGLEVEL=\"Debug\"\nLISTEN=\"127.0.0.1\"\nPORT=4249\nEXTRA_OPTS=\"--oidentd\"\n",
        )
        .unwrap();

    // Clear recorded commands and run Update with a new port
    runner.recorded.lock().unwrap().clear();
    env_cfg.app_port = 4255;
    let update_executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
    let update_outcome = update_executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel update should succeed");
    assert!(update_outcome.lock_present);
    assert_eq!(
        fs::read(&cert_path).unwrap(),
        custom_cert,
        "existing Quassel TLS certificate must be preserved on update"
    );
    let updated_defaults = fs::read_to_string(&defaults_file).unwrap();
    assert!(
            updated_defaults.contains("LOGLEVEL=\"Debug\"")
                && updated_defaults.contains("LISTEN=\"127.0.0.1\"")
                && updated_defaults.contains("EXTRA_OPTS=\"--oidentd\"")
                && updated_defaults.contains("PORT=\"4255\""),
            "custom /etc/default/quasselcore lines must be preserved on update while PORT is updated in-place: {updated_defaults}"
        );
    assert!(
        !runner
            .recorded
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.program == "openssl"),
        "openssl must not be invoked when quasselCert.pem already exists"
    );

    // Even if a subsequent reinstall fails mid-flight and rolls back, pre-existing cert must survive!
    let failing_runner = QuasselMockRunner {
        recorded: Arc::new(StdMutex::new(Vec::new())),
        fail_systemctl_restart: true,
    };
    let failing_exec = DeclarativePackageExecutor::with_runner(env_cfg.clone(), failing_runner);
    let err = failing_exec
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(matches!(err, PackageExecutorError::StepFailed { .. }));
    assert_eq!(
        fs::read(&cert_path).unwrap(),
        custom_cert,
        "rollback on failed reinstall must never delete pre-existing quasselCert.pem"
    );
    assert!(
        sqlite_db.is_file(),
        "rollback must preserve existing Quassel SQLite database"
    );

    // Remove with delete_data = false (default): must remove /var/lib/quassel/.af-version, lock, and sandbox drop-in,
    // but PRESERVE /etc/default/quasselcore, /var/lib/quassel & cert
    let remove_command_start = runner.recorded.lock().unwrap().len();
    let remove_preserve = update_executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel remove (preserve data) should succeed");
    assert!(!remove_preserve.lock_present);
    let remove_commands = runner.recorded.lock().unwrap()[remove_command_start..].to_vec();
    assert!(remove_commands.iter().any(|command| {
        command.program == "apt-get"
            && command.args.contains(&"remove".to_string())
            && command.args.contains(&"quassel-core".to_string())
    }));
    assert!(!remove_commands.iter().any(|command| {
        command.program == "apt-get" && command.args.contains(&"purge".to_string())
    }));
    assert!(!remove_commands
        .iter()
        .any(|command| command.program == "userdel"));
    assert!(!root.join("install/.quassel.lock").exists());
    assert!(!root.join("var/lib/quassel/.af-version").exists());
    assert!(
        root.join("etc/default/quasselcore").is_file(),
        "/etc/default/quasselcore must be preserved on remove when delete_data=false"
    );
    assert_eq!(
        fs::read(&cert_path).unwrap(),
        custom_cert,
        "quasselCert.pem must be preserved on remove when delete_data=false"
    );
    assert!(
        sqlite_db.is_file(),
        "quassel SQLite database must be preserved on remove when delete_data=false"
    );

    // Remove with delete_data = true: must purge /etc/default/quasselcore, /var/lib/quassel, /var/log/quassel, and user quasselcore
    let mut purge_env = env_cfg.clone();
    purge_env.delete_data = true;
    let purge_exec = DeclarativePackageExecutor::with_runner(purge_env, runner.clone());
    let purge_command_start = runner.recorded.lock().unwrap().len();
    purge_exec
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel remove (purge data) should succeed");
    assert!(!root.join("etc/default/quasselcore").exists());
    assert!(!root.join("var/lib/quassel").exists());
    assert!(!root.join("var/log/quassel").exists());
    let purge_commands = runner.recorded.lock().unwrap()[purge_command_start..].to_vec();
    assert!(purge_commands.iter().any(|command| {
        command.program == "apt-get"
            && command.args.contains(&"purge".to_string())
            && command.args.contains(&"quassel-core".to_string())
    }));
    assert!(purge_commands.iter().any(|command| {
        command.program == "userdel" && command.args.contains(&"quasselcore".to_string())
    }));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_threadfin_recipe_verifies_pinned_digests_tamper_arch_and_https_fail_closed() {
    let recipe = get_declarative_recipe("threadfin").expect("threadfin recipe must exist");
    recipe
        .validate()
        .expect("threadfin recipe must validate cleanly");

    // Ensure no ResolveGitHubReleaseTag step or unverified latest download exists in threadfin
    let mut found_download_step = false;
    for step in recipe
        .install_steps
        .iter()
        .chain(recipe.update_steps.iter())
    {
        assert!(
            !matches!(step, DeclarativeStep::ResolveGitHubReleaseTag { .. }),
            "threadfin must use pinned release 1.2.37 rather than unverified latest release lookup"
        );
        if let DeclarativeStep::DownloadBinary {
            url_template,
            arch_map,
            verification,
            ..
        } = step
        {
            found_download_step = true;
            assert_eq!(
                    url_template,
                    "https://github.com/Threadfin/Threadfin/releases/download/{{VERSION}}/{{ARCH_ASSET}}"
                );
            assert_eq!(arch_map.amd64, "Threadfin_linux_amd64_glibc_2.31_compat");
            assert_eq!(arch_map.arm64, "Threadfin_linux_arm64");
            let arch_digests = verification
                .arch_sha256
                .as_ref()
                .expect("threadfin must pin per-architecture SHA-256 digests");
            assert_eq!(arch_digests.amd64, THREADFIN_AMD64_COMPAT_SHA256);
            assert_eq!(arch_digests.arm64, THREADFIN_ARM64_SHA256);
            assert_eq!(arch_digests.armhf.as_deref(), Some(THREADFIN_ARMHF_SHA256));
            assert!(verification.require_elf_magic);
        }
    }
    assert!(found_download_step);

    // Also confirm the plain amd64 upstream digest constant matches official 1.2.37 metadata
    assert_eq!(
        THREADFIN_AMD64_PLAIN_SHA256,
        "19183013ec8da826e556bde3b511d9f93b9269f6d7eddd78a9df128529f45e4e"
    );

    let root = create_isolated_test_dir("threadfin-verify");
    let bin_path = root.join("Threadfin_linux_amd64_compat");

    // 1. Construct a valid x86_64 ELF binary (EM_X86_64 = 62) and verify arch_sha256 matching
    let amd64_elf = create_mock_elf_payload_for_arch(4096, 62);
    let amd64_sha = hex::encode(Sha256::digest(&amd64_elf));
    let arm64_elf = create_mock_elf_payload_for_arch(4096, 183);
    let arm64_sha = hex::encode(Sha256::digest(&arm64_elf));

    let policy = ArtifactVerificationPolicy {
        min_size_bytes: 2048,
        max_size_bytes: 1024 * 1024,
        expected_sha256: None,
        arch_sha256: Some(ArchAssetMap {
            amd64: amd64_sha.clone(),
            arm64: arm64_sha.clone(),
            armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
        }),
        require_gzip_magic: false,
        require_elf_magic: true,
    };

    fs::write(&bin_path, &amd64_elf).unwrap();
    let verified_sha = verify_artifact_file_for_arch(&bin_path, &policy, Some("amd64")).unwrap();
    assert_eq!(verified_sha, amd64_sha);

    // 2. Digest tamper must fail closed with ArtifactVerification error
    let mut tampered = amd64_elf.clone();
    tampered[100] ^= 0xff;
    fs::write(&bin_path, &tampered).unwrap();
    let tamper_err = verify_artifact_file_for_arch(&bin_path, &policy, Some("amd64")).unwrap_err();
    assert!(matches!(
        tamper_err,
        PackageExecutorError::ArtifactVerification(_)
    ));
    assert!(tamper_err.to_string().contains("SHA-256 mismatch"));

    // 3. Wrong architecture ELF header (e.g. arm64 binary supplied on amd64 host even if hash matches) must fail closed
    fs::write(&bin_path, &arm64_elf).unwrap();
    let wrong_arch_policy = ArtifactVerificationPolicy {
        arch_sha256: Some(ArchAssetMap {
            amd64: arm64_sha.clone(), // pretend digest matched so ELF header check is tested directly
            arm64: arm64_sha,
            armhf: Some(THREADFIN_ARMHF_SHA256.to_string()),
        }),
        ..policy.clone()
    };
    let arch_err =
        verify_artifact_file_for_arch(&bin_path, &wrong_arch_policy, Some("amd64")).unwrap_err();
    assert!(matches!(
        arch_err,
        PackageExecutorError::ArtifactVerification(_)
    ));
    assert!(arch_err.to_string().contains("ELF architecture mismatch"));

    // 4. Unsupported architecture in ArchAssetMap::resolve must fail closed
    assert!(ArchAssetMap {
        amd64: "a".to_string(),
        arm64: "b".to_string(),
        armhf: Some("c".to_string()),
    }
    .resolve("riscv64")
    .is_none());

    // 5. Non-HTTPS URL in DownloadBinary must fail validation closed
    let insecure_http_step = DeclarativeStep::DownloadBinary {
        url_template:
            "http://github.com/Threadfin/Threadfin/releases/download/1.2.37/{{ARCH_ASSET}}"
                .to_string(),
        arch_map: ArchAssetMap {
            amd64: "Threadfin_linux_amd64_compat".to_string(),
            arm64: "Threadfin_linux_arm64".to_string(),
            armhf: Some("Threadfin_linux_arm_v7".to_string()),
        },
        dest_path: "/usr/local/bin/threadfin".to_string(),
        mode: 0o755,
        verification: policy,
        progress_pct: 50,
        description: "insecure http".to_string(),
    };
    let http_err = validate_step(&insecure_http_step).unwrap_err();
    assert!(matches!(
        http_err,
        PackageExecutorError::SecurityViolation(_)
    ));
    assert!(http_err.to_string().contains("https://"));

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_incomplete_removal_retains_completion_marker_without_purging_data() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    for package_id in ["fail2ban", "quassel"] {
        let root = create_isolated_test_dir(&format!("incomplete-remove-{}", package_id));
        let recipe = get_declarative_recipe(package_id).unwrap();
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let marker = root.join(format!("install/.{}.lock", package_id));
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, "engine=declarative_rust\n").unwrap();
        let state_dir = root.join(format!("var/lib/{}", package_id));
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("sentinel"), "preserved user data").unwrap();
        let mock = MockCommandRunner {
            fail_program: Some("apt-get".to_string()),
            ..Default::default()
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
        assert!(executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {}
            )
            .await
            .is_err());
        assert!(marker.exists());
        assert_eq!(
            fs::read_to_string(state_dir.join("sentinel")).unwrap(),
            "preserved user data"
        );
        assert!(mock
            .recorded_commands()
            .iter()
            .any(|command| command.program == "systemctl"
                && command.args.first().map(String::as_str) == Some("stop")));
        let retry = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
        assert!(
            !retry
                .execute_recipe(
                    &recipe,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {}
                )
                .await
                .unwrap()
                .lock_present
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn test_threadfin_bind_default_preserves_settings_and_rollback() {
    let root = create_isolated_test_dir("threadfin-bind-default");
    let settings_path = root.join("var/lib/threadfin/conf/settings.json");
    fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
    let original = br#"{"version":"0.5.0","bindIpAddress":"","custom":{"playlist":"keep"}}"#;
    fs::write(&settings_path, original).unwrap();
    let runner = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        runner.clone(),
    );
    let recipe = get_declarative_recipe("threadfin").unwrap();
    let step = DeclarativeStep::EnsureThreadfinConfig {
        progress_pct: 85,
        description: "bind default".to_string(),
    };
    let mut journal = RollbackJournal::new(Some(root.clone()));
    executor
        .run_single_step(
            &recipe,
            &step,
            &mut HashMap::new(),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let settings: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    assert_eq!(settings["bindIpAddress"], "127.0.0.1");
    assert_eq!(settings["custom"]["playlist"], "keep");
    journal.rollback(&runner).await;
    assert_eq!(fs::read(&settings_path).unwrap(), original);
    let explicit = br#"{"version":"0.5.0","bindIpAddress":"192.0.2.10","custom":"preserve"}"#;
    fs::write(&settings_path, explicit).unwrap();
    executor
        .run_single_step(
            &recipe,
            &step,
            &mut HashMap::new(),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(fs::read(&settings_path).unwrap(), explicit);
    fs::write(&settings_path, br#"{"bindIpAddress":42}"#).unwrap();
    assert!(executor
        .run_single_step(
            &recipe,
            &step,
            &mut HashMap::new(),
            &mut journal,
            &CancellationToken::new()
        )
        .await
        .is_err());
    fs::remove_file(&settings_path).unwrap();
    executor
        .run_single_step(
            &recipe,
            &step,
            &mut HashMap::new(),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let fresh: serde_json::Value =
        serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
    assert_eq!(fresh["version"], "0.5.0");
    assert_eq!(fresh["bindIpAddress"], "127.0.0.1");
    journal.commit();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[cfg(unix)]
async fn test_existing_certificate_normalizes_mode_and_rollback_preserves_original_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let root = create_isolated_test_dir("existing-certificate-mode");
    let certificate_path = root.join("var/lib/quassel/quasselCert.pem");
    fs::create_dir_all(certificate_path.parent().unwrap()).unwrap();
    fs::write(&certificate_path, "existing private certificate").unwrap();
    fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o644)).unwrap();
    let runner = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        runner.clone(),
    );
    let recipe = get_declarative_recipe("quassel").unwrap();
    let step = recipe
        .install_steps
        .iter()
        .find(|step| matches!(step, DeclarativeStep::GenerateSelfSignedTlsCert { .. }))
        .unwrap();
    let mut journal = RollbackJournal::new(Some(root.clone()));
    executor
        .run_single_step(
            &recipe,
            step,
            &mut HashMap::new(),
            &mut journal,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        fs::metadata(&certificate_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(&certificate_path).unwrap(),
        "existing private certificate"
    );
    assert!(!runner
        .recorded_commands()
        .iter()
        .any(|command| command.program == "openssl"));
    journal.rollback(&runner).await;
    assert_eq!(
        fs::metadata(&certificate_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::read_to_string(&certificate_path).unwrap(),
        "existing private certificate"
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn test_threadfin_install_remove_cancellation_and_rollback_in_isolated_root() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("threadfin-lifecycle");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 34409;

    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());

    // 1. Non-HTTPS remote download URL must fail closed in fetch_artifact_to_temp
    let mut journal = RollbackJournal::new(Some(root.clone()));
    let cancel = CancellationToken::new();
    let http_fail = executor
            .fetch_artifact_to_temp(
                "threadfin",
                "http://github.com/Threadfin/Threadfin/releases/download/1.2.37/Threadfin_linux_amd64_compat",
                "Threadfin_linux_amd64_compat",
                &mut journal,
                &cancel,
            )
            .await
            .unwrap_err();
    assert!(matches!(
        http_fail,
        PackageExecutorError::SecurityViolation(_)
    ));

    // 2. Pre-cancelled token must abort fetch_artifact_to_temp before any network request
    let pre_cancelled = CancellationToken::new();
    pre_cancelled.cancel();
    let cancel_fetch_err = executor
            .fetch_artifact_to_temp(
                "threadfin",
                "https://github.com/Threadfin/Threadfin/releases/download/1.2.37/Threadfin_linux_amd64_compat",
                "Threadfin_linux_amd64_compat",
                &mut journal,
                &pre_cancelled,
            )
            .await
            .unwrap_err();
    assert!(matches!(
        cancel_fetch_err,
        PackageExecutorError::Cancelled(_)
    ));

    // 3. Stage a valid mock ELF binary in `artifact_cache_dir` and run the real DownloadBinary step!
    let cache_dir = root.join("artifact-cache");
    fs::create_dir_all(&cache_dir).unwrap();
    env_cfg.artifact_cache_dir = Some(cache_dir.clone());

    let elf_payload = create_mock_elf_payload_for_arch(1_100_000, 62); // > 1 MiB min_size_bytes
    let elf_sha = hex::encode(Sha256::digest(&elf_payload));
    fs::write(cache_dir.join("Threadfin_linux_amd64_compat"), &elf_payload).unwrap();

    let mut recipe = get_declarative_recipe("threadfin").unwrap();
    for step in recipe
        .install_steps
        .iter_mut()
        .chain(recipe.update_steps.iter_mut())
    {
        if let DeclarativeStep::DownloadBinary { verification, .. } = step {
            verification.arch_sha256 = Some(ArchAssetMap {
                amd64: elf_sha.clone(),
                arm64: elf_sha.clone(),
                armhf: Some(elf_sha.clone()),
            });
        }
    }

    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
    let mut events = Vec::new();
    let outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |ev| events.push(ev),
        )
        .await
        .expect("threadfin install should succeed");

    assert!(outcome.lock_present);
    assert_eq!(outcome.resolved_version.as_deref(), Some("1.2.37"));
    assert!(root.join("install/.threadfin.lock").is_file());
    assert!(root.join("usr/local/bin/threadfin").is_file());
    assert!(root.join("var/lib/threadfin/conf").is_dir());
    assert!(root.join("var/lib/threadfin/temp").is_dir());

    let unit_content =
        fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
    assert!(unit_content.contains("User=threadfin"));
    assert!(unit_content.contains("Group=threadfin"));
    assert!(unit_content.contains("Environment=HOME=/var/lib/threadfin"));
    assert!(unit_content.contains(
            "ExecStart=/usr/local/bin/threadfin -port=34409 -bind=127.0.0.1 -config=/var/lib/threadfin/conf"
        ));

    let sandbox_content = fs::read_to_string(
        root.join("etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf"),
    )
    .unwrap();
    assert!(sandbox_content.contains("ProtectSystem=strict"));
    assert!(sandbox_content.contains("/var/lib/threadfin"));

    let version_marker = fs::read_to_string(root.join("var/lib/threadfin/.af-version")).unwrap();
    assert_eq!(version_marker.trim(), "1.2.37");

    let settings_path = root.join("var/lib/threadfin/conf/settings.json");
    let settings_before_update = fs::read(&settings_path).unwrap();
    let commands_before_update = mock.recorded_commands().len();
    env_cfg.app_port = 34410;
    let update_executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
    let update_outcome = update_executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin update should restart the daemon after rewriting its unit");
    assert!(update_outcome.lock_present);
    assert_eq!(fs::read(&settings_path).unwrap(), settings_before_update);
    let updated_unit =
        fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
    assert!(updated_unit.contains("-port=34410"));
    let recorded_commands = mock.recorded_commands();
    let update_systemctl_commands: Vec<_> = recorded_commands[commands_before_update..]
        .iter()
        .filter(|command| command.program == "systemctl")
        .map(|command| command.args.join(" "))
        .collect();
    assert!(update_systemctl_commands
        .iter()
        .any(|command| command == "daemon-reload"));
    assert!(update_systemctl_commands
        .iter()
        .any(|command| command == "enable --now -- threadfin.service"));
    assert!(update_systemctl_commands
        .iter()
        .any(|command| command == "restart -- threadfin.service"));
    assert_eq!(
        update_systemctl_commands.last().map(String::as_str),
        Some("is-active --quiet -- threadfin.service")
    );

    // Verify injected failure rollback on a fresh install root cleans up unit, binary, and lock
    let fail_root = create_isolated_test_dir("threadfin-rollback");
    let fail_cache_dir = fail_root.join("artifact-cache");
    fs::create_dir_all(&fail_cache_dir).unwrap();
    fs::write(
        fail_cache_dir.join("Threadfin_linux_amd64_compat"),
        &elf_payload,
    )
    .unwrap();
    let mut fail_env = PackageExecutionEnv::isolated(&fail_root);
    fail_env.artifact_cache_dir = Some(fail_cache_dir);
    let fail_mock = MockCommandRunner {
        fail_program: Some("systemctl".to_string()),
        ..Default::default()
    };
    let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
    let fail_res = fail_exec
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await;
    assert!(matches!(
        fail_res,
        Err(PackageExecutorError::StepFailed { .. })
    ));
    assert!(!fail_root.join("install/.threadfin.lock").exists());
    assert!(!fail_root
        .join("etc/systemd/system/threadfin.service")
        .exists());
    assert!(!fail_root.join("usr/local/bin/threadfin").exists());
    let _ = fs::remove_dir_all(&fail_root);

    // Verify Threadfin removal preserves /var/lib/threadfin when delete_data=false and purges when delete_data=true
    let user_conf = root.join("var/lib/threadfin/conf/settings.json");
    fs::write(&user_conf, b"{\"port\":34409}").unwrap();

    let rem_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin remove (preserve data) should succeed");
    assert!(!rem_outcome.lock_present);
    assert!(!root.join("install/.threadfin.lock").exists());
    assert!(!root.join("usr/local/bin/threadfin").exists());
    assert!(
        user_conf.is_file(),
        "threadfin user config must be preserved when delete_data=false"
    );

    let mut purge_env = env_cfg.clone();
    purge_env.delete_data = true;
    let purge_exec = DeclarativePackageExecutor::with_runner(purge_env, mock.clone());
    purge_exec
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin remove (purge data) should succeed");
    assert!(!root.join("var/lib/threadfin").exists());

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_sol_02_lock_finalization_failure_rolls_back_mutated_config_and_preserves_old_receipt()
{
    use std::os::unix::fs::PermissionsExt;
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("sol-02-lock-finalization");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    let netdata_conf = root.join("etc/netdata/netdata.conf");
    fs::create_dir_all(netdata_conf.parent().unwrap()).unwrap();
    fs::write(&netdata_conf, "OLD OPERATOR CONFIG\n").unwrap();

    let install_dir = root.join("install");
    fs::create_dir_all(&install_dir).unwrap();
    let lock_file = install_dir.join(".netdata.lock");
    fs::write(&lock_file, "OLD RECEIPT\n").unwrap();

    // Pre-create .af-package-executor.flock while `install` is still writable so flock
    // acquisition can open the existing inode, then set `install` to 0o555 so creating
    // `.netdata.lock.bak-af.*` or `.netdata.lock.af-tmp-*` fails with EACCES.
    {
        let _guard = CrossProcessLockGuard::try_acquire(&env_cfg, "netdata").unwrap();
    }
    fs::set_permissions(&install_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let recipe = DeclarativePackageRecipe {
        package_id: "netdata".to_string(),
        label: "Netdata".to_string(),
        default_port: 19999,
        service_name: "netdata".to_string(),
        lock_file: "/install/.netdata.lock".to_string(),
        apply_systemd_sandbox: false,
        install_steps: Vec::new(),
        update_steps: vec![DeclarativeStep::WriteTemplateFile {
            path: "/etc/netdata/netdata.conf".to_string(),
            content_template: "NEW CONFIG\n".to_string(),
            mode: 0o644,
            overwrite: true,
            owner: None,
            group: None,
            progress_pct: 50,
            description: "Updating netdata.conf...".to_string(),
        }],
        remove_steps: Vec::new(),
    };

    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    let res = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await;

    // Restore 0o755 on `install` before asserting so test cleanup always succeeds
    fs::set_permissions(&install_dir, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        res.is_err(),
        "lock finalization failure on read-only /install must return Err"
    );
    assert_eq!(
        fs::read_to_string(&netdata_conf).unwrap(),
        "OLD OPERATOR CONFIG\n",
        "mutated config must be rolled back when lock receipt persistence fails"
    );
    assert_eq!(
        fs::read_to_string(&lock_file).unwrap(),
        "OLD RECEIPT\n",
        "existing lock receipt must remain intact when lock finalization fails"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_sol_03_inactive_systemd_service_after_start_or_restart_fails_and_rolls_back() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    #[derive(Clone, Default)]
    struct InactiveServiceRunner;

    impl CommandRunner for InactiveServiceRunner {
        fn run_command<'a>(
            &'a self,
            program: &'a str,
            args: &'a [String],
            _env_vars: &'a [(String, String)],
            cancel: &'a CancellationToken,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                if cancel.is_cancelled() {
                    return Err(PackageExecutorError::Cancelled(program.to_string()));
                }
                if program == "systemctl" && args.first().map(String::as_str) == Some("is-active") {
                    return Ok(CommandOutput {
                        exit_code: 3,
                        stdout: "inactive\n".to_string(),
                        stderr: String::new(),
                    });
                }
                if program == "dpkg-query" {
                    let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                    let stdout = if wants_status {
                        "installed 1.0.2-1\n".to_string()
                    } else {
                        "1.0.2-1\n".to_string()
                    };
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout,
                        stderr: String::new(),
                    });
                }
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }
    }

    for pkg_id in ["netdata", "fail2ban"] {
        let root = create_isolated_test_dir(&format!("sol-03-inactive-{pkg_id}"));
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let recipe = get_declarative_recipe(pkg_id).unwrap();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, InactiveServiceRunner);

        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_err();

        match &err {
            PackageExecutorError::StepFailed { step, reason } => {
                assert!(
                    step.starts_with("systemctl is-active"),
                    "unexpected step in StepFailed for {pkg_id}: {step}"
                );
                assert!(
                    reason.contains("failed post-activation readiness check"),
                    "unexpected reason for {pkg_id}: {reason}"
                );
            }
            other => panic!("expected StepFailed for {pkg_id}, got: {other:?}"),
        }

        let lock_rel = recipe.lock_file.trim_start_matches('/');
        assert!(
                !root.join(lock_rel).exists(),
                "completion receipt must not be written when service is inactive after start/restart ({pkg_id})"
            );
        assert!(
                !root.join(format!("etc/{pkg_id}/.af-version")).exists(),
                "staged .af-version file must be rolled back when service fails post-activation check ({pkg_id})"
            );

        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_sol_04_fail2ban_update_preserves_operator_jail_local_policy_byte_for_byte() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("sol-04-fail2ban-policy");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    let operator_jail = "[DEFAULT]\nmaxretry = 20\n[sshd]\nenabled = false\nport = 2222\n";
    let jail_path = root.join("etc/fail2ban/jail.local");
    fs::create_dir_all(jail_path.parent().unwrap()).unwrap();
    fs::write(&jail_path, operator_jail).unwrap();

    let sshd_cfg = root.join("etc/ssh/sshd_config");
    fs::create_dir_all(sshd_cfg.parent().unwrap()).unwrap();
    fs::write(&sshd_cfg, "Port 2200\n").unwrap();

    let recipe = get_declarative_recipe("fail2ban").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());

    for action in [PackageAction::Update, PackageAction::Install] {
        let outcome = executor
            .execute_recipe(&recipe, action, CancellationToken::new(), |_| {})
            .await
            .unwrap();
        assert!(outcome.lock_present);
        let actual = fs::read_to_string(&jail_path).unwrap();
        assert_eq!(
            actual, operator_jail,
            "fail2ban {:?} must preserve operator /etc/fail2ban/jail.local byte-for-byte",
            action
        );
    }

    let _ = fs::remove_dir_all(&root);
}
