use super::*;

#[test]
fn test_purge_is_explicit_per_request_and_never_inherited() {
    let request = |action: &str, delete_data: bool| PackageRunnerRequest {
        action: action.to_string(),
        package_id: "sonarr".to_string(),
        script_name: "removepackage-sonarr".to_string(),
        lifecycle_job_id: String::new(),
        app_port: 0,
        delete_data,
        ..Default::default()
    };
    assert!(!package_request_deletes_data(&request("remove", false)));
    assert!(package_request_deletes_data(&request("remove", true)));
    assert!(!package_request_deletes_data(&request("install", true)));
    assert!(!package_request_deletes_data(&request("update", true)));

    // Ordinary removal explicitly overrides any DELETE_DATA the runner
    // daemon itself may carry in its environment.
    let env = legacy_env(&request("remove", false));
    assert_eq!(env.get("DELETE_DATA"), Some(&Some("false".to_string())));
    assert_eq!(
        env.get("AF_PACKAGE_ACTION"),
        Some(&Some("remove".to_string()))
    );
    assert_eq!(
        env.get("AF_KEEP_EXISTING_SECRETS"),
        Some(&Some("0".to_string()))
    );
    assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
    assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));
    assert_eq!(env.get("AF_APP_PORT"), Some(&None));
    let env = legacy_env(&request("remove", true));
    assert_eq!(env.get("DELETE_DATA"), Some(&Some("true".to_string())));
    let mut update = request("update", true);
    update.app_port = 18989;
    let env = legacy_env(&update);
    assert_eq!(env.get("DELETE_DATA"), Some(&Some("false".to_string())));
    assert_eq!(
        env.get("AF_KEEP_EXISTING_SECRETS"),
        Some(&Some("1".to_string()))
    );
    assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
    assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));
    assert_eq!(env.get("AF_APP_PORT"), Some(&Some("18989".to_string())));
    assert_eq!(
        env.get("AETHERFLOW_APP_PORT"),
        Some(&Some("18989".to_string()))
    );

    let reinstall = request("reinstall", false);
    let env = legacy_env(&reinstall);
    assert_eq!(
        env.get("AF_KEEP_EXISTING_SECRETS"),
        Some(&Some("1".to_string()))
    );

    let install = request("install", false);
    let env = legacy_env(&install);
    assert_eq!(
        env.get("AF_KEEP_EXISTING_SECRETS"),
        Some(&Some("0".to_string()))
    );
    assert_eq!(env.get("AF_CONFIG_PASS"), Some(&None));
    assert_eq!(env.get("AF_CONFIG_USER"), Some(&None));

    // Wire compatibility: older clients omit the field and get retention.
    let legacy: PackageRunnerRequest = serde_json::from_str(
        r#"{"action":"remove","package_id":"sonarr","script_name":"removepackage-sonarr"}"#,
    )
    .unwrap();
    assert!(!legacy.delete_data);
    assert!(!serde_json::to_string(&request("remove", false))
        .unwrap()
        .contains("delete_data"));
}

#[test]
fn test_target_version_env_is_explicit_and_cleared_when_absent() {
    for (package_id, script_name, target) in [
        ("cloudplow", "installpackage-cloudplow", " 1.3.2 "),
        ("overseerr", "installpackage-overseerr", " v1.33.2 "),
    ] {
        let mut req = PackageRunnerRequest {
            action: "update".to_string(),
            package_id: package_id.to_string(),
            script_name: script_name.to_string(),
            expected_target_version: Some(target.to_string()),
            ..Default::default()
        };
        let env = legacy_env(&req);
        assert_eq!(
            env.get("AF_TARGET_VERSION"),
            Some(&Some(target.trim().to_string())),
            "{package_id} update must pass trimmed AF_TARGET_VERSION"
        );

        req.action = "install".to_string();
        req.expected_target_version = None;
        let env_none = legacy_env(&req);
        assert_eq!(
            env_none.get("AF_TARGET_VERSION"),
            Some(&None),
            "{package_id} unpinned install must strip ambient AF_TARGET_VERSION"
        );

        req.action = "reinstall".to_string();
        req.expected_target_version = Some("   ".to_string());
        let env_blank = legacy_env(&req);
        assert_eq!(
            env_blank.get("AF_TARGET_VERSION"),
            Some(&None),
            "{package_id} blank target must strip ambient AF_TARGET_VERSION"
        );
    }
}

#[test]
fn test_registry_contains_catalog_packages_and_defers_incomplete_recipes() {
    let _env_guard = crate::ENV_TEST_MUTEX.blocking_lock();
    for id in list_declarative_recipe_ids() {
        assert!(
            crate::get_runner_package_definition(&id).is_some(),
            "{}",
            id
        );
        let recipe = get_declarative_recipe(&id).unwrap();
        assert!(
            recipe.install_steps.iter().any(|step| matches!(
                step,
                DeclarativeStep::CaptureDpkgVersion { .. }
                    | DeclarativeStep::ResolveGitHubReleaseTag { .. }
                    | DeclarativeStep::InstallRcloneBinary { .. }
            )) || recipe.install_steps.iter().any(|step| matches!(
                step,
                DeclarativeStep::WriteTemplateFile { path, content_template, .. }
                    if path == "/var/lib/threadfin/.af-version"
                        && (content_template.trim() == THREADFIN_PINNED_VERSION
                            || content_template.trim() == "{{VERSION}}")
            )),
            "{} must capture an installed version",
            id
        );
    }
    for id in [
        "scrutiny",
        "clamav",
        "mosquitto",
        "prometheus",
        "syncthing",
        "novnc",
    ] {
        assert!(
            get_declarative_recipe(id).is_none(),
            "{id} must defer to legacy Bash instead of exposing a drifted declarative recipe"
        );
        assert_eq!(
            select_package_engine_with_flags(id, true, false),
            PackageEngineMode::LegacyBashFallback
        );
    }
}

#[test]
fn test_atomic_writes_and_journal_backups_are_exclusive() {
    let root = create_isolated_test_dir("exclusive-files");
    let target = root.join("settings");
    write_file_atomic_with_mode(&target, b"original", 0o600).unwrap();
    assert!(open_new_private_file(&target, 0o600).is_err());
    let planted_backup = root.join("settings.bak-af");
    let unrelated = root.join("unrelated");
    fs::write(&unrelated, b"unrelated").unwrap();
    fs::hard_link(&unrelated, &planted_backup).unwrap();
    let mut journal = RollbackJournal::new(Some(root.clone()));
    journal.stage_file_mutation(&target).unwrap();
    assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
    match &journal.entries[0] {
        RollbackEntry::RestorableFile { backup, .. } => {
            assert_ne!(backup, &planted_backup);
            assert_eq!(fs::read(backup).unwrap(), b"original");
        }
        other => panic!("unexpected rollback entry: {:?}", other),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(journal
        .stage_file_mutation(&root.with_extension("outside"))
        .is_err());
    journal.commit();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn test_isolated_root_checks_ancestors_above_root() {
    let root = create_isolated_test_dir("root-ancestors");
    let actual = root.join("actual");
    fs::create_dir_all(actual.join("nested")).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&actual, &alias).unwrap();
    let bound = alias.join("nested");
    assert!(matches!(
        validate_filesystem_path(&bound.join("settings"), Some(&bound)),
        Err(PackageExecutorError::SecurityViolation(_))
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_builtin_recipes_validate_cleanly() {
    // Accessing BUILTIN_DECLARATIVE_RECIPES must never panic and every registered recipe
    // must pass strict security validation and have full install, update, and remove steps.
    let ids = list_declarative_recipe_ids();
    let expected_ids = vec![
        "fail2ban".to_string(),
        "mergerfs".to_string(),
        "netdata".to_string(),
        "quassel".to_string(),
        "rclone".to_string(),
        "threadfin".to_string(),
        "x2go".to_string(),
        "xrdp".to_string(),
        "znc".to_string(),
    ];
    assert_eq!(ids, expected_ids);
    for deferred in ["prometheus", "syncthing", "novnc"] {
        assert!(
            get_declarative_recipe(deferred).is_none(),
            "{deferred} must not be registered in BUILTIN_DECLARATIVE_RECIPES"
        );
    }

    for id in &ids {
        let recipe = get_declarative_recipe(id).expect("registered recipe must resolve");
        recipe
            .validate()
            .expect("recipe must pass strict security validation");
        assert!(
            !recipe.install_steps.is_empty(),
            "recipe {} must have install_steps",
            id
        );
        assert!(
            !recipe.steps_for_action(PackageAction::Update).is_empty(),
            "recipe {} must have update steps",
            id
        );
        assert!(
            !recipe.remove_steps.is_empty(),
            "recipe {} must have remove_steps",
            id
        );
    }

    // Preserve security validation coverage for unsafe shared system root chown patterns:
    let bad_threadfin_dirs = DeclarativeStep::EnsureDirectories {
        paths: vec![
            "/var/lib/threadfin".to_string(),
            "/usr/local/bin".to_string(),
        ],
        mode: 0o755,
        owner: Some("threadfin".to_string()),
        group: Some("threadfin".to_string()),
        progress_pct: 30,
        description: "unsafe shared root chown".to_string(),
    };
    assert!(validate_step(&bad_threadfin_dirs).is_err());

    let bad_quassel_dirs = DeclarativeStep::EnsureDirectories {
        paths: vec!["/var/lib/quassel".to_string(), "/etc/default".to_string()],
        mode: 0o750,
        owner: Some("quasselcore".to_string()),
        group: Some("quasselcore".to_string()),
        progress_pct: 30,
        description: "unsafe /etc/default directory mutation".to_string(),
    };
    assert!(validate_step(&bad_quassel_dirs).is_err());

    let bad_tls_subj = DeclarativeStep::GenerateSelfSignedTlsCert {
        cert_path: "/var/lib/quassel/quasselCert.pem".to_string(),
        key_out_path: None,
        days: 3650,
        subject: "/CN=Bad;rm -rf /".to_string(),
        mode: 0o600,
        owner: Some("quasselcore".to_string()),
        group: Some("quasselcore".to_string()),
        overwrite: false,
        progress_pct: 50,
        description: "unsafe subject".to_string(),
    };
    assert!(validate_step(&bad_tls_subj).is_err());
}

#[test]
fn test_engine_selection_and_legacy_bash_fallback() {
    // Default gate is OFF when AETHERFLOW_ENABLE_RUST_PACKAGES is unset
    assert_eq!(
        select_package_engine("fail2ban"),
        PackageEngineMode::LegacyBashFallback
    );
    assert_eq!(
        select_package_engine("quassel"),
        PackageEngineMode::LegacyBashFallback
    );
    assert_eq!(
        select_package_engine("threadfin"),
        PackageEngineMode::LegacyBashFallback
    );
    assert_eq!(
        select_package_engine("plex"),
        PackageEngineMode::LegacyBashFallback
    );

    // Explicit flag evaluation:
    assert_eq!(
        select_package_engine_with_flags("fail2ban", false, false),
        PackageEngineMode::LegacyBashFallback
    );
    assert_eq!(
        select_package_engine_with_flags("fail2ban", true, false),
        PackageEngineMode::DeclarativeRust
    );
    // FORCE_BASH overrides ENABLE_RUST
    assert_eq!(
        select_package_engine_with_flags("fail2ban", true, true),
        PackageEngineMode::LegacyBashFallback
    );
    // Migrated packages execute via DeclarativeRust when enabled
    assert_eq!(
        select_package_engine_with_flags("quassel", true, false),
        PackageEngineMode::DeclarativeRust
    );
    assert_eq!(
        select_package_engine_with_flags("threadfin", true, false),
        PackageEngineMode::DeclarativeRust
    );
    // Unmigrated and deferred packages remain on LegacyBashFallback even when Rust packages are enabled
    for deferred in ["sonarr", "prometheus", "syncthing", "novnc"] {
        assert_eq!(
            select_package_engine_with_flags(deferred, true, false),
            PackageEngineMode::LegacyBashFallback
        );
    }
}

#[tokio::test]
async fn test_quassel_install_update_remove_and_rollback_in_isolated_root() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("quassel-lifecycle");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    let recipe = get_declarative_recipe("quassel").expect("quassel recipe must be registered");

    // 1. Install
    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
    let install_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel install must succeed");
    assert!(install_outcome.lock_present);
    assert!(root.join("install/.quassel.lock").is_file());
    assert!(root.join("var/lib/quassel/quasselCert.pem").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join("var/lib/quassel/quasselCert.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(
        fs::read_to_string(root.join("var/lib/quassel/.af-version"))
            .unwrap()
            .trim(),
        "1:0.14.2-1ubuntu2"
    );
    let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
    assert!(default_cfg.contains("PORT=\"4242\""));
    assert!(root
        .join("etc/systemd/system/quasselcore.service")
        .is_file());

    let cmds = mock.recorded_commands();
    assert!(cmds
        .iter()
        .any(|c| c.program == "openssl" && c.args.contains(&"-x509".to_string())));
    assert!(cmds
        .iter()
        .any(|c| c.program == "dpkg-query" && c.args.contains(&"quassel-core".to_string())));

    // 2. Update
    let update_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel update must succeed");
    assert!(update_outcome.lock_present);

    // 3. Remove (with delete_data = true)
    env_cfg.delete_data = true;
    let executor_rm =
        DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    let remove_outcome = executor_rm
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("quassel remove must succeed");
    assert!(!remove_outcome.lock_present);
    assert!(!root.join("install/.quassel.lock").exists());
    assert!(!root.join("etc/default/quasselcore").exists());
    assert!(!root.join("var/lib/quassel").exists());

    // 4. Failure rollback on fresh isolated root
    let fail_root = create_isolated_test_dir("quassel-rollback");
    let fail_env = PackageExecutionEnv::isolated(&fail_root);
    // Fail on systemctl enable --now after TLS cert, .af-version, and /etc/default/quasselcore were written
    let fail_mock = MockCommandRunner {
        fail_on_call: Some(9),
        ..Default::default()
    };
    let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
    let err = fail_exec
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("systemctl"));
    assert!(!fail_root.join("install/.quassel.lock").exists());
    assert!(!fail_root.join("var/lib/quassel/quasselCert.pem").exists());
    assert!(!fail_root.join("var/lib/quassel/.af-version").exists());
    assert!(!fail_root.join("etc/default/quasselcore").exists());
    assert!(!fail_root
        .join("etc/systemd/system/quasselcore.service")
        .exists());

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&fail_root);
}

#[tokio::test]
async fn test_threadfin_install_update_remove_and_rollback_in_isolated_root() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("threadfin-lifecycle");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    let elf_bytes = create_mock_elf_payload_for_arch(4096, 62);
    let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();

    let mut recipe =
        get_declarative_recipe("threadfin").expect("threadfin recipe must be registered");
    for step in recipe
        .install_steps
        .iter_mut()
        .chain(recipe.update_steps.iter_mut())
    {
        if let DeclarativeStep::DownloadBinary { verification, .. } = step {
            verification.expected_sha256 = Some(hex::encode(Sha256::digest(&elf_bytes)));
        }
    }

    // 1. Install
    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock);
    let install_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin install must succeed");
    assert!(install_outcome.lock_present);
    assert!(root.join("install/.threadfin.lock").is_file());
    assert!(root.join("usr/local/bin/threadfin").is_file());
    assert_eq!(
        fs::read_to_string(root.join("var/lib/threadfin/.af-version"))
            .unwrap()
            .trim(),
        THREADFIN_PINNED_VERSION
    );
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, mode) in [
            ("var/lib/threadfin", 0o755),
            ("var/lib/threadfin/conf", 0o750),
            ("var/lib/threadfin/.af-version", 0o644),
        ] {
            let permissions = fs::metadata(root.join(path)).unwrap().permissions();
            assert_eq!(permissions.mode() & 0o777, mode, "{path}");
        }
    }
    let unit = fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
    assert!(unit.contains("-port=34400"));

    // 2. Update
    let update_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin update must succeed");
    assert!(update_outcome.lock_present);

    // 3. Remove (with delete_data = true)
    env_cfg.delete_data = true;
    let executor_rm =
        DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    let remove_outcome = executor_rm
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin remove must succeed");
    assert!(!remove_outcome.lock_present);
    assert!(!root.join("install/.threadfin.lock").exists());
    assert!(!root.join("usr/local/bin/threadfin").exists());
    assert!(!root.join("var/lib/threadfin").exists());

    // 4. Failure rollback on fresh isolated root
    let fail_root = create_isolated_test_dir("threadfin-rollback");
    let fail_env = PackageExecutionEnv::isolated(&fail_root);
    let fail_cache = fail_env.artifact_cache_dir.clone().unwrap();
    fs::create_dir_all(&fail_cache).unwrap();
    fs::write(fail_cache.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();
    // Fail on systemctl enable --now after binary, .af-version, and systemd unit were written
    let fail_mock = MockCommandRunner {
        fail_on_call: Some(5),
        ..Default::default()
    };
    let fail_exec = DeclarativePackageExecutor::with_runner(fail_env, fail_mock);
    let err = fail_exec
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("systemctl"));
    assert!(!fail_root.join("install/.threadfin.lock").exists());
    assert!(!fail_root.join("usr/local/bin/threadfin").exists());
    assert!(!fail_root.join("var/lib/threadfin/.af-version").exists());
    assert!(!fail_root
        .join("etc/systemd/system/threadfin.service")
        .exists());

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&fail_root);
}

#[test]
fn test_security_boundary_rejects_traversal_and_forbidden_paths() {
    assert!(validate_managed_path("/etc/fail2ban/jail.local").is_ok());
    assert!(validate_managed_path("/var/lib/threadfin/conf").is_ok());
    assert!(validate_managed_path("/install/.fail2ban.lock").is_ok());
    assert!(validate_managed_path("/var/lib/quassel/quasselCert.pem").is_ok());
    assert!(validate_managed_path("/etc/default/quasselcore").is_ok());

    // Reject relative paths, parent traversal, and root/critical/shared files
    assert!(validate_managed_path("etc/fail2ban").is_err());
    assert!(validate_managed_path("/etc/fail2ban/../../etc/shadow").is_err());
    assert!(validate_managed_path("/etc/passwd").is_err());
    assert!(validate_managed_path("/etc/shadow").is_err());
    assert!(validate_managed_path("/etc").is_err());
    assert!(validate_managed_path("/etc/default").is_err());
    assert!(validate_managed_path("/usr/local/bin").is_err());
    assert!(validate_managed_path("/").is_err());
    assert!(validate_managed_path("/home/user/.bashrc").is_err());

    // Reject recursive chown on shared system roots
    assert!(validate_chown_target_path("/usr/local/bin").is_err());
    assert!(validate_chown_target_path("/etc/default").is_err());
    assert!(validate_chown_target_path("/etc").is_err());
    assert!(validate_chown_target_path("/var/lib").is_err());
    assert!(validate_chown_target_path("/var/lib/fail2ban").is_ok());

    // Reject shell injection in APT package names
    let bad_step = DeclarativeStep::AptInstall {
        packages: vec!["fail2ban; rm -rf /".to_string()],
        progress_pct: 20,
        description: "bad".to_string(),
    };
    assert!(validate_step(&bad_step).is_err());

    // Reject root user purge
    let bad_user = DeclarativeStep::PurgeSystemUser {
        username: "root".to_string(),
        home_dir: None,
        progress_pct: 50,
        description: "bad".to_string(),
    };
    assert!(validate_step(&bad_user).is_err());
}

#[test]
fn test_artifact_verification_size_magic_and_sha256() {
    let root = create_isolated_test_dir("artifact-verify");
    let small_file = root.join("small.bin");
    fs::write(&small_file, b"404: Not Found").unwrap();

    let default_policy = ArtifactVerificationPolicy::default();
    let err = verify_artifact_file(&small_file, &default_policy).unwrap_err();
    assert!(err.to_string().contains("too small"));

    // Valid ELF payload with matching SHA-256
    let elf_path = root.join("threadfin.bin");
    let elf_bytes = create_mock_elf_payload(4096);
    let expected_hash = hex::encode(Sha256::digest(&elf_bytes));
    fs::write(&elf_path, &elf_bytes).unwrap();

    let strict_policy = ArtifactVerificationPolicy {
        min_size_bytes: 1024,
        max_size_bytes: 1024 * 1024,
        expected_sha256: Some(expected_hash.clone()),
        arch_sha256: None,
        require_gzip_magic: false,
        require_elf_magic: true,
    };
    let actual_hash = verify_artifact_file(&elf_path, &strict_policy).unwrap();
    assert_eq!(actual_hash, expected_hash);

    // Wrong SHA-256 must fail
    let wrong_sha_policy = ArtifactVerificationPolicy {
        expected_sha256: Some(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        ..strict_policy
    };
    assert!(verify_artifact_file(&elf_path, &wrong_sha_policy).is_err());

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_fail2ban_install_and_remove_parity_in_isolated_root() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("fail2ban-lifecycle");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    // Seed custom SSH port in isolated /etc/ssh/sshd_config
    let sshd_cfg = root.join("etc/ssh/sshd_config");
    fs::create_dir_all(sshd_cfg.parent().unwrap()).unwrap();
    fs::write(
        &sshd_cfg,
        "# OpenSSH config\nPort 2222\nPermitRootLogin no\n",
    )
    .unwrap();

    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
    let recipe = get_declarative_recipe("fail2ban").unwrap();

    let mut events = Vec::new();
    let outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |ev| events.push(ev),
        )
        .await
        .expect("fail2ban install should succeed");

    assert!(outcome.lock_present);
    assert!(root.join("install/.fail2ban.lock").is_file());

    // Verify jail.local content matches installpackage-fail2ban parity including custom SSH port
    let jail_local = fs::read_to_string(root.join("etc/fail2ban/jail.local")).unwrap();
    assert!(jail_local.contains("backend  = systemd"));
    assert!(jail_local.contains("port    = 2222,ssh"));

    // Verify structured progress monotonically reaches 100%
    assert!(!events.is_empty());
    assert_eq!(events.last().unwrap().progress_pct, 100);
    assert_eq!(events.last().unwrap().phase, ExecutionPhase::Complete);

    // Verify SandboxApply was emitted BEFORE the systemctl activation steps
    let sandbox_pos = events
        .iter()
        .position(|e| e.phase == ExecutionPhase::SandboxApply)
        .expect("SandboxApply phase must be emitted");
    let last_step_pos = events
        .iter()
        .rposition(|e| e.phase == ExecutionPhase::ExecuteStep)
        .expect("ExecuteStep phase must be emitted");
    assert!(
        sandbox_pos < last_step_pos,
        "systemd sandbox drop-in must be applied before systemctl activation steps complete"
    );

    // Verify recorded commands used non-shell argv execution
    let cmds = mock.recorded_commands();
    assert!(cmds
        .iter()
        .any(|c| c.program == "apt-get" && c.args.contains(&"fail2ban".to_string())));
    assert!(cmds
        .iter()
        .any(|c| c.program == "systemctl" && c.args.contains(&"fail2ban.service".to_string())));

    // Now execute Remove and verify cleanup + lock removal
    fs::create_dir_all(root.join("run/fail2ban")).unwrap();
    #[cfg(unix)]
    {
        fs::create_dir_all(root.join("var")).unwrap();
        std::os::unix::fs::symlink("../run", root.join("var/run")).unwrap();
    }
    let remove_outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("fail2ban remove should succeed");

    assert!(!remove_outcome.lock_present);
    assert!(!root.join("install/.fail2ban.lock").exists());
    assert!(root.join("etc/fail2ban/jail.local").is_file());
    assert!(!root.join("run/fail2ban").exists());
    assert_eq!(
        outcome.resolved_version.as_deref(),
        Some("1:0.14.2-1ubuntu2")
    );
    assert!(mock
        .recorded_commands()
        .iter()
        .any(|command| command.program == "apt-get"
            && command.args.iter().any(|arg| arg == "remove")));

    let mut purge_env = env_cfg;
    purge_env.delete_data = true;
    let purge_executor = DeclarativePackageExecutor::with_runner(purge_env, mock.clone());
    purge_executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("explicit purge should remove application data");
    assert!(!root.join("etc/fail2ban").exists());
    assert!(mock.recorded_commands().iter().any(
        |command| command.program == "apt-get" && command.args.iter().any(|arg| arg == "purge")
    ));

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_verified_elf_binary_recipe_and_pre_service_sandbox() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("elf-binary-install");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 34400;

    // Stage mock ELF binary in isolated artifact cache with pinned SHA-256
    let elf_bytes = create_mock_elf_payload(4096);
    let expected_sha256 = hex::encode(Sha256::digest(&elf_bytes));
    let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();

    let recipe = DeclarativePackageRecipe {
            package_id: "threadfin".to_string(),
            label: "Threadfin".to_string(),
            lock_file: "/install/.threadfin.lock".to_string(),
            service_name: "threadfin".to_string(),
            default_port: 34400,
            apply_systemd_sandbox: true,
            install_steps: vec![
                DeclarativeStep::EnsureSystemUser {
                    username: "threadfin".to_string(),
                    home_dir: "/var/lib/threadfin".to_string(),
                    create_home: true,
                    progress_pct: 15,
                    description: "Ensuring threadfin user...".to_string(),
                },
                DeclarativeStep::EnsureDirectories {
                    paths: vec![
                        "/var/lib/threadfin".to_string(),
                        "/var/lib/threadfin/conf".to_string(),
                    ],
                    mode: 0o755,
                    owner: Some("threadfin".to_string()),
                    group: Some("threadfin".to_string()),
                    progress_pct: 30,
                    description: "Creating threadfin state directories...".to_string(),
                },
                DeclarativeStep::ResolveGitHubReleaseTag {
                    repo: "Threadfin/Threadfin".to_string(),
                    fallback_version: "1.2.37".to_string(),
                    strip_v_prefix: true,
                    progress_pct: 45,
                    description: "Resolving Threadfin release tag...".to_string(),
                },
                DeclarativeStep::DownloadBinary {
                    url_template: "https://example.invalid/{{TAG}}/{{ARCH_ASSET}}".to_string(),
                    arch_map: ArchAssetMap {
                        amd64: "Threadfin_linux_amd64".to_string(),
                        arm64: "Threadfin_linux_arm64".to_string(),
                        armhf: None,
                    },
                    dest_path: "/usr/local/bin/threadfin".to_string(),
                    mode: 0o755,
                    verification: ArtifactVerificationPolicy {
                        min_size_bytes: 1024,
                        max_size_bytes: 10 * 1024 * 1024,
                        expected_sha256: Some(expected_sha256),
                        arch_sha256: None,
                        require_gzip_magic: false,
                        require_elf_magic: true,
                    },
                    progress_pct: 65,
                    description: "Installing verified Threadfin ELF binary...".to_string(),
                },
                DeclarativeStep::WriteTemplateFile {
                    path: "/var/lib/threadfin/.af-version".to_string(),
                    content_template: "{{VERSION}}\n".to_string(),
                    mode: 0o644,
                    overwrite: true,
                    owner: Some("threadfin".to_string()),
                    group: Some("threadfin".to_string()),
                    progress_pct: 75,
                    description: "Recording Threadfin version...".to_string(),
                },
                DeclarativeStep::WriteSystemdUnit {
                    unit_name: "threadfin.service".to_string(),
                    content_template: "[Unit]\nDescription=Threadfin\n[Service]\nExecStart=/usr/local/bin/threadfin -port={{APP_PORT}}\n".to_string(),
                    progress_pct: 85,
                    description: "Writing threadfin.service...".to_string(),
                },
                DeclarativeStep::Systemctl {
                    unit: None,
                    operation: SystemctlOp::DaemonReload,
                    ignore_errors: false,
                    progress_pct: 90,
                    description: "Reloading systemd...".to_string(),
                },
                DeclarativeStep::Systemctl {
                    unit: Some("threadfin.service".to_string()),
                    operation: SystemctlOp::EnableNow,
                    ignore_errors: false,
                    progress_pct: 95,
                    description: "Enabling and starting threadfin.service...".to_string(),
                },
            ],
            update_steps: Vec::new(),
            remove_steps: Vec::new(),
        };

    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);

    let outcome = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("verified ELF binary recipe should succeed");

    assert!(outcome.lock_present);
    assert!(root.join("usr/local/bin/threadfin").is_file());
    assert_eq!(
        fs::read_to_string(root.join("var/lib/threadfin/.af-version"))
            .unwrap()
            .trim(),
        "1.2.37"
    );
    let unit = fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
    assert!(unit.contains("-port=34400"));

    // Verify systemd sandbox drop-in was generated for threadfin.service
    let dropin = root.join("etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf");
    assert!(dropin.is_file());
    let dropin_text = fs::read_to_string(dropin).unwrap();
    assert!(dropin_text.contains("NoNewPrivileges=yes"));

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_failure_triggers_rollback_and_preserves_prior_config_and_lock_absence() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rollback-recovery");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    // Pre-populate an existing /etc/fail2ban/jail.local to verify .bak-af rollback restoration
    let jail_path = root.join("etc/fail2ban/jail.local");
    fs::create_dir_all(jail_path.parent().unwrap()).unwrap();
    fs::write(&jail_path, "# previous user custom config\nmaxretry = 9\n").unwrap();

    let mock = MockCommandRunner {
        fail_on_call: Some(6),
        ..Default::default()
    };
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
    let recipe = get_declarative_recipe("fail2ban").unwrap();

    let mut phases = Vec::new();
    let err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |ev| phases.push(ev.phase),
        )
        .await
        .unwrap_err();

    assert!(err.to_string().contains("systemctl"));
    assert!(phases.contains(&ExecutionPhase::Rollback));
    assert!(phases.contains(&ExecutionPhase::Failed));

    // Lockfile must NOT have been written
    assert!(!root.join("install/.fail2ban.lock").exists());

    // Previous jail.local must be preserved and no .bak-af left behind
    let restored = fs::read_to_string(&jail_path).unwrap();
    assert_eq!(restored, "# previous user custom config\nmaxretry = 9\n");
    assert!(!root.join("etc/fail2ban/jail.local.bak-af").exists());

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_write_template_file_overwrite_true_rolls_back_from_bak_af_on_later_failure() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rollback-overwrite-template");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    let target_path = root.join("etc/fail2ban/jail.local");
    fs::create_dir_all(target_path.parent().unwrap()).unwrap();
    fs::write(&target_path, "# operator prior config\nmaxretry = 12\n").unwrap();

    let recipe = DeclarativePackageRecipe {
        package_id: "fail2ban".to_string(),
        label: "Fail2ban".to_string(),
        default_port: 0,
        service_name: "fail2ban".to_string(),
        lock_file: "/install/.fail2ban.lock".to_string(),
        apply_systemd_sandbox: false,
        install_steps: vec![
            DeclarativeStep::WriteTemplateFile {
                path: "/etc/fail2ban/jail.local".to_string(),
                content_template: "[sshd]\nenabled = true\n".to_string(),
                mode: 0o644,
                overwrite: true,
                owner: None,
                group: None,
                progress_pct: 50,
                description: "Overwriting config before failure...".to_string(),
            },
            DeclarativeStep::Systemctl {
                unit: Some("fail2ban.service".to_string()),
                operation: SystemctlOp::Restart,
                ignore_errors: false,
                progress_pct: 90,
                description: "Restarting fail2ban.service...".to_string(),
            },
        ],
        update_steps: Vec::new(),
        remove_steps: Vec::new(),
    };

    let mock = MockCommandRunner {
        fail_on_call: Some(0),
        ..Default::default()
    };
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
    let err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("systemctl"));
    assert!(!root.join("install/.fail2ban.lock").exists());
    assert_eq!(
        fs::read_to_string(&target_path).unwrap(),
        "# operator prior config\nmaxretry = 12\n"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_cancellation_aborts_execution_and_rolls_back() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("cancellation");
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let cancel = CancellationToken::new();

    // Trigger cancellation on the 2nd command call (`systemctl daemon-reload`)
    let mock = MockCommandRunner {
        cancel_on_call: Some((2, cancel.clone())),
        ..Default::default()
    };
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
    let recipe = get_declarative_recipe("fail2ban").unwrap();

    let mut phases = Vec::new();
    let err = executor
        .execute_recipe(&recipe, PackageAction::Install, cancel, |ev| {
            phases.push(ev.phase)
        })
        .await
        .unwrap_err();

    assert!(matches!(err, PackageExecutorError::Cancelled(_)));
    assert!(phases.contains(&ExecutionPhase::Rollback));
    assert!(phases.contains(&ExecutionPhase::Cancelled));
    assert!(!root.join("install/.fail2ban.lock").exists());
    assert!(!root.join("etc/fail2ban/jail.local").exists());

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_duplicate_concurrent_package_registration_rejected() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let tok1 = CancellationToken::new();
    let guard = register_package_cancellation("quassel", tok1).unwrap();
    assert!(is_package_execution_active("quassel"));

    let tok2 = CancellationToken::new();
    let dup_err = register_package_cancellation("quassel", tok2);
    assert!(matches!(
        dup_err,
        Err(PackageExecutorError::LockConflict(_))
    ));

    assert!(cancel_package_execution("quassel"));
    drop(guard);
    assert!(!is_package_execution_active("quassel"));
}

#[test]
fn test_targz_extraction_rejects_missing_or_non_elf_member() {
    let root = create_isolated_test_dir("targz-extract");
    let archive_path = root.join("sample.tar.gz");
    let dest_dir = root.join("usr/local/bin");
    fs::create_dir_all(&dest_dir).unwrap();

    // Build a valid .tar.gz containing an ELF binary `autobrr`
    {
        let file = File::create(&archive_path).unwrap();
        let enc = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(enc);
        let payload = create_mock_elf_payload(2048);
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "autobrr", payload.as_slice())
            .unwrap();
        tar.finish().unwrap();
    }

    let mut journal = RollbackJournal::new(Some(root.clone()));
    extract_binaries_from_targz(
        &archive_path,
        &dest_dir,
        &["autobrr".to_string()],
        0o755,
        true,
        &mut journal,
    )
    .expect("valid ELF member should extract cleanly");
    assert!(dest_dir.join("autobrr").is_file());

    // Requesting a non-existent binary member must fail
    let missing_err = extract_binaries_from_targz(
        &archive_path,
        &dest_dir,
        &["missing-bin".to_string()],
        0o755,
        true,
        &mut journal,
    )
    .unwrap_err();
    assert!(missing_err.to_string().contains("missing-bin"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_cross_process_lock_preserves_inode_and_does_not_truncate_on_conflict() {
    let root = create_isolated_test_dir("flock-inode");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    let guard1 = CrossProcessLockGuard::try_acquire(&env_cfg, "fail2ban")
        .expect("initial lock acquisition must succeed");
    let flock_path = CrossProcessLockGuard::resolve_flock_path(&env_cfg).unwrap();
    assert!(flock_path.is_file());

    let initial_content = fs::read_to_string(&flock_path).unwrap();
    assert!(initial_content.contains("pkg=fail2ban"));

    #[cfg(unix)]
    let inode_before = {
        use std::os::unix::fs::MetadataExt;
        let ino = fs::metadata(&flock_path).unwrap().ino();

        // Contending lock attempt must fail with LockConflict WITHOUT truncating the file
        let conflict_err = CrossProcessLockGuard::try_acquire(&env_cfg, "other-pkg");
        assert!(matches!(
            conflict_err,
            Err(PackageExecutorError::LockConflict(_))
        ));
        let content_during_conflict = fs::read_to_string(&flock_path).unwrap();
        assert_eq!(
            content_during_conflict, initial_content,
            "contending opener must not truncate persistent lock file before acquiring flock"
        );
        assert_eq!(fs::metadata(&flock_path).unwrap().ino(), ino);
        ino
    };

    drop(guard1);
    // Persistent flock file must NEVER be unlinked on Drop
    assert!(
        flock_path.is_file(),
        "persistent flock file must remain on disk after guard drop"
    );

    let guard2 = CrossProcessLockGuard::try_acquire(&env_cfg, "other-pkg")
        .expect("second lock acquisition after drop must succeed");
    let updated_content = fs::read_to_string(&flock_path).unwrap();
    assert!(updated_content.contains("pkg=other-pkg"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let inode_after = fs::metadata(&flock_path).unwrap().ino();
        assert_eq!(
            inode_before, inode_after,
            "persistent flock file must retain the exact same inode across lock cycles"
        );
    }
    drop(guard2);

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_queued_lock_wait_honors_cancellation_and_rejects_duplicate_inflight() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("queued-cancel");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    // Hold the process-wide package mutex to force the next operation to queue
    let held_mutex = crate::PACKAGE_MUTEX.lock().await;

    let mock = MockCommandRunner::default();
    let executor = Arc::new(DeclarativePackageExecutor::with_runner(env_cfg, mock));
    let recipe = get_declarative_recipe("fail2ban").unwrap();
    let cancel = CancellationToken::new();

    let exec_clone = Arc::clone(&executor);
    let recipe_clone = recipe.clone();
    let cancel_clone = cancel.clone();
    let queued_task = tokio::spawn(async move {
        exec_clone
            .execute_recipe(&recipe_clone, PackageAction::Install, cancel_clone, |_| {})
            .await
    });

    // Wait briefly until the queued task registers its in-flight cancellation token
    for _ in 0..50 {
        if is_package_execution_active("fail2ban") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        is_package_execution_active("fail2ban"),
        "queued task must register cancellation before waiting on PACKAGE_MUTEX"
    );

    // Duplicate in-flight operation for the same package ID must be rejected immediately
    let dup_res = executor
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await;
    assert!(matches!(
        dup_res,
        Err(PackageExecutorError::LockConflict(_))
    ));

    // Cancel the queued operation while `held_mutex` is still held
    assert!(cancel_package_execution("fail2ban"));

    let queued_res = tokio::time::timeout(Duration::from_secs(2), queued_task)
        .await
        .expect("queued task must abort promptly on cancellation without waiting for mutex")
        .unwrap();
    assert!(matches!(
        queued_res,
        Err(PackageExecutorError::Cancelled(_))
    ));
    assert!(!is_package_execution_active("fail2ban"));

    drop(held_mutex);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_ancestor_symlink_escape_and_unexpected_lstat_errors_propagated() {
    let root = create_isolated_test_dir("ancestor-lstat");
    let outside = create_isolated_test_dir("ancestor-outside");

    // 1. Verify non-NotFound lstat errors (e.g. PermissionDenied / EACCES) are propagated
    // rather than swallowed as NotFound.
    let target = root.join("etc/fail2ban/jail.local");
    let perm_err = validate_path_ancestors_with_lstat(&target, Some(&root), |p| {
        if p.ends_with("fail2ban") {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated EACCES on ancestor",
            ))
        } else {
            fs::symlink_metadata(p).map(|metadata| metadata.file_type().is_symlink())
        }
    });
    assert!(matches!(perm_err, Err(PackageExecutorError::Io(_))));

    // 2. On Unix, verify symlinked ancestor directory and ENOTDIR ancestor are rejected
    #[cfg(unix)]
    {
        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();
        let symlink_dir = etc_dir.join("fail2ban");
        std::os::unix::fs::symlink(&outside, &symlink_dir).unwrap();

        let env_cfg = PackageExecutionEnv::isolated(&root);
        let sym_res = env_cfg.resolve_path("/etc/fail2ban/jail.local");
        assert!(
            matches!(sym_res, Err(PackageExecutorError::SecurityViolation(_))),
            "symlink ancestor must be rejected with SecurityViolation"
        );

        // Create regular file `etc/not_a_dir` and query `etc/not_a_dir/child/conf` -> ENOTDIR Io error
        let file_ancestor = etc_dir.join("not_a_dir");
        fs::write(&file_ancestor, b"not a directory").unwrap();
        let enotdir_path = file_ancestor.join("child").join("conf");
        let enotdir_res = validate_filesystem_path(&enotdir_path, Some(&root));
        assert!(
            matches!(enotdir_res, Err(PackageExecutorError::Io(_))),
            "ENOTDIR on ancestor traversal must propagate as PackageExecutorError::Io"
        );
    }

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[tokio::test]
async fn test_tokio_command_runner_process_group_cancellation_and_bounded_output() {
    let runner = TokioCommandRunner {
        respect_dry_run_env: false,
    };

    // 1. Process-group cancellation: child spawns a background grandchild that inherits
    // stdout/stderr and sleeps for 60s. Cancelling must kill the entire process group
    // and return promptly without hanging on the grandchild's open pipe.
    let cancel = CancellationToken::new();
    let cancel_trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        cancel_trigger.cancel();
    });

    let args = vec!["-c".to_string(), "sh -c 'sleep 60' & sleep 60".to_string()];
    let res = tokio::time::timeout(
        Duration::from_secs(3),
        runner.run_command("sh", &args, &[], &cancel),
    )
    .await
    .expect("process-group cancellation must not hang waiting on background descendant pipes");
    assert!(matches!(res, Err(PackageExecutorError::Cancelled(_))));

    // 2. Bounded output retention: command emitting > MAX_COMMAND_OUTPUT_BYTES must be
    // drained cleanly without OOM or pipe deadlock, and truncated with marker.
    let noisy_args = vec![
        "-c".to_string(),
        "head -c 150000 /dev/zero | tr '\\0' 'A'".to_string(),
    ];
    let out = runner
        .run_command("sh", &noisy_args, &[], &CancellationToken::new())
        .await
        .expect("noisy command should succeed with bounded output");
    assert!(out.success());
    assert!(out.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES + 64);
    assert!(out.stdout.contains("[output truncated]"));

    // 3. AFM-004: Supervised rollback grace window allows Bash TERM/EXIT traps to spawn
    // cp/mv and restore backups (~100ms) cleanly before SIGKILL is ever sent.
    let trap_dir = create_isolated_test_dir("afm-004-trap-grace");
    let live_state = trap_dir.join("live.state");
    let backup_state = trap_dir.join("backup.state");
    let marker_file = trap_dir.join("rollback.marker");
    fs::write(&live_state, "schema-v1-stable\n").unwrap();
    fs::write(&backup_state, "schema-v1-stable\n").unwrap();

    let script = format!(
        r#"
set -e
rollback_done=0
rollback() {{
    if [ "$rollback_done" -eq 1 ]; then return; fi
    rollback_done=1
    echo "rollback_started=true" > "{marker}"
    sleep 0.08
    cp "{backup}" "{live}.tmp"
    mv "{live}.tmp" "{live}"
    echo "rollback_completed=true" >> "{marker}"
}}
trap rollback TERM EXIT
echo "schema-v2-migrated" > "{live}"
sleep 30
"#,
        marker = marker_file.display(),
        backup = backup_state.display(),
        live = live_state.display()
    );

    let trap_cancel = CancellationToken::new();
    let trap_cancel_trigger = trap_cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        trap_cancel_trigger.cancel();
    });

    let trap_args = vec!["-c".to_string(), script];
    let trap_res = runner
        .run_command("bash", &trap_args, &[], &trap_cancel)
        .await;
    assert!(matches!(trap_res, Err(PackageExecutorError::Cancelled(_))));
    let marker_contents = fs::read_to_string(&marker_file).unwrap_or_default();
    assert!(
            marker_contents.contains("rollback_started=true")
                && marker_contents.contains("rollback_completed=true"),
            "expected TERM/EXIT trap to complete rollback within grace window, got: {marker_contents:?}"
        );
    assert_eq!(
        fs::read_to_string(&live_state).unwrap(),
        "schema-v1-stable\n"
    );
    let _ = fs::remove_dir_all(&trap_dir);
}

#[tokio::test]
async fn test_live_progress_stream_emits_events_before_step_completion() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("live-stream");
    let env_cfg = PackageExecutionEnv::isolated(&root);

    #[derive(Clone)]
    struct GatedRunner {
        step_entered: Arc<tokio::sync::Notify>,
        allow_finish: Arc<tokio::sync::Notify>,
        first_call: Arc<AtomicBool>,
    }

    impl CommandRunner for GatedRunner {
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
                if !self.first_call.swap(true, Ordering::SeqCst) {
                    self.step_entered.notify_one();
                    self.allow_finish.notified().await;
                }
                if cancel.is_cancelled() {
                    return Err(PackageExecutorError::Cancelled(program.to_string()));
                }
                if program == "dpkg-query" {
                    let stdout = if args.iter().any(|a| a.contains("db:Status-Status")) {
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
                    stdout: format!("ok: {} {}", program, args.join(" ")),
                    stderr: String::new(),
                })
            })
        }
    }

    let step_entered = Arc::new(tokio::sync::Notify::new());
    let allow_finish = Arc::new(tokio::sync::Notify::new());
    let runner = GatedRunner {
        step_entered: Arc::clone(&step_entered),
        allow_finish: Arc::clone(&allow_finish),
        first_call: Arc::new(AtomicBool::new(false)),
    };

    let executor = Arc::new(DeclarativePackageExecutor::with_runner(env_cfg, runner));
    let recipe = get_declarative_recipe("fail2ban").unwrap();
    let mut stream = std::pin::pin!(execute_declarative_recipe_stream(
        executor,
        recipe,
        PackageAction::Install,
        CancellationToken::new(),
    ));

    // Wait until Step 1 (`apt-get update`) is actively blocked inside `run_command`
    let first_line = futures::StreamExt::next(&mut stream)
        .await
        .expect("stream must yield LockAcquire event before completion")
        .unwrap();
    assert!(first_line.contains("[PROGRESS:5]"));

    let second_line = futures::StreamExt::next(&mut stream)
        .await
        .expect("stream must yield Step 1 progress event while Step 1 is still in-flight")
        .unwrap();
    assert!(second_line.contains("[PROGRESS:20]"));
    step_entered.notified().await;

    // Release Step 1 and drain remaining stream events to 100% completion
    allow_finish.notify_one();
    let mut lines = vec![first_line, second_line];
    while let Some(item) = futures::StreamExt::next(&mut stream).await {
        lines.push(item.unwrap());
    }
    assert!(lines.last().unwrap().contains("[PROGRESS:100]"));

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_generate_self_signed_tls_cert_creates_traversable_0755_parent_dirs() {
    use std::os::unix::fs::PermissionsExt;

    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("tls-cert-0755-parents");
    let previous_umask = unsafe { libc::umask(0o077) };

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    let recipe = get_declarative_recipe("quassel").unwrap();
    let step = DeclarativeStep::GenerateSelfSignedTlsCert {
        cert_path: "/var/lib/quassel/certs/server.pem".to_string(),
        key_out_path: Some("/etc/quassel/private/server.key".to_string()),
        days: 365,
        subject: "/CN=quassel.aether.local".to_string(),
        mode: 0o600,
        owner: Some("quasselcore".to_string()),
        group: Some("quasselcore".to_string()),
        overwrite: true,
        progress_pct: 55,
        description: "Generate self-signed cert under UMask=0077".to_string(),
    };

    let result = executor
        .run_single_step(
            &recipe,
            &step,
            &mut HashMap::new(),
            &mut RollbackJournal::new(Some(root.clone())),
            &CancellationToken::new(),
        )
        .await;
    unsafe {
        libc::umask(previous_umask);
    }
    result.expect("GenerateSelfSignedTlsCert must succeed");

    for dir in ["var/lib/quassel/certs", "etc/quassel/private"] {
        let mode = fs::metadata(root.join(dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "newly created parent directory {dir} must be 0755 even under UMask=0077"
        );
    }
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_mergerfs_remove_and_purge_unmount_shell_free_fail_closed_and_preserve_mountpoints() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let recipe = get_declarative_recipe("mergerfs").unwrap();

    // Must preserve /mnt/unionfs and /mnt/mergerfs even on DELETE_DATA=true
    assert!(
        !recipe.remove_steps.iter().any(|s| matches!(
            s,
            DeclarativeStep::RemovePaths { paths, .. }
                if paths.iter().any(|p| p == "/mnt/unionfs" || p == "/mnt/mergerfs")
        )),
        "mergerfs remove_steps must preserve /mnt/unionfs and /mnt/mergerfs even on DELETE_DATA=true"
    );
    let unmount_idx = recipe
        .remove_steps
        .iter()
        .position(|s| {
            matches!(
                s,
                DeclarativeStep::UnmountPaths {
                    paths,
                    only_if_delete_data: false,
                    ..
                } if paths == &vec!["/mnt/unionfs".to_string(), "/mnt/mergerfs".to_string()]
            )
        })
        .expect("mergerfs remove_steps must include unconditional shell-free UnmountPaths");
    let apt_idx = recipe
        .remove_steps
        .iter()
        .position(|s| matches!(s, DeclarativeStep::AptRemove { .. }))
        .expect("mergerfs remove_steps must include AptRemove");
    assert!(
        unmount_idx < apt_idx,
        "mergerfs UnmountPaths must run before APT removal"
    );

    // Mounted path must fail closed on BOTH retained remove (delete_data=false) and purge (delete_data=true),
    // invoking fusermount -u and umount (never umount -l) and refusing APT/data removal.
    for delete_data in [false, true] {
        let root = create_isolated_test_dir(&format!("mergerfs-mounted-guard-{delete_data}"));
        fs::create_dir_all(root.join("install")).unwrap();
        fs::write(root.join("install/.mergerfs.lock"), "installed\n").unwrap();
        fs::create_dir_all(root.join("mnt/unionfs")).unwrap();
        fs::write(root.join("mnt/unionfs/media.mkv"), b"operator-data").unwrap();
        fs::create_dir_all(root.join("proc")).unwrap();
        fs::write(
            root.join("proc/mounts"),
            "local:remote /mnt/unionfs fuse.mergerfs rw,nosuid,nodev 0 0\n",
        )
        .unwrap();

        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.delete_data = delete_data;
        let runner = MockCommandRunner {
            fail_program: Some("fusermount".to_string()),
            ..Default::default()
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner.clone());
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("active /mnt/unionfs mount must fail closed");
        assert!(
            err.to_string().contains("still an active mountpoint"),
            "unexpected error for delete_data={delete_data}: {err}"
        );

        let cmds = runner.recorded_commands();
        assert!(cmds.iter().any(|c| {
            c.program == "fusermount"
                && c.args == vec!["-u".to_string(), "/mnt/unionfs".to_string()]
        }));
        assert!(cmds
            .iter()
            .any(|c| { c.program == "umount" && c.args == vec!["/mnt/unionfs".to_string()] }));
        assert!(
            !cmds
                .iter()
                .any(|c| c.program == "/bin/sh" || c.args.iter().any(|a| a == "-l" || a == "-uz")),
            "unmount must never invoke /bin/sh or lazy unmount flags: {cmds:?}"
        );
        assert!(
            !cmds.iter().any(|c| c.program == "apt-get"),
            "failed unmount must block apt-get removal"
        );
        assert!(root.join("install/.mergerfs.lock").is_file());
        assert_eq!(
            fs::read(root.join("mnt/unionfs/media.mkv")).unwrap(),
            b"operator-data"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // When unmounted, DELETE_DATA=true purge removes /etc/mergerfs and /var/lib/mergerfs while
    // preserving /mnt/unionfs and /mnt/mergerfs and their operator contents.
    let root = create_isolated_test_dir("mergerfs-purge-preserves-mounts");
    fs::create_dir_all(root.join("install")).unwrap();
    fs::write(root.join("install/.mergerfs.lock"), "installed\n").unwrap();
    fs::create_dir_all(root.join("etc/mergerfs")).unwrap();
    fs::write(
        root.join("etc/mergerfs/mergerfs.conf"),
        "BRANCHES=/mnt/local\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("var/lib/mergerfs")).unwrap();
    fs::write(root.join("var/lib/mergerfs/.af-version"), "2.40.2\n").unwrap();
    fs::create_dir_all(root.join("mnt/unionfs")).unwrap();
    fs::write(root.join("mnt/unionfs/keep.txt"), b"keep-unionfs").unwrap();
    fs::create_dir_all(root.join("mnt/mergerfs")).unwrap();
    fs::write(root.join("mnt/mergerfs/keep.txt"), b"keep-mergerfs").unwrap();

    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.delete_data = true;
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();
    assert!(!root.join("etc/mergerfs").exists());
    assert!(!root.join("var/lib/mergerfs").exists());
    assert_eq!(
        fs::read(root.join("mnt/unionfs/keep.txt")).unwrap(),
        b"keep-unionfs"
    );
    assert_eq!(
        fs::read(root.join("mnt/mergerfs/keep.txt")).unwrap(),
        b"keep-mergerfs"
    );
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn declarative_recipes_thread_custom_af_bind_address_and_reject_invalid() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    assert_eq!(resolve_bind_address(None).unwrap(), "127.0.0.1");
    assert_eq!(resolve_bind_address(Some("")).unwrap(), "127.0.0.1");
    assert_eq!(
        resolve_bind_address(Some("127.0.0.2")).unwrap(),
        "127.0.0.2"
    );
    assert_eq!(resolve_bind_address(Some("0.0.0.0")).unwrap(), "0.0.0.0");
    assert_eq!(resolve_bind_address(Some("::1")).unwrap(), "::1");
    for bad in [
        "127.0.0.1; id",
        "localhost\nfoo",
        "not-an-ip",
        "127.0.0.1:80",
    ] {
        assert!(
            resolve_bind_address(Some(bad)).is_err(),
            "expected invalid AF_BIND_ADDRESS {bad:?} to fail"
        );
    }
    assert_eq!(probe_host_for_bind_address("0.0.0.0"), "127.0.0.1");
    assert_eq!(probe_host_for_bind_address("::"), "[::1]");
    assert_eq!(probe_host_for_bind_address("::1"), "[::1]");
    assert_eq!(probe_host_for_bind_address("127.0.0.2"), "127.0.0.2");

    let _bind_guard = EnvVarGuard::new(&[("AF_BIND_ADDRESS", Some("127.0.0.2"))]);

    // 1. Threadfin threads custom AF_BIND_ADDRESS into unit + settings.json
    let tf_root = create_isolated_test_dir("threadfin-custom-bind");
    let tf_env = PackageExecutionEnv::isolated(&tf_root);
    let elf_bytes = create_mock_elf_payload_for_arch(4096, 62);
    let cache_dir = tf_env.artifact_cache_dir.clone().unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();
    let mut tf_recipe = get_declarative_recipe("threadfin").unwrap();
    for step in tf_recipe
        .install_steps
        .iter_mut()
        .chain(tf_recipe.update_steps.iter_mut())
    {
        if let DeclarativeStep::DownloadBinary { verification, .. } = step {
            verification.expected_sha256 = Some(hex::encode(Sha256::digest(&elf_bytes)));
        }
    }
    DeclarativePackageExecutor::with_runner(tf_env, MockCommandRunner::default())
        .execute_recipe(
            &tf_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("threadfin install with custom AF_BIND_ADDRESS must succeed");
    let tf_unit = fs::read_to_string(tf_root.join("etc/systemd/system/threadfin.service")).unwrap();
    assert!(
        tf_unit.contains("-bind=127.0.0.2"),
        "threadfin unit missing custom bind address: {tf_unit}"
    );
    let tf_settings =
        fs::read_to_string(tf_root.join("var/lib/threadfin/conf/settings.json")).unwrap();
    assert!(
        tf_settings.contains("\"bindIpAddress\": \"127.0.0.2\""),
        "threadfin settings.json missing custom bindIpAddress: {tf_settings}"
    );
    let _ = fs::remove_dir_all(&tf_root);

    // 2. ZNC threads custom AF_BIND_ADDRESS into znc.conf
    let znc_root = create_isolated_test_dir("znc-custom-bind");
    let znc_env = PackageExecutionEnv::isolated(&znc_root);
    let znc_recipe = get_declarative_recipe("znc").unwrap();
    DeclarativePackageExecutor::with_runner(znc_env, MockCommandRunner::default())
        .execute_recipe(
            &znc_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("znc install with custom AF_BIND_ADDRESS must succeed");
    let znc_conf = fs::read_to_string(znc_root.join("var/lib/znc/configs/znc.conf")).unwrap();
    assert!(
        znc_conf.contains("Host = 127.0.0.2"),
        "znc.conf missing custom Host bind address: {znc_conf}"
    );
    let _ = fs::remove_dir_all(&znc_root);

    // 3. Netdata threads custom AF_BIND_ADDRESS into netdata.conf
    let nd_root = create_isolated_test_dir("netdata-custom-bind");
    let nd_env = PackageExecutionEnv::isolated(&nd_root);
    let nd_recipe = get_declarative_recipe("netdata").unwrap();
    DeclarativePackageExecutor::with_runner(nd_env, MockCommandRunner::default())
        .execute_recipe(
            &nd_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("netdata install with custom AF_BIND_ADDRESS must succeed");
    let nd_conf = fs::read_to_string(nd_root.join("etc/netdata/netdata.conf")).unwrap();
    assert!(
        nd_conf.contains("bind to = 127.0.0.2"),
        "netdata.conf missing custom bind address: {nd_conf}"
    );
    let _ = fs::remove_dir_all(&nd_root);

    // 4. Invalid AF_BIND_ADDRESS fails closed before mutating filesystem
    env::set_var("AF_BIND_ADDRESS", "127.0.0.1; touch /tmp/pwned");
    let bad_root = create_isolated_test_dir("netdata-bad-bind");
    let bad_env = PackageExecutionEnv::isolated(&bad_root);
    let err = DeclarativePackageExecutor::with_runner(bad_env, MockCommandRunner::default())
        .execute_recipe(
            &nd_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("invalid AF_BIND_ADDRESS must fail closed");
    assert!(
        err.to_string().contains("AF_BIND_ADDRESS"),
        "unexpected error: {err}"
    );
    assert!(!bad_root.join("etc/netdata/netdata.conf").exists());
    let _ = fs::remove_dir_all(&bad_root);
}

#[tokio::test]
async fn mergerfs_install_sets_0775_mount_directories_and_threadfin_deduplicates_update_steps() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Threadfin update_steps must reuse install_steps identically without drift
    let tf_recipe = get_declarative_recipe("threadfin").unwrap();
    assert_eq!(
        serde_json::to_value(&tf_recipe.install_steps).unwrap(),
        serde_json::to_value(&tf_recipe.update_steps).unwrap(),
        "threadfin update_steps must be deduplicated directly from install_steps"
    );

    // MergerFS mount directories must be 0o775 (matching installpackage-mergerfs) while
    // config/state directories remain 0o755
    let root = create_isolated_test_dir("mergerfs-dir-modes");
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let recipe = get_declarative_recipe("mergerfs").unwrap();
    DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default())
        .execute_recipe(
            &recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect("mergerfs install must succeed");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for mount_dir in ["mnt/mergerfs", "mnt/local", "mnt/remote", "mnt/unionfs"] {
            let mode = fs::metadata(root.join(mount_dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o775, "expected 0o775 on /{mount_dir}, got {mode:o}");
        }
        for cfg_dir in ["etc/mergerfs", "var/lib/mergerfs"] {
            let mode = fs::metadata(root.join(cfg_dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "expected 0o755 on /{cfg_dir}, got {mode:o}");
        }
    }
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn apt_remove_skips_autoremove_and_purge_wording_when_delete_data_is_false() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    for pkg in ["znc", "netdata", "mergerfs", "xrdp", "x2go"] {
        let recipe = get_declarative_recipe(pkg).unwrap();
        for step in &recipe.remove_steps {
            if let DeclarativeStep::AptRemove { description, .. } = step {
                assert!(
                    !description.starts_with("Purging "),
                    "{pkg} AptRemove step must not emit misleading 'Purging ...' description: {description}"
                );
            }
        }
    }

    for delete_data in [false, true] {
        let root = create_isolated_test_dir(&format!("netdata-apt-autoremove-{delete_data}"));
        fs::create_dir_all(root.join("install")).unwrap();
        fs::write(root.join("install/.netdata.lock"), "installed\n").unwrap();
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.delete_data = delete_data;
        let runner = MockCommandRunner::default();
        let events = Arc::new(StdMutex::new(Vec::<PackageProgressEvent>::new()));
        let events_cb = events.clone();
        DeclarativePackageExecutor::with_runner(env_cfg, runner.clone())
            .execute_recipe(
                &get_declarative_recipe("netdata").unwrap(),
                PackageAction::Remove,
                CancellationToken::new(),
                move |ev| events_cb.lock().unwrap().push(ev),
            )
            .await
            .expect("netdata remove must succeed");

        let cmds = runner.recorded_commands();
        let saw_autoremove = cmds
            .iter()
            .any(|c| c.program == "apt-get" && c.args.iter().any(|a| a == "autoremove"));
        assert_eq!(
            saw_autoremove, delete_data,
            "apt-get autoremove must run iff delete_data=true (got {saw_autoremove} for delete_data={delete_data})"
        );
        let saw_purge = cmds
            .iter()
            .any(|c| c.program == "apt-get" && c.args.iter().any(|a| a == "purge"));
        assert_eq!(saw_purge, delete_data);
        if !delete_data {
            let emitted = events.lock().unwrap();
            assert!(
                emitted.iter().all(|e| !e.message.contains("Purging ")),
                "non-purge removal must not emit 'Purging ' progress messages: {emitted:?}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }
}
