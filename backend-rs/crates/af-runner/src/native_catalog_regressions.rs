async fn exercise_catalog_recipe(
    package: &str,
    apt_package: &str,
    unit: &str,
    retained_path: &str,
    retained_contents: &str,
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir(package);
    let recipe = get_declarative_recipe(package).unwrap();
    let mut environment = PackageExecutionEnv::isolated(&root);
    environment.app_port = 19876;
    let runner = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(environment.clone(), runner.clone());
    let install = executor.execute_recipe(
        &recipe, PackageAction::Install, CancellationToken::new(), |_| {},
    ).await.unwrap();
    assert!(install.lock_present, "{package}");
    let expected_ver = if package == "rclone" {
        "0.14.2"
    } else {
        "1:0.14.2-1ubuntu2"
    };
    assert_eq!(
        install.resolved_version.as_deref(),
        Some(expected_ver),
        "{package}"
    );
    let commands = runner.recorded_commands();
    let dependency = if package == "rclone" { "fuse3" } else { apt_package };
    assert!(commands.iter().any(|command| command.program == "apt-get"
        && command.args.contains(&"install".into())
        && command.args.contains(&dependency.into())), "{package}");
    assert!(commands.iter().any(|command| command.program == "systemctl"
        && command.args.contains(&unit.into())), "{package}");
    let retained = root.join(retained_path.trim_start_matches('/'));
    fs::create_dir_all(retained.parent().unwrap()).unwrap();
    fs::write(&retained, retained_contents).unwrap();
    let unrelated = root.join("mnt/local/unrelated-media");
    fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    fs::write(&unrelated, "never purge media branches").unwrap();
    executor.execute_recipe(
        &recipe, PackageAction::Update, CancellationToken::new(), |_| {},
    ).await.unwrap();
    assert!(fs::read_to_string(&retained).unwrap().contains(retained_contents), "{package}");
    if package == "netdata" {
        let config = fs::read_to_string(&retained).unwrap();
        assert!(config.contains("bind to = 127.0.0.1"));
        assert!(config.contains("default port = 19876"));
    }
    executor.execute_recipe(
        &recipe, PackageAction::Remove, CancellationToken::new(), |_| {},
    ).await.unwrap();
    assert!(retained.exists(), "default removal lost {package} state");
    assert!(!root.join(recipe.lock_file.trim_start_matches('/')).exists());
    assert!(!runner.recorded_commands().iter().any(|command| command.program == "userdel"));
    executor.execute_recipe(
        &recipe, PackageAction::Install, CancellationToken::new(), |_| {},
    ).await.unwrap();
    assert!(fs::read_to_string(&retained).unwrap().contains(retained_contents), "{package}");
    environment.delete_data = true;
    let purge = DeclarativePackageExecutor::with_runner(environment, runner.clone());
    purge.execute_recipe(
        &recipe, PackageAction::Remove, CancellationToken::new(), |_| {},
    ).await.unwrap();
    assert!(!retained.exists(), "explicit purge retained {package} state");
    assert_eq!(fs::read_to_string(unrelated).unwrap(), "never purge media branches");
    let apt_managed = runner.recorded_commands().iter().any(|command| command.program == "apt-get"
        && command.args.contains(&apt_package.into()));
    assert_eq!(apt_managed, package != "rclone", "{package}");
    let apt_purged = runner.recorded_commands().iter().any(|command| command.program == "apt-get"
        && command.args.contains(&"purge".into())
        && command.args.contains(&apt_package.into()));
    assert_eq!(apt_purged, package != "rclone", "{package}");
    fs::remove_dir_all(root).unwrap();
}

macro_rules! catalog_recipe_lifecycle_test {
    ($test:ident, $package:literal, $apt:literal, $unit:literal, $path:literal, $contents:literal) => {
        #[tokio::test]
        async fn $test() {
            exercise_catalog_recipe($package, $apt, $unit, $path, $contents).await;
        }
    };
}

catalog_recipe_lifecycle_test!(catalog_znc_lifecycle, "znc", "znc", "znc.service",
    "/var/lib/znc/configs/znc.conf", "fixture IRC credentials and custom modules\n");
catalog_recipe_lifecycle_test!(catalog_xrdp_lifecycle, "xrdp", "xrdp", "xrdp.service",
    "/etc/xrdp/startwm.sh", "#!/bin/sh\nexec operator-desktop\n");
catalog_recipe_lifecycle_test!(catalog_x2go_lifecycle, "x2go", "x2goserver", "x2goserver.service",
    "/etc/x2go/operator-session.conf", "fixture custom session settings\n");
catalog_recipe_lifecycle_test!(catalog_netdata_lifecycle, "netdata", "netdata", "netdata.service",
    "/etc/netdata/netdata.conf", "[global]\n    history = 86400\n[plugins]\n    fixture = retained\n");
catalog_recipe_lifecycle_test!(catalog_mergerfs_lifecycle, "mergerfs", "mergerfs", "mergerfs.service",
    "/etc/mergerfs/mergerfs.conf", "BRANCHES=\"/mnt/operator-source\"\n");
catalog_recipe_lifecycle_test!(catalog_rclone_lifecycle, "rclone", "rclone", "rclone.service",
    "/etc/rclone/rclone.conf", "[fixture]\ntype = drive\ntoken = retained-fixture-token\n");

#[test]
fn drifted_recipes_defer_cleanly_to_legacy_bash_fallback() {
    for package in ["prometheus", "syncthing", "novnc"] {
        assert!(
            get_declarative_recipe(package).is_none(),
            "{package} must not expose a drifted declarative recipe"
        );
        assert_eq!(
            select_package_engine_with_flags(package, true, false),
            PackageEngineMode::LegacyBashFallback,
            "{package} must fall back cleanly to LegacyBashFallback even when Rust packages are enabled"
        );
    }
}

#[tokio::test]
async fn catalog_apt_failure_preserves_receipts_and_existing_configuration() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    for package in ["znc", "xrdp", "x2go", "netdata", "mergerfs", "rclone"] {
        let root = create_isolated_test_dir(package);
        let recipe = get_declarative_recipe(package).unwrap();
        let marker = root.join(recipe.lock_file.trim_start_matches('/'));
        fs::create_dir_all(marker.parent().unwrap()).unwrap();
        fs::write(&marker, "existing receipt").unwrap();
        let configuration = root.join("etc/operator-retained.conf");
        fs::create_dir_all(configuration.parent().unwrap()).unwrap();
        fs::write(&configuration, "existing configuration and credentials").unwrap();
        let runner = MockCommandRunner { fail_program: Some("apt-get".into()), ..Default::default() };
        let executor = DeclarativePackageExecutor::with_runner(PackageExecutionEnv::isolated(&root), runner);
        assert!(executor.execute_recipe(
            &recipe, PackageAction::Update, CancellationToken::new(), |_| {},
        ).await.is_err(), "{package}");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "existing receipt");
        assert_eq!(fs::read_to_string(&configuration).unwrap(), "existing configuration and credentials");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn catalog_ini_merge_preserves_other_sections_and_is_idempotent() {
    let original = "[web]\n    default port = 19999\n    allow connections from = localhost\n[plugins]\n    custom = yes\n";
    let settings = vec![("default port".into(), "19876".into()), ("bind to".into(), "127.0.0.1".into())];
    let merged = merge_ini_settings(original, "web", &settings);
    assert!(merged.contains("allow connections from = localhost"));
    assert!(merged.contains("bind to = 127.0.0.1\n[plugins]"));
    assert!(merged.contains("custom = yes"));
    assert_eq!(merge_ini_settings(&merged, "web", &settings), merged);
}

#[tokio::test]
async fn catalog_znc_generates_unique_non_static_credentials_and_persists_receipt() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_user = env::var_os("MASTER_USER");
    let prev_pass = env::var_os("MASTER_PASS");
    let prev_af_user = env::var_os("AETHERFLOW_MASTER_USER");
    let prev_af_pass = env::var_os("AETHERFLOW_MASTER_PASS");
    let prev_creds_file = env::var_os("AETHERFLOW_MASTER_CREDS_FILE");
    env::remove_var("MASTER_USER");
    env::remove_var("MASTER_PASS");
    env::remove_var("AETHERFLOW_MASTER_USER");
    env::remove_var("AETHERFLOW_MASTER_PASS");
    env::remove_var("AETHERFLOW_MASTER_CREDS_FILE");

    let recipe = get_declarative_recipe("znc").unwrap();

    let root_a = create_isolated_test_dir("znc-sol06-a");
    let exec_a = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root_a),
        MockCommandRunner::default(),
    );
    exec_a
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let root_b = create_isolated_test_dir("znc-sol06-b");
    let exec_b = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root_b),
        MockCommandRunner::default(),
    );
    exec_b
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let conf_a = fs::read_to_string(root_a.join("var/lib/znc/configs/znc.conf")).unwrap();
    let conf_b = fs::read_to_string(root_b.join("var/lib/znc/configs/znc.conf")).unwrap();
    assert!(!conf_a.contains("366c8101d4cb9e43447641a53ee50679428f58b9afb01f57eb50eec570eda0a2"));
    assert!(!conf_a.contains("aetherflow-bootstrap"));
    assert!(!conf_a.contains("aetherflowzncsalt123"));
    assert_ne!(conf_a, conf_b, "each fresh ZNC install must generate unique salt and password hash");

    for root in [&root_a, &root_b] {
        assert!(!root.join("opt/AetherFlow/logs/znc_credentials.txt").exists());
    }

    match prev_user {
        Some(v) => env::set_var("MASTER_USER", v),
        None => env::remove_var("MASTER_USER"),
    }
    match prev_pass {
        Some(v) => env::set_var("MASTER_PASS", v),
        None => env::remove_var("MASTER_PASS"),
    }
    match prev_af_user {
        Some(v) => env::set_var("AETHERFLOW_MASTER_USER", v),
        None => env::remove_var("AETHERFLOW_MASTER_USER"),
    }
    match prev_af_pass {
        Some(v) => env::set_var("AETHERFLOW_MASTER_PASS", v),
        None => env::remove_var("AETHERFLOW_MASTER_PASS"),
    }
    match prev_creds_file {
        Some(v) => env::set_var("AETHERFLOW_MASTER_CREDS_FILE", v),
        None => env::remove_var("AETHERFLOW_MASTER_CREDS_FILE"),
    }
    let _ = fs::remove_dir_all(root_a);
    let _ = fs::remove_dir_all(root_b);
}

#[tokio::test]
async fn catalog_all_retained_recipes_have_af_version_receipts_companion_units_and_port_updates() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let expected_version_paths = [
        ("fail2ban", "etc/fail2ban/.af-version"),
        ("quassel", "var/lib/quassel/.af-version"),
        ("threadfin", "var/lib/threadfin/.af-version"),
        ("znc", "var/lib/znc/.af-version"),
        ("xrdp", "var/lib/xrdp/.af-version"),
        ("x2go", "var/lib/x2go/.af-version"),
        ("netdata", "etc/netdata/.af-version"),
        ("mergerfs", "var/lib/mergerfs/.af-version"),
        ("rclone", "var/lib/rclone/.af-version"),
    ];
    for (pkg, expected_rel_path) in expected_version_paths {
        let recipe = get_declarative_recipe(pkg).unwrap();
        assert!(
            !recipe.update_steps.is_empty(),
            "{pkg} must have non-empty update_steps"
        );
        let root = create_isolated_test_dir(&format!("af-ver-{pkg}"));
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        let mut recipe_to_run = recipe.clone();
        if pkg == "threadfin" {
            let elf_bytes = create_mock_elf_payload_for_arch(4096, 62);
            let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(cache_dir.join("Threadfin_linux_amd64"), &elf_bytes).unwrap();
            let digest = hex::encode(Sha256::digest(&elf_bytes));
            for step in recipe_to_run
                .install_steps
                .iter_mut()
                .chain(recipe_to_run.update_steps.iter_mut())
            {
                if let DeclarativeStep::DownloadBinary { verification, .. } = step {
                    verification.expected_sha256 = Some(digest.clone());
                }
            }
        }
        let runner = MockCommandRunner::default();
        let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
        executor
            .execute_recipe(
                &recipe_to_run,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap();
        assert!(
            root.join(expected_rel_path).is_file(),
            "{pkg} must write /{expected_rel_path}"
        );

        if pkg == "rclone" {
            assert!(root.join("etc/rclone/rclone.env").is_file());
            assert!(root.join("etc/systemd/system/rclone-vfs.service").is_file());
            let rclone_unit =
                fs::read_to_string(root.join("etc/systemd/system/rclone.service")).unwrap();
            assert!(rclone_unit.contains("EnvironmentFile=/etc/rclone/rclone.env"));
            executor
                .execute_recipe(
                    &recipe_to_run,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap();
            assert!(!root.join("etc/systemd/system/rclone.service").exists());
            assert!(!root.join("etc/systemd/system/rclone-vfs.service").exists());
        }
        if matches!(
            pkg,
            "netdata" | "xrdp" | "fail2ban" | "znc" | "x2go" | "mergerfs" | "rclone"
        ) {
            executor
                .execute_recipe(
                    &recipe_to_run,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap();
            assert!(
                !root.join(expected_rel_path).exists(),
                "{pkg} retained-data remove must delete /{expected_rel_path}"
            );
            if pkg == "xrdp" {
                env_cfg.delete_data = true;
                let purge_exec = DeclarativePackageExecutor::with_runner(
                    env_cfg.clone(),
                    MockCommandRunner::default(),
                );
                purge_exec
                    .execute_recipe(
                        &recipe_to_run,
                        PackageAction::Remove,
                        CancellationToken::new(),
                        |_| {},
                    )
                    .await
                    .unwrap();
                assert!(!root.join("var/lib/xrdp").exists());
            }
        }
        if pkg == "mergerfs" {
            assert!(root.join("mnt/unionfs").is_dir());
            assert!(root.join("mnt/mergerfs").is_dir());
            fs::write(root.join("mnt/unionfs/operator-data.txt"), b"keep").unwrap();
            fs::write(root.join("mnt/mergerfs/operator-data.txt"), b"keep").unwrap();
            env_cfg.delete_data = true;
            let purge_exec =
                DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
            purge_exec
                .execute_recipe(
                    &recipe_to_run,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap();
            assert!(root.join("mnt/unionfs/operator-data.txt").is_file());
            assert!(root.join("mnt/mergerfs/operator-data.txt").is_file());
            assert!(!root.join("var/lib/mergerfs").exists());
            assert!(!root.join("etc/mergerfs").exists());
        }
        let _ = fs::remove_dir_all(root);
    }

    // Verify port updates on existing configs for quassel and znc
    for (pkg, new_port) in [("quassel", 14242), ("znc", 16501)] {
        let root = create_isolated_test_dir(&format!("port-update-{pkg}"));
        let recipe = get_declarative_recipe(pkg).unwrap();
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        let exec_initial =
            DeclarativePackageExecutor::with_runner(env_cfg.clone(), MockCommandRunner::default());
        exec_initial
            .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
            .await
            .unwrap();

        if pkg == "quassel" {
            fs::write(
                root.join("etc/default/quasselcore"),
                "START=\"true\"\nUSER=\"quasselcore\"\nLOGLEVEL=\"Debug\"\nLISTEN=\"127.0.0.1\"\nPORT=4242\nCUSTOM_FLAG=\"--require-ssl\"\n",
            )
            .unwrap();
        }

        env_cfg.app_port = new_port;
        let exec_update =
            DeclarativePackageExecutor::with_runner(env_cfg.clone(), MockCommandRunner::default());
        exec_update
            .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
            .await
            .unwrap();

        match pkg {
            "quassel" => {
                let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/quasselcore.service"))
                        .unwrap();
                assert!(default_cfg.contains("PORT=\"14242\""));
                assert!(default_cfg.contains("LOGLEVEL=\"Debug\""));
                assert!(default_cfg.contains("LISTEN=\"127.0.0.1\""));
                assert!(default_cfg.contains("CUSTOM_FLAG=\"--require-ssl\""));
                assert!(unit_cfg.contains("--port=14242"));

                exec_update
                    .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
                    .await
                    .unwrap();
                assert!(root.join("etc/default/quasselcore").is_file());
                assert!(!root.join("var/lib/quassel/.af-version").exists());

                env_cfg.delete_data = true;
                let purge_runner = MockCommandRunner::default();
                let exec_purge =
                    DeclarativePackageExecutor::with_runner(env_cfg, purge_runner.clone());
                exec_purge
                    .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
                    .await
                    .unwrap();
                assert!(!root.join("etc/default/quasselcore").exists());
                assert!(purge_runner.recorded_commands().iter().any(|cmd| {
                    cmd.program == "userdel" && cmd.args.contains(&"quasselcore".to_string())
                }));
            }
            "znc" => {
                let znc_cfg =
                    fs::read_to_string(root.join("var/lib/znc/configs/znc.conf")).unwrap();
                assert!(znc_cfg.contains("Port = 16501"));
            }
            _ => unreachable!(),
        }
        let _ = fs::remove_dir_all(root);
    }
}

#[tokio::test]
async fn canonical_master_credentials() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_user = env::var_os("MASTER_USER");
    let prev_pass = env::var_os("MASTER_PASS");
    let prev_af_user = env::var_os("AETHERFLOW_MASTER_USER");
    let prev_af_pass = env::var_os("AETHERFLOW_MASTER_PASS");
    let prev_creds_file = env::var_os("AETHERFLOW_MASTER_CREDS_FILE");
    env::remove_var("MASTER_USER");
    env::remove_var("MASTER_PASS");
    env::remove_var("AETHERFLOW_MASTER_USER");
    env::remove_var("AETHERFLOW_MASTER_PASS");
    env::remove_var("AETHERFLOW_MASTER_CREDS_FILE");

    // 1. Resolve from /var/lib/aetherflow/.master.creds
    let root_var = create_isolated_test_dir("creds-var-lib");
    let var_creds = root_var.join("var/lib/aetherflow/.master.creds");
    fs::create_dir_all(var_creds.parent().unwrap()).unwrap();
    fs::write(
        &var_creds,
        r#"{"username":"canonical_admin","password":"canonical_var_lib_secret"}"#,
    )
    .unwrap();
    let (u1, p1) = resolve_master_credentials(Some(&root_var));
    assert_eq!(u1, "canonical_admin");
    assert_eq!(p1, "canonical_var_lib_secret");

    // 2. Resolve from AETHERFLOW_MASTER_CREDS_FILE (overrides default file order)
    env::set_var("AETHERFLOW_MASTER_CREDS_FILE", "/etc/aetherflow/custom_creds.json");
    let custom_creds = root_var.join("etc/aetherflow/custom_creds.json");
    fs::create_dir_all(custom_creds.parent().unwrap()).unwrap();
    fs::write(
        &custom_creds,
        r#"{"username":"env_file_user","password":"env_file_secret"}"#,
    )
    .unwrap();
    let (u2, p2) = resolve_master_credentials(Some(&root_var));
    assert_eq!(u2, "env_file_user");
    assert_eq!(p2, "env_file_secret");
    env::remove_var("AETHERFLOW_MASTER_CREDS_FILE");

    // 3. Reject "adminadmin" in earlier files and fall through to /install/.aetherflow.conf,
    // or generate and persist 0600 /var/lib/aetherflow/.master.creds when none exist.
    let root_gen = create_isolated_test_dir("creds-persist");
    let bad_creds = root_gen.join("opt/AetherFlow/backend/data/.master.creds");
    fs::create_dir_all(bad_creds.parent().unwrap()).unwrap();
    fs::write(&bad_creds, r#"{"username":"admin","password":"adminadmin"}"#).unwrap();
    let (u3, p3) = resolve_master_credentials(Some(&root_gen));
    assert_eq!(u3, "admin");
    assert_ne!(p3, "adminadmin");
    assert!(!p3.is_empty());
    let persisted_path = root_gen.join("var/lib/aetherflow/.master.creds");
    assert!(persisted_path.is_file());
    let persisted_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&persisted_path).unwrap()).unwrap();
    assert_eq!(persisted_json["username"], "admin");
    let raw_persisted_pw = persisted_json["password"].as_str().unwrap();
    if af_db::resolve_runtime_aes_key().is_some() {
        assert!(raw_persisted_pw.starts_with("enc:v1:"));
    }
    assert_eq!(
        af_db::decrypt_secret_if_needed(raw_persisted_pw).unwrap(),
        p3
    );
    let (u3_reload, p3_reload) = resolve_master_credentials(Some(&root_gen));
    assert_eq!(u3_reload, "admin");
    assert_eq!(p3_reload, p3);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&persisted_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    match prev_user {
        Some(v) => env::set_var("MASTER_USER", v),
        None => env::remove_var("MASTER_USER"),
    }
    match prev_pass {
        Some(v) => env::set_var("MASTER_PASS", v),
        None => env::remove_var("MASTER_PASS"),
    }
    match prev_af_user {
        Some(v) => env::set_var("AETHERFLOW_MASTER_USER", v),
        None => env::remove_var("AETHERFLOW_MASTER_USER"),
    }
    match prev_af_pass {
        Some(v) => env::set_var("AETHERFLOW_MASTER_PASS", v),
        None => env::remove_var("AETHERFLOW_MASTER_PASS"),
    }
    match prev_creds_file {
        Some(v) => env::set_var("AETHERFLOW_MASTER_CREDS_FILE", v),
        None => env::remove_var("AETHERFLOW_MASTER_CREDS_FILE"),
    }
    let _ = fs::remove_dir_all(root_var);
    let _ = fs::remove_dir_all(root_gen);
}

#[tokio::test]
async fn rclone_legacy_credentials_survive_retained_remove_and_are_erased_on_purge() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-lifecycle");
    let fixture = |logical: &str| root.join(logical.trim_start_matches('/'));
    let credentials = b"# operator settings\nRCLONE_RC_USER=operator\nRCLONE_RC_PASS='retain spaces'\n";
    let paths: [(&str, &[u8]); 9] = [
        ("/etc/aetherflow/rclone.env", credentials),
        ("/etc/aetherflow/aetherflow.env", b"unrelated"),
        ("/etc/rclone/rclone.conf", b"[remote]\ntype = drive\n"),
        ("/etc/rclone/custom.conf", b"custom config"),
        ("/var/lib/rclone/cache/operator", b"retained cache"),
        ("/usr/bin/rclone", b"distro binary"),
        ("/usr/local/bin/rclone", b"operator binary"),
        ("/mnt/remote/sentinel", b"operator data"),
        ("/usr/bin/rclone.af-backup.foreign/sentinel", b"unclaimed archive"),
    ];
    for (logical, content) in paths {
        let path = fixture(logical);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    let old_archive = fixture("/usr/bin/rclone.af-backup.legacy");
    fs::create_dir(&old_archive).unwrap();
    fs::write(old_archive.join(".af-archive-owner"), b"rclone\n").unwrap();
    let canonical = fixture("/etc/rclone/rclone.env");
    let managed = fixture(crate::package_executor::RCLONE_BIN);
    let recipe = get_declarative_recipe("rclone").unwrap();
    let runner = MockCommandRunner::default();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.keep_existing_secrets = true;
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());

    for action in [PackageAction::Install, PackageAction::Remove, PackageAction::Reinstall] {
        executor.execute_recipe(&recipe, action, CancellationToken::new(), |_| {})
            .await.unwrap();
        let content = fs::read_to_string(&canonical).unwrap();
        assert!(content.starts_with(std::str::from_utf8(credentials).unwrap()));
        assert!(content.contains("RCLONE_USER=\"operator\"\nRCLONE_PASS=\"retain spaces\"\n"));
        for (logical, content) in paths {
            assert_eq!(fs::read(fixture(logical)).unwrap(), content, "{logical}");
        }
        assert_eq!(managed.is_file(), action != PackageAction::Remove);
    }
    let unit = fs::read_to_string(fixture("/etc/systemd/system/rclone.service")).unwrap();
    assert!(unit.contains(&format!("ExecStart={} ", crate::package_executor::RCLONE_BIN)));
    let vfs = fs::read_to_string(fixture("/etc/systemd/system/rclone-vfs.service")).unwrap();
    assert!(vfs.contains(&format!("ExecStart={} mount ", crate::package_executor::RCLONE_BIN)));

    env_cfg.delete_data = true;
    DeclarativePackageExecutor::with_runner(env_cfg, runner)
        .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
        .await.unwrap();
    for path in [canonical.clone(), managed, old_archive, fixture("/etc/aetherflow/rclone.env"),
                 fixture("/etc/rclone/rclone.conf"), fixture("/var/lib/rclone")] {
        assert!(!path.exists(), "{}", path.display());
    }
    for index in [1, 3, 5, 6, 7, 8] {
        let (logical, content) = paths[index];
        assert_eq!(fs::read(fixture(logical)).unwrap(), content, "{logical}");
    }
    executor.execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await.unwrap();
    assert!(!fs::read_to_string(canonical).unwrap().contains("retain spaces"));
    assert!(!fixture("/etc/aetherflow/rclone.env").exists());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn rclone_retained_remove_then_explicit_purge_preserves_unrelated_and_rollback_keeps_retained() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-retained-then-purge");
    let fixture = |logical: &str| root.join(logical.trim_start_matches('/'));

    let unrelated: [(&str, &[u8]); 7] = [
        ("/usr/bin/rclone", b"distro binary"),
        ("/usr/local/bin/rclone", b"operator binary"),
        ("/etc/rclone/custom.conf", b"[operator-custom]\n"),
        ("/etc/aetherflow/aetherflow.env", b"GLOBAL_SECRET=keep\n"),
        ("/mnt/remote/sentinel", b"operator mount data"),
        ("/usr/bin/rclone.af-backup.foreign/sentinel", b"unclaimed archive"),
        (
            "/install/.sonarr.retained",
            b"package=sonarr\nstate=retained\nupdated_at=2026-11-22T00:00:00Z\n",
        ),
    ];
    for (logical, content) in unrelated {
        let p = fixture(logical);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    let recipe = get_declarative_recipe("rclone").unwrap();
    let runner = MockCommandRunner::default();
    let base_env = PackageExecutionEnv::isolated(&root);

    // 1. Install rclone -> writes .rclone.lock, no .rclone.retained
    DeclarativePackageExecutor::with_runner(base_env.clone(), runner.clone())
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(fixture("/install/.rclone.lock").is_file());
    assert!(!fixture("/install/.rclone.retained").exists());
    assert!(fixture("/etc/rclone/rclone.conf").is_file());
    assert!(fixture("/etc/rclone/rclone.env").is_file());
    assert!(fixture("/var/lib/rclone").is_dir());

    // 2. Ordinary retained remove (delete_data=false) removes .rclone.lock, writes .rclone.retained,
    //    and preserves managed config/state.
    DeclarativePackageExecutor::with_runner(base_env.clone(), runner.clone())
        .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(!fixture("/install/.rclone.lock").exists());
    assert!(fixture("/install/.rclone.retained").is_file());
    assert!(fixture("/etc/rclone/rclone.conf").is_file());
    assert!(fixture("/etc/rclone/rclone.env").is_file());
    assert!(fixture("/var/lib/rclone").is_dir());

    let retained_insp =
        crate::inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
            .unwrap();
    assert_eq!(
        retained_insp.eligibility,
        crate::PackagePurgeEligibility::RetainedProven
    );
    assert!(retained_insp.receipt_status.is_retained_only());

    // 3. A failed purge preserves .rclone.retained so the operator can retry safely.
    let mut failing_recipe = recipe.clone();
    failing_recipe.remove_steps.push(DeclarativeStep::RunCommand {
        program: "/bin/false".into(),
        args: vec!["purge-fail".into()],
        only_if_delete_data: true,
        ignore_errors: false,
        progress_pct: 99,
        description: "Inject purge failure before receipt commit".into(),
    });
    let mut purge_env = base_env.clone();
    purge_env.delete_data = true;
    let failing_runner = MockCommandRunner {
        fail_program: Some("/bin/false".into()),
        ..Default::default()
    };
    let err = DeclarativePackageExecutor::with_runner(purge_env.clone(), failing_runner)
        .execute_recipe(
            &failing_recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("/bin/false"), "{err}");
    assert!(fixture("/install/.rclone.retained").is_file());

    // 4. Successful explicit purge removes .rclone.retained and managed data while preserving
    //    every unrelated file and other packages' retained receipts.
    DeclarativePackageExecutor::with_runner(purge_env, runner.clone())
        .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    for removed in [
        "/install/.rclone.lock",
        "/install/.rclone.retained",
        "/etc/rclone/rclone.conf",
        "/etc/rclone/rclone.env",
        "/var/lib/rclone",
        crate::package_executor::RCLONE_BIN,
        crate::package_executor::RCLONE_BIN_OWNER,
    ] {
        assert!(!fixture(removed).exists(), "{removed} should be purged");
    }
    for (logical, content) in unrelated {
        assert_eq!(
            fs::read(fixture(logical)).unwrap(),
            content,
            "unrelated path {logical} must be preserved"
        );
    }

    // 5. After purge, rclone is NotPresent even though unrelated files remain on disk.
    let after_purge =
        crate::inspect_package_purge_state("rclone", Some("/install/.rclone.lock"), Some(&root))
            .unwrap();
    assert_eq!(
        after_purge.eligibility,
        crate::PackagePurgeEligibility::NotPresent
    );
    assert!(!after_purge.allows_purge());

    // 6. Reinstalling after retained removal clears .rclone.retained.
    DeclarativePackageExecutor::with_runner(base_env.clone(), runner.clone())
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    DeclarativePackageExecutor::with_runner(base_env.clone(), runner.clone())
        .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(fixture("/install/.rclone.retained").is_file());
    DeclarativePackageExecutor::with_runner(base_env, runner)
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(fixture("/install/.rclone.lock").is_file());
    assert!(!fixture("/install/.rclone.retained").exists());

    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn rclone_failed_migration_restores_unit_and_credentials() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-migration-rollback");
    let legacy = root.join("etc/aetherflow/rclone.env");
    let unit = root.join("etc/systemd/system/rclone.service");
    let distro = root.join("usr/bin/rclone");
    let original: [(&Path, &[u8]); 3] = [
        (&legacy, b"RCLONE_RC_USER=operator\nRCLONE_RC_PASS=legacy\n"),
        (&unit, b"[Service]\nEnvironmentFile=/etc/aetherflow/rclone.env\nExecStart=/usr/bin/rclone rcd --rc-web-gui\n"),
        (&distro, b"distribution binary"),
    ];
    for (path, content) in original {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    let mut recipe = get_declarative_recipe("rclone").unwrap();
    recipe.install_steps.push(DeclarativeStep::RunCommand {
        program: "/bin/false".into(),
        args: vec!["fixture".into()],
        only_if_delete_data: false,
        ignore_errors: false,
        progress_pct: 99,
        description: "Inject a failure after Rclone migration".into(),
    });
    let runner = MockCommandRunner { fail_program: Some("/bin/false".into()), ..Default::default() };
    let executor = DeclarativePackageExecutor::with_runner(PackageExecutionEnv::isolated(&root), runner);
    let error = executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await.unwrap_err();
    assert!(error.to_string().contains("/bin/false"), "{error}");
    for (path, content) in original {
        assert_eq!(fs::read(path).unwrap(), content, "{}", path.display());
    }
    for path in [
        crate::package_executor::RCLONE_BIN,
        crate::package_executor::RCLONE_BIN_OWNER,
        crate::package_executor::RCLONE_ENV,
    ] {
        assert!(!root.join(path.trim_start_matches('/')).exists(), "{path}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn rclone_password_escaping() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-escaping");
    let legacy = root.join("etc/aetherflow/rclone.env");
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    let original = "RCLONE_RC_USER=\"admin\\\"user\"\nRCLONE_RC_PASS=old\n";
    fs::write(&legacy, original).unwrap();
    let recipe = get_declarative_recipe("rclone").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.password = Some(r#"valid"quoted\pass$word`1"#.to_string());
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let env_content = fs::read_to_string(root.join("etc/rclone/rclone.env")).unwrap();
    assert!(
        env_content.contains(r#"RCLONE_RC_USER="admin\"user""#),
        "unexpected rclone.env user line: {env_content}"
    );
    assert!(
        env_content.contains(r#"RCLONE_RC_PASS="valid\"quoted\\pass\$word\`1""#),
        "unexpected rclone.env pass line: {env_content}"
    );

    assert_eq!(fs::read_to_string(legacy).unwrap(), original);
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn failed_dpkg_query() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("failed-dpkg-query");
    let recipe = get_declarative_recipe("znc").unwrap();
    let runner = MockCommandRunner {
        fail_program: Some("dpkg-query".to_string()),
        ..Default::default()
    };
    let executor =
        DeclarativePackageExecutor::with_runner(PackageExecutionEnv::isolated(&root), runner);
    let err = executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("dpkg-query"),
        "expected dpkg-query failure, got: {err}"
    );
    assert!(!root.join("var/lib/znc/.af-version").exists());
    assert!(!root.join("install/.znc.lock").exists());

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn rollback_service_state() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rollback-service-state");
    let recipe = get_declarative_recipe("quassel").unwrap();
    let existing_unit = root.join("etc/systemd/system/quasselcore.service");
    fs::create_dir_all(existing_unit.parent().unwrap()).unwrap();
    let original_unit_body = "[Unit]\nDescription=Existing Active Quassel\n[Service]\nExecStart=/usr/bin/quasselcore --port=4242\n";
    fs::write(&existing_unit, original_unit_body).unwrap();

    // Fail on call 10 (`systemctl enable --now -- quasselcore.service`) after overwriting unit
    let runner = MockCommandRunner {
        fail_on_call: Some(10),
        ..Default::default()
    };
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        runner.clone(),
    );
    let err = executor
        .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await
        .unwrap_err();
    assert!(err.to_string().contains("systemctl"));
    assert_eq!(
        fs::read_to_string(&existing_unit).unwrap(),
        original_unit_body
    );

    let cmds = runner.recorded_commands();
    let fail_idx = cmds
        .iter()
        .position(|c| c.program == "systemctl" && c.args.contains(&"enable".to_string()))
        .expect("systemctl enable must have been attempted");
    let rollback_cmds = &cmds[fail_idx + 1..];
    assert!(
        rollback_cmds
            .iter()
            .any(|c| c.program == "systemctl" && c.args == vec!["daemon-reload".to_string()]),
        "rollback must run systemctl daemon-reload: {rollback_cmds:?}"
    );
    assert!(
        rollback_cmds.iter().any(|c| {
            c.program == "systemctl"
                && c.args == vec!["start".to_string(), "quasselcore.service".to_string()]
        }),
        "rollback must run systemctl start quasselcore.service: {rollback_cmds:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn novnc_credential_format_is_obfuscated_and_roundtrips() {
    // Verify standard RFB/vncpasswd DES test vector ("password" -> [0xdb, 0xd8, 0x3c, 0xfd, 0x72, 0x7a, 0x14, 0x58])
    assert_eq!(
        encode_tigervnc_passwd("password"),
        [0xdb, 0xd8, 0x3c, 0xfd, 0x72, 0x7a, 0x14, 0x58]
    );
    assert_eq!(
        decode_tigervnc_passwd(&encode_tigervnc_passwd("password")).as_deref(),
        Some("password")
    );
    assert_eq!(
        decode_tigervnc_passwd(&encode_tigervnc_passwd("short")).as_deref(),
        Some("short")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_fail2ban_succeeds_when_prometheus_compatibility_symlink_exists() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("native-fail2ban-with-prometheus-alias");
    fs::create_dir_all(root.join("usr/local/bin")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::write(
        root.join("usr/local/bin/prometheus"),
        b"fixture existing runtime\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        root.join("usr/local/bin/prometheus"),
        root.join("usr/bin/prometheus"),
    )
    .unwrap();

    let recipe = get_declarative_recipe("fail2ban").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        MockCommandRunner::default(),
    );
    let outcome = executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await;
    assert!(
        outcome.is_ok(),
        "fail2ban install failed when /usr/bin/prometheus symlink existed: {:?}",
        outcome.err()
    );
    assert!(root.join("install/.fail2ban.lock").is_file());

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn af_aud_002_mergerfs_and_rclone_purge_preflight_and_mountpoint_guard() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("af-aud-002-fuse-preflight");

    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.delete_data = true;
    let runner = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());

    let mergerfs_recipe = get_declarative_recipe("mergerfs").unwrap();
    let unmount_idx = mergerfs_recipe
        .remove_steps
        .iter()
        .position(|s| matches!(
            s,
            DeclarativeStep::UnmountPaths { paths, .. }
                if paths == &vec!["/mnt/unionfs".to_string(), "/mnt/mergerfs".to_string()]
        ))
        .expect("mergerfs uninstall must emit shell-free DeclarativeStep::UnmountPaths preflight");
    assert!(
        !mergerfs_recipe
            .remove_steps
            .iter()
            .any(|s| matches!(s, DeclarativeStep::RunCommand { .. })),
        "mergerfs uninstall must not shell out via RunCommand"
    );
    let remove_idx = mergerfs_recipe
        .remove_steps
        .iter()
        .position(|s| {
            matches!(
                s,
                DeclarativeStep::RemovePaths { paths, only_if_delete_data: true, .. }
                    if paths.iter().any(|p| p == "/var/lib/mergerfs")
            )
        })
        .expect("mergerfs DELETE_DATA=true uninstall must remove /var/lib/mergerfs");
    assert!(
        !mergerfs_recipe.remove_steps.iter().any(|s| matches!(
            s,
            DeclarativeStep::RemovePaths { paths, .. }
                if paths.iter().any(|p| p == "/mnt/unionfs" || p == "/mnt/mergerfs")
        )),
        "mergerfs DELETE_DATA=true uninstall must preserve /mnt/unionfs and /mnt/mergerfs"
    );
    assert!(
        unmount_idx < remove_idx,
        "mergerfs unmount preflight must run before RemovePaths"
    );

    let rclone_recipe = get_declarative_recipe("rclone").unwrap();
    let rclone_cmd_idx = rclone_recipe
        .remove_steps
        .iter()
        .position(|s| matches!(s, DeclarativeStep::RunCommand { .. }))
        .expect("rclone DELETE_DATA=true uninstall must emit DeclarativeStep::RunCommand preflight");
    let rclone_remove_idx = rclone_recipe
        .remove_steps
        .iter()
        .position(|s| matches!(s, DeclarativeStep::RemoveRcloneFiles { .. }))
        .expect("rclone DELETE_DATA=true uninstall must remove AetherFlow files");
    assert!(rclone_cmd_idx < rclone_remove_idx);

    // The mock command leaves /proc/mounts unchanged, simulating an active mount.
    fs::create_dir_all(root.join("mnt/remote")).unwrap();
    fs::write(root.join("mnt/remote/sentinel.txt"), b"keep").unwrap();
    fs::create_dir_all(root.join("proc")).unwrap();
    fs::write(
        root.join("proc/mounts"),
        "rclone:remote /mnt/remote fuse.rclone rw,nosuid,nodev 0 0\n",
    )
    .unwrap();

    let err = executor
        .execute_recipe(
            &rclone_recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("active mountpoint"),
        "expected purge preflight to refuse an active mountpoint, got: {err}"
    );
    assert!(
        root.join("mnt/remote/sentinel.txt").is_file(),
        "sentinel file inside mounted /mnt/remote must not be deleted"
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn af_aud_003_and_004_rclone_password_and_znc_multi_listener_and_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("af-aud-003-004-rclone-znc");

    // 1. ZNC Version = major.minor and preserving secondary <Listener> ports
    let znc_recipe = get_declarative_recipe("znc").unwrap();
    let mut znc_env = PackageExecutionEnv::isolated(&root);
    znc_env.app_port = 6501;
    let znc_runner = MockCommandRunner {
        dpkg_version_stdout: Some("1.9.1-2build1\n".to_string()),
        ..Default::default()
    };
    let znc_exec = DeclarativePackageExecutor::with_runner(znc_env.clone(), znc_runner.clone());
    znc_exec
        .execute_recipe(&znc_recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let znc_conf_path = root.join("var/lib/znc/configs/znc.conf");
    let initial_conf = fs::read_to_string(&znc_conf_path).unwrap();
    assert!(
        initial_conf.contains("Version = 1.9\n"),
        "expected znc.conf Version = 1.9 (major.minor), got: {initial_conf}"
    );

    // Append a secondary <Listener> block on port 6697
    let multi_listener_conf = format!(
        "{}\n<Listener listener1>\n    Port = 6697\n    IPv4 = true\n    SSL = true\n</Listener>\n",
        initial_conf
    );
    fs::write(&znc_conf_path, &multi_listener_conf).unwrap();

    znc_env.app_port = 16501;
    let znc_update = DeclarativePackageExecutor::with_runner(znc_env, znc_runner);
    znc_update
        .execute_recipe(&znc_recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let updated_conf = fs::read_to_string(&znc_conf_path).unwrap();
    assert!(
        updated_conf.contains("Port = 16501"),
        "primary listener port must update to 16501: {updated_conf}"
    );
    assert!(
        updated_conf.contains("Port = 6697"),
        "secondary listener port 6697 must be preserved: {updated_conf}"
    );

    // 2. Rclone preserved rclone.env updates RCLONE_RC_PASS when password is explicitly provided on reinstall
    let rclone_recipe = get_declarative_recipe("rclone").unwrap();
    let mut rclone_env = PackageExecutionEnv::isolated(&root);
    let rclone_exec =
        DeclarativePackageExecutor::with_runner(rclone_env.clone(), MockCommandRunner::default());
    rclone_exec
        .execute_recipe(
            &rclone_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();

    let rclone_env_path = root.join("etc/rclone/rclone.env");
    fs::write(
        &rclone_env_path,
        "RCLONE_RC_USER=\"custom-op\"\nRCLONE_RC_PASS=\"old-pass\"\n",
    )
    .unwrap();

    rclone_env.password = Some("NewExplicitPass2026!".to_string());
    let rclone_reinstall =
        DeclarativePackageExecutor::with_runner(rclone_env, MockCommandRunner::default());
    rclone_reinstall
        .execute_recipe(
            &rclone_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();

    let updated_rclone_env = fs::read_to_string(&rclone_env_path).unwrap();
    assert!(
        updated_rclone_env.contains("RCLONE_RC_USER=\"custom-op\""),
        "custom RCLONE_RC_USER must be preserved: {updated_rclone_env}"
    );
    assert!(
        updated_rclone_env.contains("RCLONE_RC_PASS=\"NewExplicitPass2026!\""),
        "RCLONE_RC_PASS must update when explicit password is supplied: {updated_rclone_env}"
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn f01_reinstall_action_preserves_existing_secrets_in_legacy_and_declarative_paths() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_pass = env::var_os("AF_PASS");
    env::set_var("AF_PASS", "ambient-runner-secret");

    let req = PackageRunnerRequest {
        action: "reinstall".to_string(),
        package_id: "sonarr".to_string(),
        script_name: "installpackage-sonarr".to_string(),
        lifecycle_job_id: "job-reinstall-f01".to_string(),
        app_port: 8989,
        delete_data: false,
        ..Default::default()
    };
    assert_eq!(PackageAction::parse("reinstall"), Some(PackageAction::Reinstall));
    assert_eq!(PackageOperation::parse("reinstall"), Some(PackageOperation::Reinstall));
    assert!(script_matches_package_identity(
        "reinstall",
        "sonarr",
        "installpackage-sonarr"
    ));

    let mut cmd = tokio::process::Command::new("bash");
    apply_legacy_package_environment(&mut cmd, &req);
    let env_map: std::collections::HashMap<String, Option<String>> = cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|val| val.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(
        env_map.get("AF_KEEP_EXISTING_SECRETS").and_then(|v| v.as_deref()),
        Some("1"),
        "reinstall must set AF_KEEP_EXISTING_SECRETS=1"
    );
    assert_eq!(
        env_map.get("AF_LIFECYCLE_ACTION").and_then(|v| v.as_deref()),
        Some("reinstall"),
        "reinstall must set AF_LIFECYCLE_ACTION=reinstall"
    );
    assert_eq!(
        env_map.get("AF_PASS"),
        Some(&None),
        "reinstall must strip ambient AF_PASS from child process environment"
    );

    match prev_pass {
        Some(v) => env::set_var("AF_PASS", v),
        None => env::remove_var("AF_PASS"),
    }
}

#[tokio::test]
async fn afm03_native_rclone_honors_keep_existing_secrets() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_pass = env::var_os("AF_PASS");
    env::set_var("AF_PASS", "ambient-runner-master-secret");

    let root = create_isolated_test_dir("afm03-rclone-keep-secrets");
    let rclone_env_path = root.join("etc/rclone/rclone.env");
    fs::create_dir_all(rclone_env_path.parent().unwrap()).unwrap();
    fs::write(
        &rclone_env_path,
        "RCLONE_RC_USER=\"operator\"\nRCLONE_RC_PASS=\"operator-retained-secret\"\n",
    )
    .unwrap();

    let rclone_recipe = get_declarative_recipe("rclone").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.keep_existing_secrets = true;
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    executor
        .execute_recipe(
            &rclone_recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();

    let preserved = fs::read_to_string(&rclone_env_path).unwrap();
    assert!(
        preserved.contains("RCLONE_RC_PASS=\"operator-retained-secret\""),
        "expected RCLONE_RC_PASS=operator-retained-secret to be preserved when keep_existing_secrets=true, got: {preserved}"
    );
    assert!(
        !preserved.contains("ambient-runner-master-secret"),
        "ambient AF_PASS must never overwrite RCLONE_RC_PASS when keep_existing_secrets=true: {preserved}"
    );

    match prev_pass {
        Some(v) => env::set_var("AF_PASS", v),
        None => env::remove_var("AF_PASS"),
    }
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn afm05_native_recipes_verify_http_readiness_and_reject_missing_listener() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let expected = [
        ("znc", "/"),
        ("rclone", "/metrics"),
        ("netdata", "/api/v1/info"),
        ("threadfin", "/status"),
    ];

    for (pkg_id, expected_path) in expected {
        let recipe = get_declarative_recipe(pkg_id).unwrap();
        assert!(
            recipe.install_steps.iter().any(|s| matches!(
                s,
                DeclarativeStep::WaitForHttpReady { path, .. } if path == expected_path
            )),
            "{pkg_id} install_steps must include WaitForHttpReady({expected_path})"
        );
        assert!(
            recipe.update_steps.iter().any(|s| matches!(
                s,
                DeclarativeStep::WaitForHttpReady { path, .. } if path == expected_path
            )),
            "{pkg_id} update_steps must include WaitForHttpReady({expected_path})"
        );
    }

    struct SilentSuccessRunner;
    impl CommandRunner for SilentSuccessRunner {
        fn run_command<'a>(
            &'a self,
            _program: &'a str,
            _args: &'a [String],
            _env_vars: &'a [(String, String)],
            _cancel: &'a CancellationToken,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }
    }

    let root = create_isolated_test_dir("afm05-netdata-no-listener");
    let netdata_recipe = get_declarative_recipe("netdata").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 19989;
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, SilentSuccessRunner);
    let err = executor
        .execute_recipe(
            &netdata_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await;
    assert!(
        err.is_err(),
        "netdata install without a live listener on port 19989 must fail readiness verification"
    );
    assert!(
        !root.join("install/.netdata.lock").exists(),
        "failed netdata readiness check must not leave lock file behind"
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn f03_default_bash_lifecycle_writes_and_removes_systemd_sandbox_dropin() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("f03-bash-sandbox-dropin");
    fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
    fs::write(root.join("var/lib/sonarr/.af-version"), "4.0.0\n").unwrap();

    ensure_package_sandbox_dropin_under_root(Some(&root), "sonarr", "install").unwrap();
    let dropin = root.join("etc/systemd/system/sonarr.service.d/aetherflow-sandbox.conf");
    assert!(
        dropin.is_file(),
        "expected default Bash install path to write systemd sandbox drop-in at {}",
        dropin.display()
    );

    ensure_package_sandbox_dropin_under_root(Some(&root), "sonarr", "reinstall").unwrap();
    assert!(
        dropin.is_file(),
        "expected default Bash reinstall path to preserve/write systemd sandbox drop-in"
    );

    ensure_package_sandbox_dropin_under_root(Some(&root), "sonarr", "remove").unwrap();
    assert!(
        !dropin.exists(),
        "expected default Bash remove path to delete systemd sandbox drop-in"
    );
    assert!(
        !root.join("var/lib/sonarr/.af-version").exists(),
        "expected default Bash remove path to clean up stale .af-version receipt"
    );

    let _ = fs::remove_dir_all(root);
}
