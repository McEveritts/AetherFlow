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
    assert_eq!(install.resolved_version.as_deref(), Some("0.14.2"));
    let commands = runner.recorded_commands();
    assert!(commands.iter().any(|command| command.program == "apt-get"
        && command.args.contains(&"install".into())
        && command.args.contains(&apt_package.into())), "{package}");
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
    assert!(runner.recorded_commands().iter().any(|command| command.program == "apt-get"
        && command.args.contains(&"purge".into())
        && command.args.contains(&apt_package.into())), "{package}");
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
catalog_recipe_lifecycle_test!(catalog_novnc_lifecycle, "novnc", "novnc", "novnc.service",
    "/var/lib/novnc/operator-password", "fixture retained desktop password\n");
catalog_recipe_lifecycle_test!(catalog_x2go_lifecycle, "x2go", "x2goserver", "x2goserver.service",
    "/etc/x2go/operator-session.conf", "fixture custom session settings\n");
catalog_recipe_lifecycle_test!(catalog_prometheus_lifecycle, "prometheus", "prometheus", "prometheus.service",
    "/etc/prometheus/prometheus.yml", "scrape_configs: []\n# retained fixture scrape credentials\n");
catalog_recipe_lifecycle_test!(catalog_netdata_lifecycle, "netdata", "netdata", "netdata.service",
    "/etc/netdata/netdata.conf", "[global]\n    history = 86400\n[plugins]\n    fixture = retained\n");
catalog_recipe_lifecycle_test!(catalog_mergerfs_lifecycle, "mergerfs", "mergerfs", "mergerfs.service",
    "/etc/mergerfs/mergerfs.conf", "BRANCHES=\"/mnt/operator-source\"\n");
catalog_recipe_lifecycle_test!(catalog_rclone_lifecycle, "rclone", "rclone", "rclone.service",
    "/etc/rclone/rclone.conf", "[fixture]\ntype = drive\ntoken = retained-fixture-token\n");
catalog_recipe_lifecycle_test!(catalog_syncthing_lifecycle, "syncthing", "syncthing", "syncthing.service",
    "/var/lib/syncthing/.config/syncthing/config.xml", "<configuration>fixture existing identity</configuration>\n");

#[tokio::test]
async fn catalog_apt_failure_preserves_receipts_and_existing_configuration() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    for package in ["znc", "xrdp", "novnc", "x2go", "prometheus", "netdata", "mergerfs", "rclone", "syncthing"] {
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

    let creds_path = root_a.join("opt/AetherFlow/logs/znc_credentials.txt");
    assert!(creds_path.is_file());
    let creds = fs::read_to_string(&creds_path).unwrap();
    assert!(creds.contains("ZNC Admin User: admin\nZNC Admin Password: "));
    assert!(!creds.contains("aetherflow-bootstrap"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&creds_path).unwrap().permissions().mode() & 0o777,
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
    let _ = fs::remove_dir_all(root_a);
    let _ = fs::remove_dir_all(root_b);
}

#[tokio::test]
async fn catalog_all_twelve_recipes_have_af_version_receipts_companion_units_and_port_updates() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let expected_version_paths = [
        ("fail2ban", "etc/fail2ban/.af-version"),
        ("quassel", "var/lib/quassel/.af-version"),
        ("threadfin", "var/lib/threadfin/.af-version"),
        ("znc", "var/lib/znc/.af-version"),
        ("xrdp", "var/lib/xrdp/.af-version"),
        ("novnc", "etc/novnc/.af-version"),
        ("x2go", "var/lib/x2go/.af-version"),
        ("prometheus", "etc/prometheus/.af-version"),
        ("netdata", "etc/netdata/.af-version"),
        ("mergerfs", "var/lib/mergerfs/.af-version"),
        ("rclone", "var/lib/rclone/.af-version"),
        ("syncthing", "var/lib/syncthing/.af-version"),
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
            assert!(rclone_unit.contains("EnvironmentFile=-/etc/rclone/rclone.env"));
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
        if pkg == "novnc" {
            assert!(root.join("etc/systemd/system/novnc-xvnc.service").is_file());
            env_cfg.delete_data = true;
            let purge_runner = MockCommandRunner::default();
            let purge_exec =
                DeclarativePackageExecutor::with_runner(env_cfg.clone(), purge_runner.clone());
            purge_exec
                .execute_recipe(
                    &recipe_to_run,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap();
            assert!(purge_runner.recorded_commands().iter().any(|cmd| {
                cmd.program == "userdel" && cmd.args.contains(&"novnc".to_string())
            }));
        }
        if pkg == "prometheus" {
            assert!(root.join("etc/systemd/system/node_exporter.service").is_file());
            let cmds = runner.recorded_commands();
            assert!(cmds.iter().any(|cmd| {
                cmd.program == "systemctl"
                    && cmd.args.contains(&"stop".to_string())
                    && cmd.args.contains(&"prometheus-node-exporter.service".to_string())
            }));
            assert!(!cmds.iter().any(|cmd| {
                cmd.program == "systemctl"
                    && cmd.args.contains(&"enable".to_string())
                    && cmd.args.contains(&"--now".to_string())
                    && cmd.args.contains(&"prometheus-node-exporter.service".to_string())
            }));
            assert!(cmds.iter().any(|cmd| {
                cmd.program == "systemctl"
                    && cmd.args.contains(&"enable".to_string())
                    && cmd.args.contains(&"--now".to_string())
                    && cmd.args.contains(&"node_exporter.service".to_string())
            }));
            assert!(cmds.iter().any(|cmd| {
                cmd.program == "systemctl"
                    && cmd.args.contains(&"enable".to_string())
                    && cmd.args.contains(&"--now".to_string())
                    && cmd.args.contains(&"prometheus.service".to_string())
            }));
            executor
                .execute_recipe(
                    &recipe_to_run,
                    PackageAction::Remove,
                    CancellationToken::new(),
                    |_| {},
                )
                .await
                .unwrap();
            assert!(!root.join("etc/systemd/system/node_exporter.service").exists());
        }
        if matches!(
            pkg,
            "netdata" | "xrdp" | "fail2ban" | "znc" | "x2go" | "mergerfs" | "rclone" | "syncthing"
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
            assert!(!root.join("mnt/unionfs").exists());
            assert!(!root.join("mnt/mergerfs").exists());
            assert!(!root.join("var/lib/mergerfs").exists());
        }
        let _ = fs::remove_dir_all(root);
    }

    // Verify port updates on existing configs for quassel, znc, and prometheus
    for (pkg, new_port) in [("quassel", 14242), ("znc", 16501), ("prometheus", 19090)] {
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
            "prometheus" => {
                let default_cfg =
                    fs::read_to_string(root.join("etc/default/prometheus")).unwrap();
                let yml_cfg =
                    fs::read_to_string(root.join("etc/prometheus/prometheus.yml")).unwrap();
                assert!(default_cfg.contains("--web.listen-address=127.0.0.1:19090"));
                assert!(yml_cfg.contains("127.0.0.1:19090"));
                assert!(yml_cfg.contains("127.0.0.1:9100"));
            }
            _ => unreachable!(),
        }
        let _ = fs::remove_dir_all(root);
    }
}

#[tokio::test]
async fn novnc_auth_downgrade() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_pass = env::var_os("MASTER_PASS");
    env::set_var("MASTER_PASS", "S3cr3tVncPass!2026");

    let root = create_isolated_test_dir("novnc-auth-probe");
    let recipe = get_declarative_recipe("novnc").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        MockCommandRunner::default(),
    );
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let vnc_dir = root.join("var/lib/novnc/.vnc");
    assert!(vnc_dir.is_dir());
    let passwd_path = vnc_dir.join("passwd");
    assert!(passwd_path.is_file());
    let bytes = fs::read(&passwd_path).unwrap();
    assert_eq!(bytes.len(), 8);
    assert_ne!(bytes.as_slice(), b"S3cr3tVncPass!2026\n");
    assert_eq!(
        decode_tigervnc_passwd(&bytes).as_deref(),
        Some("S3cr3tVn")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&vnc_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&passwd_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Verify a valid retained 8-byte obfuscated VNC password is preserved on update/reinstall
    env::set_var("MASTER_PASS", "DifferentPass!2026");
    executor
        .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    let retained_bytes = fs::read(&passwd_path).unwrap();
    assert_eq!(retained_bytes.len(), 8);
    assert_ne!(retained_bytes.as_slice(), b"S3cr3tVncPass!2026\n");
    assert_eq!(
        decode_tigervnc_passwd(&retained_bytes).as_deref(),
        Some("S3cr3tVn")
    );

    // Verify a legacy plaintext /var/lib/novnc/.vnc/passwd is upgraded to 8-byte obfuscated format
    env::set_var("MASTER_PASS", "S3cr3tVncPass!2026");
    fs::write(&passwd_path, b"S3cr3tVncPass!2026\n").unwrap();
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    let upgraded_bytes = fs::read(&passwd_path).unwrap();
    assert_eq!(upgraded_bytes.len(), 8);
    assert_ne!(upgraded_bytes.as_slice(), b"S3cr3tVncPass!2026\n");
    assert_eq!(
        decode_tigervnc_passwd(&upgraded_bytes).as_deref(),
        Some("S3cr3tVn")
    );

    let xvnc_unit =
        fs::read_to_string(root.join("etc/systemd/system/novnc-xvnc.service")).unwrap();
    assert!(!xvnc_unit.contains("-SecurityTypes None"));
    assert!(xvnc_unit.contains("-PasswordFile /var/lib/novnc/.vnc/passwd"));
    assert!(xvnc_unit.contains("-SecurityTypes VncAuth,TLSVnc"));
    assert!(xvnc_unit.contains("ExecStartPost=/bin/sh /var/lib/novnc/.vnc/xstartup"));

    match prev_pass {
        Some(v) => env::set_var("MASTER_PASS", v),
        None => env::remove_var("MASTER_PASS"),
    }
    let _ = fs::remove_dir_all(root);
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
    assert_eq!(persisted_json["password"], p3);
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
async fn rclone_password_escaping() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_user = env::var_os("MASTER_USER");
    let prev_pass = env::var_os("MASTER_PASS");
    env::set_var("MASTER_USER", r#"admin"user"#);
    env::set_var("MASTER_PASS", r#"valid"quoted\pass$word`1"#);

    let root = create_isolated_test_dir("rclone-escaping");
    let recipe = get_declarative_recipe("rclone").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        MockCommandRunner::default(),
    );
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

    match prev_user {
        Some(v) => env::set_var("MASTER_USER", v),
        None => env::remove_var("MASTER_USER"),
    }
    match prev_pass {
        Some(v) => env::set_var("MASTER_PASS", v),
        None => env::remove_var("MASTER_PASS"),
    }
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

    // Fail on call 9 (`systemctl enable --now -- quasselcore.service`) after overwriting unit
    let runner = MockCommandRunner {
        fail_on_call: Some(9),
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

#[tokio::test]
async fn prometheus_version_path() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("prometheus-bin-parity");
    let usr_bin = root.join("usr/bin");
    fs::create_dir_all(&usr_bin).unwrap();
    fs::write(usr_bin.join("prometheus"), b"#!/bin/sh\necho 'prometheus, version 2.53.0'\n")
        .unwrap();
    fs::write(
        usr_bin.join("prometheus-node-exporter"),
        b"#!/bin/sh\necho 'node_exporter, version 1.8.2'\n",
    )
    .unwrap();

    let recipe = get_declarative_recipe("prometheus").unwrap();
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor =
        DeclarativePackageExecutor::with_runner(env_cfg.clone(), MockCommandRunner::default());
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let local_prom = root.join("usr/local/bin/prometheus");
    let local_node = root.join("usr/local/bin/node_exporter");
    assert!(local_prom.is_file());
    assert!(local_node.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&local_prom).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&local_node).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    executor
        .execute_recipe(&recipe, PackageAction::Remove, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(!local_prom.exists());
    assert!(!local_node.exists());

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn novnc_credential_format_is_obfuscated_and_roundtrips() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_user = env::var_os("MASTER_USER");
    let prev_pass = env::var_os("MASTER_PASS");
    let prev_af_pass = env::var_os("AETHERFLOW_MASTER_PASS");
    let prev_vnc_pass = env::var_os("AETHERFLOW_VNC_PASSWORD");

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

    env::remove_var("AETHERFLOW_MASTER_PASS");
    env::set_var("MASTER_USER", "audit-fixture");
    env::set_var("MASTER_PASS", "test-test-test-test");
    env::set_var("AETHERFLOW_VNC_PASSWORD", "test-test-test-test");

    let root = create_isolated_test_dir("novnc-credential-format");
    let recipe = get_declarative_recipe("novnc").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&root),
        MockCommandRunner::default(),
    );
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let passwd_path = root.join("var/lib/novnc/.vnc/passwd");
    let bytes = fs::read(&passwd_path).unwrap();
    assert_eq!(bytes.len(), 8);
    assert_ne!(bytes.as_slice(), b"test-test-test-test\n");
    assert_eq!(
        decode_tigervnc_passwd(&bytes).as_deref(),
        Some("test-tes")
    );

    match prev_user {
        Some(v) => env::set_var("MASTER_USER", v),
        None => env::remove_var("MASTER_USER"),
    }
    match prev_pass {
        Some(v) => env::set_var("MASTER_PASS", v),
        None => env::remove_var("MASTER_PASS"),
    }
    match prev_af_pass {
        Some(v) => env::set_var("AETHERFLOW_MASTER_PASS", v),
        None => env::remove_var("AETHERFLOW_MASTER_PASS"),
    }
    match prev_vnc_pass {
        Some(v) => env::set_var("AETHERFLOW_VNC_PASSWORD", v),
        None => env::remove_var("AETHERFLOW_VNC_PASSWORD"),
    }
    let _ = fs::remove_dir_all(root);
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
async fn prometheus_mixed_engine_update_syncs_usr_local_bin_runtime() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let prev_prom_ver = env::var_os("PROMETHEUS_VERSION");
    env::set_var("PROMETHEUS_VERSION", "3.0.0");

    let root = create_isolated_test_dir("prometheus-mixed-engine-update");
    fs::create_dir_all(root.join("usr/local/bin")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    fs::create_dir_all(root.join("etc/prometheus")).unwrap();

    let unit = "[Service]\nExecStart=/usr/local/bin/prometheus --storage.tsdb.path=/var/lib/prometheus\n";
    fs::write(root.join("etc/systemd/system/prometheus.service"), unit).unwrap();
    fs::write(
        root.join("usr/local/bin/prometheus"),
        b"fixture existing runtime 2.0.0\n",
    )
    .unwrap();
    fs::write(
        root.join("usr/local/bin/node_exporter"),
        b"fixture existing node runtime 2.0.0\n",
    )
    .unwrap();
    fs::write(root.join("etc/prometheus/.af-version"), b"2.0.0\n").unwrap();
    fs::write(
        root.join("usr/bin/prometheus"),
        b"fixture apt runtime 3.0.0\n",
    )
    .unwrap();
    fs::write(
        root.join("usr/bin/prometheus-node-exporter"),
        b"fixture apt node runtime 3.0.0\n",
    )
    .unwrap();

    let recipe = get_declarative_recipe("prometheus").unwrap();
    let env_cfg = PackageExecutionEnv::isolated(&root);

    // 1. Test forced failure after AptInstall during Update rolls back /usr/local/bin/prometheus to 2.0.0
    let failing_runner = MockCommandRunner {
        dpkg_version_stdout: Some("3.0.0-1\n".to_string()),
        fail_systemctl_is_active: true,
        ..Default::default()
    };
    let failing_exec = DeclarativePackageExecutor::with_runner(env_cfg.clone(), failing_runner);
    let err = failing_exec
        .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await;
    assert!(err.is_err(), "forced failure after AptInstall must return Err");
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/prometheus")).unwrap(),
        "fixture existing runtime 2.0.0\n",
        "/usr/local/bin/prometheus must roll back to 2.0.0 when a later step fails"
    );
    assert_eq!(
        fs::read_to_string(root.join("etc/prometheus/.af-version")).unwrap(),
        "2.0.0\n",
        "/etc/prometheus/.af-version must roll back to 2.0.0 when a later step fails"
    );

    // 2. Test Update succeeds and syncs /usr/local/bin/prometheus and /etc/prometheus/.af-version to 3.0.0
    let runner = MockCommandRunner {
        dpkg_version_stdout: Some("3.0.0-1\n".to_string()),
        ..Default::default()
    };
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), runner.clone());
    executor
        .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(root.join("etc/prometheus/.af-version")).unwrap(),
        "3.0.0\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/prometheus")).unwrap(),
        "fixture apt runtime 3.0.0\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/node_exporter")).unwrap(),
        "fixture apt node runtime 3.0.0\n"
    );

    // 3. Test Install (retained reinstall) also syncs /usr/local/bin/prometheus to 3.0.0
    fs::write(
        root.join("usr/local/bin/prometheus"),
        b"fixture existing runtime 2.0.0\n",
    )
    .unwrap();
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(root.join("etc/prometheus/.af-version")).unwrap(),
        "3.0.0\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("usr/local/bin/prometheus")).unwrap(),
        "fixture apt runtime 3.0.0\n"
    );

    match prev_prom_ver {
        Some(v) => env::set_var("PROMETHEUS_VERSION", v),
        None => env::remove_var("PROMETHEUS_VERSION"),
    }
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn sol_04_prometheus_preserved_default_injects_listen_address_when_missing() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("sol-04-prometheus-preserved-default");
    let default_path = root.join("etc/default/prometheus");
    fs::create_dir_all(default_path.parent().unwrap()).unwrap();

    // Case 1: existing /etc/default/prometheus has ARGS="" without --web.listen-address
    fs::write(&default_path, "ARGS=\"\"\n").unwrap();

    let recipe = get_declarative_recipe("prometheus").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 19876;
    let executor =
        DeclarativePackageExecutor::with_runner(env_cfg.clone(), MockCommandRunner::default());
    executor
        .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let updated = fs::read_to_string(&default_path).unwrap();
    assert!(
        updated.contains("--web.listen-address=127.0.0.1:19876"),
        "expected /etc/default/prometheus with ARGS=\"\" to gain --web.listen-address=127.0.0.1:19876, got: {updated}"
    );

    // Case 2: existing /etc/default/prometheus has custom flags in ARGS without --web.listen-address
    fs::write(&default_path, "ARGS=\"--storage.tsdb.retention.time=15d\"\n").unwrap();
    env_cfg.app_port = 19877;
    let executor2 =
        DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    executor2
        .execute_recipe(&recipe, PackageAction::Update, CancellationToken::new(), |_| {})
        .await
        .unwrap();

    let updated2 = fs::read_to_string(&default_path).unwrap();
    assert!(
        updated2.contains("--storage.tsdb.retention.time=15d")
            && updated2.contains("--web.listen-address=127.0.0.1:19877"),
        "expected existing ARGS flags to be preserved alongside injected --web.listen-address, got: {updated2}"
    );

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
    let run_cmd_idx = mergerfs_recipe
        .remove_steps
        .iter()
        .position(|s| matches!(s, DeclarativeStep::RunCommand { .. }))
        .expect("mergerfs DELETE_DATA=true uninstall must emit DeclarativeStep::RunCommand preflight");
    let remove_idx = mergerfs_recipe
        .remove_steps
        .iter()
        .position(|s| {
            matches!(
                s,
                DeclarativeStep::RemovePaths { paths, .. }
                    if paths.iter().any(|p| p == "/mnt/unionfs" || p == "/mnt/mergerfs")
            )
        })
        .expect("mergerfs DELETE_DATA=true uninstall must remove /mnt/unionfs and /mnt/mergerfs");
    assert!(
        run_cmd_idx < remove_idx,
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
        .position(|s| {
            matches!(
                s,
                DeclarativeStep::RemovePaths { paths, .. }
                    if paths.iter().any(|p| p == "/mnt/remote")
            )
        })
        .expect("rclone DELETE_DATA=true uninstall must include /mnt/remote in RemovePaths");
    assert!(
        rclone_cmd_idx < rclone_remove_idx,
        "rclone unmount preflight must run before RemovePaths"
    );

    // Verify RemovePaths refuses to traverse a path listed as active in /proc/mounts
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
        "expected RemovePaths to refuse active mountpoint, got: {err}"
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
        ("syncthing", "/rest/noauth/health"),
        ("prometheus", "/-/healthy"),
        ("rclone", "/metrics"),
        ("netdata", "/api/v1/info"),
        ("novnc", "/vnc.html"),
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

    let root = create_isolated_test_dir("afm05-syncthing-no-listener");
    let syncthing_recipe = get_declarative_recipe("syncthing").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 19989;
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, SilentSuccessRunner);
    let err = executor
        .execute_recipe(
            &syncthing_recipe,
            PackageAction::Install,
            CancellationToken::new(),
            |_| {},
        )
        .await;
    assert!(
        err.is_err(),
        "syncthing install without a live listener on port 19989 must fail readiness verification"
    );
    assert!(
        !root.join("install/.syncthing.lock").exists(),
        "failed syncthing readiness check must not leave lock file behind"
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
