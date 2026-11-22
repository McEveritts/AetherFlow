use super::*;

fn version_rel_path_for_recipe(pkg_id: &str) -> &'static str {
    match pkg_id {
        "fail2ban" => "etc/fail2ban/.af-version",
        "quassel" => "var/lib/quassel/.af-version",
        "threadfin" => "var/lib/threadfin/.af-version",
        "znc" => "var/lib/znc/.af-version",
        "xrdp" => "var/lib/xrdp/.af-version",
        "x2go" => "var/lib/x2go/.af-version",
        "netdata" => "etc/netdata/.af-version",
        "mergerfs" => "var/lib/mergerfs/.af-version",
        "rclone" => "var/lib/rclone/.af-version",
        other => panic!("unexpected recipe id: {other}"),
    }
}

fn stage_threadfin_cached_binary(
    env_cfg: &PackageExecutionEnv,
    recipe: &mut DeclarativePackageRecipe,
    payload_byte: u8,
) {
    let mut elf_bytes = create_mock_elf_payload_for_arch(1_100_000, 62);
    elf_bytes[512] = payload_byte;
    let cache_dir = env_cfg.artifact_cache_dir.clone().unwrap();
    fs::create_dir_all(&cache_dir).unwrap();
    for name in [
        "Threadfin_linux_amd64_glibc_2.31_compat",
        "Threadfin_linux_amd64_compat",
        "Threadfin_linux_amd64",
    ] {
        fs::write(cache_dir.join(name), &elf_bytes).unwrap();
    }
    let digest = hex::encode(Sha256::digest(&elf_bytes));
    for step in recipe
        .install_steps
        .iter_mut()
        .chain(recipe.update_steps.iter_mut())
    {
        if let DeclarativeStep::DownloadBinary { verification, .. } = step {
            verification.expected_sha256 = Some(digest.clone());
            verification.arch_sha256 = Some(ArchAssetMap {
                amd64: digest.clone(),
                arm64: digest.clone(),
                armhf: Some(digest.clone()),
            });
        }
    }
}

fn seed_operator_state_for_recipe(root: &Path, pkg_id: &str) -> Vec<(PathBuf, String)> {
    let write_sentinel = |rel: &str, content: &str, token: &str| -> (PathBuf, String) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        (path, token.to_string())
    };

    match pkg_id {
            "fail2ban" => vec![write_sentinel(
                "etc/fail2ban/jail.local",
                "[DEFAULT]\nbantime = 7200\n# operator-fail2ban-sentinel\n[sshd]\nenabled = true\nport = ssh\n",
                "operator-fail2ban-sentinel",
            )],
            "quassel" => vec![
                write_sentinel(
                    "etc/default/quasselcore",
                    "START=\"true\"\nUSER=\"quasselcore\"\nLISTEN=\"127.0.0.1\"\nPORT=\"18100\"\nCUSTOM_FLAG=\"--operator-quassel-sentinel\"\n",
                    "--operator-quassel-sentinel",
                ),
                write_sentinel(
                    "var/lib/quassel/quasselCert.pem",
                    "-----BEGIN CERTIFICATE-----\noperator-quassel-cert-sentinel\n-----END CERTIFICATE-----\n",
                    "operator-quassel-cert-sentinel",
                ),
            ],
            "threadfin" => vec![write_sentinel(
                "var/lib/threadfin/conf/settings.json",
                "{\n  \"bindIpAddress\": \"127.0.0.1\",\n  \"custom\": {\n    \"playlist\": \"operator-threadfin-sentinel\"\n  },\n  \"version\": \"0.5.0\"\n}",
                "operator-threadfin-sentinel",
            )],
            "znc" => {
                let znc_conf_path = root.join("var/lib/znc/configs/znc.conf");
                let mut existing = fs::read_to_string(&znc_conf_path).unwrap();
                existing.push_str("\n// operator-znc-conf-sentinel\n");
                fs::write(&znc_conf_path, &existing).unwrap();
                vec![
                    (znc_conf_path, "operator-znc-conf-sentinel".to_string()),
                    write_sentinel(
                        "var/lib/znc/znc.pem",
                        "-----BEGIN CERTIFICATE-----\noperator-znc-pem-sentinel\n-----END CERTIFICATE-----\n",
                        "operator-znc-pem-sentinel",
                    ),
                ]
            }
            "xrdp" => vec![
                write_sentinel(
                    "etc/xrdp/startwm.sh",
                    "#!/bin/sh\n# operator-xrdp-startwm-sentinel\nexec startxfce4\n",
                    "operator-xrdp-startwm-sentinel",
                ),
                write_sentinel(
                    "etc/xrdp/xrdp.ini",
                    "[Globals]\nport=3389\n; operator-xrdp-ini-sentinel\n",
                    "operator-xrdp-ini-sentinel",
                ),
            ],
            "x2go" => vec![write_sentinel(
                "etc/x2go/x2goserver.conf",
                "[limit users]\n# operator-x2go-sentinel\n",
                "operator-x2go-sentinel",
            )],
            "netdata" => vec![write_sentinel(
                "etc/netdata/netdata.conf",
                "[global]\n    history = 86400\n    # operator-netdata-sentinel\n[web]\n    bind to = 127.0.0.1\n    default port = 18100\n",
                "operator-netdata-sentinel",
            )],
            "mergerfs" => vec![write_sentinel(
                "etc/mergerfs/mergerfs.conf",
                "BRANCHES=\"/mnt/mergerfs/local=RW:/mnt/operator-mergerfs-sentinel=RO\"\n",
                "operator-mergerfs-sentinel",
            )],
            "rclone" => vec![
                write_sentinel(
                    "etc/rclone/rclone.conf",
                    "[remote]\ntype = drive\ntoken = operator-rclone-conf-sentinel\n",
                    "operator-rclone-conf-sentinel",
                ),
                write_sentinel(
                    "etc/rclone/rclone.env",
                    "RCLONE_RC_USER=\"operator-rclone-env-sentinel\"\n",
                    "operator-rclone-env-sentinel",
                ),
            ],
            other => panic!("unexpected recipe id: {other}"),
        }
}

#[tokio::test]
async fn test_all_retained_native_recipes_in_place_reinstall_preserves_operator_state_and_updates_version_and_port(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let recipe_ids = list_declarative_recipe_ids();
    assert_eq!(recipe_ids.len(), 9);

    for pkg_id in recipe_ids {
        let root = create_isolated_test_dir(&format!("reinstall-9-{pkg_id}"));
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18100;

        let mut recipe = get_declarative_recipe(&pkg_id).unwrap();
        if pkg_id == "threadfin" {
            stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x11);
        }

        let initial_runner = MockCommandRunner {
            dpkg_version_stdout: Some("2.1.0\n".to_string()),
            ..Default::default()
        };
        let initial_exec = DeclarativePackageExecutor::with_runner(env_cfg.clone(), initial_runner);
        let initial_outcome = initial_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_or_else(|e| panic!("initial install of {pkg_id} failed: {e}"));
        assert!(initial_outcome.lock_present, "{pkg_id}");

        let lock_path = root.join(recipe.lock_file.trim_start_matches('/'));
        let version_path = root.join(version_rel_path_for_recipe(&pkg_id));
        assert!(lock_path.is_file(), "{pkg_id} lock receipt must exist");
        assert!(version_path.is_file(), "{pkg_id} .af-version must exist");

        if pkg_id != "threadfin" {
            assert_eq!(
                fs::read_to_string(&version_path).unwrap().trim(),
                "2.1.0",
                "{pkg_id} initial .af-version"
            );
            assert!(
                fs::read_to_string(&lock_path)
                    .unwrap()
                    .contains("version=2.1.0"),
                "{pkg_id} initial lock version"
            );
        }

        let sentinels = seed_operator_state_for_recipe(&root, &pkg_id);

        // In-place reinstall without removing the package (lock receipt and operator state remain on disk)
        assert!(
            lock_path.is_file(),
            "{pkg_id} lock receipt must remain present prior to in-place reinstall"
        );
        env_cfg.app_port = 18200;
        if pkg_id == "threadfin" {
            stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x22);
        }
        let reinstall_runner = MockCommandRunner {
            dpkg_version_stdout: Some("2.2.0\n".to_string()),
            ..Default::default()
        };
        let reinstall_exec =
            DeclarativePackageExecutor::with_runner(env_cfg.clone(), reinstall_runner.clone());
        let reinstall_outcome = reinstall_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_or_else(|e| panic!("in-place reinstall of {pkg_id} failed: {e}"));
        assert!(reinstall_outcome.lock_present, "{pkg_id}");

        // 1. Verify operator-customized state/secrets were preserved across in-place reinstall
        for (sentinel_path, expected_token) in &sentinels {
            let raw_bytes = fs::read(sentinel_path).unwrap_or_else(|e| {
                panic!(
                    "failed to read preserved state {} for {pkg_id}: {e}",
                    sentinel_path.display()
                )
            });
            let matches_sentinel = String::from_utf8_lossy(&raw_bytes).contains(expected_token)
                || hex::encode(&raw_bytes) == *expected_token;
            assert!(
                matches_sentinel,
                "{pkg_id} in-place reinstall clobbered operator sentinel {expected_token:?} in {}",
                sentinel_path.display()
            );
        }

        // 2. Verify updated version receipt in .af-version and /install/.<pkg>.lock
        let expected_version = if pkg_id == "threadfin" {
            THREADFIN_PINNED_VERSION
        } else {
            "2.2.0"
        };
        assert_eq!(
            reinstall_outcome.resolved_version.as_deref(),
            Some(expected_version),
            "{pkg_id} resolved_version after reinstall"
        );
        assert_eq!(
            fs::read_to_string(&version_path).unwrap().trim(),
            expected_version,
            "{pkg_id} .af-version after reinstall"
        );
        let lock_body = fs::read_to_string(&lock_path).unwrap();
        assert!(
            lock_body.contains(&format!("version={expected_version}")),
            "{pkg_id} lock receipt must record version={expected_version}, got:\n{lock_body}"
        );

        // 3. Verify updated APP_PORT / LISTEN_PORT (18200) is reflected in config/unit files
        match pkg_id.as_str() {
            "quassel" => {
                let default_cfg = fs::read_to_string(root.join("etc/default/quasselcore")).unwrap();
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/quasselcore.service"))
                        .unwrap();
                assert!(default_cfg.contains("PORT=\"18200\""));
                assert!(unit_cfg.contains("--port=18200"));
            }
            "threadfin" => {
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/threadfin.service")).unwrap();
                assert!(unit_cfg.contains("-port=18200"));
            }
            "znc" => {
                let znc_cfg =
                    fs::read_to_string(root.join("var/lib/znc/configs/znc.conf")).unwrap();
                assert!(znc_cfg.contains("Port = 18200"));
            }
            "netdata" => {
                let netdata_cfg =
                    fs::read_to_string(root.join("etc/netdata/netdata.conf")).unwrap();
                assert!(netdata_cfg.contains("default port = 18200"));
                assert!(netdata_cfg.contains("bind to = 127.0.0.1"));
            }
            "rclone" => {
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/rclone.service")).unwrap();
                assert!(unit_cfg.contains("--rc-addr=127.0.0.1:18200"));
            }
            _ => {}
        }

        // 4. Verify `systemctl is-active --quiet` was executed after service activation
        let primary_unit = normalize_unit_filename(&recipe.service_name);
        let cmds = reinstall_runner.recorded_commands();
        assert!(
                cmds.iter().any(|cmd| {
                    cmd.program == "systemctl"
                        && cmd.args
                            == vec![
                                "is-active".to_string(),
                                "--quiet".to_string(),
                                "--".to_string(),
                                primary_unit.clone(),
                            ]
                }),
                "{pkg_id} reinstall must verify post-activation readiness via systemctl is-active --quiet -- {primary_unit}"
            );

        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_all_retained_native_recipes_in_place_reinstall_failure_injection_rolls_back_and_retains_prior_state(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let recipe_ids = list_declarative_recipe_ids();
    assert_eq!(recipe_ids.len(), 9);

    for pkg_id in recipe_ids {
        let root = create_isolated_test_dir(&format!("reinstall-fail-9-{pkg_id}"));
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18100;

        let mut recipe = get_declarative_recipe(&pkg_id).unwrap();
        if pkg_id == "threadfin" {
            stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x11);
        }

        let initial_runner = MockCommandRunner {
            dpkg_version_stdout: Some("2.1.0\n".to_string()),
            ..Default::default()
        };
        let initial_exec = DeclarativePackageExecutor::with_runner(env_cfg.clone(), initial_runner);
        let initial_outcome = initial_exec
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .unwrap_or_else(|e| panic!("initial install of {pkg_id} failed: {e}"));
        assert!(initial_outcome.lock_present, "{pkg_id}");

        let sentinels = seed_operator_state_for_recipe(&root, &pkg_id);
        let lock_path = root.join(recipe.lock_file.trim_start_matches('/'));
        let version_path = root.join(version_rel_path_for_recipe(&pkg_id));

        let mut tracked_paths: Vec<PathBuf> = vec![lock_path.clone(), version_path.clone()];
        for (sentinel_path, _) in &sentinels {
            if !tracked_paths.contains(sentinel_path) {
                tracked_paths.push(sentinel_path.clone());
            }
        }
        for unit_rel in [
            "etc/systemd/system/quasselcore.service",
            "etc/systemd/system/threadfin.service",
            "etc/systemd/system/znc.service",
            "etc/systemd/system/mergerfs.service",
            "etc/systemd/system/rclone.service",
            "etc/systemd/system/rclone-vfs.service",
            "usr/local/bin/threadfin",
        ] {
            let candidate = root.join(unit_rel);
            if candidate.is_file() {
                tracked_paths.push(candidate);
            }
        }

        let snapshots_before: Vec<(PathBuf, Vec<u8>)> = tracked_paths
            .into_iter()
            .map(|p| {
                let bytes = fs::read(&p).unwrap_or_else(|e| {
                    panic!("failed to snapshot {} for {pkg_id}: {e}", p.display())
                });
                (p, bytes)
            })
            .collect();

        // Attempt an in-place reinstall with changed port (18200) and updated version (2.2.0),
        // injecting a post-activation readiness check failure (`systemctl is-active` exit code 3).
        env_cfg.app_port = 18200;
        if pkg_id == "threadfin" {
            stage_threadfin_cached_binary(&env_cfg, &mut recipe, 0x99);
        }
        let failing_runner = MockCommandRunner {
            dpkg_version_stdout: Some("2.2.0\n".to_string()),
            fail_systemctl_is_active: true,
            ..Default::default()
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
            .expect_err(&format!(
                "in-place reinstall of {pkg_id} must fail when systemctl is-active returns 3"
            ));

        match &err {
            PackageExecutorError::StepFailed { step, reason } => {
                assert!(
                    step.starts_with("systemctl is-active"),
                    "expected systemctl is-active failure for {pkg_id}, got step={step}"
                );
                assert!(
                    reason.contains("failed post-activation readiness check"),
                    "unexpected failure reason for {pkg_id}: {reason}"
                );
            }
            other => panic!("expected StepFailed for {pkg_id}, got: {other:?}"),
        }

        // Verify rollback restored all mutated files (version, configs, units, binary) and retained prior lock receipt
        for (path, expected_bytes) in &snapshots_before {
            assert!(
                path.is_file(),
                "{pkg_id} rollback must retain pre-existing file {}",
                path.display()
            );
            let actual_bytes = fs::read(path).unwrap();
            assert_eq!(
                &actual_bytes,
                expected_bytes,
                "{pkg_id} rollback must restore exact prior bytes for {}",
                path.display()
            );
        }

        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_afmp005_wait_for_http_ready_retries_transient_failure_and_succeeds_within_deadline() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("afmp005-http-retry");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 18384;

    let curl_attempts = Arc::new(AtomicUsize::new(0));
    let curl_attempts_clone = curl_attempts.clone();

    #[derive(Clone)]
    struct TransientCurlRunner {
        curl_attempts: Arc<AtomicUsize>,
    }

    impl CommandRunner for TransientCurlRunner {
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
                if program == "curl" {
                    let n = self.curl_attempts.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        return Ok(CommandOutput {
                            exit_code: 7,
                            stdout: String::new(),
                            stderr: format!("curl: (7) Failed to connect on attempt {}", n + 1),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "200\n".to_string(),
                        stderr: String::new(),
                    });
                }
                if program == "dpkg-query" {
                    let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                    let stdout = if wants_status {
                        "installed 1.27.0\n".to_string()
                    } else {
                        "1.27.0\n".to_string()
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

    let recipe = get_declarative_recipe("znc").unwrap();
    let executor = DeclarativePackageExecutor::with_runner(
        env_cfg,
        TransientCurlRunner {
            curl_attempts: curl_attempts_clone,
        },
    );
    let outcome = executor
            .execute_recipe(&recipe, PackageAction::Install, CancellationToken::new(), |_| {})
            .await
            .expect("WaitForHttpReady must succeed when attempt 3 returns 200 OK after 2 transient failures");
    assert!(outcome.lock_present);
    assert_eq!(curl_attempts.load(Ordering::SeqCst), 3);

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_afmp002_native_failed_update_stops_service_restores_state_downgrades_pkg_and_enforces_receipt_honesty(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    #[derive(Clone)]
    struct UpdateRollbackRunner {
        recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
        state_dir: PathBuf,
        fail_stop: bool,
        fail_downgrade: bool,
    }

    impl CommandRunner for UpdateRollbackRunner {
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

                // Simulate service restart migrating the application database to schema-v2
                if program == "systemctl" && args.first().map(String::as_str) == Some("restart") {
                    let _ = fs::write(
                        self.state_dir.join("index-v0.14.0.db"),
                        b"schema-v2-migrated",
                    );
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }

                // Simulate WaitForHttpReady failing after service restart
                if program == "curl" {
                    return Ok(CommandOutput {
                        exit_code: 7,
                        stdout: String::new(),
                        stderr: "curl: (7) Failed to connect".to_string(),
                    });
                }

                if program == "systemctl" && args.first().map(String::as_str) == Some("stop") {
                    if self.fail_stop {
                        return Ok(CommandOutput {
                            exit_code: 1,
                            stdout: String::new(),
                            stderr: "Failed to stop znc.service".to_string(),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }

                if program == "systemctl" && args.first().map(String::as_str) == Some("is-active") {
                    // During forward step (`--quiet`), return 0 (active); during rollback quiescence check (no `--quiet`), return 3 (inactive) unless fail_stop
                    let is_quiet = args.iter().any(|a| a == "--quiet");
                    if is_quiet || self.fail_stop {
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: "active\n".to_string(),
                            stderr: String::new(),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 3,
                        stdout: "inactive\n".to_string(),
                        stderr: String::new(),
                    });
                }

                if program == "apt-get" && args.iter().any(|a| a == "--allow-downgrades") {
                    if self.fail_downgrade {
                        return Ok(CommandOutput {
                            exit_code: 100,
                            stdout: String::new(),
                            stderr: "E: Version '1.0.0' for 'znc' was not found".to_string(),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "downgraded znc to 1.0.0\n".to_string(),
                        stderr: String::new(),
                    });
                }

                if program == "dpkg-query" {
                    let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                    let stdout = if wants_status {
                        "installed 2.0.0\n".to_string()
                    } else {
                        "2.0.0\n".to_string()
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

    env::set_var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS", "2");
    env::set_var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS", "5");

    let recipe = get_declarative_recipe("znc").unwrap();

    // Case 1: Full clean rollback (stop succeeds, state restore succeeds, package downgrade succeeds -> receipt restored to 1.0.0)
    {
        let root = create_isolated_test_dir("afmp002-clean-rollback");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let state_dir = root.join("var/lib/znc");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.znc.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=znc\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/znc.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=ZNC\n[Service]\nExecStart=/usr/bin/znc\n",
        )
        .unwrap();

        let recorded = Arc::new(StdMutex::new(Vec::new()));
        let runner = UpdateRollbackRunner {
            recorded: recorded.clone(),
            state_dir: state_dir.clone(),
            fail_stop: false,
            fail_downgrade: false,
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("update must fail when WaitForHttpReady fails");
        assert!(!err.to_string().contains("incomplete rollback/recovery"));

        // Verify service was stopped before state restoration, state was restored to schema-v1, package was downgraded, and .af-version is 1.0.0
        assert_eq!(
            fs::read(state_dir.join("index-v0.14.0.db")).unwrap(),
            b"schema-v1-original"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join(".af-version"))
                .unwrap()
                .trim(),
            "1.0.0"
        );
        let cmds = recorded.lock().unwrap().clone();
        let stop_pos = cmds
            .iter()
            .position(|c| {
                c.program == "systemctl" && c.args == vec!["stop", "--", "znc.service"]
            })
            .expect("rollback must stop znc.service");
        let downgrade_pos = cmds
            .iter()
            .position(|c| {
                c.program == "apt-get"
                    && c.args.contains(&"--allow-downgrades".to_string())
                    && c.args.contains(&"znc=1.0.0".to_string())
            })
            .expect("rollback must downgrade znc to 1.0.0");
        assert!(stop_pos < downgrade_pos);

        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Package downgrade fails -> receipt honesty gate refuses to restore stale 1.0.0 .af-version receipt
    {
        let root = create_isolated_test_dir("afmp002-downgrade-fails");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let state_dir = root.join("var/lib/znc");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.znc.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=znc\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/znc.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=ZNC\n[Service]\nExecStart=/usr/bin/znc\n",
        )
        .unwrap();

        let recorded = Arc::new(StdMutex::new(Vec::new()));
        let runner = UpdateRollbackRunner {
            recorded,
            state_dir: state_dir.clone(),
            fail_stop: false,
            fail_downgrade: true,
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("update must fail with incomplete rollback error when downgrade fails");
        assert!(
            err.to_string().contains("incomplete rollback/recovery"),
            "expected incomplete rollback error, got: {err}"
        );

        // Receipt honesty rule: since binary downgrade to 1.0.0 failed, .af-version must NOT claim 1.0.0!
        assert_eq!(
                fs::read_to_string(state_dir.join(".af-version")).unwrap().trim(),
                "2.0.0",
                "receipt honesty gate must not restore stale 1.0.0 receipt when binary downgrade failed"
            );

        let _ = fs::remove_dir_all(&root);
    }

    // Case 3: Service stop fails -> refuses to overwrite live mutable state directory and refuses to restore stale .af-version
    {
        let root = create_isolated_test_dir("afmp002-stop-fails");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let state_dir = root.join("var/lib/znc");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.znc.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=znc\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/znc.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=ZNC\n[Service]\nExecStart=/usr/bin/znc\n",
        )
        .unwrap();

        let recorded = Arc::new(StdMutex::new(Vec::new()));
        let runner = UpdateRollbackRunner {
            recorded,
            state_dir: state_dir.clone(),
            fail_stop: true,
            fail_downgrade: false,
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner);
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("update must fail with incomplete rollback error when service stop fails");
        assert!(
            err.to_string().contains("incomplete rollback/recovery"),
            "expected incomplete rollback error, got: {err}"
        );

        // Live mutable state directory must not be overwritten while service is still active, and recovery backup is preserved
        assert_eq!(
            fs::read(state_dir.join("index-v0.14.0.db")).unwrap(),
            b"schema-v2-migrated"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join(".af-version"))
                .unwrap()
                .trim(),
            "2.0.0"
        );

        let _ = fs::remove_dir_all(&root);
    }

    env::remove_var("AETHERFLOW_HTTP_READY_MAX_ATTEMPTS");
    env::remove_var("AETHERFLOW_HTTP_READY_RETRY_DELAY_MS");
}

