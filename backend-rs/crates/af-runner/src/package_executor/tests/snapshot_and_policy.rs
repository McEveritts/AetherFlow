use super::*;

#[tokio::test]
async fn test_pc04_cumulative_snapshot_ceiling_rejects_before_copy_across_multiple_state_dirs() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("pc04-cumulative-ceiling");

    let var_lib_znc = root.join("var/lib/znc");
    let etc_znc = root.join("etc/znc");
    fs::create_dir_all(&var_lib_znc).unwrap();
    fs::create_dir_all(&etc_znc).unwrap();

    // Seed prior app data alongside two sparse files that individually fit under 2 GiB
    // but cumulatively exceed the default 2 GiB ceiling.
    fs::write(var_lib_znc.join("znc.conf"), b"<prior-data/>").unwrap();
    fs::File::create(var_lib_znc.join("index-a.db"))
        .unwrap()
        .set_len(1100 * 1024 * 1024)
        .unwrap();
    fs::File::create(etc_znc.join("index-b.db"))
        .unwrap()
        .set_len(1100 * 1024 * 1024)
        .unwrap();

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let err = journal
        .stage_directory_snapshots_with_cancel(&[var_lib_znc.clone(), etc_znc.clone()], None)
        .unwrap_err();
    assert!(
        matches!(&err, PackageExecutorError::ExecutionError(msg) if msg.contains("2147483648-byte copy ceiling")),
        "unexpected error: {err:?}"
    );
    assert!(journal.dir_snapshots.is_empty());

    // Ensure preflight rejected before copying either directory (no .bak-af-state.* created).
    for parent in [root.join("var/lib"), root.join("etc")] {
        let has_backup = fs::read_dir(&parent)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".bak-af-state."));
        assert!(
            !has_backup,
            "must not create backup directory in {}",
            parent.display()
        );
    }

    // End-to-end declarative executor path must reject before mutating prior app data.
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, MockCommandRunner::default());
    let recipe = get_declarative_recipe("znc").unwrap();
    let exec_err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&exec_err, PackageExecutorError::ExecutionError(msg) if msg.contains("2147483648-byte copy ceiling")),
        "unexpected executor error: {exec_err:?}"
    );
    assert_eq!(
        fs::read(var_lib_znc.join("znc.conf")).unwrap(),
        b"<prior-data/>"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_pc04_incremental_snapshot_admission_free_space_and_budget() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("pc04-incremental-admission");
    let dir_a = root.join("var/lib/app-a");
    let dir_b = root.join("var/lib/app-b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();
    fs::write(dir_a.join("a.bin"), vec![b'A'; 600]).unwrap();
    fs::write(dir_b.join("b.bin"), vec![b'B'; 600]).unwrap();

    {
        let _env = EnvVarGuard::new(&[
            ("AETHERFLOW_MAX_SNAPSHOT_BYTES", Some("1024")),
            ("AETHERFLOW_TEST_FORCE_DISK_FULL", None),
        ]);
        let mut journal = RollbackJournal::new(Some(root.clone()));
        journal.stage_directory_snapshot(&dir_a).unwrap();
        let err = journal.stage_directory_snapshot(&dir_b).unwrap_err();
        assert!(
            matches!(&err, PackageExecutorError::ExecutionError(msg) if msg.contains("1024-byte copy ceiling")),
            "expected cumulative ceiling failure, got: {err:?}"
        );
        assert_eq!(journal.dir_snapshots.len(), 1);
        journal.commit();
    }

    {
        let _env = EnvVarGuard::new(&[
            ("AETHERFLOW_MAX_SNAPSHOT_BYTES", None),
            ("AETHERFLOW_TEST_FORCE_DISK_FULL", Some("1")),
        ]);
        let mut journal = RollbackJournal::new(Some(root.clone()));
        let err = journal.stage_directory_snapshot(&dir_a).unwrap_err();
        assert!(
            matches!(&err, PackageExecutorError::ExecutionError(msg) if msg.contains("Insufficient disk space to snapshot")),
            "expected insufficient disk space failure, got: {err:?}"
        );
        assert!(journal.dir_snapshots.is_empty());
    }

    // Direct copy_dir_snapshot_recursive budget enforcement (TOCTOU growth guard).
    let dst = root.join("var/lib/app-a.copy");
    let mut tight_budget = SnapshotBudget::new(100);
    let copy_err =
        copy_dir_snapshot_recursive(&dir_a, &dst, Some(&root), Some(&mut tight_budget), None)
            .unwrap_err();
    assert!(
        matches!(&copy_err, PackageExecutorError::ExecutionError(msg) if msg.contains("exceeded the copy budget")),
        "expected budget failure, got: {copy_err:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
#[cfg(unix)]
async fn test_pc04_snapshot_retains_nofollow_cancellation_and_rollback_restore() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("pc04-nofollow-cancel-rollback");

    // 1. No-follow policy rejects symlinks inside snapshotted dir and cleans up partial staging.
    let symlink_dir = root.join("var/lib/sym-app");
    fs::create_dir_all(&symlink_dir).unwrap();
    fs::write(symlink_dir.join("a.txt"), b"ok").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", symlink_dir.join("escape")).unwrap();

    let mut sym_journal = RollbackJournal::new(Some(root.clone()));
    let sym_err = sym_journal
        .stage_directory_snapshot(&symlink_dir)
        .unwrap_err();
    assert!(
        matches!(sym_err, PackageExecutorError::SecurityViolation(_)),
        "expected SecurityViolation for symlink entry, got: {sym_err:?}"
    );
    assert!(sym_journal.dir_snapshots.is_empty());

    // 2. Pre-cancelled token aborts before creating backups and preserves prior data.
    let app_dir = root.join("var/lib/clean-app");
    fs::create_dir_all(&app_dir).unwrap();
    fs::write(app_dir.join("state.db"), b"prior-app-data").unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let mut cancel_journal = RollbackJournal::new(Some(root.clone()));
    let cancel_err = cancel_journal
        .stage_directory_snapshots_with_cancel(
            std::slice::from_ref(&app_dir),
            Some((&cancelled, "clean-app")),
        )
        .unwrap_err();
    assert!(matches!(cancel_err, PackageExecutorError::Cancelled(_)));
    assert!(cancel_journal.dir_snapshots.is_empty());
    assert_eq!(
        fs::read(app_dir.join("state.db")).unwrap(),
        b"prior-app-data"
    );

    // 3. Rollback restore must succeed even if capture limit is later tightened.
    {
        let _env = EnvVarGuard::new(&[
            ("AETHERFLOW_MAX_SNAPSHOT_BYTES", Some("4096")),
            ("AETHERFLOW_TEST_FORCE_DISK_FULL", None),
        ]);
        let mut rb_journal = RollbackJournal::new(Some(root.clone()));
        rb_journal.stage_directory_snapshot(&app_dir).unwrap();
        fs::write(app_dir.join("state.db"), b"mutated-before-failure").unwrap();

        env::set_var("AETHERFLOW_MAX_SNAPSHOT_BYTES", "4");
        let _notes = rb_journal.rollback(&MockCommandRunner::default()).await;
        assert!(rb_journal.incomplete_rollback_error.is_none());
        assert_eq!(
            fs::read(app_dir.join("state.db")).unwrap(),
            b"prior-app-data"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn threadfin_and_pihole_exact_version_policy_fails_closed_before_mutation() {
    use futures::StreamExt;

    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let _guard = EnvVarGuard::new(&[
        ("AETHERFLOW_THREADFIN_SHA256", None),
        ("THREADFIN_SHA256", None),
        ("AF_THREADFIN_SHA256", None),
        ("AETHERFLOW_PACKAGE_SHA256_OVERRIDE", None),
        ("AETHERFLOW_THREADFIN_VERSION", None),
        ("THREADFIN_VERSION", None),
        ("AF_THREADFIN_VERSION", None),
        ("AETHERFLOW_PACKAGE_VERSION_OVERRIDE", None),
        ("AF_TARGET_VERSION", None),
    ]);

    // 1. Threadfin pinned target validation accepts 1.2.37/v1.2.37 and rejects unpinned targets
    assert_eq!(
        validate_threadfin_target_policy(None).unwrap().0,
        THREADFIN_PINNED_VERSION
    );
    assert_eq!(
        validate_threadfin_target_policy(Some("1.2.37")).unwrap().0,
        THREADFIN_PINNED_VERSION
    );
    assert_eq!(
        validate_threadfin_target_policy(Some("v1.2.37")).unwrap().0,
        THREADFIN_PINNED_VERSION
    );
    assert!(validate_threadfin_target_policy(Some("1.2.36")).is_err());
    assert!(validate_threadfin_target_policy(Some("latest")).is_err());

    // Malformed / skip SHA-256 override and unpinned version override without SHA-256 fail closed
    env::set_var("AF_THREADFIN_SHA256", "skip");
    assert!(validate_threadfin_target_policy(None).is_err());
    env::remove_var("AF_THREADFIN_SHA256");

    env::set_var("AF_THREADFIN_VERSION", "1.2.36");
    assert!(validate_threadfin_target_policy(None).is_err());
    env::set_var("AF_THREADFIN_SHA256", THREADFIN_AMD64_COMPAT_SHA256);
    assert_eq!(
        validate_threadfin_target_policy(Some("1.2.36")).unwrap().0,
        "1.2.36"
    );
    assert!(validate_threadfin_target_policy(Some("1.2.37")).is_err());
    env::remove_var("AF_THREADFIN_VERSION");
    env::remove_var("AF_THREADFIN_SHA256");

    // 2. Pi-hole vendor policy rejects updates and pinned installs/reinstalls, allows unpinned install/reinstall/remove
    assert!(validate_package_target_policy("pihole", "vendor", "", "update", Some("6.9")).is_err());
    assert!(validate_package_target_policy("pihole", "vendor", "", "update", None).is_err());
    assert!(
        validate_package_target_policy("pihole", "vendor", "", "install", Some("6.9")).is_err()
    );
    assert!(
        validate_package_target_policy("pihole", "vendor", "", "reinstall", Some("6.8")).is_err()
    );
    assert!(validate_package_target_policy("pihole", "vendor", "", "install", None).is_ok());
    assert!(validate_package_target_policy("pihole", "vendor", "", "reinstall", None).is_ok());
    assert!(validate_package_target_policy("pihole", "vendor", "", "remove", Some("6.9")).is_ok());

    // 3. Declarative Threadfin rejects mismatched expected_target_version before any command runs
    let root = create_isolated_test_dir("threadfin-policy-fail-closed");
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.expected_target_version = Some("1.2.36".to_string());
    let recipe = get_declarative_recipe("threadfin").unwrap();
    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg.clone(), mock.clone());
    let err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, PackageExecutorError::Validation(_)),
        "{err:?}"
    );
    assert!(
        mock.recorded_commands().is_empty(),
        "no host command may run before rejecting mismatched Threadfin target"
    );
    assert!(!root.join("install/.threadfin.lock").exists());

    // 4. execute_package_request_stream fails closed before sandbox/script mutation
    let root_str = root.to_string_lossy().into_owned();
    let _fs_guard = EnvVarGuard::new(&[
        ("AETHERFLOW_FS_ROOT", Some(root_str.as_str())),
        ("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", None),
        ("AETHERFLOW_PACKAGES_CONFIG", None),
    ]);
    let pihole_lines: Vec<String> = execute_package_request_stream(PackageRunnerRequest {
        action: "update".to_string(),
        package_id: "pihole".to_string(),
        script_name: "installpackage-pihole".to_string(),
        expected_target_version: Some("6.9".to_string()),
        ..Default::default()
    })
    .filter_map(|item| async move { item.ok() })
    .collect()
    .await;
    assert!(
        pihole_lines
            .iter()
            .any(|l| l.starts_with("__RUNNER_EXIT_ERROR__:") && l.contains("vendor installer")),
        "{pihole_lines:?}"
    );

    let threadfin_lines: Vec<String> = execute_package_request_stream(PackageRunnerRequest {
        action: "install".to_string(),
        package_id: "threadfin".to_string(),
        script_name: "installpackage-threadfin".to_string(),
        expected_target_version: Some("1.2.36".to_string()),
        ..Default::default()
    })
    .filter_map(|item| async move { item.ok() })
    .collect()
    .await;
    assert!(
        threadfin_lines
            .iter()
            .any(|l| l.starts_with("__RUNNER_EXIT_ERROR__:")
                && l.contains("pinned to version 1.2.37")),
        "{threadfin_lines:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn listenarr_target_policy_and_official_asset_eligibility() {
    assert_eq!(
        listenarr_release_asset_suffix_for_arch("x86_64").unwrap(),
        "linux-x64.zip"
    );
    assert_eq!(
        listenarr_release_asset_suffix_for_arch("amd64").unwrap(),
        "linux-x64.zip"
    );
    let arm64_err = listenarr_release_asset_suffix_for_arch("aarch64").unwrap_err();
    assert!(arm64_err.contains("arm64") && arm64_err.contains("Linux x64"));
    assert!(listenarr_release_asset_suffix_for_arch("armv7l").is_err());

    let valid_sha = "sha256:98ba3e01089554f632fa55f27bba4afe2393579061ca6aea9fb71658c72d2aac";
    let official_url = "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip";

    assert!(listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        official_url,
        Some(valid_sha),
        false,
        "linux-x64.zip",
    ));
    // Companion checksum suffices when digest is omitted
    assert!(listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        official_url,
        None,
        true,
        "linux-x64.zip",
    ));
    // Missing digest and missing companion fails closed
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        official_url,
        None,
        false,
        "linux-x64.zip",
    ));
    // Empty URL, untrusted host, cross-tag URL, malformed digest, or non-x64 asset all fail
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        "",
        Some(valid_sha),
        false,
        "linux-x64.zip",
    ));
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        "https://evil.example/listenarr-1.10.6-canary-linux-x64.zip",
        Some(valid_sha),
        false,
        "linux-x64.zip",
    ));
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.6-canary-linux-x64.zip",
        Some(valid_sha),
        false,
        "linux-x64.zip",
    ));
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-linux-x64.zip",
        official_url,
        Some("sha256:badhex"),
        true,
        "linux-x64.zip",
    ));
    assert!(!listenarr_release_asset_is_eligible(
        "v1.10.6-canary",
        "listenarr-1.10.6-canary-win-x64.zip",
        "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-win-x64.zip",
        Some(valid_sha),
        false,
        "linux-x64.zip",
    ));

    // Architecture & target policy validation
    assert!(validate_package_target_policy_for_arch(
        "listenarr",
        "github",
        "",
        "install",
        None,
        "x86_64"
    )
    .is_ok());
    assert!(validate_package_target_policy_for_arch(
        "listenarr",
        "github",
        "",
        "update",
        Some("1.10.6-canary"),
        "x86_64"
    )
    .is_ok());
    assert!(validate_package_target_policy_for_arch(
        "listenarr",
        "github",
        "",
        "update",
        Some("0.2.71"),
        "x86_64"
    )
    .is_ok());
    for bad in ["latest", "canary", "prerelease", "../v1.10.6-canary"] {
        assert!(
            validate_package_target_policy_for_arch(
                "listenarr",
                "github",
                "",
                "update",
                Some(bad),
                "x86_64"
            )
            .is_err(),
            "target {bad} must fail policy validation"
        );
    }
    for action in ["install", "update", "reinstall"] {
        let err = validate_package_target_policy_for_arch(
            "listenarr",
            "github",
            "",
            action,
            Some("1.10.6-canary"),
            "aarch64",
        )
        .unwrap_err();
        assert!(err.contains("arm64") && err.contains("Linux x64"), "{err}");
    }
    assert!(validate_package_target_policy_for_arch(
        "listenarr",
        "github",
        "",
        "remove",
        None,
        "aarch64"
    )
    .is_ok());
}

#[tokio::test]
async fn test_declarative_apt_exact_non_candidate_selection_and_rollback() {
    use std::collections::HashMap;

    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    #[derive(Clone)]
    struct StatefulAptRunner {
        recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
        repo: HashMap<String, Vec<String>>,
        dpkg: Arc<StdMutex<HashMap<String, (String, String)>>>,
        override_install: Option<(String, String)>,
    }

    impl CommandRunner for StatefulAptRunner {
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

                if program == "openssl" {
                    if let Some(pos) = args.iter().position(|a| a == "-out") {
                        if let Some(out_path) = args.get(pos + 1) {
                            fs::write(out_path, b"SYNTH-CERT\n").unwrap();
                        }
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }

                if program == "dpkg-query" {
                    let pkg = args.last().cloned().unwrap_or_default();
                    let dpkg = self.dpkg.lock().unwrap();
                    if let Some((status, ver)) = dpkg.get(&pkg) {
                        let wants_status = args.iter().any(|a| a.contains("db:Status-Status"));
                        let stdout = if wants_status {
                            format!("{status} {ver}\n")
                        } else {
                            format!("{ver}\n")
                        };
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout,
                            stderr: String::new(),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: format!("dpkg-query: no packages found matching {pkg}\n"),
                    });
                }

                if program == "apt-get" {
                    let is_remove = args.iter().any(|a| a == "remove");
                    let is_install = args.iter().any(|a| a == "install");
                    let allow_downgrades = args.iter().any(|a| a == "--allow-downgrades");
                    let mut dpkg = self.dpkg.lock().unwrap();
                    if is_remove {
                        for arg in args.iter().skip_while(|a| *a != "remove").skip(1) {
                            if !arg.starts_with('-') {
                                dpkg.remove(arg);
                            }
                        }
                        return Ok(CommandOutput {
                            exit_code: 0,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }
                    if is_install {
                        let mut skip_next = false;
                        let mut specs = Vec::new();
                        for arg in args.iter().skip_while(|a| *a != "install").skip(1) {
                            if skip_next {
                                skip_next = false;
                                continue;
                            }
                            if arg == "-o" {
                                skip_next = true;
                                continue;
                            }
                            if arg.starts_with('-') {
                                continue;
                            }
                            specs.push(arg.clone());
                        }
                        for spec in specs {
                            if let Some((pkg, ver)) = spec.split_once('=') {
                                let available = self
                                    .repo
                                    .get(pkg)
                                    .map(|vs| vs.iter().any(|v| v == ver))
                                    .unwrap_or(false);
                                if !available {
                                    return Ok(CommandOutput {
                                        exit_code: 100,
                                        stdout: String::new(),
                                        stderr: format!(
                                            "E: Version '{ver}' for '{pkg}' was not found\n"
                                        ),
                                    });
                                }
                                if let Some((ref st, ref ov)) = self.override_install {
                                    if pkg == "quassel-core" && !allow_downgrades {
                                        dpkg.insert(pkg.to_string(), (st.clone(), ov.clone()));
                                        continue;
                                    }
                                }
                                dpkg.insert(
                                    pkg.to_string(),
                                    ("installed".to_string(), ver.to_string()),
                                );
                            } else {
                                let chosen = self
                                    .repo
                                    .get(&spec)
                                    .and_then(|vs| vs.last())
                                    .cloned()
                                    .unwrap_or_else(|| "1.0-1".to_string());
                                dpkg.insert(spec, ("installed".to_string(), chosen));
                            }
                        }
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: String::new(),
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

    let mut repo = HashMap::new();
    repo.insert(
        "quassel-core".to_string(),
        vec![
            "1:0.13.1-1".to_string(),
            "1:0.14.0-1+deb12u1".to_string(),
            "1:0.14.0-2+deb12u1".to_string(),
        ],
    );
    repo.insert("openssl".to_string(), vec!["3.0.15-1~deb12u1".to_string()]);

    let recipe = get_declarative_recipe("quassel").unwrap();

    // 1. Non-candidate exact selection pins ONLY quassel-core, leaves openssl unpinned, writes full Debian version receipt
    {
        let root = create_isolated_test_dir("decl-apt-non-candidate");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.expected_target_version = Some("1:0.14.0-1+deb12u1".to_string());
        let runner = StatefulAptRunner {
            recorded: Arc::new(StdMutex::new(Vec::new())),
            repo: repo.clone(),
            dpkg: Arc::new(StdMutex::new(HashMap::new())),
            override_install: None,
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner.clone());
        let outcome = executor
            .execute_recipe(
                &recipe,
                PackageAction::Install,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect("non-candidate exact APT install must succeed");

        assert_eq!(
            outcome.resolved_version.as_deref(),
            Some("1:0.14.0-1+deb12u1")
        );
        assert_eq!(
            fs::read_to_string(root.join("var/lib/quassel/.af-version"))
                .unwrap()
                .trim(),
            "1:0.14.0-1+deb12u1"
        );
        let cmds = runner.recorded.lock().unwrap().clone();
        assert!(cmds.iter().any(|c| c.program == "apt-get"
            && c.args
                .contains(&"quassel-core=1:0.14.0-1+deb12u1".to_string())));
        assert!(!cmds
            .iter()
            .any(|c| c.program == "apt-get" && c.args.iter().any(|a| a.starts_with("openssl="))));
        let _ = fs::remove_dir_all(&root);
    }

    // 2. Post-install version mismatch AND non-installed status reject BEFORE systemctl activation and roll back cleanly
    for (label, override_state) in [
        ("mismatch", ("installed", "1:0.14.0-2+deb12u1")),
        ("half-installed", ("half-installed", "1:0.14.0-1+deb12u1")),
    ] {
        let root = create_isolated_test_dir(&format!("decl-apt-rollback-{label}"));
        fs::create_dir_all(root.join("var/lib/quassel")).unwrap();
        fs::write(root.join("var/lib/quassel/.af-version"), "1:0.13.1-1\n").unwrap();
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.expected_target_version = Some("1:0.14.0-1+deb12u1".to_string());
        let mut initial_dpkg = HashMap::new();
        initial_dpkg.insert(
            "quassel-core".to_string(),
            ("installed".to_string(), "1:0.13.1-1".to_string()),
        );
        let dpkg_arc = Arc::new(StdMutex::new(initial_dpkg));
        let runner = StatefulAptRunner {
            recorded: Arc::new(StdMutex::new(Vec::new())),
            repo: repo.clone(),
            dpkg: dpkg_arc.clone(),
            override_install: Some((override_state.0.to_string(), override_state.1.to_string())),
        };
        let executor = DeclarativePackageExecutor::with_runner(env_cfg, runner.clone());
        let err = executor
            .execute_recipe(
                &recipe,
                PackageAction::Update,
                CancellationToken::new(),
                |_| {},
            )
            .await
            .expect_err("mismatched or non-installed APT state must fail closed");
        assert!(
            err.to_string().contains("quassel-core"),
            "{label}: unexpected error: {err}"
        );
        let cmds = runner.recorded.lock().unwrap().clone();
        assert!(
            !cmds.iter().any(|c| c.program == "systemctl"
                && c.args.iter().any(|a| a == "restart" || a == "enable")),
            "{label}: service must not be activated before dpkg verification succeeds"
        );
        assert_eq!(
            dpkg_arc.lock().unwrap().get("quassel-core"),
            Some(&("installed".to_string(), "1:0.13.1-1".to_string())),
            "{label}: APT rollback must restore prior version 1:0.13.1-1"
        );
        assert_eq!(
            fs::read_to_string(root.join("var/lib/quassel/.af-version"))
                .unwrap()
                .trim(),
            "1:0.13.1-1"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // 3. Epoch-aware ZNC config version extraction
    assert_eq!(format_znc_major_minor("1:1.9.1-2+deb13u1"), "1.9");
    assert_eq!(format_znc_major_minor("1.8.2-3.1+deb12u1"), "1.8");

    // 4. Policy validation parity for APT exact Debian versions
    assert!(validate_package_target_policy(
        "quassel",
        "apt",
        "quassel-core",
        "install",
        Some("1:0.14.0-1+deb12u1")
    )
    .is_ok());
    assert!(
        validate_package_target_policy("quassel", "apt", "quassel-core", "install", None).is_ok()
    );
    for bad in ["v1.2.3", "latest", "1.2.*", "1.2_3", "deadbeef"] {
        assert!(
            validate_package_target_policy("quassel", "apt", "quassel-core", "install", Some(bad))
                .is_err(),
            "APT policy must reject {bad:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn rclone_declarative_and_legacy_bash_paths_coordinate_rc_api_port_reservations() {
    use std::os::unix::fs::PermissionsExt;

    let root = create_isolated_test_dir("rclone-port-coord");
    let rclone_bin = root.join("opt/AetherFlow/apps/rclone/rclone");
    let unit_path = root.join("etc/systemd/system/rclone.service");
    let env_path = root.join("etc/rclone/rclone.env");
    for d in [
        rclone_bin.parent().unwrap(),
        unit_path.parent().unwrap(),
        env_path.parent().unwrap(),
    ] {
        fs::create_dir_all(d).unwrap();
    }

    let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    rusqlite::Connection::open(&db_path).unwrap().execute_batch(
        "CREATE TABLE app_ingress_configs (app_name TEXT PRIMARY KEY, listen_port INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
         CREATE TABLE package_lifecycle_jobs (package_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, service_units TEXT NOT NULL);
         INSERT INTO app_ingress_configs VALUES ('sonarr', 5573);
         INSERT INTO retained_app_ingress_configs VALUES ('radarr', '{\"appName\":\"radarr\",\"listenPort\":17000}');
         INSERT INTO package_lifecycle_jobs VALUES ('lidarr','job-lidarr','install','installing','[\"lidarr\",\"port:17001\"]');
         INSERT INTO package_lifecycle_jobs VALUES ('rclone','job-rc-1','install','installing','[\"rclone\",\"port:5572\"]');",
    ).unwrap();

    fs::write(&rclone_bin, "#!/bin/sh\nif [ \"$1\" = rcd ]; then echo '--rc-enable-metrics'; else echo '--addr --api-addr --rc-enable-metrics --no-open-browser'; fi\n").unwrap();
    fs::set_permissions(&rclone_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let cmd_envs = |req: &PackageRunnerRequest| {
        let mut cmd = tokio::process::Command::new("/bin/true");
        configure_legacy_rclone_api_port_env(&mut cmd, req, Some(&root), 5572);
        cmd.as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|x| x.to_string_lossy().into_owned()),
                )
            })
            .collect::<HashMap<_, _>>()
    };

    // 1. Legacy Bash runner handoff skips reserved ports, sets AF_RCLONE_API_PORT, and records port:<N> on job.
    let bash_req = PackageRunnerRequest {
        action: "install".into(),
        package_id: "rclone".into(),
        script_name: "installpackage-rclone".into(),
        lifecycle_job_id: "job-rc-1".into(),
        app_port: 5572,
        ..Default::default()
    };
    let legacy_envs = cmd_envs(&bash_req);
    let legacy_api_port: u16 = legacy_envs["AF_RCLONE_API_PORT"]
        .as_deref()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (17002..=19999).contains(&legacy_api_port),
        "{legacy_api_port}"
    );
    assert_eq!(legacy_envs.get("AF_RCLONE_API_PORT_ERROR"), Some(&None));
    let job_units: String = rusqlite::Connection::open(&db_path).unwrap()
        .query_row("SELECT service_units FROM package_lifecycle_jobs WHERE package_id='rclone' AND job_id='job-rc-1'", [], |r| r.get(0)).unwrap();
    assert!(
        job_units.contains(&format!("port:{legacy_api_port}")),
        "{job_units}"
    );

    // Conflicting explicit secondary_port fails closed via AF_RCLONE_API_PORT_ERROR.
    let mut conflict_req = bash_req.clone();
    conflict_req.secondary_port = 5573;
    assert!(cmd_envs(&conflict_req)["AF_RCLONE_API_PORT_ERROR"]
        .as_deref()
        .unwrap_or("")
        .contains("already reserved by another application"));

    // 2. Declarative WriteSystemdUnit allocates, preserves on update, reallocates on GUI collision, honors rclone.env.
    let unit_step = DeclarativeStep::WriteSystemdUnit {
        unit_name: "rclone.service".into(),
        content_template: "[Service]\nExecStart={{RCLONE_EXEC_START}}\n".into(),
        progress_pct: 70,
        description: "write rclone unit".into(),
    };
    let recipe = get_declarative_recipe("rclone").unwrap();
    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.lifecycle_job_id = "job-rc-1".into();
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let (cancel, mut journal) = (
        CancellationToken::new(),
        RollbackJournal::new(Some(root.clone())),
    );
    macro_rules! run_unit {
        ($vars:expr) => {
            executor.run_single_step(&recipe, &unit_step, $vars, &mut journal, &cancel)
        };
    }
    let parsed_unit = || crate::parse_rclone_unit_ports(&fs::read_to_string(&unit_path).unwrap());

    let mut vars = HashMap::from([
        ("APP_PORT".into(), "5572".into()),
        ("LIFECYCLE_ACTION".into(), "install".into()),
    ]);
    run_unit!(&mut vars).await.unwrap();
    let alloc_port = parsed_unit().api_port.unwrap();
    assert!((17002..=19999).contains(&alloc_port), "{alloc_port}");

    // Update preserves unit --api-addr; moving GUI onto old RC port reallocates RC away.
    run_unit!(&mut HashMap::from([
        ("APP_PORT".into(), "5572".into()),
        ("LIFECYCLE_ACTION".into(), "install".into())
    ]))
    .await
    .unwrap();
    assert_eq!(parsed_unit().api_port, Some(alloc_port));
    run_unit!(&mut HashMap::from([
        ("APP_PORT".into(), alloc_port.to_string()),
        ("LIFECYCLE_ACTION".into(), "install".into())
    ]))
    .await
    .unwrap();
    let moved = parsed_unit();
    assert_eq!(moved.gui_port, Some(alloc_port));
    assert!(moved
        .api_port
        .is_some_and(|p| p != alloc_port && !matches!(p, 5573 | 17000 | 17001)));

    // rclone.env override honored; conflicting override fails closed.
    fs::write(
        &env_path,
        "RCLONE_RC_USER=admin\nRCLONE_RC_PASS=pw\nRCLONE_API_PORT=17890\n",
    )
    .unwrap();
    run_unit!(&mut HashMap::from([
        ("APP_PORT".into(), "5572".into()),
        ("LIFECYCLE_ACTION".into(), "install".into())
    ]))
    .await
    .unwrap();
    assert_eq!(parsed_unit().api_port, Some(17890));
    fs::write(
        &env_path,
        "RCLONE_RC_USER=admin\nRCLONE_RC_PASS=pw\nRCLONE_API_PORT=5573\n",
    )
    .unwrap();
    assert!(
        run_unit!(&mut HashMap::from([("APP_PORT".into(), "5572".into())]))
            .await
            .unwrap_err()
            .to_string()
            .contains("already reserved by another application")
    );
    fs::remove_file(&env_path).unwrap();

    // Busy loopback port skips 5573 cleanly.
    let empty_root = create_isolated_test_dir("rclone-loopback-busy");
    assert_eq!(
        declarative_recipes::resolve_and_reserve_rclone_api_port_with(
            Some(&empty_root),
            5572,
            None,
            "",
            None,
            |p| p != 5573
        )
        .unwrap(),
        17000
    );
    let missing_job = declarative_recipes::resolve_and_reserve_rclone_api_port_with(
        Some(&empty_root),
        5572,
        None,
        "missing-rclone-job",
        Some("install"),
        |_| true,
    )
    .unwrap_err();
    assert!(missing_job
        .to_string()
        .contains("active lifecycle database"));
    let _ = fs::remove_dir_all(&empty_root);

    // Single-port rcd binary clears RCLONE_API_PORT and emits no --api-addr.
    fs::write(
        &rclone_bin,
        "#!/bin/sh\necho '--rc-web-gui --rc-enable-metrics --rc-web-gui-no-open-browser'\n",
    )
    .unwrap();
    let mut rcd_vars = HashMap::from([
        ("APP_PORT".into(), "5572".into()),
        ("RCLONE_API_PORT".into(), "17890".into()),
    ]);
    run_unit!(&mut rcd_vars).await.unwrap();
    let rcd_unit = fs::read_to_string(&unit_path).unwrap();
    assert!(
        rcd_unit.contains(" rcd --rc-web-gui --rc-addr=127.0.0.1:5572")
            && !rcd_unit.contains("--api-addr")
    );
    assert!(
        !rcd_vars.contains_key("RCLONE_API_PORT")
            && rcd_vars.get("RCLONE_MODE").map(String::as_str) == Some("rcd")
    );
    let _ = fs::remove_dir_all(&root);
}
