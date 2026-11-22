use super::*;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::atomic::AtomicUsize;

fn legacy_env(req: &PackageRunnerRequest) -> HashMap<String, Option<String>> {
    let mut cmd = Command::new("bash");
    apply_legacy_package_environment(&mut cmd, req);
    cmd.as_std()
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

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
    for id in ["scrutiny", "clamav", "mosquitto"] {
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

/// Serializes async execution tests that share process-global `PACKAGE_MUTEX`,
/// `ACTIVE_CANCELLATIONS`, or environment variable state (`ENV_TEST_MUTEX`).
pub(super) use crate::ENV_TEST_MUTEX as TEST_EXECUTION_SERIALIZER;

/// Deterministic mock command runner that records every command invocation and never executes
/// live privileged OS commands.
#[derive(Clone, Default)]
struct MockCommandRunner {
    recorded: Arc<StdMutex<Vec<RecordedCommand>>>,
    fail_on_call: Option<usize>,
    fail_program: Option<String>,
    cancel_on_call: Option<(usize, CancellationToken)>,
    call_counter: Arc<AtomicUsize>,
    dpkg_version_stdout: Option<String>,
    fail_systemctl_is_active: bool,
}

impl MockCommandRunner {
    fn recorded_commands(&self) -> Vec<RecordedCommand> {
        self.recorded.lock().unwrap().clone()
    }
}

impl CommandRunner for MockCommandRunner {
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
            let idx = self.call_counter.fetch_add(1, Ordering::SeqCst);
            if let Some((trigger_idx, ref token)) = self.cancel_on_call {
                if idx == trigger_idx {
                    token.cancel();
                }
            }
            if cancel.is_cancelled() {
                return Err(PackageExecutorError::Cancelled(program.to_string()));
            }

            self.recorded.lock().unwrap().push(RecordedCommand {
                program: program.to_string(),
                args: args.to_vec(),
                env: env_vars.to_vec(),
            });

            if self.fail_on_call == Some(idx) || self.fail_program.as_deref() == Some(program) {
                return Ok(CommandOutput {
                    exit_code: 100,
                    stdout: String::new(),
                    stderr: format!("simulated failure in {} {:?}", program, args),
                });
            }

            if self.fail_systemctl_is_active
                && program == "systemctl"
                && args.first().map(String::as_str) == Some("is-active")
            {
                return Ok(CommandOutput {
                    exit_code: 3,
                    stdout: "inactive\n".to_string(),
                    stderr: String::new(),
                });
            }

            // Simulate `id -u <user>` returning non-zero on first check so `useradd` is exercised
            if program == "id" {
                return Ok(CommandOutput {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "no such user".to_string(),
                });
            }

            // Simulate `dpkg-query -W -f=${Version} <pkg>` returning a Debian epoch+revision version
            if program == "dpkg-query" {
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout: self
                        .dpkg_version_stdout
                        .clone()
                        .unwrap_or_else(|| "1:0.14.2-1ubuntu2\n".to_string()),
                    stderr: String::new(),
                });
            }

            if program == "curl" {
                let has_auth = args.iter().any(|a| a == "-K");
                let is_unauth_rc = args
                    .iter()
                    .any(|a| a.contains("/metrics") || a.contains("/core/version"));
                let status = if is_unauth_rc && !has_auth {
                    "401"
                } else {
                    "200"
                };
                return Ok(CommandOutput {
                    exit_code: 0,
                    stdout: format!("\n{status}\n"),
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

fn create_isolated_test_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = env::temp_dir().join(format!(
        "af-runner-pkg-test-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn create_mock_elf_payload(size: usize) -> Vec<u8> {
    create_mock_elf_payload_for_arch(size, 62) // EM_X86_64 = 62
}

fn create_mock_elf_payload_for_arch(size: usize, e_machine: u16) -> Vec<u8> {
    let mut data = vec![0x7f, b'E', b'L', b'F'];
    data.resize(size.max(2048), 0x90);
    // ELF little-endian (EI_DATA = 1 at offset 5) and e_machine at offset 18..20
    data[4] = if e_machine == 40 { 1 } else { 2 }; // ELFCLASS32 for ARM, ELFCLASS64 for x86_64/aarch64
    data[5] = 1; // ELFDATA2LSB
    let machine_bytes = e_machine.to_le_bytes();
    data[18] = machine_bytes[0];
    data[19] = machine_bytes[1];
    data
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
        "novnc".to_string(),
        "prometheus".to_string(),
        "quassel".to_string(),
        "rclone".to_string(),
        "syncthing".to_string(),
        "threadfin".to_string(),
        "x2go".to_string(),
        "xrdp".to_string(),
        "znc".to_string(),
    ];
    assert_eq!(ids, expected_ids);

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
    // Unmigrated packages remain on LegacyBashFallback even when Rust packages are enabled
    assert_eq!(
        select_package_engine_with_flags("sonarr", true, false),
        PackageEngineMode::LegacyBashFallback
    );
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
        "0.14.2"
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
        fail_on_call: Some(8),
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
            ("var/lib/threadfin", 0o751),
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
    assert_eq!(outcome.resolved_version.as_deref(), Some("0.14.2"));
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
        fail_on_call: Some(5),
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
    let flock_path = guard1.lock_file_path.clone();
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
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "1:0.14.0-1ubuntu2\n".to_string(),
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
    assert_eq!(outcome.resolved_version.as_deref(), Some("0.14.0"));
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
    assert_eq!(version_marker.trim(), "0.14.0");

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
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "1.0.2-1\n".to_string(),
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
fn version_rel_path_for_recipe(pkg_id: &str) -> &'static str {
    match pkg_id {
        "fail2ban" => "etc/fail2ban/.af-version",
        "quassel" => "var/lib/quassel/.af-version",
        "threadfin" => "var/lib/threadfin/.af-version",
        "znc" => "var/lib/znc/.af-version",
        "xrdp" => "var/lib/xrdp/.af-version",
        "novnc" => "etc/novnc/.af-version",
        "x2go" => "var/lib/x2go/.af-version",
        "prometheus" => "etc/prometheus/.af-version",
        "netdata" => "etc/netdata/.af-version",
        "mergerfs" => "var/lib/mergerfs/.af-version",
        "rclone" => "var/lib/rclone/.af-version",
        "syncthing" => "var/lib/syncthing/.af-version",
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
            "novnc" => {
                let passwd_path = root.join("var/lib/novnc/.vnc/passwd");
                fs::create_dir_all(passwd_path.parent().unwrap()).unwrap();
                let encoded = encode_tigervnc_passwd("OpVncS3c");
                fs::write(&passwd_path, encoded).unwrap();
                vec![
                    (passwd_path, hex::encode(encoded)),
                    write_sentinel(
                        "var/lib/novnc/.vnc/xstartup",
                        "#!/bin/sh\n# operator-novnc-xstartup-sentinel\nexec startxfce4\n",
                        "operator-novnc-xstartup-sentinel",
                    ),
                ]
            }
            "x2go" => vec![write_sentinel(
                "etc/x2go/x2goserver.conf",
                "[limit users]\n# operator-x2go-sentinel\n",
                "operator-x2go-sentinel",
            )],
            "prometheus" => {
                let prom_yml_path = root.join("etc/prometheus/prometheus.yml");
                let mut existing_yml = fs::read_to_string(&prom_yml_path).unwrap();
                existing_yml.push_str("# operator-prometheus-yml-sentinel\n");
                fs::write(&prom_yml_path, &existing_yml).unwrap();
                vec![
                    write_sentinel(
                        "etc/default/prometheus",
                        "ARGS=\"--web.listen-address=127.0.0.1:18100 --storage.tsdb.path=/var/lib/prometheus/metrics2 --operator-prometheus-default-sentinel\"\n",
                        "--operator-prometheus-default-sentinel",
                    ),
                    (prom_yml_path, "operator-prometheus-yml-sentinel".to_string()),
                ]
            }
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
            "syncthing" => vec![write_sentinel(
                "var/lib/syncthing/.config/syncthing/config.xml",
                "<configuration><gui><apikey>operator-syncthing-sentinel</apikey></gui></configuration>\n",
                "operator-syncthing-sentinel",
            )],
            other => panic!("unexpected recipe id: {other}"),
        }
}

#[tokio::test]
async fn test_all_12_native_recipes_in_place_reinstall_preserves_operator_state_and_updates_version_and_port(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let recipe_ids = list_declarative_recipe_ids();
    assert_eq!(recipe_ids.len(), 12);

    for pkg_id in recipe_ids {
        let root = create_isolated_test_dir(&format!("reinstall-12-{pkg_id}"));
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
            "novnc" => {
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/novnc.service")).unwrap();
                assert!(unit_cfg.contains("127.0.0.1:18200"));
            }
            "prometheus" => {
                let default_cfg = fs::read_to_string(root.join("etc/default/prometheus")).unwrap();
                let yml_cfg =
                    fs::read_to_string(root.join("etc/prometheus/prometheus.yml")).unwrap();
                assert!(default_cfg.contains("127.0.0.1:18200"));
                assert!(yml_cfg.contains("127.0.0.1:18200"));
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
            "syncthing" => {
                let unit_cfg =
                    fs::read_to_string(root.join("etc/systemd/system/syncthing.service")).unwrap();
                assert!(unit_cfg.contains("--gui-address=127.0.0.1:18200"));
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
async fn test_all_12_native_recipes_in_place_reinstall_failure_injection_rolls_back_and_retains_prior_state(
) {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let recipe_ids = list_declarative_recipe_ids();
    assert_eq!(recipe_ids.len(), 12);

    for pkg_id in recipe_ids {
        let root = create_isolated_test_dir(&format!("reinstall-fail-12-{pkg_id}"));
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
            "etc/systemd/system/novnc.service",
            "etc/systemd/system/novnc-xvnc.service",
            "etc/systemd/system/node_exporter.service",
            "etc/systemd/system/mergerfs.service",
            "etc/systemd/system/rclone.service",
            "etc/systemd/system/rclone-vfs.service",
            "etc/systemd/system/syncthing.service",
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
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "1.27.0\n".to_string(),
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

    let recipe = get_declarative_recipe("syncthing").unwrap();
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
                            stderr: "Failed to stop syncthing.service".to_string(),
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
                            stderr: "E: Version '1.0.0' for 'syncthing' was not found".to_string(),
                        });
                    }
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "downgraded syncthing to 1.0.0\n".to_string(),
                        stderr: String::new(),
                    });
                }

                if program == "dpkg-query" {
                    return Ok(CommandOutput {
                        exit_code: 0,
                        stdout: "2.0.0\n".to_string(),
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

    let recipe = get_declarative_recipe("syncthing").unwrap();

    // Case 1: Full clean rollback (stop succeeds, state restore succeeds, package downgrade succeeds -> receipt restored to 1.0.0)
    {
        let root = create_isolated_test_dir("afmp002-clean-rollback");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let state_dir = root.join("var/lib/syncthing");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.syncthing.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/syncthing.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n",
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
                c.program == "systemctl" && c.args == vec!["stop", "--", "syncthing.service"]
            })
            .expect("rollback must stop syncthing.service");
        let downgrade_pos = cmds
            .iter()
            .position(|c| {
                c.program == "apt-get"
                    && c.args.contains(&"--allow-downgrades".to_string())
                    && c.args.contains(&"syncthing=1.0.0".to_string())
            })
            .expect("rollback must downgrade syncthing to 1.0.0");
        assert!(stop_pos < downgrade_pos);

        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Package downgrade fails -> receipt honesty gate refuses to restore stale 1.0.0 .af-version receipt
    {
        let root = create_isolated_test_dir("afmp002-downgrade-fails");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.app_port = 18384;

        let state_dir = root.join("var/lib/syncthing");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.syncthing.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/syncthing.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n",
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

        let state_dir = root.join("var/lib/syncthing");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join(".af-version"), "1.0.0\n").unwrap();
        fs::write(state_dir.join("index-v0.14.0.db"), b"schema-v1-original").unwrap();
        let lock_path = root.join("install/.syncthing.lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "package=syncthing\nversion=1.0.0\n").unwrap();
        let unit_path = root.join("etc/systemd/system/syncthing.service");
        fs::create_dir_all(unit_path.parent().unwrap()).unwrap();
        fs::write(
            &unit_path,
            "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n",
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

#[test]
fn test_afmp004_runner_jellyfin_blueprint_preserves_operator_remote_access_and_known_proxies() {
    let root = create_isolated_test_dir("afmp004-jellyfin-runner");
    let net_xml = root.join("etc/jellyfin/network.xml");
    fs::create_dir_all(net_xml.parent().unwrap()).unwrap();
    let initial_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <InternalHttpPort>8096</InternalHttpPort>
  <PublicHttpPort>8096</PublicHttpPort>
  <EnableIPV4>true</EnableIPV4>
  <EnableRemoteAccess>false</EnableRemoteAccess>
  <KnownProxies><string>10.20.30.40</string></KnownProxies>
</NetworkConfiguration>
"#;
    fs::write(&net_xml, initial_xml).unwrap();

    apply_runner_blueprint_app_config(Some(&root), "jellyfin", 18096);

    let updated = fs::read_to_string(&net_xml).unwrap();
    assert!(updated.contains("<InternalHttpPort>18096</InternalHttpPort>"));
    assert!(updated.contains("<PublicHttpPort>18096</PublicHttpPort>"));
    assert!(
        updated.contains("<EnableRemoteAccess>false</EnableRemoteAccess>"),
        "must preserve explicit EnableRemoteAccess=false, got:\n{updated}"
    );
    assert!(
        updated.contains("<KnownProxies><string>10.20.30.40</string></KnownProxies>"),
        "must preserve custom KnownProxies, got:\n{updated}"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_afmp_sol_001_runner_blueprint_preserves_apache_access_policy() {
    let root = create_isolated_test_dir("afmp-sol-001-runner-apache");
    let sites_avail = root.join("etc/apache2/sites-available");
    let sites_en = root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();

    let int_conf = sites_avail.join("aetherflow-app-qui.conf");
    let ext_conf = sites_avail.join("aetherflow-ext-qui.conf");
    let en_ext_conf = sites_en.join("aetherflow-ext-qui.conf");

    let existing_int = "\
# Managed by AetherFlow v3.2.6
<VirtualHost *:80>
    ServerName qui.aether.local
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    RequestHeader set X-Forwarded-Proto \"http\"
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
    let existing_ext = "\
# Managed by AetherFlow v3.2.6 (External Ingress)
<VirtualHost *:80>
    ServerName qui.example.com
    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
    ProxyPass / http://127.0.0.1:8376/
    ProxyPassReverse / http://127.0.0.1:8376/
    <Location /qui>
        AuthType Basic
        AuthName \"Restricted Qui\"
        AuthUserFile /etc/apache2/.htpasswd
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
    fs::write(&int_conf, existing_int).unwrap();
    fs::write(&ext_conf, existing_ext).unwrap();
    fs::write(&en_ext_conf, existing_ext).unwrap();

    try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "qui", 18376, |_| Ok(None))
        .unwrap();

    for path in [&int_conf, &ext_conf, &en_ext_conf] {
        let updated = fs::read_to_string(path).unwrap();
        assert!(
            updated.contains("ws://127.0.0.1:18376/$1"),
            "must update websocket RewriteRule port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("ProxyPass / http://127.0.0.1:18376/"),
            "must update ProxyPass port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("ProxyPassReverse / http://127.0.0.1:18376/"),
            "must update ProxyPassReverse port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("<Location /qui>"),
            "must preserve <Location /qui> block in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("AuthType Basic"),
            "must preserve AuthType Basic in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("Require ip 192.0.2.0/24"),
            "must preserve Require ip 192.0.2.0/24 in {}: {updated}",
            path.display()
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn blueprint_vhost_rejects_required_directory_target() {
    let root = create_isolated_test_dir("blueprint-vhost-directory");
    let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
    fs::create_dir_all(&target).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
    assert!(
        result.is_err(),
        "required managed vhost directory must not be silently skipped: {result:?}"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains(&target.display().to_string()));
    assert!(target.is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_rejects_required_symlink_target() {
    let root = create_isolated_test_dir("blueprint-vhost-symlink");
    let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
    let operator_config = root.join("operator.conf");
    let original = "<VirtualHost *:80>\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&operator_config, original).unwrap();
    std::os::unix::fs::symlink(&operator_config, &target).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
    assert!(
        result.is_err(),
        "required managed vhost symlink must not be silently skipped: {result:?}"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains(&target.display().to_string()));
    assert!(fs::symlink_metadata(target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(operator_config).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}

const BLUEPRINT_VHOST_FIXTURE: &str = "<VirtualHost *:80>\n    ServerName sonarr.example.com\n    ProxyPass / http://127.0.0.1:8989/\n    ProxyPassReverse / http://127.0.0.1:8989/\n</VirtualHost>\n";
const BLUEPRINT_APP_CONFIG_FIXTURE: &str = "<Config><Port>8989</Port><BindAddress>127.0.0.1</BindAddress><AuthenticationMethod>Forms</AuthenticationMethod><AnalyticsEnabled>False</AnalyticsEnabled></Config>\n";

fn blueprint_ingress_fixture(root: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(root.join("ingress.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_ingress_configs (
                app_name TEXT PRIMARY KEY, public_domain TEXT NOT NULL,
                external_access_enabled INTEGER NOT NULL, listen_port INTEGER NOT NULL,
                tls_enabled INTEGER NOT NULL, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE retained_app_ingress_configs (
                app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL
            );",
    )
    .unwrap();
    conn
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_app_inspection_failure_restores_earlier_mutation() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = create_isolated_test_dir("blueprint-app-inspection-failure");
    let app_config = root.join("var/lib/sonarr/config.xml");
    let later_config = root.join("var/lib/sonarr/.config/sonarr/config.xml");
    let inaccessible = root.join("var/lib/sonarr/.config");
    fs::create_dir_all(later_config.parent().unwrap()).unwrap();
    fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    fs::write(&later_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    let permissions = fs::metadata(&inaccessible).unwrap().permissions();
    fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o000)).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "sonarr", 18989);
    fs::set_permissions(&inaccessible, permissions).unwrap();
    let error = result.unwrap_err().to_string();

    assert!(
        error.contains("failed to inspect required blueprint config"),
        "{error}"
    );
    assert!(
        error.contains(&later_config.display().to_string()),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(app_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    assert_eq!(
        fs::read_to_string(later_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn blueprint_vhost_read_failure_restores_app_config() {
    let root = create_isolated_test_dir("blueprint-vhost-read-failure");
    let app_config = root.join("var/lib/sonarr/config.xml");
    let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    fs::create_dir_all(app_config.parent().unwrap()).unwrap();
    fs::create_dir_all(internal.parent().unwrap()).unwrap();
    fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
    fs::write(&external, [0xff, 0xfe]).unwrap();

    let error =
        try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "sonarr", 18989, |_| {
            panic!("invalid vhost must fail before ingress lookup")
        })
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("failed to read required Apache vhost"),
        "{error}"
    );
    assert!(error.contains(&external.display().to_string()), "{error}");
    assert_eq!(
        fs::read_to_string(app_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    assert_eq!(
        fs::read_to_string(internal).unwrap(),
        BLUEPRINT_VHOST_FIXTURE
    );
    assert_eq!(fs::read(external).unwrap(), [0xff, 0xfe]);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_failed_late_write_rolls_back_updates_creates_and_deletes() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for existing_internal in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-late-write");
        let app_config = root.join("var/lib/sonarr/config.xml");
        let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
        let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        let enabled = root.join("etc/apache2/sites-enabled/aetherflow-app-sonarr.conf");
        fs::create_dir_all(app_config.parent().unwrap()).unwrap();
        fs::create_dir_all(internal.parent().unwrap()).unwrap();
        fs::create_dir_all(enabled.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::set_permissions(&app_config, fs::Permissions::from_mode(0o640)).unwrap();
        if existing_internal {
            fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
            fs::set_permissions(&internal, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(&enabled, BLUEPRINT_VHOST_FIXTURE).unwrap();
        let enabled_directory = enabled.parent().unwrap();
        let permissions = fs::metadata(enabled_directory).unwrap().permissions();
        fs::set_permissions(enabled_directory, fs::Permissions::from_mode(0o555)).unwrap();

        let result = try_apply_runner_blueprint_app_config_with_ingress(
            Some(&root),
            "sonarr",
            18989,
            |_| Ok(Some(af_models::AppIngressConfig::default())),
        );
        fs::set_permissions(enabled_directory, permissions).unwrap();
        let error = result.unwrap_err().to_string();

        assert!(
            error.contains("failed to write required Apache vhost"),
            "{error}"
        );
        assert!(error.contains(&enabled.display().to_string()), "{error}");
        assert!(
            error.contains("restored previous blueprint configuration"),
            "{error}"
        );
        assert!(!error.contains("incomplete rollback"), "{error}");
        assert_eq!(
            fs::read_to_string(&app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::metadata(app_config).unwrap().permissions().mode() & 0o777,
            0o640
        );
        if existing_internal {
            assert_eq!(
                fs::read_to_string(&internal).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            assert_eq!(
                fs::metadata(internal).unwrap().permissions().mode() & 0o777,
                0o600
            );
        } else {
            assert!(!internal.exists());
        }
        assert_eq!(
            fs::read_to_string(&external).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert_eq!(
            fs::metadata(external).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_to_string(enabled).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_failed_delete_is_explicit_and_preserves_original() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = create_isolated_test_dir("blueprint-vhost-delete-failure");
    let target = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, BLUEPRINT_VHOST_FIXTURE).unwrap();
    let directory = target.parent().unwrap();
    let permissions = fs::metadata(directory).unwrap().permissions();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
    let mut changes = RunnerBlueprintConfigChanges::new(Some(&root));
    let result = changes.remove_vhost(&target);
    fs::set_permissions(directory, permissions).unwrap();
    let error = changes.rollback(result.unwrap_err()).to_string();

    assert!(
        error.contains("failed to remove required Apache vhost"),
        "{error}"
    );
    assert!(error.contains(&target.display().to_string()), "{error}");
    assert_eq!(fs::read_to_string(target).unwrap(), BLUEPRINT_VHOST_FIXTURE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn blueprint_vhost_incomplete_rollback_is_honest_and_continues_other_restores() {
    for previously_existed in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-incomplete-rollback");
        let restored = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
        let blocked = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(restored.parent().unwrap()).unwrap();
        fs::write(&restored, BLUEPRINT_VHOST_FIXTURE).unwrap();
        if previously_existed {
            fs::write(&blocked, BLUEPRINT_VHOST_FIXTURE).unwrap();
        }
        let mut changes = RunnerBlueprintConfigChanges::new(Some(&root));
        changes
            .write_vhost(&restored, "updated internal config")
            .unwrap();
        changes
            .write_vhost(&blocked, "updated external config")
            .unwrap();
        fs::remove_file(&blocked).unwrap();
        fs::create_dir(&blocked).unwrap();

        let error = changes
            .rollback(PackageExecutorError::VerificationFailed(
                "fixture configtest failure".to_string(),
            ))
            .to_string();

        assert!(error.contains("fixture configtest failure"), "{error}");
        assert!(error.contains("incomplete rollback"), "{error}");
        assert!(error.contains(&blocked.display().to_string()), "{error}");
        assert!(!error.contains("restored previous"), "{error}");
        assert_eq!(
            fs::read_to_string(restored).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert!(blocked.is_dir());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn blueprint_vhost_ingress_lookup_errors_restore_app_config_without_changing_ingress() {
    for corrupt_retained in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-ingress-error");
        let conn = blueprint_ingress_fixture(&root);
        if corrupt_retained {
            conn.execute(
                "INSERT INTO retained_app_ingress_configs VALUES ('sonarr', 'invalid JSON')",
                [],
            )
            .unwrap();
        } else {
            conn.execute("DROP TABLE app_ingress_configs", []).unwrap();
        }
        let app_config = root.join("var/lib/sonarr/config.xml");
        let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(app_config.parent().unwrap()).unwrap();
        fs::create_dir_all(external.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();

        let error = try_apply_runner_blueprint_app_config_with_ingress(
            Some(&root),
            "sonarr",
            18989,
            |canonical| load_runner_blueprint_ingress(&conn, canonical),
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("failed to load blueprint ingress for sonarr"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::read_to_string(external).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert!(!root
            .join("etc/apache2/sites-available/aetherflow-app-sonarr.conf")
            .exists());
        drop(conn);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_absent_ingress_preserves_external_domain_aliases_and_custom_blocks() {
    let root = create_isolated_test_dir("blueprint-vhost-enabled-aliases");
    let conn = blueprint_ingress_fixture(&root);
    let available = root.join("etc/apache2/sites-available");
    let enabled = root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&available).unwrap();
    fs::create_dir_all(&enabled).unwrap();
    let external = available.join("aetherflow-ext-qui.conf");
    let original = "<VirtualHost *:443>\n    ServerName operator.example.com\n    SSLEngine on\n    SSLCertificateFile /operator/certificate.pem\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
    fs::write(&external, original).unwrap();
    let policy = available.join("operator-policy.conf");
    let custom =
        "<Location /private>\n    AuthType Basic\n    Require ip 192.0.2.0/24\n</Location>\n";
    fs::write(&policy, custom).unwrap();
    let aliases = [
        (
            "aetherflow-app-qui.conf",
            "../sites-available/aetherflow-app-qui.conf",
        ),
        (
            "aetherflow-ext-qui.conf",
            "../sites-available/aetherflow-ext-qui.conf",
        ),
        ("qui.conf", "../sites-available/operator-policy.conf"),
    ];
    for (name, target) in aliases {
        std::os::unix::fs::symlink(target, enabled.join(name)).unwrap();
    }

    try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "qui", 18376, |canonical| {
        load_runner_blueprint_ingress(&conn, canonical)
    })
    .unwrap();

    let updated_external = fs::read_to_string(external).unwrap();
    assert!(updated_external.contains("ServerName operator.example.com"));
    assert!(updated_external.contains("<VirtualHost *:443>"));
    assert!(updated_external.contains("SSLCertificateFile /operator/certificate.pem"));
    assert!(updated_external.contains("http://127.0.0.1:18376/"));
    assert!(updated_external.contains(custom.trim()));
    assert!(
        fs::read_to_string(available.join("aetherflow-app-qui.conf"))
            .unwrap()
            .contains(custom.trim())
    );
    assert_eq!(fs::read_to_string(policy).unwrap(), custom);
    for (name, target) in aliases {
        assert_eq!(
            fs::read_link(enabled.join(name)).unwrap(),
            Path::new(target)
        );
    }
    assert!(load_runner_blueprint_ingress(&conn, "qui")
        .unwrap()
        .is_none());
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_rclone_both_cli_variants_render_app_port_and_metrics() {
    let mut vars = HashMap::new();
    vars.insert("APP_PORT".to_string(), "19572".to_string());
    vars.insert("RCLONE_API_PORT".to_string(), "19573".to_string());
    vars.insert("MASTER_USER".to_string(), "admin".to_string());
    vars.insert("RCLONE_PASS".to_string(), "secret".to_string());

    // 1. Modern variant: rclone rcd
    let rcd_cmd = "/usr/bin/rclone rcd --rc-web-gui --rc-web-gui-no-open-browser --rc-addr=127.0.0.1:{{APP_PORT}} --rc-enable-metrics --config=/etc/rclone/rclone.conf";
    let rcd_rendered = interpolate_template(rcd_cmd, &vars);
    assert!(rcd_rendered.contains("--rc-addr=127.0.0.1:19572"));
    assert!(rcd_rendered.contains("--rc-enable-metrics"));
    assert!(!rcd_rendered.contains("{{APP_PORT}}"));
    assert!(!rcd_rendered.contains("5572"));

    // 2. Legacy fallback variant: rclone gui
    let gui_cmd = "/usr/bin/rclone gui --addr=127.0.0.1:{{APP_PORT}} --api-addr=127.0.0.1:{{RCLONE_API_PORT}} --user=${RCLONE_RC_USER} --pass=${RCLONE_RC_PASS} --enable-metrics --no-open-browser --config=/etc/rclone/rclone.conf";
    let gui_rendered = interpolate_template(gui_cmd, &vars);
    assert!(gui_rendered.contains("--addr=127.0.0.1:19572"));
    assert!(gui_rendered.contains("--api-addr=127.0.0.1:19573"));
    assert!(gui_rendered.contains("--user=${RCLONE_RC_USER}"));
    assert!(gui_rendered.contains("--pass=${RCLONE_RC_PASS}"));
    assert!(gui_rendered.contains("--enable-metrics"));
    assert!(!gui_rendered.contains("{{APP_PORT}}"));
    assert!(!gui_rendered.contains("{{RCLONE_API_PORT}}"));
    assert!(!gui_rendered.contains("5572"));

    // 3. Verify recipe systemd unit template contains {{RCLONE_EXEC_START}} placeholder
    let recipe = get_declarative_recipe("rclone").unwrap();
    let unit_step = recipe
        .install_steps
        .iter()
        .find_map(|s| match s {
            DeclarativeStep::WriteSystemdUnit {
                unit_name,
                content_template,
                ..
            } if unit_name == "rclone.service" => Some(content_template),
            _ => None,
        })
        .expect("rclone.service template must exist");

    // Verify template has {{RCLONE_EXEC_START}} and not hardcoded 5572
    assert!(unit_step.contains("ExecStart={{RCLONE_EXEC_START}}"));
    assert!(!unit_step.contains("127.0.0.1:5572"));

    // Simulate modern rcd substitution on unit template
    let root = create_isolated_test_dir("rclone-cli-mode");
    let rcd_start = detect_rclone_exec_start_for_root(&root);
    fs::remove_dir_all(root).unwrap();
    assert!(rcd_start.contains("{{APP_PORT}}"));
    let rcd_content = unit_step.replace("{{RCLONE_EXEC_START}}", &rcd_start);
    let rendered_rcd = interpolate_template(&rcd_content, &vars);
    assert!(rendered_rcd.contains("127.0.0.1:19572"));
    assert!(!rendered_rcd.contains("{{APP_PORT}}"));
    assert!(!rendered_rcd.contains("5572"));

    let root = create_isolated_test_dir("rclone-gui-mode");
    let binary = root.join("opt/AetherFlow/apps/rclone/rclone");
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    for (help, expected_metrics) in [
        (
            "--addr --api-addr --rc-enable-metrics --enable-metrics --no-open-browser",
            "--rc-enable-metrics",
        ),
        (
            "--addr --api-addr --enable-metrics --no-open-browser",
            "--enable-metrics",
        ),
    ] {
        fs::write(
            &binary,
            format!("#!/bin/sh\n[ \"$1\" = gui ] && printf '%s\\n' '{help}'\n"),
        )
        .unwrap();
        fs::set_permissions(&binary, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let detected = detect_rclone_exec_start_for_root(&root);
        let rendered = interpolate_template(
            &unit_step.replace("{{RCLONE_EXEC_START}}", &detected),
            &vars,
        );
        assert!(rendered.contains("/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:19572 --api-addr=127.0.0.1:19573 "));
        assert!(rendered.contains(&format!(" {expected_metrics} ")));
        assert!(rendered.contains("--cache-dir=/var/lib/rclone/cache"));
        assert!(!rendered.contains("--user="));
        assert!(!rendered.contains("--pass="));
    }
    fs::remove_dir_all(root).unwrap();
}

struct LocalHttpServer {
    pub port: u16,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

async fn start_local_http_server<F>(handler: F) -> LocalHttpServer
where
    F: Fn(&str, &str, Option<&str>) -> (u16, &'static str, String) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                conn = listener.accept() => {
                    let Ok((mut socket, _)) = conn else { break };
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 4096];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let mut lines = req.lines();
                        let first_line = lines.next().unwrap_or("");
                        let mut parts = first_line.split_whitespace();
                        let method = parts.next().unwrap_or("GET");
                        let path = parts.next().unwrap_or("/");

                        let mut auth_header = None;
                        for line in lines {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("authorization") {
                                    auth_header = Some(v.trim().to_string());
                                }
                            }
                        }

                        let (status, content_type, body) = handler(method, path, auth_header.as_deref());
                        let status_text = match status {
                            200 => "OK",
                            401 => "Unauthorized",
                            404 => "Not Found",
                            405 => "Method Not Allowed",
                            _ => "Error",
                        };
                        let mut resp = format!(
                            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                            status,
                            status_text,
                            content_type,
                            body.len()
                        );
                        if status == 401 {
                            resp.push_str("WWW-Authenticate: Basic realm=\"rclone\"\r\n");
                        }
                        resp.push_str("\r\n");
                        resp.push_str(&body);

                        let _ = socket.write_all(resp.as_bytes()).await;
                        let _ = socket.flush().await;
                    });
                }
            }
        }
    });

    LocalHttpServer {
        port,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    }
}

#[tokio::test]
async fn test_rclone_authenticated_wait_for_http_ready_rcd_and_gui() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    let recipe = get_declarative_recipe("rclone").unwrap();

    // 1. Case 1 (rcd mode): /metrics returns 401 unauthenticated, 200 # HELP rclone_version_info with Basic Auth,
    // and /core/version returns 401 unauthenticated, 200 {"version":"1.65.0"} with Basic Auth -> passes
    {
        let server = start_local_http_server(|method, path, auth| {
                let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
                if path == "/metrics" {
                    if auth != Some(expected_auth) {
                        return (401, "text/plain", "Unauthorized\n".to_string());
                    }
                    return (
                        200,
                        "text/plain",
                        "# HELP rclone_version_info Rclone version\nrclone_version_info{version=\"v1.65.0\"} 1\n".to_string(),
                    );
                }
                if path == "/core/version" && method == "POST" {
                    if auth != Some(expected_auth) {
                        return (401, "application/json", "{\"error\":\"unauthorized\"}\n".to_string());
                    }
                    return (200, "application/json", "{\"version\":\"1.65.0\"}\n".to_string());
                }
                (404, "text/plain", "Not Found\n".to_string())
            }).await;

        // An existing unit can still select the legacy file while both copies are present.
        let root = create_isolated_test_dir("rclone-auth-rcd-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        for (logical, content) in [
            (
                "etc/aetherflow/rclone.env",
                "RCLONE_USER=admin\nRCLONE_PASS=mysecret\n",
            ),
            (
                "etc/rclone/rclone.env",
                "RCLONE_RC_USER=other\nRCLONE_RC_PASS=other\n",
            ),
            (
                "etc/systemd/system/rclone.service",
                "[Service]\nEnvironmentFile=-/etc/aetherflow/rclone.env\n",
            ),
        ] {
            let path = root.join(logical);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone RC HTTP listener".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "authenticated WaitForHttpReady for rclone rcd must succeed: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);

        // 1b: Failure with wrong credentials (server returns 401)
        let root_wrong = create_isolated_test_dir("rclone-auth-wrong-live");
        let env_cfg_wrong = PackageExecutionEnv::isolated(&root_wrong);
        let env_file_wrong = root_wrong.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file_wrong.parent().unwrap()).unwrap();
        fs::write(
            &env_file_wrong,
            "RCLONE_RC_USER=\"wrong\"\nRCLONE_RC_PASS=\"wrongpass\"\n",
        )
        .unwrap();

        let executor_wrong = DeclarativePackageExecutor::new(env_cfg_wrong);
        let res_wrong = executor_wrong
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res_wrong.is_err(),
            "wrong credentials WaitForHttpReady must fail on 401"
        );
        let _ = fs::remove_dir_all(&root_wrong);
    }

    // 2. Case 2 (unauthenticated /metrics exposure): /metrics returns 200 # HELP rclone_... WITHOUT credentials -> rejected (is_err())!
    {
        let server = start_local_http_server(|_method, path, _auth| {
                if path == "/metrics" {
                    return (
                        200,
                        "text/plain",
                        "# HELP rclone_version_info Rclone version\nrclone_version_info{version=\"v1.65.0\"} 1\n".to_string(),
                    );
                }
                (404, "text/plain", "Not Found\n".to_string())
            }).await;

        let root = create_isolated_test_dir("rclone-unauth-exposure-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone unauthenticated metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated /metrics exposure must be rejected with Err: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // 3. Case 3 (rcd with /metrics returning 405 Method Not Allowed or 404):
    // Supplies FULL set of variables created by the real recipe:
    // APP_PORT, RCLONE_API_PORT = APP_PORT + 1, RCLONE_WEB_MODE = "rcd", RCLONE_MODE = "rcd".
    // Also writes an active rclone.service unit without --api-addr.
    // Verifies single-port rcd readiness stays in single-port mode, rejects 405 on /metrics,
    // and succeeds when /metrics + /core/version (or /rc/noopauth) behave as a valid single-port rcd listener.
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (405, "text/plain", "405 Method Not Allowed\n".to_string());
            }
            if (path == "/core/version" || path == "/rc/noopauth") && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-auth-405-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        // Write active rclone.service unit without --api-addr (pure single-port rcd)
        let svc_file = root.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file.parent().unwrap()).unwrap();
        fs::write(
                &svc_file,
                format!(
                    "[Unit]\nDescription=Rclone RC Web GUI Service\n[Service]\nExecStart=/usr/bin/rclone rcd --rc-web-gui --rc-addr=127.0.0.1:{}\n",
                    server.port
                ),
            ).unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg.clone());
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        // Supply RCLONE_API_PORT = APP_PORT + 1 as populated by recipe generator
        vars.insert("RCLONE_API_PORT".to_string(), (server.port + 1).to_string());
        vars.insert("RCLONE_WEB_MODE".to_string(), "rcd".to_string());
        vars.insert("RCLONE_MODE".to_string(), "rcd".to_string());

        // Assert that detect_rclone_separate_api_port stays None (single-port mode)
        let sep_port = detect_rclone_separate_api_port(&env_cfg, &vars, server.port);
        assert_eq!(
                sep_port, None,
                "single-port rcd unit without --api-addr must not detect separate api port even when RCLONE_API_PORT is present"
            );

        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying Rclone 405 rejection on /metrics in single-port rcd mode"
                .to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "single-port rcd with 405 on /metrics must NOT be accepted: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // 4. Case 4 (Split-port rclone gui mode, matching real Rclone 1.75.2 gui):
    // GUI listener on APP_PORT returns unauthenticated 200 OK <html>Rclone GUI</html> on both / and /metrics,
    // while the RC API listener on APP_PORT + 1 (--api-addr) returns 401 Unauthorized without credentials
    // and 200 OK with Basic Auth on BOTH /metrics and /core/version -> passes!
    // And if the RC API listener on APP_PORT + 1 returns 200 WITHOUT credentials, it is rejected (is_err())!
    {
        let server_gui = start_local_http_server(|_method, path, _auth| {
            if path == "/" || path == "/metrics" {
                return (200, "text/html", "<html>Rclone GUI</html>\n".to_string());
            }
            (200, "text/html", "<html>Rclone GUI</html>\n".to_string())
        })
        .await;

        let expected_auth = "Basic Z3VpX3VzZXI6Z3VpX3Bhc3M=";
        let server_api = start_local_http_server(move |method, path, auth| {
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        // 4a: Success with protected API server on --api-addr
        let root = create_isolated_test_dir("rclone-split-port-gui-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"gui_user\"\nRCLONE_RC_PASS=\"gui_pass\"\n",
        )
        .unwrap();

        // Write rclone.service with --api-addr
        let svc_file = root.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file.parent().unwrap()).unwrap();
        fs::write(
                &svc_file,
                format!(
                    "[Unit]\nDescription=Rclone GUI\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:{} --api-addr=127.0.0.1:{} --enable-metrics --no-open-browser\n",
                    server_gui.port, server_api.port
                ),
            ).unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server_gui.port.to_string());
        vars.insert("RCLONE_API_PORT".to_string(), server_api.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying split-port Rclone GUI readiness".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "split-port gui mode must succeed when RC API is protected: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);

        // 4b: RC API listener on --api-addr returns 200 WITHOUT credentials -> must be rejected (is_err())!
        let server_api_unauth = start_local_http_server(|method, path, _auth| {
            if path == "/metrics" && method == "GET" {
                return (401, "text/plain", "Unauthorized\n".to_string());
            }
            if path == "/core/version" && method == "POST" {
                // Unauthenticated request returns 200 -> auth bypass!
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root_bypass = create_isolated_test_dir("rclone-split-port-bypass-live");
        let env_cfg_bypass = PackageExecutionEnv::isolated(&root_bypass);
        let env_file_bypass = root_bypass.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file_bypass.parent().unwrap()).unwrap();
        fs::write(
            &env_file_bypass,
            "RCLONE_RC_USER=\"gui_user\"\nRCLONE_RC_PASS=\"gui_pass\"\n",
        )
        .unwrap();

        let svc_file_bypass = root_bypass.join("etc/systemd/system/rclone.service");
        fs::create_dir_all(svc_file_bypass.parent().unwrap()).unwrap();
        fs::write(
                &svc_file_bypass,
                format!(
                    "[Unit]\nDescription=Rclone GUI\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:{} --api-addr=127.0.0.1:{} --enable-metrics --no-open-browser\n",
                    server_gui.port, server_api_unauth.port
                ),
            ).unwrap();

        let executor_bypass = DeclarativePackageExecutor::new(env_cfg_bypass);
        let mut vars_bypass = HashMap::new();
        vars_bypass.insert("APP_PORT".to_string(), server_gui.port.to_string());
        vars_bypass.insert(
            "RCLONE_API_PORT".to_string(),
            server_api_unauth.port.to_string(),
        );

        let res_bypass = executor_bypass
            .run_single_step(
                &recipe,
                &step,
                &mut vars_bypass,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res_bypass.is_err(),
            "RC API listener returning 200 without credentials must be rejected with Err: {:?}",
            res_bypass
        );
        let _ = fs::remove_dir_all(&root_bypass);
    }

    // 5. Case 5 (Non-rclone package "prometheus" when /etc/rclone/rclone.env exists): no Authorization header sent -> passes
    {
        let seen_auth_headers = Arc::new(StdMutex::new(Vec::<Option<String>>::new()));
        let headers_tracker = seen_auth_headers.clone();
        let server = start_local_http_server(move |_method, path, auth| {
            headers_tracker
                .lock()
                .unwrap()
                .push(auth.map(|s| s.to_string()));
            if path == "/-/healthy" {
                (
                    200,
                    "text/plain",
                    "Prometheus Server is Healthy.\n".to_string(),
                )
            } else {
                (200, "text/plain", "ok\n".to_string())
            }
        })
        .await;

        let root = create_isolated_test_dir("rclone-non-rclone-prometheus-live");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        // Intentionally create /etc/rclone/rclone.env inside root
        let rclone_env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(rclone_env_file.parent().unwrap()).unwrap();
        fs::write(
            &rclone_env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let prom_recipe =
            get_declarative_recipe("prometheus").expect("prometheus recipe must exist");
        let executor = DeclarativePackageExecutor::new(env_cfg);
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/-/healthy".to_string(),
            progress_pct: 98,
            description: "Verifying Prometheus HTTP listener readiness".to_string(),
        };

        let res = executor
            .run_single_step(
                &prom_recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_ok(),
            "readiness for prometheus must succeed: {:?}",
            res
        );

        let recorded_headers = seen_auth_headers.lock().unwrap().clone();
        assert!(
            !recorded_headers.is_empty(),
            "prometheus server must have received requests"
        );
        for auth in &recorded_headers {
            assert!(
                auth.is_none(),
                "non-rclone package probe must never send an Authorization header, got: {:?}",
                auth
            );
        }
        let _ = fs::remove_dir_all(&root);
    }
}

fn create_test_rclone_zip(staging_dir: &Path, reported_version: &str) -> (PathBuf, String) {
    let bin_path = staging_dir.join("rclone");
    let c_code = format!(
            "#include <stdio.h>\nint main(int argc, char** argv) {{ puts(\"rclone {}\"); return 0; }}\n",
            reported_version
        );
    let mut child = std::process::Command::new("gcc")
        .args(["-x", "c", "-", "-o", &bin_path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("gcc must be available for testing ELF binary verification");
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(c_code.as_bytes());
    }
    assert!(child.wait().unwrap().success());

    let zip_path = staging_dir.join("test_rclone.zip");
    let status = std::process::Command::new("zip")
        .args([
            "-j",
            &zip_path.to_string_lossy(),
            &bin_path.to_string_lossy(),
        ])
        .status()
        .expect("zip command must succeed");
    assert!(status.success());

    let zip_bytes = fs::read(&zip_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&zip_bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());

    (zip_path, sha256_hex)
}

#[tokio::test]
async fn test_rclone_install_rejects_sha256_mismatch() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-sha256-mismatch");
    let work_dir = create_isolated_test_dir("rclone-work-mismatch");
    let (zip_path, _real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    // Deliberately incorrect SHA-256 digest
    vars.insert(
        "RCLONE_ARCHIVE_SHA256".to_string(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    );

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "SHA-256 mismatch must fail closed: {:?}", res);

    let dest_bin = root.join("usr/local/bin/rclone");
    assert!(
        !dest_bin.exists(),
        "Binary must not be installed when SHA-256 verification fails"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_rejects_wrong_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-wrong-version");
    let work_dir = create_isolated_test_dir("rclone-work-wrong-version");
    // Binary reports v1.60.0 while target version is 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.60.0");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_err(),
        "Binary reporting wrong version (v1.60.0 vs target 1.75.2) must be rejected: {:?}",
        res
    );

    let dest_bin = root.join("usr/local/bin/rclone");
    assert!(
        !dest_bin.exists(),
        "Binary must not be installed when version check fails"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_succeeds_with_valid_sha256_and_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-install-ok");
    use std::os::unix::fs::PermissionsExt;
    let runtime_dir = root.join("opt/AetherFlow/apps/rclone");
    fs::create_dir_all(&runtime_dir).unwrap();
    let apps_dir = runtime_dir.parent().unwrap();
    for path in [apps_dir, runtime_dir.as_path()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let work_dir = create_isolated_test_dir("rclone-work-ok");
    // Binary reports v1.75.2 matching target 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_ok(),
        "Valid SHA-256 and matching version must succeed: {:?}",
        res
    );

    assert!(root.join(RCLONE_BIN.trim_start_matches('/')).is_file());
    assert!(root
        .join(RCLONE_BIN_OWNER.trim_start_matches('/'))
        .is_file());
    assert!(!root.join("usr/bin/rclone").exists());
    assert!(!root.join("usr/local/bin/rclone").exists());

    for path in [apps_dir, runtime_dir.as_path()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o711
        );
    }

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_readiness_rejects_exposed_core_version_as_auth_bypass() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Server where /metrics properly requires auth (returns 401 unauthenticated, 200 authenticated),
    // but /core/version returns 200 WITHOUT authentication (exposed RC endpoint).
    let server = start_local_http_server(|method, path, auth| {
        let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
        if path == "/metrics" && method == "GET" {
            if auth != Some(expected_auth) {
                return (401, "text/plain", "Unauthorized\n".to_string());
            }
            return (
                200,
                "text/plain",
                "# HELP rclone_version_info\n".to_string(),
            );
        }
        if path == "/core/version" && method == "POST" {
            // Exposure: returns 200 even unauthenticated!
            return (
                200,
                "application/json",
                "{\"version\":\"1.75.2\"}\n".to_string(),
            );
        }
        (404, "text/plain", "Not Found\n".to_string())
    })
    .await;

    let root = create_isolated_test_dir("rclone-exposed-core-version");
    let env_cfg = PackageExecutionEnv::isolated(&root);
    let env_file = root.join("etc/rclone/rclone.env");
    fs::create_dir_all(env_file.parent().unwrap()).unwrap();
    fs::write(
        &env_file,
        "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
    )
    .unwrap();

    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();
    let mut vars = HashMap::new();
    vars.insert("APP_PORT".to_string(), server.port.to_string());
    let step = DeclarativeStep::WaitForHttpReady {
        path: "/metrics".to_string(),
        progress_pct: 98,
        description: "Verifying exposed core version rejection".to_string(),
    };

    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut RollbackJournal::new(None),
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "exposed /core/version returning 200 unauthenticated must be rejected as an authentication bypass: {:?}", res);
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_rclone_readiness_rejects_unauthenticated_404_or_500_on_metrics() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Test 1: /metrics returns 404 unauthenticated
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (404, "text/plain", "Not Found\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-unauth-404-metrics");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying unauthenticated 404 metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated 404 on /metrics must NOT be accepted as ready: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Test 2: /metrics returns 500 unauthenticated
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (500, "text/plain", "Internal Server Error\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                if auth != Some(expected_auth) {
                    return (
                        401,
                        "application/json",
                        "{\"error\":\"unauthorized\"}\n".to_string(),
                    );
                }
                return (
                    200,
                    "application/json",
                    "{\"version\":\"1.75.2\"}\n".to_string(),
                );
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-unauth-500-metrics");
        let env_cfg = PackageExecutionEnv::isolated(&root);
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying unauthenticated 500 metrics rejection".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "unauthenticated 500 on /metrics must NOT be accepted as ready: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_rclone_readiness_rejects_mock_or_dry_run_output_when_dry_run_false() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Case 1: Server returns "ok: curl 200" on unauthenticated /metrics
    {
        let server = start_local_http_server(|method, path, _auth| {
            if path == "/metrics" && method == "GET" {
                return (200, "text/plain", "ok: curl 200\n".to_string());
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-mock-metrics-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying mock output rejection on metrics".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(res.is_err(), "server returning 'ok: curl 200' on unauthenticated /metrics must be rejected when dry_run=false: {:?}", res);
        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Server returns "[dry-run] curl" on unauthenticated /core/version
    {
        let server = start_local_http_server(|method, path, auth| {
            let expected_auth = "Basic YWRtaW46bXlzZWNyZXQ=";
            if path == "/metrics" && method == "GET" {
                if auth != Some(expected_auth) {
                    return (401, "text/plain", "Unauthorized\n".to_string());
                }
                return (
                    200,
                    "text/plain",
                    "# HELP rclone_version_info\n".to_string(),
                );
            }
            if path == "/core/version" && method == "POST" {
                return (200, "text/plain", "[dry-run] curl\n".to_string());
            }
            (404, "text/plain", "Not Found\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("rclone-dryrun-version-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;
        let env_file = root.join("etc/rclone/rclone.env");
        fs::create_dir_all(env_file.parent().unwrap()).unwrap();
        fs::write(
            &env_file,
            "RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"mysecret\"\n",
        )
        .unwrap();

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("rclone").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/metrics".to_string(),
            progress_pct: 98,
            description: "Verifying [dry-run] output rejection on version".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(res.is_err(), "server returning '[dry-run] curl' on unauthenticated /core/version must be rejected when dry_run=false: {:?}", res);
        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn test_non_rclone_readiness_rejects_mock_or_dry_run_output_when_dry_run_false() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;

    // Case 1: Server returns "ok: curl 200" on GET /-/healthy
    {
        let server = start_local_http_server(|_method, _path, _auth| {
            (200, "text/plain", "ok: curl 200\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("non-rclone-mock-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("prometheus").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/-/healthy".to_string(),
            progress_pct: 98,
            description: "Verifying mock output rejection for non-rclone".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "non-rclone returning 'ok: curl 200' must be rejected when dry_run=false: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Case 2: Server returns "[dry-run] curl" on GET /-/healthy
    {
        let server = start_local_http_server(|_method, _path, _auth| {
            (200, "text/plain", "[dry-run] curl\n".to_string())
        })
        .await;

        let root = create_isolated_test_dir("non-rclone-dryrun-reject");
        let mut env_cfg = PackageExecutionEnv::isolated(&root);
        env_cfg.dry_run = false;

        let executor = DeclarativePackageExecutor::new(env_cfg);
        let recipe = get_declarative_recipe("prometheus").unwrap();
        let mut vars = HashMap::new();
        vars.insert("APP_PORT".to_string(), server.port.to_string());
        let step = DeclarativeStep::WaitForHttpReady {
            path: "/-/healthy".to_string(),
            progress_pct: 98,
            description: "Verifying [dry-run] output rejection for non-rclone".to_string(),
        };

        let res = executor
            .run_single_step(
                &recipe,
                &step,
                &mut vars,
                &mut RollbackJournal::new(None),
                &CancellationToken::new(),
            )
            .await;
        assert!(
            res.is_err(),
            "non-rclone returning '[dry-run] curl' must be rejected when dry_run=false: {:?}",
            res
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[test]
fn test_stale_rclone_web_unit_does_not_override_active_single_port_unit() {
    let root = create_isolated_test_dir("stale-rclone-web-unit");

    // Create active single-port rclone.service WITHOUT --api-addr
    let rclone_svc = root.join("etc/systemd/system/rclone.service");
    fs::create_dir_all(rclone_svc.parent().unwrap()).unwrap();
    fs::write(
            &rclone_svc,
            "[Unit]\nDescription=Rclone\n[Service]\nExecStart=/usr/bin/rclone rcd --rc-addr=127.0.0.1:5572\n",
        ).unwrap();

    // Create stale split-port rclone-web.service WITH --api-addr
    let stale_web_svc = root.join("etc/systemd/system/rclone-web.service");
    fs::write(
            &stale_web_svc,
            "[Unit]\nDescription=Stale Rclone Web\n[Service]\nExecStart=/usr/bin/rclone gui --addr=127.0.0.1:5572 --api-addr=127.0.0.1:5573\n",
        ).unwrap();

    let vars = HashMap::new();
    let detected = detect_rclone_separate_api_port_for_root(&root, &vars, 5572);
    assert_eq!(
        detected, None,
        "active rclone.service must not be overridden by stale rclone-web.service with --api-addr"
    );

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_rclone_rollback_preserves_preexisting_binary_and_symlink_on_failure() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-rollback-preserves");
    let work_dir = create_isolated_test_dir("rclone-work-preserves");

    // Pre-create pre-existing /usr/local/bin/rclone and /usr/bin/rclone symlink
    let usr_local_bin = root.join("usr/local/bin/rclone");
    fs::create_dir_all(usr_local_bin.parent().unwrap()).unwrap();
    fs::write(&usr_local_bin, b"original-rclone-binary-v1.60.0").unwrap();

    let usr_bin = root.join("usr/bin/rclone");
    fs::create_dir_all(usr_bin.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/usr/local/bin/rclone", &usr_bin).unwrap();

    // Stage zip with mismatched SHA-256
    let (zip_path, _real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary with sha mismatch".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert(
        "RCLONE_ARCHIVE_SHA256".to_string(),
        "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb".to_string(),
    );

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    assert!(res.is_err(), "SHA-256 mismatch must fail");

    // The pre-existing binary and symlink MUST remain completely intact!
    assert!(
        usr_local_bin.is_file(),
        "pre-existing /usr/local/bin/rclone must remain intact"
    );
    assert_eq!(
        fs::read(&usr_local_bin).unwrap(),
        b"original-rclone-binary-v1.60.0"
    );
    assert!(
        usr_bin.exists() || fs::symlink_metadata(&usr_bin).is_ok(),
        "pre-existing /usr/bin/rclone must exist"
    );
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(&usr_bin).unwrap(),
        PathBuf::from("/usr/local/bin/rclone")
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_upgrade_and_rollback_preserve_distro_and_operator_binaries() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-symlink-dest");
    let work_dir = create_isolated_test_dir("rclone-symlink-work");

    let operator = root.join("usr/local/bin/rclone");
    fs::create_dir_all(operator.parent().unwrap()).unwrap();
    fs::write(&operator, b"operator payload").unwrap();

    let distro = root.join("usr/bin/rclone");
    fs::create_dir_all(distro.parent().unwrap()).unwrap();
    fs::write(&distro, b"distro payload").unwrap();

    let managed = root.join(RCLONE_BIN.trim_start_matches('/'));
    let owner = root.join(RCLONE_BIN_OWNER.trim_start_matches('/'));
    fs::create_dir_all(managed.parent().unwrap()).unwrap();
    fs::write(&managed, b"prior managed payload").unwrap();
    fs::write(&owner, b"rclone\n").unwrap();

    // Stage zip with matching target version 1.75.2
    let (zip_path, real_sha) = create_test_rclone_zip(&work_dir, "v1.75.2");

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Upgrading the managed Rclone binary".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), real_sha);

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    res.unwrap();
    assert_ne!(fs::read(&managed).unwrap(), b"prior managed payload");
    assert_eq!(fs::read(&distro).unwrap(), b"distro payload");
    assert_eq!(fs::read(&operator).unwrap(), b"operator payload");

    let _notes = journal.rollback(&executor.runner).await;
    assert_eq!(fs::read(&managed).unwrap(), b"prior managed payload");
    assert_eq!(fs::read(&distro).unwrap(), b"distro payload");
    assert_eq!(fs::read(&operator).unwrap(), b"operator payload");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[tokio::test]
async fn test_rclone_install_requires_dash_dash_version() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("rclone-dashdash-ver-root");
    let work_dir = create_isolated_test_dir("rclone-dashdash-ver-work");

    let bin_path = work_dir.join("rclone");
    let c_code = r#"#include <stdio.h>
#include <string.h>
int main(int argc, char** argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        return 2; // fails on --version
    }
    if (argc > 1 && strcmp(argv[1], "version") == 0) {
        puts("rclone v1.75.2");
        return 0; // succeeds on version fallback
    }
    return 1;
}
"#;
    let mut child = std::process::Command::new("gcc")
        .args(["-x", "c", "-", "-o", &bin_path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("gcc must be available for testing ELF binary verification");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(c_code.as_bytes());
    }
    assert!(child.wait().unwrap().success());

    let zip_path = work_dir.join("test_rclone_subcmd.zip");
    let status = std::process::Command::new("zip")
        .args([
            "-j",
            &zip_path.to_string_lossy(),
            &bin_path.to_string_lossy(),
        ])
        .status()
        .expect("zip command must succeed");
    assert!(status.success());

    let zip_bytes = fs::read(&zip_path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&zip_bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());

    let env_cfg = PackageExecutionEnv::isolated(&root);
    let executor = DeclarativePackageExecutor::new(env_cfg);
    let recipe = get_declarative_recipe("rclone").unwrap();

    let step = DeclarativeStep::InstallRcloneBinary {
        progress_pct: 60,
        description: "Installing rclone binary with failing --version".to_string(),
    };

    let mut vars = HashMap::new();
    vars.insert("AF_TARGET_VERSION".to_string(), "1.75.2".to_string());
    vars.insert(
        "RCLONE_ARCHIVE_PATH".to_string(),
        zip_path.to_string_lossy().to_string(),
    );
    vars.insert("RCLONE_ARCHIVE_SHA256".to_string(), sha256_hex);

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let res = executor
        .run_single_step(
            &recipe,
            &step,
            &mut vars,
            &mut journal,
            &CancellationToken::new(),
        )
        .await;
    assert!(
        res.is_err(),
        "Install must fail when --version fails, even if 'version' succeeds"
    );
    let err_str = format!("{:?}", res);
    assert!(
        err_str.contains("--version"),
        "Error must cite failed self-test '--version': {}",
        err_str
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&work_dir);
}

#[test]
fn test_preflight_rejects_tmpfs_staging() {
    let shm_dir = Path::new("/dev/shm");
    if !shm_dir.exists() {
        return;
    }
    let test_root = shm_dir.join(format!("af-test-tmpfs-{}", uuid::Uuid::new_v4()));
    let var_tmp_dir = test_root.join("var/tmp");
    fs::create_dir_all(&var_tmp_dir).unwrap();

    // 1. Direct check_filesystem_capacity_and_inodes on /dev/shm/.../var/tmp must reject tmpfs
    let direct_res = check_filesystem_capacity_and_inodes(&var_tmp_dir, 512 * 1024 * 1024, 1024);
    assert!(
        direct_res.is_err(),
        "check_filesystem_capacity_and_inodes on tmpfs /var/tmp must fail"
    );
    let err_msg = direct_res.unwrap_err();
    assert!(
        err_msg.contains("tmpfs"),
        "Error message must specify tmpfs rejection: {}",
        err_msg
    );

    // 2. preflight_check_disk_and_inodes with fs_root in /dev/shm must reject tmpfs /var/tmp
    let preflight_res = preflight_check_disk_and_inodes(Some(&test_root));
    assert!(
        preflight_res.is_err(),
        "preflight_check_disk_and_inodes must reject tmpfs staging root"
    );

    // 3. AF_REJECT_TMPFS_STAGING=1 must also reject tmpfs on any check path
    std::env::set_var("AF_REJECT_TMPFS_STAGING", "1");
    let env_res = check_filesystem_capacity_and_inodes(&test_root, 512 * 1024 * 1024, 1024);
    assert!(
        env_res.is_err(),
        "AF_REJECT_TMPFS_STAGING=1 must reject tmpfs mount"
    );
    std::env::remove_var("AF_REJECT_TMPFS_STAGING");

    let _ = fs::remove_dir_all(&test_root);
}

#[test]
fn test_incomplete_rollback_line_detection_and_formatting() {
    let lines = [
            "Rclone rollback aborted because service quiescence failed; preserving recovery archive /var/backups/rclone (incomplete-rollback)",
            "Application recovery is incomplete; recovery backup preserved",
            "Rollback incomplete; recovery backup preserved",
            "Failed to stop unit sonarr.service",
        ];

    for line in lines {
        let lower = line.to_ascii_lowercase();
        assert!(
            crate::package_lifecycle::is_incomplete_rollback_error(line)
                || lower.contains("incomplete-rollback")
                || lower.contains("incomplete rollback")
                || lower.contains("recovery backup preserved"),
            "Line must match incomplete rollback criteria: {line}"
        );

        let sanitized = crate::package_lifecycle::sanitize_lifecycle_field(line.trim());
        let exit_err = format!(
                "__RUNNER_EXIT_ERROR__:exit status 1 [STAGE:rollback] [CATEGORY:incomplete_rollback] [SUMMARY:{}] | incomplete-rollback\n",
                sanitized
            );

        assert!(
            crate::package_lifecycle::is_incomplete_rollback_error(&exit_err),
            "Formatted exit error must be identified by is_incomplete_rollback_error: {exit_err}"
        );
    }
}

#[test]
fn test_format_exit_failure_diagnostics_overrides_stage_and_diag_json_on_incomplete_rollback() {
    let raw_diag = serde_json::json!({
        "stage": "installer",
        "category": "installer_failure",
        "summary": "install boom",
    });

    let inc_line = "Failed to stop unit test.service (incomplete-rollback)";
    let exit_msg = format_exit_failure_diagnostics(1, Some(&raw_diag), Some(inc_line))
        .expect("Must format diagnostic exit message");

    // 1. Message must have [STAGE:rollback] [CATEGORY:incomplete_rollback]
    assert!(
        exit_msg.contains("[STAGE:rollback]"),
        "Must override stage to rollback: {exit_msg}"
    );
    assert!(
        exit_msg.contains("[CATEGORY:incomplete_rollback]"),
        "Must set category to incomplete_rollback: {exit_msg}"
    );
    assert!(
        exit_msg.contains("install boom; Failed to stop unit test.service (incomplete-rollback)"),
        "Summary must combine: {exit_msg}"
    );

    // 2. Trailing AF_DIAG_FAILURE={...} must have stage: rollback, category: incomplete_rollback, and updated summary
    let marker = "AF_DIAG_FAILURE=";
    let pos = exit_msg
        .find(marker)
        .expect("Must contain AF_DIAG_FAILURE marker");
    let json_part = exit_msg[pos + marker.len()..].trim();
    let parsed: serde_json::Value =
        serde_json::from_str(json_part).expect("Trailing JSON must be valid");

    assert_eq!(
        parsed.get("stage").and_then(|v| v.as_str()),
        Some("rollback")
    );
    assert_eq!(
        parsed.get("category").and_then(|v| v.as_str()),
        Some("incomplete_rollback")
    );
    assert_eq!(
        parsed.get("summary").and_then(|v| v.as_str()),
        Some("install boom; Failed to stop unit test.service (incomplete-rollback)")
    );
}

include!("../native_catalog_regressions.rs");

fn create_apache_test_certificate(directory: &Path, san: &str) {
    fs::create_dir_all(directory).unwrap();
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=example.test",
            "-addext",
            &format!("subjectAltName={san}"),
            "-keyout",
        ])
        .arg(directory.join("privkey.pem"))
        .arg("-out")
        .arg(directory.join("fullchain.pem"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn generated_master_credentials_include_encrypted_digest() {
    use std::os::unix::fs::PermissionsExt;
    let _env = crate::ENV_TEST_MUTEX.lock().await;
    let root = create_isolated_test_dir("generated-master-digest");
    let vars = [
        "AETHERFLOW_MASTER_PASS",
        "MASTER_PASS",
        "AF_PASS",
        "AETHERFLOW_VNC_PASSWORD",
        "AETHERFLOW_MASTER_CREDS_FILE",
        "AES_MASTER_KEY",
    ];
    let previous = vars.map(|key| (key, env::var_os(key)));
    for key in vars {
        env::remove_var(key);
    }
    env::set_var("AES_MASTER_KEY", "11".repeat(32));
    let result = try_resolve_master_credentials(Some(&root));
    let path = root.join("var/lib/aetherflow/.master.creds");
    let stored = fs::read_to_string(&path).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let password = af_db::decrypt_secret_if_needed(stored["password"].as_str().unwrap());
    let stored_digest = af_db::decrypt_secret_if_needed(stored["ha1"].as_str().unwrap());
    for (key, value) in previous {
        if let Some(value) = value {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }
    let (user, secret) = result.unwrap();
    assert_eq!(stored["username"], user);
    assert!(stored["password"].as_str().unwrap().starts_with("enc:v1:"));
    assert!(stored["ha1"].as_str().unwrap().starts_with("enc:v1:"));
    assert!(password.is_ok_and(|password| password == secret));
    let expected = hex::encode(af_models::md5::md5_digest(
        format!("{user}:Welcome to AetherFlow:{secret}").as_bytes(),
    ));
    assert!(stored_digest.is_ok_and(|digest| digest == expected));
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn threadfin_ignores_unpinned_target_and_catalog_matches_native_recipes() {
    let _env = crate::ENV_TEST_MUTEX.lock().await;
    let key = "AF_TARGET_VERSION";
    let previous = env::var_os(key);
    env::set_var(key, "99.9.9");
    let version = resolve_threadfin_target_version();
    if let Some(value) = previous {
        env::set_var(key, value);
    } else {
        env::remove_var(key);
    }
    assert_eq!(version, THREADFIN_PINNED_VERSION);
    let recipes: HashMap<String, af_models::PackageAutomation> =
        serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
    assert_eq!(recipes["threadfin"].update_source, "pinned");
    assert!(recipes["threadfin"].require_download_sha256);
    assert_eq!(recipes["prometheus"].update_source, "github");
    assert_eq!(recipes["prometheus"].update_repo, "prometheus/prometheus");
    assert_eq!(recipes["prometheus"].update_package, "prometheus");
    assert_eq!(
        recipes["prometheus"].version_command,
        ["/usr/local/bin/prometheus", "--version"]
    );
}

#[test]
fn apache_tls_uses_base_cert_only_for_covered_names() {
    let root = create_isolated_test_dir("base-san-cert");
    let base = root.join("etc/letsencrypt/live/example.test");
    create_apache_test_certificate(&base, "DNS:one.example.test,DNS:two.env.example.test");
    assert!(check_domain_tls_ready("one.example.test", Some(&root)));
    assert!(check_domain_tls_ready("two.env.example.test", Some(&root)));
    assert!(!check_domain_tls_ready("other.example.test", Some(&root)));

    create_apache_test_certificate(&base, "DNS:*.example.test");
    let pair = apache_tls_pair("other.example.test", Some(&root)).unwrap();
    assert_eq!(pair.0, "/etc/letsencrypt/live/example.test/fullchain.pem");
    assert!(!check_domain_tls_ready("two.env.example.test", Some(&root)));

    create_apache_test_certificate(&root.join("different-key"), "DNS:*.example.test");
    fs::copy(
        root.join("different-key/privkey.pem"),
        base.join("privkey.pem"),
    )
    .unwrap();
    assert!(!check_domain_tls_ready("other.example.test", Some(&root)));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn newly_created_non_secret_parents_are_traversable() {
    use std::os::unix::fs::PermissionsExt;
    let root = create_isolated_test_dir("install-parent-permissions");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.join("opt/new-app");
    create_dir_all_0755(&target).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for path in [target, root.join("opt")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_apache_vhost_pins_kasm_tls_and_requires_auth_for_public_backends() {
    let root = create_isolated_test_dir("managed-vhost-tls-auth");
    let cert = root.join("var/lib/kasmvnc/.vnc/aetherflow-cert.pem");
    fs::create_dir_all(cert.parent().unwrap()).unwrap();
    fs::write(&cert, "upstream-cert-fixture").unwrap();
    let mut req = af_models::RunnerApacheVhostRequest {
        app_name: "kasmvnc".to_owned(),
        listen_port: 8444,
        ..Default::default()
    };
    let kasm_tls = apache_upstream_tls("kasmvnc", Some(&root)).unwrap();
    let rendered = render_managed_apache_vhost(
        &req,
        "kasmvnc.aether.local",
        true,
        &kasm_tls,
        Some(&root),
        &[],
        &[],
    )
    .unwrap();
    assert!(
        rendered.contains("SSLProxyCACertificateFile /var/lib/kasmvnc/.vnc/aetherflow-cert.pem")
    );
    assert!(rendered.contains("wss://127.0.0.1:8444/"));
    assert!(rendered.contains("https://127.0.0.1:8444/"));

    req.app_name = "prometheus".to_string();
    req.tls_enabled = true;
    let domain = "metrics.example.test";
    let options = LibreSpeedUpstreamTlsConfig::default();
    let legacy = "<Location /custom>\n    Require all granted\n</Location>\n";
    let pending =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[], &[legacy])
            .unwrap();
    assert!(pending.contains("TLS certificate provisioning pending"));
    assert!(pending.contains("RewriteRule ^ - [R=503,L]"));
    assert!(pending.contains("ProxyPass /.well-known/acme-challenge/ !"));
    assert!(!pending.contains("ProxyPass / http"));
    assert!(!pending.contains("AuthType Basic"));
    assert!(!pending.contains("<VirtualHost *:443>"));
    assert!(pending.contains("# af-tls-pending: <Location /custom>"));
    assert!(!check_domain_tls_ready(domain, Some(&root)));
    let htpasswd = root.join(APACHE_HTPASSWD.trim_start_matches('/'));
    fs::create_dir_all(htpasswd.parent().unwrap()).unwrap();
    fs::write(&htpasswd, "fixture").unwrap();
    let tls_dir = root.join("etc/letsencrypt/live").join(domain);
    create_apache_test_certificate(&tls_dir, "DNS:metrics.example.test");
    let managed =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&pending], &[])
            .unwrap();
    assert!(managed.contains("RewriteRule ^ https://metrics.example.test%{REQUEST_URI} [R=308,L]"));
    assert!(managed.contains("<Location /custom>"));
    assert!(
        managed
            .find("ProxyPass /.well-known/acme-challenge/ !")
            .unwrap()
            < managed.find("[R=308,L]").unwrap()
    );
    for header in [
        "X-Real-IP",
        "X-Forwarded-Host",
        "X-Aetherflow-User",
        "Remote-User",
        "X-Forwarded-User",
    ] {
        assert!(managed.contains(&format!("RequestHeader unset {header}")));
    }
    assert!(managed.contains("RequestHeader set X-Real-IP \"%{REMOTE_ADDR}s\""));
    assert!(managed.contains("<VirtualHost *:443>"));
    assert!(managed
        .contains("SSLCertificateKeyFile /etc/letsencrypt/live/metrics.example.test/privkey.pem"));
    assert!(managed.contains("AuthUserFile /etc/apache2/AetherFlow/htpasswd"));
    assert!(managed.contains("Require valid-user"));
    let rerendered =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&managed], &[])
            .unwrap();
    assert_eq!(managed, rerendered);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_apache_vhost_routes_protected_apps_through_the_gateway() {
    let root = create_isolated_test_dir("managed-vhost-gateway");
    let options = LibreSpeedUpstreamTlsConfig::default();
    let domain = "app.example.test";
    let old_auth = r#"    <If "true">
        AuthType Basic
        AuthName "AetherFlow"
        AuthBasicProvider file
        AuthUserFile /etc/apache2/AetherFlow/htpasswd
        AuthMerging And
        Require valid-user
    </If>
"#;
    let inherited = format!(
        "<VirtualHost *:443>\n    ServerName {domain}\n    ProxyPass / http://127.0.0.1:19090/\n{old_auth}</VirtualHost>\n"
    );
    let tls_dir = root.join("etc/letsencrypt/live").join(domain);
    create_apache_test_certificate(&tls_dir, "DNS:app.example.test");
    for app in [
        "mcvnc",
        "scrutiny",
        "prometheus",
        "flaresolverr",
        "jackett",
        "threadfin",
        "unmanic",
        "netdata",
        "autoscan",
    ] {
        let req = af_models::RunnerApacheVhostRequest {
            app_name: app.into(),
            listen_port: 19090,
            public_domain: Some(domain.into()),
            external_access_enabled: true,
            tls_enabled: true,
            ..Default::default()
        };
        let body = render_managed_apache_vhost(
            &req,
            domain,
            false,
            &options,
            Some(&root),
            &[&inherited],
            &[],
        )
        .unwrap();
        let (http, tls) = body.split_once("<VirtualHost *:443>").unwrap();
        assert!(http.contains(ACME_HTTP_EXEMPTION));
        assert!(http.contains(ACME_REWRITE_GUARD));
        assert!(http.contains("RewriteRule ^ https://app.example.test%{REQUEST_URI} [R=308,L]"));
        assert!(!http.contains(GATEWAY_APP_HEADER));
        assert!(tls.contains("ProxyPreserveHost On"));
        assert!(tls.contains("RequestHeader unset X-Forwarded-For"));
        assert!(tls.contains("RewriteRule /(.*) ws://127.0.0.1:8080/$1 [P,L]"));
        assert!(tls.contains("ProxyPass / http://127.0.0.1:8080/"));
        assert!(tls.contains("ProxyPassReverse / http://127.0.0.1:19090/"));
        assert!(tls.contains(&format!("RequestHeader set {GATEWAY_APP_HEADER} {app}")));
        assert!(!tls.contains("AuthUserFile"));
        assert!(!tls.contains("ProxyPass / http://127.0.0.1:19090/"));
        let mut missing_ingress = req.clone();
        missing_ingress.listen_port = 19091;
        missing_ingress.external_access_enabled = false;
        assert_eq!(
            update_legacy_apache_vhost(&body, &missing_ingress, &options, Some(&root), true)
                .unwrap(),
            body
        );
        assert_eq!(
            render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&body], &[])
                .unwrap(),
            body
        );

        if app == "netdata" {
            let mut plain = req;
            plain.tls_enabled = false;
            let body =
                render_managed_apache_vhost(&plain, domain, false, &options, Some(&root), &[], &[])
                    .unwrap();
            assert!(
                body.find(ACME_HTTP_EXEMPTION).unwrap()
                    < body.find("ProxyPass / http://127.0.0.1:8080/").unwrap()
            );
            assert!(
                body.find(ACME_REWRITE_GUARD).unwrap()
                    < body.find("RewriteRule /(.*) ws://127.0.0.1:8080/").unwrap()
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn inherited_apache_vhost_and_rutorrent_keep_apache_auth() {
    let root = create_isolated_test_dir("inherited-vhost-auth");
    let htpasswd = root.join(APACHE_HTPASSWD.trim_start_matches('/'));
    fs::create_dir_all(htpasswd.parent().unwrap()).unwrap();
    fs::write(htpasswd, "fixture").unwrap();
    let mut req = af_models::RunnerApacheVhostRequest {
        app_name: "rutorrent".into(),
        listen_port: 8087,
        public_domain: Some("torrent.example.test".into()),
        external_access_enabled: true,
        ..Default::default()
    };
    let options = LibreSpeedUpstreamTlsConfig::default();
    let body = render_managed_apache_vhost(
        &req,
        "torrent.example.test",
        false,
        &options,
        Some(&root),
        &[],
        &[],
    )
    .unwrap();
    assert!(body.contains("ProxyPass / http://127.0.0.1:8087/"));
    assert!(body.contains(APACHE_HTPASSWD));
    assert!(!body.contains(GATEWAY_APP_HEADER));

    let legacy = "\
<VirtualHost *:80>
    ServerName app.example.test
    ProxyPass / http://127.0.0.1:19090/
    <Location /private>
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
    req.app_name = "prometheus".into();
    req.public_domain = Some("app.example.test".into());
    req.listen_port = 19091;
    let updated = update_legacy_apache_vhost(legacy, &req, &options, Some(&root), false).unwrap();
    assert!(updated.contains("ProxyPass / http://127.0.0.1:19091/"));
    assert!(updated.contains("Require ip 192.0.2.0/24"));
    assert!(updated.contains("AuthMerging And"));
    assert!(updated.contains(APACHE_HTPASSWD));
    assert!(!updated.contains(GATEWAY_APP_HEADER));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_librespeed_apache_vhost_honors_and_toggles_upstream_tls() {
    assert!(!parse_librespeed_root_tls_flag("enable_tls = false\n"));
    assert!(parse_librespeed_root_tls_flag(
        "listen_port = 8988\nenable_tls = true # comment\n"
    ));
    assert!(!parse_librespeed_root_tls_flag(
        "enable_tls = false\n[extra]\nenable_tls = true\n"
    ));
    assert!(parse_librespeed_root_tls_flag(
        "enable_tls = true\nbanner = \"\"\"\n# example:\nenable_tls = false\n\"\"\"\n"
    ));
    assert!(parse_librespeed_root_tls_flag(
        "enable_tls = true\nnotes = '''\nenable_tls = false\n'''\n"
    ));

    let http_default = "# Managed by AetherFlow v3.2.6\n<VirtualHost *:80>\n    ServerName librespeed.aether.local\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{HTTP:Upgrade} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:8988/$1 [P,L]\n    ProxyPass / http://127.0.0.1:8988/\n    ProxyPassReverse / http://127.0.0.1:8988/\n    RequestHeader set X-Forwarded-Proto \"http\"\n    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf\n</VirtualHost>\n";

    // Pin operator certificate via SSLProxyCACertificateFile + SSLProxyVerify require when enable_tls=true
    let pinned_tls = render_or_update_runner_apache_vhost_with_ca(
        Some(http_default),
        http_default,
        Some("librespeed.aether.local"),
        18988,
        Some(true),
        Some("/opt/librespeed/cert.pem"),
        &["    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string()],
    );
    assert!(pinned_tls.contains("SSLProxyEngine On"));
    assert!(pinned_tls.contains("SSLProxyVerify require"));
    assert!(pinned_tls.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
    assert!(!pinned_tls.contains("SSLProxyVerify none"));
    assert!(pinned_tls.contains("wss://127.0.0.1:18988/$1"));
    assert!(pinned_tls.contains("ProxyPass / https://127.0.0.1:18988/"));
    assert!(pinned_tls.contains("ProxyPassReverse / https://127.0.0.1:18988/"));

    // Fail closed if enable_tls=true in settings.toml lacks a valid regular tls_cert_file
    let tmp_dir = std::env::temp_dir().join(format!(
        "af-runner-librespeed-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(tmp_dir.join("etc/apache2/sites-available")).unwrap();
    fs::create_dir_all(tmp_dir.join("etc/apache2/sites-enabled")).unwrap();
    fs::create_dir_all(tmp_dir.join("opt/librespeed")).unwrap();
    fs::write(
            tmp_dir.join("opt/librespeed/settings.toml"),
            "enable_tls = true\ntls_cert_file = \"/opt/librespeed/missing-cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
        )
        .unwrap();
    let mut changes = RunnerBlueprintConfigChanges::new(Some(&tmp_dir));
    let err =
        apply_runner_blueprint_app_config_changes(&mut changes, "librespeed", 18988, |_| Ok(None))
            .expect_err("enable_tls=true without valid tls_cert_file must fail closed");
    assert!(
        err.to_string().contains("SSLProxyCACertificateFile"),
        "unexpected error: {err}"
    );

    // Succeeds with pinned SSLProxyCACertificateFile once regular tls_cert_file exists
    fs::write(
        tmp_dir.join("opt/librespeed/cert.pem"),
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
            tmp_dir.join("opt/librespeed/settings.toml"),
            "enable_tls = true\ntls_cert_file = \"/opt/librespeed/cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
        )
        .unwrap();
    let mut ok_changes = RunnerBlueprintConfigChanges::new(Some(&tmp_dir));
    apply_runner_blueprint_app_config_changes(&mut ok_changes, "librespeed", 18988, |_| Ok(None))
        .expect("enable_tls=true with valid regular tls_cert_file must succeed");
    let rendered_on_disk = fs::read_to_string(
        tmp_dir.join("etc/apache2/sites-available/aetherflow-app-librespeed.conf"),
    )
    .unwrap();
    assert!(rendered_on_disk.contains("SSLProxyVerify require"));
    assert!(rendered_on_disk.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
    assert!(!rendered_on_disk.contains("SSLProxyVerify none"));
    let _ = fs::remove_dir_all(&tmp_dir);

    // Downgrade back to HTTP cleanly when enable_tls=false
    let demoted_http = render_or_update_runner_apache_vhost(
        Some(&pinned_tls),
        http_default,
        Some("librespeed.aether.local"),
        18989,
        Some(false),
        &["    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string()],
    );
    assert!(!demoted_http.contains("SSLProxyEngine"));
    assert!(!demoted_http.contains("SSLProxyCACertificateFile"));
    assert!(demoted_http.contains("ws://127.0.0.1:18989/$1"));
    assert!(demoted_http.contains("ProxyPass / http://127.0.0.1:18989/"));
}

#[test]
fn parse_apt_cache_candidate_version_extracts_normalized_version() {
    let policy =
        "prometheus:\n  Installed: 2.45.3+ds-2\n  Candidate: 2:2.53.0+ds-1\n  Version table:\n";
    let parsed = parse_apt_cache_candidate_version(policy).unwrap();
    assert_eq!(parsed, "2.53.0");
    assert!(af_release::lifecycle::versions_match_target(
        &parsed, "2.53.0"
    ));
    assert!(!af_release::lifecycle::versions_match_target(
        &parsed, "3.2.1"
    ));
    assert_eq!(
        parse_apt_cache_candidate_version(
            "prometheus:\n  Installed: (none)\n  Candidate: (none)\n"
        ),
        None
    );
}

#[tokio::test]
async fn prometheus_update_rejects_mismatched_apt_version_when_target_version_differs() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("prometheus-target-mismatch");
    let version_file = root.join("etc/prometheus/.af-version");
    fs::create_dir_all(version_file.parent().unwrap()).unwrap();
    fs::write(&version_file, "2.53.0\n").unwrap();

    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 9090;
    env_cfg.expected_target_version = Some("3.2.1".to_string());

    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
    let recipe = get_declarative_recipe("prometheus").unwrap();

    let err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("prometheus update must reject mismatched APT version against target 3.2.1");
    assert!(err.to_string().contains("3.2.1"), "unexpected error: {err}");
    // Must preserve pre-existing .af-version receipt on rollback.
    assert_eq!(fs::read_to_string(&version_file).unwrap().trim(), "2.53.0");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn novnc_uses_tigervnc_rfb_authentication_and_a_separate_xfce_session() {
    // Known DES-ECB vector using the bit-reversed RFB key.
    let cipher = encode_tigervnc_passwd("password and ignored bytes");
    assert_eq!(hex::encode(cipher), "dbd83cfd727a1458");
    assert_ne!(&cipher, b"password");
    assert_eq!(decode_tigervnc_passwd(&cipher).as_deref(), Some("password"));

    let recipe = get_declarative_recipe("novnc").unwrap();
    let unit = |name: &str| {
        recipe
            .install_steps
            .iter()
            .find_map(|step| match step {
                DeclarativeStep::WriteSystemdUnit {
                    unit_name,
                    content_template,
                    ..
                } if unit_name == name => Some(content_template.as_str()),
                _ => None,
            })
            .unwrap()
    };
    let xvnc = unit("novnc-xvnc.service");
    assert!(xvnc.contains("-PasswordFile /var/lib/novnc/.vnc/passwd"));
    assert!(xvnc.contains("Type=exec"));
    assert!(xvnc.contains("PrivateTmp=yes"));
    assert!(xvnc.contains("ExecStartPre=!/usr/bin/mkdir -p -m 1777 /tmp/.X11-unix"));
    assert!(!xvnc.contains("ExecStartPost="));
    let session = unit("novnc-session.service");
    for setting in [
        "BindsTo=novnc-xvnc.service",
        "After=novnc-xvnc.service",
        "JoinsNamespaceOf=novnc-xvnc.service",
        "PrivateTmp=yes",
        "User=novnc",
        "Group=novnc",
        "WorkingDirectory=/var/lib/novnc",
        "Environment=HOME=/var/lib/novnc DISPLAY=:1",
        "ExecStartPre=/usr/bin/timeout 10s",
        "test -S /tmp/.X11-unix/X1",
        "ExecStart=/var/lib/novnc/.vnc/xstartup",
    ] {
        assert!(session.contains(setting), "{setting}");
    }
    assert!(unit("novnc.service").contains("Requires=novnc-xvnc.service novnc-session.service"));
    assert!(crate::is_managed_runner_systemd_unit(
        "novnc-session.service"
    ));
    assert!(recipe.install_steps.iter().any(|step| matches!(step,
        DeclarativeStep::WriteTemplateFile { path, mode: 0o750, content_template, .. }
            if path.ends_with("/xstartup") && content_template.contains("export DISPLAY=:1")
                && content_template.contains("exec dbus-run-session startxfce4")
    )));
    assert!(recipe.install_steps.iter().any(|step| matches!(step,
        DeclarativeStep::Systemctl { unit: Some(unit), operation: SystemctlOp::EnableNow, .. }
            if unit == "novnc-session.service"
    )));
}

#[test]
fn apache_htpasswd_provisions_bcrypt_and_fails_closed_without_credentials() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = env::temp_dir().join(format!("af-htpasswd-{}", uuid::Uuid::new_v4()));
    let path = root.join("etc/apache2/AetherFlow/htpasswd");
    assert!(ensure_apache_htpasswd_with(&path, || None).is_err());
    assert!(!path.exists());
    assert!(external_auth_policy("netdata", Some(&root)).is_err());
    let hash = format!("$2b$10{}{}", '$', "a".repeat(53));
    let entry = apache_bcrypt_entry("admin", &hash).unwrap();
    assert!(entry.starts_with("admin:$2y$10$"));
    ensure_apache_htpasswd_with(&path, || Some(entry.clone())).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), entry);
    let meta = path.metadata().unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.gid(), crate::lookup_group_gid("www-data").unwrap_or(0));
    }
    ensure_apache_htpasswd_with(&path, || panic!("must preserve an existing file")).unwrap();
    for app in ["netdata", "unmanic", "autoscan"] {
        assert!(external_auth_policy(app, Some(&root))
            .unwrap()
            .contains("Require valid-user"));
    }
    fs::write(&path, "").unwrap();
    assert!(ensure_apache_htpasswd_with(&path, || None).is_err());
    ensure_apache_htpasswd_with(&path, || Some(entry.clone())).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), entry);
    fs::remove_dir_all(root).unwrap();
}

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvVarGuard {
    fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            saved.push((*key, env::var_os(key)));
            match value {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(val) => env::set_var(key, val),
                None => env::remove_var(key),
            }
        }
    }
}

#[tokio::test]
async fn test_pc04_cumulative_snapshot_ceiling_rejects_before_copy_across_multiple_state_dirs() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("pc04-cumulative-ceiling");

    let var_lib_syncthing = root.join("var/lib/syncthing");
    let etc_syncthing = root.join("etc/syncthing");
    fs::create_dir_all(&var_lib_syncthing).unwrap();
    fs::create_dir_all(&etc_syncthing).unwrap();

    // Seed prior app data alongside two sparse files that individually fit under 2 GiB
    // but cumulatively exceed the default 2 GiB ceiling.
    fs::write(var_lib_syncthing.join("config.xml"), b"<prior-data/>").unwrap();
    fs::File::create(var_lib_syncthing.join("index-a.db"))
        .unwrap()
        .set_len(1100 * 1024 * 1024)
        .unwrap();
    fs::File::create(etc_syncthing.join("index-b.db"))
        .unwrap()
        .set_len(1100 * 1024 * 1024)
        .unwrap();

    let mut journal = RollbackJournal::new(Some(root.clone()));
    let err = journal
        .stage_directory_snapshots_with_cancel(
            &[var_lib_syncthing.clone(), etc_syncthing.clone()],
            None,
        )
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
    let recipe = get_declarative_recipe("syncthing").unwrap();
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
        fs::read(var_lib_syncthing.join("config.xml")).unwrap(),
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
