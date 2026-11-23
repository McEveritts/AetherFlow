use super::*;

#[tokio::test]
async fn teardown_success_respects_explicit_purge_and_only_then_clears_marker() {
    for purge in [false, true] {
        let fixture = TeardownFixture::new("");
        assert!(fixture.remove(purge).await.is_ok());
        assert!(!fixture.root.join("install/.znc.lock").exists());
        assert_eq!(
            fixture.root.join("var/lib/znc/configs/znc.conf").is_file(),
            !purge
        );
        assert!(fixture
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.progress_pct == 100));
        let commands = fixture.runner.commands.lock().unwrap();
        assert_eq!(
            commands.iter().any(|(program, _)| program == "userdel"),
            purge
        );
        assert!(commands
            .iter()
            .any(|(program, arguments)| program == "apt-get"
                && arguments.contains(&if purge {
                    "purge".to_string()
                } else {
                    "remove".to_string()
                })));
        assert_eq!(
            commands.iter().any(|(program, arguments)| {
                program == "apt-get" && arguments.contains(&"autoremove".to_string())
            }),
            purge,
            "apt-get autoremove must run only when DELETE_DATA/purge is true"
        );
        if !purge {
            assert!(
                fixture
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|event| !event.message.contains("Purging ")),
                "non-purge teardown must not emit misleading 'Purging ' messages"
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn teardown_data_path_failure_does_not_clear_marker_or_follow_symlink() {
    let fixture = TeardownFixture::new("");
    let data = fixture.root.join("var/lib/znc");
    let unrelated = fixture.root.join("var/lib/unrelated");
    fs::create_dir_all(&unrelated).unwrap();
    fs::write(unrelated.join("sentinel"), "unrelated data").unwrap();
    fs::remove_dir_all(&data).unwrap();
    std::os::unix::fs::symlink(&unrelated, &data).unwrap();
    assert!(fixture.remove(true).await.is_err());
    assert!(fixture.root.join("install/.znc.lock").is_file());
    assert!(unrelated.join("sentinel").is_file());
    assert!(!fixture
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.progress_pct == 100));
}

#[derive(Clone, Default)]
#[allow(clippy::type_complexity)]
struct TeardownRunner {
    commands: Arc<StdMutex<Vec<(String, Vec<String>)>>>,
    fail_operation: String,
    fail_unit: String,
    unit_state: String,
    state_exit_code: i32,
    account_exit_code: i32,
}

impl CommandRunner for TeardownRunner {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        _envs: &'a [(String, String)],
        cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            cancel.check("teardown-fixture")?;
            self.commands
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            let operation = if program == "systemctl" {
                args.first().map(String::as_str).unwrap_or("")
            } else if program == "apt-get" {
                if args.iter().any(|argument| argument == "autoremove") {
                    "autoremove"
                } else {
                    "apt-get"
                }
            } else {
                program
            };
            if operation == "show" {
                return Ok(CommandOutput {
                    exit_code: self.state_exit_code,
                    stdout: self.unit_state.clone(),
                    stderr: String::new(),
                });
            }
            if program == "getent" {
                return Ok(CommandOutput {
                    exit_code: self.account_exit_code,
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            Ok(CommandOutput {
                exit_code: if operation == self.fail_operation
                    && (self.fail_unit.is_empty() || args.contains(&self.fail_unit))
                {
                    1
                } else {
                    0
                },
                stdout: String::new(),
                stderr: format!("fixture {operation}"),
            })
        })
    }
}

struct TeardownFixture {
    root: PathBuf,
    runner: TeardownRunner,
    events: StdMutex<Vec<PackageProgressEvent>>,
}

impl TeardownFixture {
    fn new(fail_operation: &str) -> Self {
        let root = env::temp_dir().join(format!("af-teardown-{}", uuid::Uuid::new_v4()));
        for directory in [
            "install",
            "etc/systemd/system/znc.service.d",
            "var/lib/znc/configs",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        for (path, content) in [
            ("install/.znc.lock", "installed"),
            ("etc/systemd/system/znc.service", "fixture unit"),
            (
                "etc/systemd/system/znc.service.d/sandbox.conf",
                "fixture sandbox",
            ),
            ("var/lib/znc/configs/znc.conf", "retained configuration"),
        ] {
            fs::write(root.join(path), content).unwrap();
        }
        Self {
            root,
            runner: TeardownRunner {
                fail_operation: fail_operation.to_string(),
                ..Default::default()
            },
            events: StdMutex::new(Vec::new()),
        }
    }

    async fn remove(&self, purge: bool) -> Result<PackageExecutionOutcome, PackageExecutorError> {
        let _serial = super::tests::TEST_EXECUTION_SERIALIZER.lock().await;
        let mut environment = PackageExecutionEnv::isolated(&self.root);
        environment.delete_data = purge;
        DeclarativePackageExecutor::with_runner(environment, self.runner.clone())
            .execute_recipe(
                &get_declarative_recipe("znc").unwrap(),
                PackageAction::Remove,
                CancellationToken::new(),
                |event| self.events.lock().unwrap().push(event),
            )
            .await
    }
}

impl Drop for TeardownFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn teardown_failed_stop_blocks_ordinary_remove() {
    assert_failed_stop_preserves_state(false).await;
}

#[tokio::test]
async fn teardown_failed_stop_blocks_explicit_purge() {
    assert_failed_stop_preserves_state(true).await;
}

async fn assert_failed_stop_preserves_state(purge: bool) {
    let fixture = TeardownFixture::new("stop");
    let outcome = fixture.remove(purge).await;
    let commands = fixture.runner.commands.lock().unwrap();
    println!("purge={purge} outcome={outcome:?} commands={commands:?}");
    assert!(
        outcome.is_err(),
        "an unproven stop must not report successful removal"
    );
    for path in [
        "install/.znc.lock",
        "etc/systemd/system/znc.service",
        "var/lib/znc/configs/znc.conf",
    ] {
        assert!(fixture.root.join(path).is_file(), "must retain {path}");
    }
    assert!(!commands
        .iter()
        .any(|(program, _)| ["apt-get", "userdel", "groupdel"].contains(&program.as_str())));
    assert!(!fixture
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.progress_pct == 100));
}

#[tokio::test]
async fn teardown_known_inactive_or_absent_stop_is_idempotent() {
    for state in [
        "LoadState=loaded\nActiveState=inactive\n",
        "LoadState=not-found\nActiveState=inactive\n",
    ] {
        let mut fixture = TeardownFixture::new("stop");
        fixture.runner.unit_state = state.to_string();
        assert!(fixture.remove(false).await.is_ok());
        assert!(!fixture.root.join("install/.znc.lock").exists());
        assert!(fixture.root.join("var/lib/znc/configs/znc.conf").is_file());
    }
}

#[tokio::test]
async fn teardown_unknown_active_failed_or_unreadable_state_fails_closed() {
    for (state, exit_code) in [
        ("LoadState=loaded\nActiveState=active\n", 0),
        ("LoadState=loaded\nActiveState=failed\n", 0),
        ("LoadState=not-found\nActiveState=active\n", 0),
        ("LoadState=loaded\nActiveState=inactive\n", 1),
        ("ActiveState=inactive\n", 0),
    ] {
        let mut fixture = TeardownFixture::new("stop");
        fixture.runner.unit_state = state.to_string();
        fixture.runner.state_exit_code = exit_code;
        assert!(fixture.remove(true).await.is_err());
        assert!(fixture.root.join("var/lib/znc/configs/znc.conf").is_file());
        assert!(fixture.root.join("install/.znc.lock").is_file());
    }
}

#[tokio::test]
async fn teardown_required_command_failures_never_complete_or_remove_marker() {
    for operation in [
        "disable",
        "reset-failed",
        "apt-get",
        "autoremove",
        "userdel",
        "groupdel",
        "daemon-reload",
    ] {
        let fixture = TeardownFixture::new(operation);
        assert!(
            fixture.remove(true).await.is_err(),
            "must reject {operation} failure"
        );
        assert!(
            fixture.root.join("install/.znc.lock").is_file(),
            "must retain marker after {operation} failure"
        );
        assert!(!fixture
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.progress_pct == 100));
        if !["userdel", "groupdel", "daemon-reload"].contains(&operation) {
            assert!(fixture.root.join("var/lib/znc/configs/znc.conf").is_file());
        }
    }
}

#[tokio::test]
async fn teardown_disable_failure_requires_absence_not_only_inactivity() {
    for (load_state, expected_success) in [("loaded", false), ("not-found", true)] {
        let mut fixture = TeardownFixture::new("disable");
        fixture.runner.unit_state = format!("LoadState={load_state}\nActiveState=inactive\n");
        assert_eq!(fixture.remove(false).await.is_ok(), expected_success);
    }
}

#[tokio::test]
async fn teardown_absent_accounts_are_idempotent_but_lookup_failure_is_not() {
    for (exit_code, expected_success) in [(2, true), (1, false)] {
        let mut fixture = TeardownFixture::new("");
        fixture.runner.account_exit_code = exit_code;
        assert_eq!(fixture.remove(true).await.is_ok(), expected_success);
        assert!(!fixture
            .runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, _)| program == "userdel" || program == "groupdel"));
    }
}

#[tokio::test]
async fn teardown_unit_or_dropin_filesystem_error_gates_data_and_marker() {
    for (relative, directory) in [
        ("etc/systemd/system/znc.service", true),
        ("etc/systemd/system/znc.service.d", false),
    ] {
        let fixture = TeardownFixture::new("");
        let path = fixture.root.join(relative);
        if directory {
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
        } else {
            fs::remove_dir_all(&path).unwrap();
            fs::write(&path, "not a drop-in directory").unwrap();
        }
        assert!(fixture.remove(true).await.is_err());
        assert!(fixture.root.join("var/lib/znc/configs/znc.conf").is_file());
        assert!(fixture.root.join("install/.znc.lock").is_file());
    }
}

#[tokio::test]
async fn teardown_missing_unit_and_dropin_paths_are_idempotent() {
    let fixture = TeardownFixture::new("");
    fs::remove_file(fixture.root.join("etc/systemd/system/znc.service")).unwrap();
    fs::remove_dir_all(fixture.root.join("etc/systemd/system/znc.service.d")).unwrap();
    assert!(fixture.remove(false).await.is_ok());
}

#[tokio::test]
async fn teardown_final_marker_unlink_failure_never_emits_complete() {
    let fixture = TeardownFixture::new("");
    let marker = fixture.root.join("install/.znc.lock");
    fs::remove_file(&marker).unwrap();
    fs::create_dir(&marker).unwrap();
    assert!(fixture.remove(false).await.is_err());
    assert!(marker.is_dir());
    assert!(!fixture
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.progress_pct == 100));
}

#[tokio::test]
async fn teardown_preflight_gates_apt_first_and_companion_recipes() {
    let _serial = super::tests::TEST_EXECUTION_SERIALIZER.lock().await;
    for package in ["fail2ban", "quassel"] {
        let fixture = TeardownFixture::new("stop");
        let recipe = get_declarative_recipe(package).unwrap();
        let marker = fixture.root.join(format!("install/.{package}.lock"));
        fs::write(&marker, "installed").unwrap();
        let executor = DeclarativePackageExecutor::with_runner(
            PackageExecutionEnv::isolated(&fixture.root),
            fixture.runner.clone(),
        );
        assert!(executor
            .execute_recipe(
                &recipe,
                PackageAction::Remove,
                CancellationToken::new(),
                |_| {}
            )
            .await
            .is_err());
        assert!(marker.is_file());
        assert!(!fixture
            .runner
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|(program, _)| program == "apt-get"));
    }
    let mut fixture = TeardownFixture::new("stop");
    fixture.runner.fail_unit = "z-companion.service".to_string();
    let mut recipe = get_declarative_recipe("znc").unwrap();
    recipe.remove_steps.push(DeclarativeStep::PurgeSystemdUnit {
        unit_name: "z-companion.service".to_string(),
        progress_pct: 96,
        description: "fixture companion".to_string(),
    });
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&fixture.root),
        fixture.runner.clone(),
    );
    assert!(executor
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {}
        )
        .await
        .is_err());
    assert!(fixture
        .root
        .join("etc/systemd/system/znc.service")
        .is_file());
    assert!(fixture.root.join("install/.znc.lock").is_file());
}

#[tokio::test]
async fn teardown_ignore_errors_cannot_bypass_a_required_stop() {
    let fixture = TeardownFixture::new("stop");
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&fixture.root),
        fixture.runner.clone(),
    );
    let step = DeclarativeStep::Systemctl {
        unit: Some("znc.service".to_string()),
        operation: SystemctlOp::Stop,
        ignore_errors: true,
        progress_pct: 10,
        description: "fixture stop".to_string(),
    };
    assert!(executor
        .run_single_step(
            &get_declarative_recipe("znc").unwrap(),
            &step,
            &mut HashMap::new(),
            &mut RollbackJournal::new(Some(fixture.root.clone())),
            &CancellationToken::new()
        )
        .await
        .is_err());
}

#[tokio::test]
async fn teardown_pre_stop_orders_novnc_and_socket_units_before_workers() {
    let _serial = super::tests::TEST_EXECUTION_SERIALIZER.lock().await;
    let fixture = TeardownFixture::new("");
    let systemd_dir = fixture.root.join("etc/systemd/system");
    fs::create_dir_all(&systemd_dir).unwrap();
    for unit in [
        "novnc.service",
        "novnc-session.service",
        "novnc-xvnc.service",
    ] {
        fs::write(systemd_dir.join(unit), "[Unit]\nDescription=fixture\n").unwrap();
    }
    fs::write(fixture.root.join("install/.novnc.lock"), "installed").unwrap();

    // Explicit multi-unit teardown fixture verifying proxy -> session -> xvnc stop ordering.
    let multi_unit_recipe = DeclarativePackageRecipe {
        package_id: "novnc".to_string(),
        label: "noVNC Fixture".to_string(),
        default_port: 6080,
        service_name: "novnc".to_string(),
        lock_file: "/install/.novnc.lock".to_string(),
        apply_systemd_sandbox: false,
        install_steps: vec![],
        update_steps: vec![],
        remove_steps: vec![
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc-xvnc.service".to_string(),
                progress_pct: 20,
                description: "stop xvnc".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc-session.service".to_string(),
                progress_pct: 40,
                description: "stop session".to_string(),
            },
            DeclarativeStep::PurgeSystemdUnit {
                unit_name: "novnc.service".to_string(),
                progress_pct: 60,
                description: "stop proxy".to_string(),
            },
        ],
    };
    let executor = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&fixture.root),
        fixture.runner.clone(),
    );
    executor
        .execute_recipe(
            &multi_unit_recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();

    let stops: Vec<String> = fixture
        .runner
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|(prog, args)| {
            prog == "systemctl" && args.first().map(String::as_str) == Some("stop")
        })
        .filter_map(|(_, args)| args.last().cloned())
        .collect();
    assert!(stops.len() >= 3, "expected pre-teardown stops: {stops:?}");
    assert_eq!(
        &stops[..3],
        &[
            "novnc.service".to_string(),
            "novnc-session.service".to_string(),
            "novnc-xvnc.service".to_string(),
        ]
    );

    // Also verify a recipe with a .socket stops the socket before its worker service
    let fixture2 = TeardownFixture::new("");
    let mut recipe = get_declarative_recipe("znc").unwrap();
    recipe.remove_steps.push(DeclarativeStep::PurgeSystemdUnit {
        unit_name: "znc.socket".to_string(),
        progress_pct: 25,
        description: "fixture socket".to_string(),
    });
    let executor2 = DeclarativePackageExecutor::with_runner(
        PackageExecutionEnv::isolated(&fixture2.root),
        fixture2.runner.clone(),
    );
    executor2
        .execute_recipe(
            &recipe,
            PackageAction::Remove,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .unwrap();
    let stops2: Vec<String> = fixture2
        .runner
        .commands
        .lock()
        .unwrap()
        .iter()
        .filter(|(prog, args)| {
            prog == "systemctl" && args.first().map(String::as_str) == Some("stop")
        })
        .filter_map(|(_, args)| args.last().cloned())
        .collect();
    assert!(
        stops2.len() >= 2,
        "expected socket-first pre-teardown stops: {stops2:?}"
    );
    assert_eq!(stops2[0], "znc.socket");
    assert_eq!(stops2[1], "znc.service");
}
