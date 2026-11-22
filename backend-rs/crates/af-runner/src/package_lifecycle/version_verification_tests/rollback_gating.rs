use super::*;

#[tokio::test]
async fn test_script_failure_triggers_receipt_and_blueprint_rollback_when_services_restart_cleanly()
{
    let (root, _path, conn, _) = test_fixture();
    let sonarr_dir = root.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_dir).unwrap();
    let opt_sonarr = root.join("opt/sonarr");
    std::fs::create_dir_all(&opt_sonarr).unwrap();

    let receipt_file = opt_sonarr.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let config_file = sonarr_dir.join("config.xml");
    std::fs::write(&config_file, b"<Config><Port>8989</Port></Config>\n").unwrap();

    let uncommitted_receipt = root.join("var/lib/sonarr/.af-version");

    let package = Package {
        name: "sonarr".into(),
        service_name: "sonarr".into(),
        service_type: "systemd".into(),
        default_port: 8989,
        ..Default::default()
    };

    struct FailScriptBackend {
        receipt_file: PathBuf,
        uncommitted_receipt: PathBuf,
        config_file: PathBuf,
    }
    impl LifecycleBackend for FailScriptBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8989
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let receipt_path = self.receipt_file.clone();
            let uncommitted_path = self.uncommitted_receipt.clone();
            let config_path = self.config_file.clone();
            Box::pin(async move {
                std::fs::write(&receipt_path, b"2.0.0-uncommitted\n").unwrap();
                std::fs::create_dir_all(uncommitted_path.parent().unwrap()).unwrap();
                std::fs::write(&uncommitted_path, b"2.0.0-uncommitted\n").unwrap();
                std::fs::write(&config_path, b"<Config><Port>9999</Port></Config>\n").unwrap();
                anyhow::bail!("installer script failed deliberately")
            })
        }
    }

    let backend = FailScriptBackend {
        receipt_file: receipt_file.clone(),
        uncommitted_receipt: uncommitted_receipt.clone(),
        config_file: config_file.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "sonarr".into(),
        action: "install".into(),
        script_name: "installpackage-sonarr".into(),
        app_port: 8989,
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["sonarr".into()]).unwrap();
    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must return failed receipt when installer script fails"
    );

    // Verify receipt and blueprint files were restored
    assert_eq!(
        std::fs::read_to_string(&receipt_file).unwrap(),
        "1.0.0\n",
        "Pre-existing receipt must be restored on script failure"
    );
    assert!(
        !uncommitted_receipt.exists(),
        "Newly created receipt must be deleted on script failure"
    );
    assert_eq!(
        std::fs::read_to_string(&config_file).unwrap(),
        "<Config><Port>8989</Port></Config>\n",
        "Pre-existing blueprint config must be restored on script failure"
    );

    let (status, failure_category, sanitized_summary): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='sonarr'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(failure_category, "installer");
    assert!(
        sanitized_summary
            .as_deref()
            .unwrap_or("")
            .contains("installer script failed deliberately"),
        "Diagnostics must retain script failure: {:?}",
        sanitized_summary
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_post_commit_rollback_error_persisted_in_diagnostics() {
    let (root, _path, conn, package) = test_fixture();
    let req = PackageRunnerRequest {
        package_id: "syncthing".into(),
        action: "install".into(),
        script_name: "installpackage-syncthing".into(),
        app_port: 8384,
        ..Default::default()
    };

    struct PostCommitFailBackend {
        root: PathBuf,
    }
    impl LifecycleBackend for PostCommitFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let r = self.root.clone();
            Box::pin(async move {
                // Create var/lib as directory with syncthing as regular file (causing ENOTDIR on rollback)
                let var_lib = r.join("var/lib");
                std::fs::create_dir_all(&var_lib).unwrap();
                let syncthing_file = var_lib.join("syncthing");
                let _ = std::fs::remove_dir_all(&syncthing_file);
                std::fs::write(&syncthing_file, b"blocking regular file").unwrap();
                Ok(())
            })
        }
    }

    let backend = PostCommitFailBackend { root: root.clone() };
    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();

    // Drop the settings table so post_commit fails when trying to synchronize ingress
    op.conn.execute("DROP TABLE settings", []).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must mark receipt as failed when post-commit sync fails"
    );

    let (status, category, diag): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "configuration");
    let summary = diag.expect("sanitized_summary must be persisted");
    assert!(
        summary.contains("receipt restoration error:"),
        "Diagnostic summary must preserve post-commit rollback error: {}",
        summary
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_coordinated_operation_quiesce_restore_restart_order() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    // Sub-scenario A: Script failure order
    // Expected: stop -> script -> stop -> rollback -> start -> active
    {
        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/syncthing-order-script-fail");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let package = Package {
            name: "syncthing-order-script-fail".into(),
            service_name: "syncthing-order-script-fail".into(),
            service_type: "systemd".into(),
            default_port: 8384,
            ..Default::default()
        };

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let events_for_hook = events.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| {
                s.path
                    .to_string_lossy()
                    .contains("syncthing-order-script-fail")
            }) {
                events_for_hook.lock().unwrap().push("rollback".to_string());
            }
        }));

        struct OrderScriptFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            receipt_file: PathBuf,
            receipt_at_start: Arc<std::sync::Mutex<Option<String>>>,
        }
        impl LifecycleBackend for OrderScriptFailBackend {
            fn runtime_port(&self, _: &str) -> i32 {
                8384
            }
            fn available_port(&self, _: i32) -> bool {
                true
            }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let rolled_back = self
                    .events
                    .lock()
                    .unwrap()
                    .contains(&"rollback".to_string());
                if rolled_back {
                    self.events.lock().unwrap().push("active".to_string());
                }
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let events = self.events.lock().unwrap();
                let last_stop = events.iter().rposition(|e| e == "stop");
                let last_start = events.iter().rposition(|e| e == "start");
                let is_q = match (last_stop, last_start) {
                    (Some(s), Some(st)) => s > st,
                    (Some(_), None) => true,
                    _ => false,
                };
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(
                &'a self,
                _: &'a str,
                action: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                if action == "start" {
                    let content = std::fs::read_to_string(&self.receipt_file).ok();
                    *self.receipt_at_start.lock().unwrap() = content;
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(
                &'a self,
                _: &'a PackageRunnerRequest,
                _: &'a mpsc::Sender<String>,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                let rf = self.receipt_file.clone();
                Box::pin(async move {
                    std::fs::write(&rf, b"2.0.0-broken\n").unwrap();
                    anyhow::bail!("simulated installer failure")
                })
            }
        }

        let receipt_at_start = Arc::new(std::sync::Mutex::new(None));
        let backend = OrderScriptFailBackend {
            events: events.clone(),
            receipt_file: receipt_file.clone(),
            receipt_at_start: receipt_at_start.clone(),
        };

        let req = PackageRunnerRequest {
            package_id: "syncthing-order-script-fail".into(),
            action: "update".into(),
            script_name: "updatepackage-syncthing".into(),
            app_port: 8384,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            package,
            vec!["syncthing-order-script-fail".into()],
        )
        .unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["stop", "script", "stop", "rollback", "start", "active"],
            "Script failure must follow exact order: stop -> script -> stop -> rollback -> start -> active"
        );

        // Assert rollback_operation_state ALWAYS happens before final service restart and verification
        let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
        let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
        let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
        assert!(
            rollback_pos < final_start_pos,
            "rollback_operation_state MUST occur before final service restart"
        );
        assert!(
            final_start_pos < final_active_pos,
            "Final service restart MUST occur before active verification"
        );

        // Verify receipt was restored on disk BEFORE start was called!
        assert_eq!(
            receipt_at_start.lock().unwrap().as_deref(),
            Some("1.0.0\n"),
            "Receipt on disk must be restored before service restart executes"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    // Sub-scenario B: Certification failure order
    // Expected: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active
    {
        let (root, _path, conn, _) = test_fixture();
        let opt_dir = root.join("opt/syncthing-order-cert-fail");
        std::fs::create_dir_all(&opt_dir).unwrap();
        let receipt_file = opt_dir.join(".af-version");
        std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

        let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let events_for_rb = events.clone();
        let events_for_cf = events.clone();

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |snaps| {
            if snaps.iter().any(|s| {
                s.path
                    .to_string_lossy()
                    .contains("syncthing-order-cert-fail")
            }) {
                events_for_rb.lock().unwrap().push("rollback".to_string());
            }
        }));
        *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = Some(Box::new(move |pkg| {
            if pkg == "syncthing-order-cert-fail" {
                events_for_cf
                    .lock()
                    .unwrap()
                    .push("certify_fail".to_string());
            }
        }));

        struct OrderCertFailBackend {
            events: Arc<std::sync::Mutex<Vec<String>>>,
            receipt_file: PathBuf,
            receipts_at_start: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl LifecycleBackend for OrderCertFailBackend {
            fn runtime_port(&self, _: &str) -> i32 {
                8384
            }
            fn available_port(&self, _: i32) -> bool {
                true
            }
            fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let rolled_back = self
                    .events
                    .lock()
                    .unwrap()
                    .contains(&"rollback".to_string());
                if rolled_back {
                    self.events.lock().unwrap().push("active".to_string());
                }
                Box::pin(async { Ok(true) })
            }
            fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
                let events = self.events.lock().unwrap();
                let last_stop = events.iter().rposition(|e| e == "stop");
                let last_start = events.iter().rposition(|e| e == "start");
                let is_q = match (last_stop, last_start) {
                    (Some(s), Some(st)) => s > st,
                    (Some(_), None) => true,
                    _ => false,
                };
                Box::pin(async move { Ok(is_q) })
            }
            fn control<'a>(
                &'a self,
                _: &'a str,
                action: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push(action.to_string());
                if action == "start" {
                    let content = std::fs::read_to_string(&self.receipt_file).unwrap_or_default();
                    self.receipts_at_start.lock().unwrap().push(content);
                }
                Box::pin(async { Ok(()) })
            }
            fn script<'a>(
                &'a self,
                _: &'a PackageRunnerRequest,
                _: &'a mpsc::Sender<String>,
            ) -> BoxFuture<'a, Result<()>> {
                self.events.lock().unwrap().push("script".to_string());
                let rf = self.receipt_file.clone();
                Box::pin(async move {
                    // Installer succeeds but writes version 1.5.0 which mismatches expected target 2.0.0
                    std::fs::write(&rf, b"1.5.0\n").unwrap();
                    Ok(())
                })
            }
        }

        let receipts_at_start = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = OrderCertFailBackend {
            events: events.clone(),
            receipt_file: receipt_file.clone(),
            receipts_at_start: receipts_at_start.clone(),
        };

        let syncthing_package = Package {
            name: "syncthing-order-cert-fail".into(),
            service_name: "syncthing-order-cert-fail".into(),
            service_type: "systemd".into(),
            default_port: 8384,
            ..Default::default()
        };

        let req = PackageRunnerRequest {
            package_id: "syncthing-order-cert-fail".into(),
            action: "update".into(),
            script_name: "updatepackage-syncthing".into(),
            app_port: 8384,
            expected_target_version: Some("2.0.0".into()),
            ..Default::default()
        };

        let mut op = CoordinatedOperation::admit(
            conn,
            req,
            syncthing_package,
            vec!["syncthing-order-cert-fail".into()],
        )
        .unwrap();
        let (sender, _receiver) = mpsc::channel(32);
        let receipt = op.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed");

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;
        *super::TEST_CERTIFY_FAIL_HOOK.lock().unwrap() = None;

        let recorded = events.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["stop", "script", "start", "certify_fail", "stop", "rollback", "start", "active"],
            "Certification failure must follow exact order: stop -> script -> start -> certify_fail -> stop -> rollback -> start -> active"
        );

        // Assert rollback_operation_state ALWAYS happens before final service restart and verification
        let rollback_pos = recorded.iter().position(|e| e == "rollback").unwrap();
        let final_start_pos = recorded.iter().rposition(|e| e == "start").unwrap();
        let final_active_pos = recorded.iter().rposition(|e| e == "active").unwrap();
        assert!(
            rollback_pos < final_start_pos,
            "rollback_operation_state MUST occur before final service restart"
        );
        assert!(
            final_start_pos < final_active_pos,
            "Final service restart MUST occur before active verification"
        );

        // First start saw installer version 1.5.0, but final restart saw restored version 1.0.0!
        let starts = receipts_at_start.lock().unwrap().clone();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0], "1.5.0\n");
        assert_eq!(
            starts[1], "1.0.0\n",
            "Final service restart must see restored pre-op receipt"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn test_parse_systemd_active_state_only_active_is_true() {
    // "active" must be confirmed active
    assert!(super::parse_systemd_active_state("active").unwrap());
    assert!(super::parse_systemd_active_state("  active  \n").unwrap());

    // Transitional and stopped states must return Ok(false)
    assert!(!super::parse_systemd_active_state("activating").unwrap());
    assert!(!super::parse_systemd_active_state("deactivating").unwrap());
    assert!(!super::parse_systemd_active_state("reloading").unwrap());
    assert!(!super::parse_systemd_active_state("inactive").unwrap());
    assert!(!super::parse_systemd_active_state("failed").unwrap());

    // Unknown states must return Err
    assert!(super::parse_systemd_active_state("unknown").is_err());
    assert!(super::parse_systemd_active_state("maintenance").is_err());
    assert!(super::parse_systemd_active_state("").is_err());
}

#[test]
fn test_parse_systemd_quiesced_state_inactive_and_failed_are_true() {
    // Genuinely quiescent states must return Ok(true)
    assert!(super::parse_systemd_quiesced_state("inactive").unwrap());
    assert!(super::parse_systemd_quiesced_state("  inactive  \n").unwrap());
    assert!(super::parse_systemd_quiesced_state("failed").unwrap());

    // Live and transitional states must return Ok(false)
    assert!(!super::parse_systemd_quiesced_state("active").unwrap());
    assert!(!super::parse_systemd_quiesced_state("activating").unwrap());
    assert!(!super::parse_systemd_quiesced_state("deactivating").unwrap());
    assert!(!super::parse_systemd_quiesced_state("reloading").unwrap());

    // Unknown states must return Err
    assert!(super::parse_systemd_quiesced_state("unknown").is_err());
    assert!(super::parse_systemd_quiesced_state("maintenance").is_err());
    assert!(super::parse_systemd_quiesced_state("").is_err());
}

#[test]
fn test_is_incomplete_rollback_error_hyphenated_and_diagnostics() {
    assert!(is_incomplete_rollback_error("incomplete-rollback"));
    assert!(is_incomplete_rollback_error("incomplete rollback"));
    assert!(is_incomplete_rollback_error("incomplete_rollback"));
    assert!(is_incomplete_rollback_error("Rclone rollback aborted because service quiescence failed; preserving recovery archive ... (incomplete-rollback)"));
    assert!(is_incomplete_rollback_error(
        "Application recovery is incomplete; recovery backup preserved"
    ));
    assert!(is_incomplete_rollback_error(
        "Rollback incomplete; recovery backup preserved"
    ));
    assert!(is_incomplete_rollback_error(
        "Failed to stop unit sonarr.service"
    ));

    // Unrelated errors must return false
    assert!(!is_incomplete_rollback_error("connection reset by peer"));
    assert!(!is_incomplete_rollback_error("file not found"));
}

#[tokio::test]
async fn test_restore_and_restart_units_quiesce_failure_gates_restoration_and_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct QuiesceFailBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for QuiesceFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            if action == "stop" {
                Box::pin(async { anyhow::bail!("systemctl stop failed deliberately") })
            } else {
                Box::pin(async { Ok(()) })
            }
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = QuiesceFailBackend {
        events: events.clone(),
    };

    let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rb_called_hook = rollback_called.clone();
    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
        rb_called_hook.store(true, std::sync::atomic::Ordering::SeqCst);
    }));

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-quiesce-fail",
        "mockpkg",
        &stopped,
        &stopped,
        &[],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        false,
        true,
    )
    .await;

    *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

    // 1. rollback_operation_state must NOT have been called!
    assert!(
        !rollback_called.load(std::sync::atomic::Ordering::SeqCst),
        "Rollback must be gated on successful quiescence"
    );

    // 2. Services must NOT have been restarted!
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must only receive stop, never start or active verification"
    );

    // 3. receipt_restore_error must indicate quiescence failure
    let r_err =
        receipt_restore_error.expect("receipt_restore_error must be set on quiesce failure");
    assert!(r_err.contains(
        "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"
    ));

    // 4. restart_failures must contain the stop failure
    assert!(!restart_failures.is_empty());
    assert!(restart_failures[0].contains("stop before restoration failed"));
}

#[tokio::test]
async fn test_restore_and_restart_units_snapshot_restore_failure_gates_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct SnapshotFailBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for SnapshotFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let temp_dir =
        std::env::temp_dir().join(format!("af-test-snap-fail-gate-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let blocking_file = temp_dir.join("block");
    std::fs::write(&blocking_file, b"file").unwrap();
    // Path whose parent is a regular file will fail stepwise directory traversal during restoration!
    let bad_snap = FileSnapshot::absent(blocking_file.join(".af-version"));

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = SnapshotFailBackend {
        events: events.clone(),
    };

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-snap-fail",
        "mockpkg",
        &stopped,
        &stopped,
        &[bad_snap],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        false,
        true,
    )
    .await;

    let _ = std::fs::remove_dir_all(&temp_dir);

    // 1. Backend must have stopped the unit, but NEVER called start or active
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must not call start after snapshot restoration failure"
    );

    // 2. receipt_restore_error must be populated
    assert!(receipt_restore_error.is_some());

    // 3. restart_failures must record refusal to restart
    assert!(restart_failures.iter().any(|f| f
        .contains("Refusing to restart pre-stopped service after snapshot restoration failure")));
}

#[tokio::test]
async fn test_restore_and_restart_units_incomplete_rollback_gates_restart() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct IncRollbackBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LifecycleBackend for IncRollbackBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let backend = IncRollbackBackend {
        events: events.clone(),
    };

    let stopped = vec!["mock-unit.service".to_string()];
    let mut receipt_restore_error = None;
    let mut restart_failures = Vec::new();

    CoordinatedOperation::restore_and_restart_units(
        &backend,
        "job-inc-rb",
        "mockpkg",
        &stopped,
        &stopped,
        &[],
        &[],
        &mut receipt_restore_error,
        &mut restart_failures,
        true, // incomplete_rollback = true
        true,
    )
    .await;

    // 1. Backend must have stopped the unit, but NEVER called start or active
    let recorded = events.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stop"],
        "Backend must not call start after incomplete rollback"
    );

    // 2. restart_failures must record refusal to restart
    assert!(restart_failures
        .iter()
        .any(|f| f.contains("Refusing to restart pre-stopped service after incomplete rollback")));
}

#[tokio::test]
async fn test_skipped_runtime_restoration_preserves_recovery_snapshot() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct RecoveryBlockedBackend {
        quiescent: bool,
        events: std::sync::Mutex<Vec<String>>,
    }
    impl LifecycleBackend for RecoveryBlockedBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events.lock().unwrap().push("active".to_string());
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(self.quiescent) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(action.to_string());
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    for (quiescent, incomplete_rollback) in [(false, false), (true, true)] {
        let root =
            std::env::temp_dir().join(format!("af-test-blocked-recovery-{}", uuid::Uuid::new_v4()));
        let runtime = root.join("opt/sonarr");
        std::fs::create_dir_all(&runtime).unwrap();
        let live_file = runtime.join("database.db");
        std::fs::write(&live_file, b"original-database").unwrap();
        let env_cfg = crate::PackageExecutionEnv::isolated(&root);
        let snapshot = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        let backup_root = snapshot.backup_root.clone();
        let backup_file = snapshot
            .entries
            .iter()
            .find_map(|entry| match entry {
                RuntimeSnapshotEntry::Directory {
                    target_path,
                    backup_path,
                    ..
                } if target_path == &runtime => Some(backup_path.join("database.db")),
                _ => None,
            })
            .expect("runtime directory must be captured");
        std::fs::write(&live_file, b"installer-modified-database").unwrap();
        let backend = RecoveryBlockedBackend {
            quiescent,
            events: std::sync::Mutex::new(Vec::new()),
        };
        let units = vec!["sonarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units_with_runtime(
            &backend,
            "job-blocked-recovery",
            "sonarr",
            &units,
            &units,
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            incomplete_rollback,
            true,
            Some(snapshot),
        )
        .await;

        assert_eq!(*backend.events.lock().unwrap(), vec!["stop"]);
        assert_eq!(
            std::fs::read(&live_file).unwrap(),
            b"installer-modified-database"
        );
        assert!(!restart_failures.is_empty());
        if quiescent {
            assert!(receipt_restore_error.is_none());
            assert!(restart_failures
                .iter()
                .any(|failure| failure.contains("incomplete rollback")));
        } else {
            assert!(receipt_restore_error.unwrap().contains("quiescence failed"));
        }
        assert!(backup_root.is_dir());
        assert_eq!(std::fs::read(&backup_file).unwrap(), b"original-database");
        force_remove_backup_tree(&root);
    }
}

#[tokio::test]
async fn test_absent_unit_rollback_allows_snapshot_restoration_whereas_active_stop_failure_gates_restoration(
) {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();

    struct AbsentRollbackBackend {
        fail_as_absent: bool,
        quiescent_result: bool,
        events: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl LifecycleBackend for AbsentRollbackBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{unit}"));
            let res = self.quiescent_result;
            Box::pin(async move { Ok(res) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(format!("{action}:{unit}"));
            if action == "stop" {
                if self.fail_as_absent {
                    Box::pin(async {
                        anyhow::bail!("Unit radarr.service not loaded (exit status: 5)")
                    })
                } else {
                    Box::pin(async {
                        anyhow::bail!("Failed to stop radarr.service: unit is active and locked")
                    })
                }
            } else {
                Box::pin(async { Ok(()) })
            }
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // Scenario 1: Absent unit on fresh install rollback
    // control("stop") fails with "Unit radarr.service not loaded (exit status: 5)"
    // but quiescent returns Ok(true).
    // Rollback restoration MUST proceed!
    {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = AbsentRollbackBackend {
            fail_as_absent: true,
            quiescent_result: true,
            events: events.clone(),
        };

        let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb_hook = rollback_called.clone();
        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
            rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let units = vec!["radarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-absent-unit",
            "radarr",
            &units,
            &[], // fresh install: no restart units
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        // Rollback restoration must NOT be gated because the unit is absent and quiescent!
        assert!(
            rollback_called.load(std::sync::atomic::Ordering::SeqCst),
            "Rollback must proceed for absent quiescent unit"
        );
        assert!(
            receipt_restore_error.is_none(),
            "receipt_restore_error must not be set on benign absent stop"
        );
        assert!(
            restart_failures.is_empty(),
            "restart_failures must be empty for absent quiescent unit"
        );
    }

    // Scenario 2: Active unit where stop fails
    // control("stop") fails on active unit and quiescent returns false (or error is not absent).
    // Rollback restoration MUST be gated!
    {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = AbsentRollbackBackend {
            fail_as_absent: false,
            quiescent_result: false,
            events: events.clone(),
        };

        let rollback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rb_hook = rollback_called.clone();
        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = Some(Box::new(move |_| {
            rb_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let units = vec!["radarr.service".to_string()];
        let mut receipt_restore_error = None;
        let mut restart_failures = Vec::new();

        CoordinatedOperation::restore_and_restart_units(
            &backend,
            "job-active-stop-fail",
            "radarr",
            &units,
            &[],
            &[],
            &[],
            &mut receipt_restore_error,
            &mut restart_failures,
            false,
            true,
        )
        .await;

        *super::TEST_ROLLBACK_HOOK.lock().unwrap() = None;

        // Rollback restoration MUST be gated on non-absent quiesce failure!
        assert!(
            !rollback_called.load(std::sync::atomic::Ordering::SeqCst),
            "Rollback must be gated when active unit stop fails"
        );
        assert!(
            receipt_restore_error.is_some(),
            "receipt_restore_error must indicate quiescence failure"
        );
        assert!(receipt_restore_error.as_ref().unwrap().contains(
            "Skipped snapshot restoration because service quiescence failed (incomplete-rollback)"
        ));
        assert!(!restart_failures.is_empty());
        assert!(restart_failures[0].contains("radarr.service: stop before restoration failed"));
    }
}
