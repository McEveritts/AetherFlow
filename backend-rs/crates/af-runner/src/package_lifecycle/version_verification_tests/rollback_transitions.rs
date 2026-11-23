use super::*;

#[tokio::test]
async fn test_rollback_quiesces_initially_inactive_unit_started_during_install() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-multi-unit");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-multi-unit".into(),
        service_name: "unit-a.service".into(),
        service_type: "systemd".into(),
        default_port: 8384,
        ..Default::default()
    };

    let unit_a_active = Arc::new(std::sync::Mutex::new(true));
    let unit_b_active = Arc::new(std::sync::Mutex::new(false));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_a = unit_a_active.clone();
    let hook_b = unit_b_active.clone();

    let _rollback_hook = RollbackHookGuard::set(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-multi-unit"))
        {
            let a_is_active = *hook_a.lock().unwrap();
            let b_is_active = *hook_b.lock().unwrap();
            assert!(
                !a_is_active,
                "unit-a.service must be inactive BEFORE rollback_operation_state"
            );
            assert!(
                !b_is_active,
                "unit-b.service must be inactive BEFORE rollback_operation_state"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    });

    struct MultiUnitBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_a_active: Arc<std::sync::Mutex<bool>>,
        unit_b_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for MultiUnitBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = match unit {
                "unit-a.service" => *self.unit_a_active.lock().unwrap(),
                "unit-b.service" => *self.unit_b_active.lock().unwrap(),
                _ => false,
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    if unit == "unit-a.service" {
                        *self.unit_a_active.lock().unwrap() = false;
                    } else if unit == "unit-b.service" {
                        *self.unit_b_active.lock().unwrap() = false;
                    }
                }
                "start" => {
                    if unit == "unit-a.service" {
                        *self.unit_a_active.lock().unwrap() = true;
                    } else if unit == "unit-b.service" {
                        *self.unit_b_active.lock().unwrap() = true;
                    }
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Installer script starts initially-inactive unit-b.service
            *self.unit_b_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("script_started:unit-b.service".to_string());
            // Then script fails
            Box::pin(async { anyhow::bail!("installer failed deliberately") })
        }
    }

    let backend = MultiUnitBackend {
        events: events.clone(),
        unit_a_active: unit_a_active.clone(),
        unit_b_active: unit_b_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-multi-unit".into(),
        action: "update".into(),
        script_name: "updatepackage-test-multi".into(),
        app_port: 8384,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(
        conn,
        req,
        package,
        vec!["unit-a.service".into(), "unit-b.service".into()],
    )
    .unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    drop(_rollback_hook);

    let recorded = events.lock().unwrap().clone();

    // 1. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 2. Both unit-a and unit-b must have been stopped BEFORE rollback
    let stop_a_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:unit-a.service")
        .expect("unit-a must be stopped before rollback");
    let stop_b_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:unit-b.service")
        .expect("unit-b must be stopped before rollback");
    assert!(stop_a_quiesce < rollback_pos);
    assert!(stop_b_quiesce < rollback_pos);

    // 3. ONLY unit-a.service must be restarted after rollback
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert_eq!(
        starts_after_rollback,
        vec!["start:unit-a.service"],
        "Only initially-active unit-a must be restarted"
    );

    // 4. Verify final active states: unit-a is active, unit-b remains inactive
    assert!(
        *unit_a_active.lock().unwrap(),
        "unit-a must be active after restoration"
    );
    assert!(
        !*unit_b_active.lock().unwrap(),
        "unit-b must remain inactive after restoration"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_fresh_install_script_fail_quiesces_installer_started_unit() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;

    let (root, _path, conn, _) = test_fixture();
    // Genuine fresh install: no /opt/<package> directory or receipt on disk!

    let package = Package {
        name: "test-fresh-pkg".into(),
        service_name: "fresh-unit.service".into(),
        service_type: "systemd".into(),
        default_port: 8484,
        ..Default::default()
    };

    let fresh_unit_active = Arc::new(std::sync::Mutex::new(false));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_unit = fresh_unit_active.clone();

    let _rollback_hook = RollbackHookGuard::set(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-fresh-pkg"))
        {
            let unit_is_active = *hook_unit.lock().unwrap();
            assert!(
                !unit_is_active,
                "fresh-unit.service must be quiesced/inactive BEFORE rollback_operation_state"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    });

    struct FreshInstallBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        fresh_unit_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for FreshInstallBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8484
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = if unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap()
            } else {
                false
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            if action == "stop" && unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap() = false;
            } else if action == "start" && unit == "fresh-unit.service" {
                *self.fresh_unit_active.lock().unwrap() = true;
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Fresh installer starts fresh-unit.service during installation
            *self.fresh_unit_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("installer_started:fresh-unit.service".to_string());
            // Then installer fails
            Box::pin(async { anyhow::bail!("fresh installer failed deliberately") })
        }
    }

    let backend = FreshInstallBackend {
        events: events.clone(),
        fresh_unit_active: fresh_unit_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-fresh-pkg".into(),
        action: "install".into(),
        script_name: "installpackage-test-fresh".into(),
        app_port: 8484,
        expected_target_version: Some("1.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["fresh-unit.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    drop(_rollback_hook);

    let recorded = events.lock().unwrap().clone();

    // 1. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 2. fresh-unit.service must have been stopped during rollback quiescence (before rollback hook)
    let stop_quiesce = recorded[..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:fresh-unit.service")
        .expect("fresh-unit.service must be stopped during rollback quiescence");
    assert!(stop_quiesce < rollback_pos);

    // 3. fresh-unit.service must NOT have been started after rollback (it was not initially active)
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert!(
        starts_after_rollback.is_empty(),
        "Fresh installer started unit must not be restarted after rollback"
    );

    // 4. Verify final active state: fresh-unit is inactive
    assert!(
        !*fresh_unit_active.lock().unwrap(),
        "fresh-unit.service must remain inactive"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_running_oneshot_quiesced_on_rollback_and_not_restarted() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-oneshot");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-oneshot".into(),
        service_name: "recyclarr.timer".into(),
        service_type: "systemd".into(),
        default_port: 8585,
        ..Default::default()
    };

    let timer_active = Arc::new(std::sync::Mutex::new(true));
    let oneshot_active = Arc::new(std::sync::Mutex::new(true)); // oneshot is currently running!
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    let hook_events = events.clone();
    let hook_timer = timer_active.clone();
    let hook_oneshot = oneshot_active.clone();

    let _rollback_hook = RollbackHookGuard::set(move |snaps| {
        if snaps
            .iter()
            .any(|s| s.path.to_string_lossy().contains("test-oneshot"))
        {
            let timer_is_active = *hook_timer.lock().unwrap();
            let oneshot_is_active = *hook_oneshot.lock().unwrap();
            assert!(
                !timer_is_active,
                "recyclarr.timer must be inactive BEFORE rollback"
            );
            assert!(
                !oneshot_is_active,
                "recyclarr oneshot must be inactive BEFORE rollback"
            );
            hook_events.lock().unwrap().push("rollback".to_string());
        }
    });

    struct OneshotBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        timer_active: Arc<std::sync::Mutex<bool>>,
        oneshot_active: Arc<std::sync::Mutex<bool>>,
    }

    impl LifecycleBackend for OneshotBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8585
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let is_act = match unit {
                "recyclarr.timer" => *self.timer_active.lock().unwrap(),
                "recyclarr" => *self.oneshot_active.lock().unwrap(),
                _ => false,
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    if unit == "recyclarr.timer" {
                        *self.timer_active.lock().unwrap() = false;
                    } else if unit == "recyclarr" {
                        *self.oneshot_active.lock().unwrap() = false;
                    }
                }
                "start" => {
                    if unit == "recyclarr.timer" {
                        *self.timer_active.lock().unwrap() = true;
                    } else if unit == "recyclarr" {
                        *self.oneshot_active.lock().unwrap() = true;
                    }
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            // Installer script starts running oneshot again
            *self.oneshot_active.lock().unwrap() = true;
            self.events
                .lock()
                .unwrap()
                .push("script_started:recyclarr".to_string());
            // Then fails
            Box::pin(async { anyhow::bail!("installer failed deliberately") })
        }
    }

    let backend = OneshotBackend {
        events: events.clone(),
        timer_active: timer_active.clone(),
        oneshot_active: oneshot_active.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-oneshot".into(),
        action: "update".into(),
        script_name: "updatepackage-test-oneshot".into(),
        app_port: 8585,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(
        conn,
        req,
        package,
        vec!["recyclarr.timer".into(), "recyclarr".into()],
    )
    .unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    drop(_rollback_hook);

    let recorded = events.lock().unwrap().clone();

    // 1. Both timer and running oneshot must be stopped before script execution (pre-operation)
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:recyclarr.timer".to_string()));
    assert!(recorded[..script_pos].contains(&"stop:recyclarr".to_string()));

    // 2. Rollback must have occurred
    let rollback_pos = recorded
        .iter()
        .position(|e| e == "rollback")
        .expect("Rollback must be recorded");

    // 3. During rollback quiescence, running oneshot is stopped
    let stop_oneshot_quiesce = recorded[script_pos..rollback_pos]
        .iter()
        .rposition(|e| e == "stop:recyclarr");
    assert!(
        stop_oneshot_quiesce.is_some(),
        "Running oneshot recyclarr must be stopped during rollback quiescence"
    );

    // 4. ONLY recyclarr.timer is restarted after rollback; recyclarr oneshot is NOT restarted!
    let starts_after_rollback: Vec<_> = recorded[rollback_pos..]
        .iter()
        .filter(|e| e.starts_with("start:"))
        .cloned()
        .collect();
    assert_eq!(
        starts_after_rollback,
        vec!["start:recyclarr.timer".to_string()],
        "Only recyclarr.timer should be restarted, not oneshot"
    );

    // 5. Final states
    assert!(
        *timer_active.lock().unwrap(),
        "recyclarr.timer must be active"
    );
    assert!(
        !*oneshot_active.lock().unwrap(),
        "recyclarr oneshot must be inactive"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_unit_in_transitional_state_stopped_before_op_and_restarted_on_rollback() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;

    // Verify parse_systemd_active_state directly: only "active" is true
    assert!(parse_systemd_active_state("active").unwrap());
    assert!(!parse_systemd_active_state("activating").unwrap());
    assert!(!parse_systemd_active_state("reloading").unwrap());
    assert!(!parse_systemd_active_state("deactivating").unwrap());
    assert!(!parse_systemd_active_state("inactive").unwrap());
    assert!(!parse_systemd_active_state("failed").unwrap());

    // Verify parse_systemd_quiesced_state directly: only inactive/failed are true
    assert!(!parse_systemd_quiesced_state("active").unwrap());
    assert!(!parse_systemd_quiesced_state("activating").unwrap());
    assert!(!parse_systemd_quiesced_state("reloading").unwrap());
    assert!(!parse_systemd_quiesced_state("deactivating").unwrap());
    assert!(parse_systemd_quiesced_state("inactive").unwrap());
    assert!(parse_systemd_quiesced_state("failed").unwrap());

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-trans");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-trans".into(),
        service_name: "trans-unit.service".into(),
        service_type: "systemd".into(),
        default_port: 8686,
        ..Default::default()
    };

    // Initially in transitional state: !quiescent() reports true because parse_systemd_quiesced_state treats activating as false
    let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    struct TransBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_state: Arc<std::sync::Mutex<String>>,
    }

    impl LifecycleBackend for TransBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8686
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_act = parse_systemd_active_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}", unit, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_q = parse_systemd_quiesced_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{}:{}", unit, is_q));
            Box::pin(async move { Ok(is_q) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    *self.unit_state.lock().unwrap() = "inactive".to_string();
                }
                "start" => {
                    *self.unit_state.lock().unwrap() = "active".to_string();
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            Box::pin(async { anyhow::bail!("script failed deliberately") })
        }
    }

    let backend = TransBackend {
        events: events.clone(),
        unit_state: unit_state.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-trans".into(),
        action: "update".into(),
        script_name: "updatepackage-test-trans".into(),
        app_port: 8686,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["trans-unit.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    let recorded = events.lock().unwrap().clone();

    // 1. Pre-operation stopped trans-unit.service because !backend.quiescent returned true for "activating"
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:trans-unit.service".to_string()));

    // 2. Rollback restarts trans-unit.service because it was included in stopped
    assert!(recorded[script_pos..].contains(&"start:trans-unit.service".to_string()));
    assert_eq!(*unit_state.lock().unwrap(), "active");

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_transitional_unit_fails_post_start_health_certification() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;

    let (root, _path, conn, _) = test_fixture();
    let opt_dir = root.join("opt/test-trans-cert");
    std::fs::create_dir_all(&opt_dir).unwrap();
    let receipt_file = opt_dir.join(".af-version");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let package = Package {
        name: "test-trans-cert".into(),
        service_name: "trans-cert.service".into(),
        service_type: "systemd".into(),
        default_port: 8787,
        ..Default::default()
    };

    // Initially in transitional state: "activating"
    let unit_state = Arc::new(std::sync::Mutex::new("activating".to_string()));
    let events = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    struct TransCertBackend {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        unit_state: Arc<std::sync::Mutex<String>>,
    }

    impl LifecycleBackend for TransCertBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8787
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_act = parse_systemd_active_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("active:{}:{}:{}", unit, st, is_act));
            Box::pin(async move { Ok(is_act) })
        }
        fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
            let st = self.unit_state.lock().unwrap().clone();
            let is_q = parse_systemd_quiesced_state(&st).unwrap();
            self.events
                .lock()
                .unwrap()
                .push(format!("quiescent:{}:{}:{}", unit, st, is_q));
            Box::pin(async move { Ok(is_q) })
        }
        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{}", action, unit));
            match action {
                "stop" => {
                    *self.unit_state.lock().unwrap() = "inactive".to_string();
                }
                "start" => {
                    // Remains stuck in transitional "activating" state instead of reaching "active"
                    *self.unit_state.lock().unwrap() = "activating".to_string();
                }
                _ => {}
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push("script".to_string());
            Box::pin(async { Ok(()) })
        }
    }

    let backend = TransCertBackend {
        events: events.clone(),
        unit_state: unit_state.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "test-trans-cert".into(),
        action: "update".into(),
        script_name: "updatepackage-test-trans-cert".into(),
        app_port: 8787,
        expected_target_version: Some("2.0.0".into()),
        ..Default::default()
    };

    let mut op =
        CoordinatedOperation::admit(conn, req, package, vec!["trans-cert.service".into()]).unwrap();

    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Operation must fail when service remains in activating state after start"
    );

    let recorded = events.lock().unwrap().clone();

    // 1. Pre-operation stopped trans-cert.service because !backend.quiescent returned true for activating
    let script_pos = recorded
        .iter()
        .position(|e| e == "script")
        .expect("Script must run");
    assert!(recorded[..script_pos].contains(&"stop:trans-cert.service".to_string()));

    // 2. Start was attempted after installer script
    let start_pos = recorded
        .iter()
        .position(|e| e == "start:trans-cert.service")
        .expect("Start must be called");
    assert!(start_pos > script_pos);

    // 3. Post-start active check saw "activating" and returned false, failing certification
    assert!(recorded.contains(&"active:trans-cert.service:activating:false".to_string()));

    // 4. Job diagnostic records that unit is not active after start
    let (diag,): (Option<String>,) = op
        .conn
        .query_row(
            "SELECT sanitized_summary FROM package_lifecycle_jobs WHERE package_id='test-trans-cert'",
            [],
            |row| Ok((row.get(0)?,)),
        )
        .unwrap();
    assert!(diag
        .as_deref()
        .unwrap_or("")
        .contains("is not active after start"));

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_post_certification_failure_restores_runtime_state_and_receipt() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;
    let (root, _path, conn, package) = test_fixture();

    let opt_syncthing = root.join("opt/syncthing");
    std::fs::create_dir_all(&opt_syncthing).unwrap();
    let bin_file = opt_syncthing.join("syncthing");
    std::fs::write(&bin_file, b"bin-1.22.0").unwrap();

    let usr_bin = root.join("usr/local/bin");
    std::fs::create_dir_all(&usr_bin).unwrap();
    let usr_bin_file = usr_bin.join("syncthing");
    std::fs::write(&usr_bin_file, b"bin-1.22.0").unwrap();

    let var_lib_syncthing = root.join("var/lib/syncthing");
    std::fs::create_dir_all(&var_lib_syncthing).unwrap();
    let config_txt = var_lib_syncthing.join("config.txt");
    std::fs::write(&config_txt, b"state-1.22.0").unwrap();
    let receipt_file = var_lib_syncthing.join(".af-version");
    std::fs::write(&receipt_file, b"1.22.0\n").unwrap();

    struct PostCertFailBackend {
        root: PathBuf,
        actions: Arc<std::sync::Mutex<Vec<String>>>,
        files_before_final_start: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }
    impl LifecycleBackend for PostCertFailBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8384
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            let acts = self.actions.lock().unwrap();
            let last_stop = acts.iter().rposition(|e| e == "stop");
            let last_start = acts.iter().rposition(|e| e == "start");
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
            let r = self.root.clone();
            let acts = self.actions.clone();
            let files_rec = self.files_before_final_start.clone();
            let action_str = action.to_string();
            Box::pin(async move {
                acts.lock().unwrap().push(action_str.clone());
                if action_str == "start" {
                    let total_starts = acts
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|a| a.as_str() == "start")
                        .count();
                    if total_starts >= 2 {
                        // This is the post-rollback restart!
                        let bin = std::fs::read_to_string(r.join("opt/syncthing/syncthing"))
                            .unwrap_or_default();
                        let usr_bin = std::fs::read_to_string(r.join("usr/local/bin/syncthing"))
                            .unwrap_or_default();
                        let cfg = std::fs::read_to_string(r.join("var/lib/syncthing/config.txt"))
                            .unwrap_or_default();
                        let ver = std::fs::read_to_string(r.join("var/lib/syncthing/.af-version"))
                            .unwrap_or_default();
                        let mut lock = files_rec.lock().unwrap();
                        *lock = vec![
                            ("bin".into(), bin),
                            ("usr_bin".into(), usr_bin),
                            ("cfg".into(), cfg),
                            ("ver".into(), ver),
                        ];
                    }
                }
                Ok(())
            })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            let r = self.root.clone();
            Box::pin(async move {
                std::fs::write(r.join("opt/syncthing/syncthing"), b"bin-1.23.4").unwrap();
                std::fs::write(r.join("usr/local/bin/syncthing"), b"bin-1.23.4").unwrap();
                std::fs::write(r.join("var/lib/syncthing/config.txt"), b"state-1.23.4").unwrap();
                std::fs::write(r.join("var/lib/syncthing/.af-version"), b"1.23.4\n").unwrap();
                Ok(())
            })
        }
    }

    let actions = Arc::new(std::sync::Mutex::new(Vec::new()));
    let files_before_final_start = Arc::new(std::sync::Mutex::new(Vec::new()));
    let backend = PostCertFailBackend {
        root: root.clone(),
        actions: actions.clone(),
        files_before_final_start: files_before_final_start.clone(),
    };

    let req = PackageRunnerRequest {
        package_id: "syncthing".into(),
        action: "update".into(),
        script_name: "updatepackage-syncthing".into(),
        app_port: 8384,
        expected_target_version: Some("1.24.0".into()), // forces target certification failure
        ..Default::default()
    };

    let mut op = CoordinatedOperation::admit(conn, req, package, vec!["syncthing".into()]).unwrap();
    let (sender, _receiver) = mpsc::channel(32);
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(
        receipt.status, "failed",
        "Execute must mark receipt as failed when certification fails"
    );

    // Verify BEFORE final restart:
    let recorded = files_before_final_start.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            ("bin".into(), "bin-1.22.0".into()),
            ("usr_bin".into(), "bin-1.22.0".into()),
            ("cfg".into(), "state-1.22.0".into()),
            ("ver".into(), "1.22.0\n".into()),
        ],
        "Files BEFORE final restart must be restored to 1.22.0"
    );

    // Verify on disk afterward:
    assert_eq!(std::fs::read_to_string(&bin_file).unwrap(), "bin-1.22.0");
    assert_eq!(
        std::fs::read_to_string(&usr_bin_file).unwrap(),
        "bin-1.22.0"
    );
    assert_eq!(
        std::fs::read_to_string(&config_txt).unwrap(),
        "state-1.22.0"
    );
    assert_eq!(
        std::fs::read_to_string(&receipt_file).unwrap().trim(),
        "1.22.0"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_coordinated_operation_orders_socket_timer_and_novnc_quiesce_and_restore() {
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;
    struct RecordingBackend {
        events: std::sync::Mutex<Vec<String>>,
    }

    impl LifecycleBackend for RecordingBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            0
        }

        fn available_port(&self, _: i32) -> bool {
            true
        }

        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }

        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }

        fn control<'a>(
            &'a self,
            unit: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.events.lock().unwrap().push(format!("{action} {unit}"));
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

    for (pkg, units, expected) in [
        (
            "librespeed",
            vec![
                "librespeed.service".to_string(),
                "librespeed.socket".to_string(),
            ],
            vec![
                "stop librespeed.socket",
                "stop librespeed.service",
                "start librespeed.socket",
                "start librespeed.service",
            ],
        ),
        (
            "novnc",
            vec![
                "novnc-xvnc.service".to_string(),
                "novnc-session.service".to_string(),
                "novnc.service".to_string(),
            ],
            vec![
                "stop novnc.service",
                "stop novnc-session.service",
                "stop novnc-xvnc.service",
                "start novnc-xvnc.service",
                "start novnc-session.service",
                "start novnc.service",
            ],
        ),
        (
            "recyclarr",
            vec![
                "recyclarr.service".to_string(),
                "recyclarr.timer".to_string(),
            ],
            vec![
                "stop recyclarr.timer",
                "stop recyclarr.service",
                "start recyclarr.service",
                "start recyclarr.timer",
            ],
        ),
    ] {
        let backend = RecordingBackend {
            events: std::sync::Mutex::new(Vec::new()),
        };
        let mut receipt_err = None;
        let mut restart_failures = Vec::new();
        CoordinatedOperation::restore_and_restart_units_with_runtime(
            &backend,
            "job-order-check",
            pkg,
            &units,
            &units,
            &[],
            &[],
            &mut receipt_err,
            &mut restart_failures,
            false,
            true,
            None,
        )
        .await;
        assert!(receipt_err.is_none(), "{pkg}: {receipt_err:?}");
        assert!(restart_failures.is_empty(), "{pkg}: {restart_failures:?}");
        assert_eq!(*backend.events.lock().unwrap(), expected, "{pkg}");
    }
}
