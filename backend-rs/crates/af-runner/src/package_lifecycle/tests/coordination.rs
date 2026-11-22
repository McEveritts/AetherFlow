use super::*;

#[tokio::test]
async fn direct_remove_reinstall_and_explicit_purge_share_durable_ingress_callbacks() {
    let (root, path, conn, package) = fixture();
    let backend = FakeBackend::default();
    let (sender, _receiver) = mpsc::channel(32);
    let mut remove = CoordinatedOperation::admit(
        conn,
        request("remove"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    let terminal = remove.execute(&backend, &sender).await.unwrap();
    assert_eq!(terminal.status, "completed");
    assert_eq!(persisted(&remove.conn).0, terminal.job_id);
    assert_eq!(
        remove
            .conn
            .query_row("SELECT COUNT(*) FROM app_updates", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        remove
            .conn
            .query_row("SELECT COUNT(*) FROM app_ingress_configs", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let retained = af_db::load_lifecycle_ingress(&remove.conn, "syncthing")
        .unwrap()
        .unwrap();
    assert_eq!(retained.public_domain, "custom.example.test");
    assert!(!retained.tls_enabled);
    drop(remove);
    let mut install = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("install"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    assert_eq!(
        install.execute(&backend, &sender).await.unwrap().app_port,
        18384
    );
    assert_eq!(
        install
            .conn
            .query_row("SELECT listen_port FROM app_ingress_configs", [], |row| row
                .get::<_, i32>(0))
            .unwrap(),
        18384
    );
    drop(install);
    let mut purge = request("remove");
    purge.delete_data = true;
    let mut purge = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        purge,
        package,
        vec!["syncthing".into()],
    )
    .unwrap();
    assert_eq!(
        purge.execute(&backend, &sender).await.unwrap().status,
        "completed"
    );
    assert!(af_db::load_lifecycle_ingress(&purge.conn, "syncthing")
        .unwrap()
        .is_none());
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec![
            "script remove port=0 purge=false",
            "script install port=18384 purge=false",
            "script remove port=0 purge=true"
        ]
    );
    drop(purge);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn update_retains_custom_port_and_reservation_until_timer_and_service_restore() {
    let (root, path, conn, package) = fixture();
    let backend = FakeBackend {
        conflict_database: Some(path),
        root: Some(root.clone()),
        ..Default::default()
    };
    let (sender, _receiver) = mpsc::channel(32);
    let mut operation = CoordinatedOperation::admit(
        conn,
        request("update"),
        package,
        vec![
            "syncthing".into(),
            "syncthing.timer".into(),
            "recyclarr".into(),
        ],
    )
    .unwrap();
    assert_eq!(
        operation.execute(&backend, &sender).await.unwrap().status,
        "completed"
    );
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec![
            "stop syncthing.timer",
            "stop syncthing",
            "script update port=18384 purge=false",
            "start syncthing",
            "start syncthing.timer"
        ]
    );
    drop(operation);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn required_callback_and_script_failures_never_become_completed_receipts() {
    for failure in [
        "retention",
        "installer",
        "service_restore",
        "invalid_port",
        "stop",
    ] {
        let (root, _, conn, package) = fixture();
        if failure == "retention" {
            conn.execute_batch("DROP TABLE app_updates").unwrap();
        }
        let backend = FakeBackend {
            fail_script: failure == "installer",
            fail_stop: failure == "stop",
            fail_restore: failure == "service_restore",
            runtime_port: if failure == "invalid_port" { 70000 } else { 0 },
            ..Default::default()
        };
        let (sender, _receiver) = mpsc::channel(32);
        let action = if failure == "retention" {
            "remove"
        } else {
            "update"
        };
        let mut operation =
            CoordinatedOperation::admit(conn, request(action), package, vec!["syncthing".into()])
                .unwrap();
        let receipt = operation.execute(&backend, &sender).await.unwrap();
        assert_eq!(receipt.status, "failed", "{failure}");
        let (_, status, category) = persisted(&operation.conn);
        assert_eq!(status, "failed");
        assert_eq!(
            category,
            if matches!(failure, "invalid_port" | "stop") {
                "preparation"
            } else {
                failure
            }
        );
        if failure == "retention" {
            assert_eq!(
                operation
                    .conn
                    .query_row("SELECT COUNT(*) FROM app_ingress_configs", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        if failure == "installer" {
            assert!(backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call == "start syncthing"));
            let stored = std::fs::read(operation.conn.path().unwrap()).unwrap();
            assert!(!String::from_utf8_lossy(&stored).contains("secret-do-not-persist"));
        }
        if failure == "invalid_port" {
            assert!(backend.calls.lock().unwrap().is_empty());
        }
        if failure == "stop" {
            assert_eq!(
                *backend.calls.lock().unwrap(),
                vec!["stop syncthing", "stop syncthing"]
            );
        }
        drop(operation);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn stream_disconnect_does_not_drop_worker_owner_or_required_callbacks() {
    let (root, path, conn, package) = fixture();
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let backend = FakeBackend {
        started: Some(started.clone()),
        release: Some(release.clone()),
        ..Default::default()
    };
    let operation =
        CoordinatedOperation::admit(conn, request("remove"), package, vec!["syncthing".into()])
            .unwrap();
    let identity = operation.request.lifecycle_job_id.clone();
    let (finished, done) = tokio::sync::oneshot::channel();
    let receiver = spawn_worker(request("remove"), move |_, sender| async move {
        let mut operation = operation;
        let result = operation.execute(&backend, &sender).await;
        let _ = finished.send(());
        result
    });
    started.notified().await;
    drop(receiver);
    let conn = Connection::open(&path).unwrap();
    lifecycle::reconcile_jobs(&conn, &path).unwrap();
    assert_eq!(persisted(&conn).1, "uninstalling");
    release.notify_one();
    done.await.unwrap();
    assert_eq!(persisted(&conn), (identity, "completed".into(), "".into()));
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM retained_app_ingress_configs",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn dropped_coordinator_is_interrupted_only_after_maintenance_lock_is_available() {
    let (root, path, conn, package) = fixture();
    let operation =
        CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
            .unwrap();
    let identity = operation.request.lifecycle_job_id.clone();
    let guard = crate::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    drop(operation);
    assert!(crate::acquire_lifecycle_admission_lock(Some(&root)).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(persisted(&conn).1, "updating");
    drop(guard);
    let _admission = crate::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    lifecycle::reconcile_jobs(&conn, &path).unwrap();
    assert_eq!(persisted(&conn).1, "interrupted");
    assert!(lifecycle::finish_job(&conn, "syncthing", &identity, "update", true, "").is_err());
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn in_place_reinstall_pre_stops_active_units_and_restores_on_completion_and_failure() {
    let (root, path, conn, mut package) = fixture();
    let lock_path = root.join("install/.syncthing.lock");
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    std::fs::write(&lock_path, "installed\n").unwrap();
    package.lock_file = lock_path.to_string_lossy().into_owned();

    // 1. In-place reinstall (action="install" with lock_file present on disk) pre-stops active units
    // and starts them in reverse order after the installer script completes.
    let backend = FakeBackend::default();
    let (sender, _receiver) = mpsc::channel(32);
    let mut reinstall = CoordinatedOperation::admit(
        conn,
        request("install"),
        package.clone(),
        vec!["syncthing".into(), "syncthing.timer".into()],
    )
    .unwrap();
    let receipt = reinstall.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "completed");
    assert_eq!(
        *backend.calls.lock().unwrap(),
        vec![
            "stop syncthing.timer",
            "stop syncthing",
            "script install port=18384 purge=false",
            "start syncthing",
            "start syncthing.timer",
        ]
    );
    drop(reinstall);

    // 2. Failed in-place reinstall still restores pre-stopped units in reverse order.
    let fail_backend = FakeBackend {
        fail_script: true,
        ..Default::default()
    };
    let mut failed_reinstall = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("install"),
        package,
        vec!["syncthing".into(), "syncthing.timer".into()],
    )
    .unwrap();
    let fail_receipt = failed_reinstall
        .execute(&fail_backend, &sender)
        .await
        .unwrap();
    assert_eq!(fail_receipt.status, "failed");
    assert_eq!(
        *fail_backend.calls.lock().unwrap(),
        vec![
            "stop syncthing.timer",
            "stop syncthing",
            "script install port=18384 purge=false",
            "stop syncthing.timer",
            "stop syncthing",
            "start syncthing",
            "start syncthing.timer",
        ]
    );
    drop(failed_reinstall);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn afmp003_stopped_or_retained_application_port_is_never_stolen_by_another_application() {
    let (root, path, mut conn, mut package) = fixture();
    // Reset syncthing's own saved config from fixture so we test fresh port allocation for a second app
    conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
    // Persist port 8384 for stopped application `radarr` and retain port 17000 for removed application `sonarr`
    conn.execute(
        "INSERT INTO app_ingress_configs(app_name,public_domain,external_access_enabled,listen_port,tls_enabled)
         VALUES ('radarr','',0,8384,0)",
        [],
    )
    .unwrap();
    af_db::synchronize_lifecycle_ingress(&mut conn, "sonarr", "remove", "", 0, false, "").ok();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO retained_app_ingress_configs(app_name, config_json) VALUES ('sonarr', ?1)",
        [serde_json::to_string(&af_models::AppIngressConfig {
            app_name: "sonarr".into(),
            listen_port: 17000,
            ..Default::default()
        })
        .unwrap()],
    )
    .unwrap();

    package.default_port = 8384;
    let backend = FakeBackend::default();

    // Explicit request for a port owned by stopped `radarr` (8384) or retained `sonarr` (17000) must be rejected at admission
    let mut steal_req = request("install");
    steal_req.app_port = 8384;
    assert!(
        CoordinatedOperation::admit(
            Connection::open(&path).unwrap(),
            steal_req,
            package.clone(),
            vec!["syncthing".into()],
        )
        .is_err(),
        "admit must reject explicit app_port owned by stopped radarr"
    );

    // Automatic port resolution for `syncthing` (default_port = 8384) must skip 8384 (owned by radarr)
    // and skip 17000 (retained by sonarr), allocating 17001 instead!
    let (sender, _receiver) = mpsc::channel(32);
    let mut op =
        CoordinatedOperation::admit(conn, request("install"), package, vec!["syncthing".into()])
            .unwrap();
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "completed");
    assert_eq!(receipt.app_port, 17001);

    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn afmp_sol_003_symlinked_sonarr_config_fails_closed_without_recording_port() {
    let (root, _path, conn, _package) = fixture();
    conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
    let sonarr_dir = root.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_dir).unwrap();
    let target_cfg = root.join("var/lib/sonarr-target-config.xml");
    std::fs::write(&target_cfg, "<Config><Port>8989</Port></Config>\n").unwrap();
    std::os::unix::fs::symlink(&target_cfg, sonarr_dir.join("config.xml")).unwrap();

    let package = Package {
        name: "sonarr".into(),
        service_name: "sonarr".into(),
        service_type: "systemd".into(),
        default_port: 8989,
        ..Default::default()
    };
    let mut req = PackageRunnerRequest {
        package_id: "sonarr".into(),
        action: "install".into(),
        script_name: "installpackage-sonarr".into(),
        app_port: 18989,
        ..Default::default()
    };
    let backend = FakeBackend::default();
    let (sender, _receiver) = mpsc::channel(32);
    let mut op = CoordinatedOperation::admit(
        conn,
        std::mem::take(&mut req),
        package,
        vec!["sonarr".into()],
    )
    .unwrap();
    let exec_res = op.execute(&backend, &sender).await;
    assert!(
        exec_res.is_err(),
        "Execute must fail closed at preflight when blueprint target is a symlink"
    );
    let (status, category): (String, String) = op
        .conn
        .query_row(
            "SELECT status, failure_category FROM package_lifecycle_jobs WHERE package_id='sonarr'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "preflight");
    assert!(
        af_db::load_lifecycle_ingress(&op.conn, "sonarr")
            .unwrap()
            .is_none(),
        "app_ingress_configs must not record port 18989 when config.xml mutation fails"
    );
    assert_eq!(
        std::fs::read_to_string(&target_cfg).unwrap(),
        "<Config><Port>8989</Port></Config>\n"
    );
    drop(op);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn incomplete_rollback_refuses_to_restart_pre_stopped_units() {
    let (root, _path, conn, package) = fixture();
    let backend = FakeBackend {
        script_error_message: Some(
            "step failed; incomplete rollback: recovery backup preserved at /var/lib/syncthing.bak"
                .into(),
        ),
        ..Default::default()
    };
    let (sender, _receiver) = mpsc::channel(32);
    let mut op = CoordinatedOperation::admit(
        conn,
        request("update"),
        package,
        vec!["syncthing".into(), "syncthing.timer".into()],
    )
    .unwrap();
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");
    let calls = backend.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "stop syncthing.timer",
            "stop syncthing",
            "script update port=18384 purge=false",
            "stop syncthing.timer",
            "stop syncthing",
        ],
        "pre-stopped units must NOT be restarted after incomplete rollback"
    );
    let (_, status, category) = persisted(&op.conn);
    assert_eq!(status, "failed");
    assert_eq!(category, "service_restore");
    drop(op);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn update_rejects_missing_or_invalid_target_version_at_admission() {
    let (root, _path, conn, package) = fixture();
    let mut req = request("update");
    req.expected_target_version = None;
    assert!(
        CoordinatedOperation::admit(conn, req, package.clone(), vec!["syncthing".into()]).is_err(),
        "admission must reject update request with missing target version"
    );

    let (_r2, _p2, conn2, _pkg2) = fixture();
    let mut req2 = request("update");
    req2.expected_target_version = Some("invalid target with spaces".into());
    assert!(
        CoordinatedOperation::admit(conn2, req2, package, vec!["syncthing".into()]).is_err(),
        "admission must reject update request with invalid target version"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn update_fails_target_verification_when_live_probe_fails_or_mismatches() {
    let (root, _path, conn, package) = fixture();
    // Backend does not write target version to .af-version, so live probe will find nothing!
    let backend = FakeBackend::default();
    let (sender, _receiver) = mpsc::channel(32);
    let mut op =
        CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
            .unwrap();
    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");
    let (_, status, category) = persisted(&op.conn);
    assert_eq!(status, "failed");
    assert_eq!(category, "target_verification");
    drop(op);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_service_restart_inactive_unit_triggers_receipt_and_blueprint_rollback() {
    let (root, _path, conn, package) = fixture();
    let receipt_file = root.join("var/lib/syncthing/.af-version");
    std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
    std::fs::write(&receipt_file, b"v1.22.0").unwrap();

    let backend = FakeBackend {
        root: Some(root.clone()),
        inactive_after_start: true,
        ..Default::default()
    };
    let (sender, _receiver) = mpsc::channel(32);
    let mut op =
        CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
            .unwrap();

    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    let (status, category, diag): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "service_restore");
    assert!(
        diag.as_deref()
            .unwrap_or("")
            .contains("not active after start"),
        "Diagnostic summary must detail unit inactive after start: {:?}",
        diag
    );

    // Candidate receipt MUST have been rolled back to v1.22.0, NOT the installer's v1.23.4
    let restored_content = std::fs::read_to_string(&receipt_file).unwrap();
    assert_eq!(
        restored_content, "v1.22.0",
        "Receipt must be restored to pre-operation version on restart failure"
    );

    drop(op);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_service_unit_exiting_during_certification_triggers_receipt_rollback() {
    let (root, _path, conn, package) = fixture();
    let receipt_file = root.join("var/lib/syncthing/.af-version");
    std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
    std::fs::write(&receipt_file, b"v1.22.0").unwrap();

    let backend = FakeBackend {
        root: Some(root.clone()),
        inactive_after_certification: true,
        ..Default::default()
    };
    let (sender, _receiver) = mpsc::channel(32);
    let mut op =
        CoordinatedOperation::admit(conn, request("update"), package, vec!["syncthing".into()])
            .unwrap();

    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    let (status, category, diag): (String, String, Option<String>) = op
        .conn
        .query_row(
            "SELECT status, failure_category, sanitized_summary FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "service_restore");
    assert!(
        diag.as_deref()
            .unwrap_or("")
            .contains("exited or became inactive during certification"),
        "Diagnostic summary must report post-certification unit exit: {:?}",
        diag
    );

    // Receipt rolled back to v1.22.0
    let restored_content = std::fs::read_to_string(&receipt_file).unwrap();
    assert_eq!(restored_content, "v1.22.0");

    drop(op);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn test_blueprint_config_rollback_on_target_certification_failure() {
    let (root, _path, conn, _package) = fixture();
    let sonarr_package = Package {
        name: "sonarr".into(),
        service_name: "sonarr".into(),
        service_type: "systemd".into(),
        default_port: 8989,
        ..Default::default()
    };
    let config_file = root.join("var/lib/sonarr/config.xml");
    std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
    std::fs::write(
        &config_file,
        b"<Config><Port>8989</Port><ApiKey>PRE_OP_KEY</ApiKey></Config>\n",
    )
    .unwrap();

    let receipt_file = root.join("var/lib/sonarr/.af-version");
    std::fs::write(&receipt_file, b"2.0.0\n").unwrap();

    let req = PackageRunnerRequest {
        package_id: "sonarr".into(),
        action: "update".into(),
        script_name: "updatepackage-sonarr".into(),
        expected_target_version: Some("3.0.0".into()),
        app_port: 8989,
        ..Default::default()
    };

    struct BlueprintMutationBackend {
        root: PathBuf,
        config_file: PathBuf,
        receipt_file: PathBuf,
        stopped: Arc<std::sync::Mutex<bool>>,
    }
    impl LifecycleBackend for BlueprintMutationBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8989
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn quiescent<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            let s = *self.stopped.lock().unwrap();
            Box::pin(async move { Ok(s) })
        }
        fn control<'a>(
            &'a self,
            _: &'a str,
            action: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            if action == "stop" {
                *self.stopped.lock().unwrap() = true;
            } else if action == "start" {
                *self.stopped.lock().unwrap() = false;
            }
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                // Installer mutates blueprint config and writes receipt that mismatches target
                std::fs::write(
                    &self.config_file,
                    b"<Config><Port>8989</Port><ApiKey>MODIFIED_KEY</ApiKey></Config>\n",
                )
                .unwrap();
                std::fs::write(&self.receipt_file, b"2.5.0\n").unwrap();
                let bin = self.root.join("usr/bin/sonarr");
                let _ = std::fs::create_dir_all(bin.parent().unwrap());
                let _ = std::fs::write(&bin, b"#!/bin/sh\necho \"sonarr 2.5.0\"\n");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755));
                }
                Ok(())
            })
        }
    }

    let backend = BlueprintMutationBackend {
        root: root.clone(),
        config_file: config_file.clone(),
        receipt_file: receipt_file.clone(),
        stopped: Arc::new(std::sync::Mutex::new(false)),
    };

    let (sender, _receiver) = mpsc::channel(32);
    let mut op =
        CoordinatedOperation::admit(conn, req, sonarr_package, vec!["sonarr".into()]).unwrap();

    let receipt = op.execute(&backend, &sender).await.unwrap();
    assert_eq!(receipt.status, "failed");

    let (status, category): (String, String) = op
        .conn
        .query_row(
            "SELECT status, failure_category FROM package_lifecycle_jobs WHERE package_id='sonarr'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(category, "target_verification");

    // The blueprint config file MUST have been rolled back to PRE_OP_KEY!
    let rolled_back_config = std::fs::read_to_string(&config_file).unwrap();
    assert!(
        rolled_back_config.contains("PRE_OP_KEY"),
        "Blueprint config must be rolled back on certification failure, got: {}",
        rolled_back_config
    );
    assert!(
        !rolled_back_config.contains("MODIFIED_KEY"),
        "Modified blueprint config must not persist after certification failure"
    );

    // The receipt MUST have been rolled back to 2.0.0!
    let rolled_back_receipt = std::fs::read_to_string(&receipt_file).unwrap();
    assert_eq!(rolled_back_receipt.trim(), "2.0.0");

    drop(op);
    let _ = std::fs::remove_dir_all(root);
}
