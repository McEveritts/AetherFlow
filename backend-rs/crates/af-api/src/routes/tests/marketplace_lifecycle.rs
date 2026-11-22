use super::*;

#[tokio::test]
async fn test_dispatch_package_update_pre_stop_skips_maintainerr_and_stops_radarr() {
    use std::sync::{Arc, Mutex};

    let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let maintainerr_recorder = Arc::clone(&recorded_control_actions);

    let maintainerr_stopped = pre_stop_units_for_package_update_with(
        "update",
        "maintainerr",
        "",
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder_handle = Arc::clone(&maintainerr_recorder);
            async move {
                recorder_handle
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
    )
    .await
    .expect("maintainerr pre-stop decision should succeed");
    assert!(
        maintainerr_stopped.is_empty(),
        "maintainerr must not be pre-stopped by API update dispatcher"
    );
    assert!(
        recorded_control_actions.lock().unwrap().is_empty(),
        "control callback must not receive stop for maintainerr"
    );

    let radarr_recorder = Arc::clone(&recorded_control_actions);
    let radarr_stopped = pre_stop_units_for_package_update_with(
        "update",
        "radarr",
        "",
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder_handle = Arc::clone(&radarr_recorder);
            async move {
                recorder_handle
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
    )
    .await
    .expect("radarr pre-stop decision should succeed");

    assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
    assert_eq!(
        *recorded_control_actions.lock().unwrap(),
        vec!["stop radarr".to_string()]
    );

    recorded_control_actions.lock().unwrap().clear();
    for shared_app in ["nextcloud", "rutorrent", "organizr"] {
        let recorder = Arc::clone(&recorded_control_actions);
        let stopped = pre_stop_units_for_package_update_with(
            "update",
            shared_app,
            "",
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder_handle = Arc::clone(&recorder);
                async move {
                    recorder_handle
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
        )
        .await
        .expect("shared-vhost pre-stop decision should succeed");
        assert!(
            stopped.is_empty(),
            "{} must not pre-stop shared apache2 on update",
            shared_app
        );
    }
    assert!(
        recorded_control_actions.lock().unwrap().is_empty(),
        "shared-vhost updates must not invoke stop on apache2"
    );
}

#[tokio::test]
async fn test_dispatch_package_update_maintainerr_port_preservation_and_fail_closed() {
    use std::sync::{Arc, Mutex};

    let recorded_control_actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded_dispatch_ports: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    let queried_apps: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    for alias_id in ["maintainerr", "af-maintainerr", "af-maintainerr.service"] {
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        queried_apps.lock().unwrap().clear();

        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let app_recorder = Arc::clone(&queried_apps);

        let (allocated_port, stopped_units, dispatch_res) =
            run_package_lifecycle_dispatch_gate_with(
                "update",
                alias_id,
                6246,
                "",
                |_app_id| 0,
                move |app_id| {
                    app_recorder.lock().unwrap().push(app_id.to_string());
                    Ok(Some(AppIngressConfig {
                        app_name: app_id.to_string(),
                        listen_port: 17420,
                        ..Default::default()
                    }))
                },
                |_app_id, _default_port| 6246,
                af_services::resolve_service_units,
                |_unit_name| "running".to_string(),
                move |unit_name, control_action| {
                    let recorder = Arc::clone(&control_recorder);
                    async move {
                        recorder
                            .lock()
                            .unwrap()
                            .push(format!("{} {}", control_action, unit_name));
                        Ok(())
                    }
                },
                move |port| {
                    let recorder = Arc::clone(&dispatch_recorder);
                    async move {
                        recorder.lock().unwrap().push(port);
                        Ok(())
                    }
                },
            )
            .await
            .expect("maintainerr update with valid non-default port should succeed");

        assert!(dispatch_res.is_ok());
        assert_eq!(allocated_port, 17420);
        assert!(stopped_units.is_empty());
        assert_eq!(
            *queried_apps.lock().unwrap(),
            vec!["maintainerr".to_string()]
        );
        assert!(
            recorded_control_actions.lock().unwrap().is_empty(),
            "maintainerr update must not invoke unit control for {}",
            alias_id
        );
        assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
    }

    // Missing ingress row must fail closed before any unit control or package dispatch
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let missing_err = run_package_lifecycle_dispatch_gate_with(
        "update",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Ok(None),
        |_app_id, _default_port| 6246,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect_err("missing ingress mapping must fail closed");
    assert!(
        missing_err.contains("missing persisted ingress port mapping for maintainerr update"),
        "unexpected missing-mapping error: {}",
        missing_err
    );
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

    // Unreadable DB / query error must fail closed without falling back to 6246
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let db_err = run_package_lifecycle_dispatch_gate_with(
        "update",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Err(anyhow::anyhow!("sqlite disk I/O error")),
        |_app_id, _default_port| 6246,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect_err("unreadable ingress DB must fail closed");
    assert!(
        db_err.contains("cannot read existing configured port for maintainerr")
            && db_err.contains("sqlite disk I/O error"),
        "unexpected DB error: {}",
        db_err
    );
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert!(recorded_dispatch_ports.lock().unwrap().is_empty());

    // Out-of-range / invalid ports must fail closed with zero control or dispatch calls
    for invalid_port in [0, -1, 80, 1023, 65536, 70000] {
        recorded_control_actions.lock().unwrap().clear();
        recorded_dispatch_ports.lock().unwrap().clear();
        let control_recorder = Arc::clone(&recorded_control_actions);
        let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
        let port_err = run_package_lifecycle_dispatch_gate_with(
            "update",
            "maintainerr",
            6246,
            "",
            |_app_id| 0,
            move |app_id| {
                Ok(Some(AppIngressConfig {
                    app_name: app_id.to_string(),
                    listen_port: invalid_port,
                    ..Default::default()
                }))
            },
            |_app_id, _default_port| 6246,
            af_services::resolve_service_units,
            |_unit_name| "running".to_string(),
            move |unit_name, control_action| {
                let recorder = Arc::clone(&control_recorder);
                async move {
                    recorder
                        .lock()
                        .unwrap()
                        .push(format!("{} {}", control_action, unit_name));
                    Ok(())
                }
            },
            move |port| {
                let recorder = Arc::clone(&dispatch_recorder);
                async move {
                    recorder.lock().unwrap().push(port);
                    Ok(())
                }
            },
        )
        .await
        .expect_err("invalid persisted port must fail closed");
        assert!(
            port_err.contains(&format!(
                "invalid persisted listen port {} for maintainerr update",
                invalid_port
            )),
            "unexpected error for invalid port {}: {}",
            invalid_port,
            port_err
        );
        assert!(recorded_control_actions.lock().unwrap().is_empty());
        assert!(recorded_dispatch_ports.lock().unwrap().is_empty());
    }

    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let (radarr_port, radarr_stopped, radarr_res) = run_package_lifecycle_dispatch_gate_with(
        "update",
        "radarr",
        7878,
        "",
        |_app_id| 17878,
        |_app_id| Ok(None),
        |_app_id, _default_port| 7878,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect("radarr update must preserve its authoritative native port");
    assert!(radarr_res.is_ok());
    assert_eq!(radarr_port, 17878);
    assert_eq!(radarr_stopped, vec!["radarr".to_string()]);
    assert_eq!(
        *recorded_control_actions.lock().unwrap(),
        vec!["stop radarr".to_string()]
    );
    assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17878]);

    // Fresh install of maintainerr preserves install port allocation without pre-existing ingress
    recorded_control_actions.lock().unwrap().clear();
    recorded_dispatch_ports.lock().unwrap().clear();
    let control_recorder = Arc::clone(&recorded_control_actions);
    let dispatch_recorder = Arc::clone(&recorded_dispatch_ports);
    let (install_port, install_stopped, install_res) = run_package_lifecycle_dispatch_gate_with(
        "install",
        "maintainerr",
        6246,
        "",
        |_app_id| 0,
        |_app_id| Ok(None),
        |_app_id, _default_port| 17420,
        af_services::resolve_service_units,
        |_unit_name| "running".to_string(),
        move |unit_name, control_action| {
            let recorder = Arc::clone(&control_recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", control_action, unit_name));
                Ok(())
            }
        },
        move |port| {
            let recorder = Arc::clone(&dispatch_recorder);
            async move {
                recorder.lock().unwrap().push(port);
                Ok(())
            }
        },
    )
    .await
    .expect("fresh maintainerr install should allocate port");
    assert!(install_res.is_ok());
    assert_eq!(install_port, 17420);
    assert!(install_stopped.is_empty());
    assert!(recorded_control_actions.lock().unwrap().is_empty());
    assert_eq!(*recorded_dispatch_ports.lock().unwrap(), vec![17420]);
}

#[tokio::test]
async fn test_finalize_post_script_lifecycle_restarts_and_verifies_before_saving() {
    let timeline = std::cell::RefCell::new(Vec::new());
    let stopped = ["radarr".into(), "companion".into()];
    let version = finalize_post_script_lifecycle_with(
        &stopped,
        async {
            timeline.borrow_mut().push("blueprint".to_string());
            Ok(Some(AppIngressConfig::default()))
        },
        |unit, action| {
            timeline.borrow_mut().push(format!("{action} {unit}"));
            async { Ok(()) }
        },
        |unit| {
            timeline.borrow_mut().push(format!("check {unit}"));
            "running".into()
        },
        async {
            timeline.borrow_mut().push("refresh".into());
            Some("v2".into())
        },
        |_| {
            timeline.borrow_mut().push("commit".into());
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(version.as_deref(), Some("v2"));
    assert_eq!(
        timeline.into_inner(),
        [
            "blueprint",
            "start companion",
            "start radarr",
            "refresh",
            "check radarr",
            "check companion",
            "commit",
        ]
    );
}

#[test]
fn test_uninstall_purge_requires_explicit_true() {
    let parse = |value: Option<&str>| {
        parse_uninstall_purge(&UninstallQuery {
            purge: value.map(str::to_string),
        })
    };
    assert_eq!(parse(None), Ok(false));
    assert_eq!(parse(Some("")), Ok(false));
    assert_eq!(parse(Some("false")), Ok(false));
    assert_eq!(parse(Some("true")), Ok(true));
    assert_eq!(parse(Some("1")), Ok(true));
    assert!(parse(Some("yes")).is_err());
    assert!(parse(Some("TRUE ; rm")).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn package_admission_reconciles_dead_same_package_before_catalog_validation() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    let package_id = "lifecycle-admission-fixture";
    let package = af_models::Package {
        name: package_id.into(),
        label: "Lifecycle admission fixture".into(),
        service_name: package_id.into(),
        lock_file: "/install/.lifecycle-admission-fixture.lock".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![package]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );
    af_db::init_db().unwrap();
    let scripts = root.join("packages/package/install");
    std::fs::create_dir_all(&scripts).unwrap();
    let script_name = format!("installpackage-{package_id}");
    let script = scripts.join(&script_name);
    std::fs::write(&script, "#!/bin/sh\nexit 91\n").unwrap();
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    assert_eq!(
        af_runner::resolve_package_script_path("install", &script_name),
        Some(std::path::PathBuf::from("packages/package/install").join(&script_name))
    );
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "abandoned-install".into(),
            package_id: package_id.into(),
            action: "install".into(),
            status: "installing".into(),
            progress: 20,
            last_line: String::new(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    drop(af_services::take_package_job_lease(package_id, "abandoned-install").unwrap());
    assert_eq!(
        af_services::package_job_snapshot().unwrap().active[package_id].status,
        "installing"
    );
    let execution_blocked = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
    let response = dispatch_package_lifecycle(
        package_id.into(),
        "install",
        "installing",
        false,
        progress_test_user("admin", None),
        HeaderMap::new(),
    )
    .await;
    let response_status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_status, StatusCode::OK, "{payload}");
    let identity = payload["job_id"].as_str().unwrap();
    assert_ne!(identity, "abandoned-install");
    assert_eq!(
        af_services::package_job_snapshot().unwrap().active[package_id].job_id,
        identity
    );
    let rejected = dispatch_package_lifecycle(
        package_id.into(),
        "install",
        "installing",
        false,
        progress_test_user("admin", None),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert!(af_services::finish_package_job(
        package_id,
        "install",
        true,
        "late",
        "abandoned-install"
    )
    .is_none());
    af_services::finish_package_job(package_id, "install", true, "fixture done", identity).unwrap();
    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    drop(execution_blocked);
}

#[tokio::test(flavor = "current_thread")]
async fn finalize_post_script_lifecycle_preserves_routing_on_required_failure() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    use af_services::PackageJobFailure::{Configuration, ServiceRestore};

    let (root, conn) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let original = AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "custom.example.test".into(),
        external_access_enabled: false,
        tls_enabled: true,
        listen_port: 18989,
        ..Default::default()
    };
    af_db::set_app_ingress_config(&original).unwrap();
    af_db::archive_app_ingress_config("sonarr", false).unwrap();
    let retained = af_db::get_retained_app_ingress_config("sonarr").unwrap();
    af_db::set_app_ingress_config(&original).unwrap();
    let original = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();

    let vhost = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    std::fs::create_dir_all(vhost.parent().unwrap()).unwrap();
    std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:18989/\n").unwrap();
    let blueprint_snapshots = af_runner::package_lifecycle::snapshot_blueprint_targets(
        "sonarr",
        &af_runner::PackageExecutionEnv {
            fs_root: Some(root.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let prior_vhost = std::fs::read(&vhost).unwrap();

    let job_id = "ingress-update";
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: job_id.into(),
            package_id: "sonarr".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 85,
            last_line: String::new(),
            started_at: "fixture-start".into(),
            expected_target_version: None,
        }
    ));
    conn.execute_batch(
        "CREATE TABLE ingress_writes(port INTEGER);
         CREATE TRIGGER count_ingress_update AFTER UPDATE ON app_ingress_configs
         BEGIN INSERT INTO ingress_writes VALUES (NEW.listen_port); END;
         CREATE TRIGGER fail_ingress_update AFTER UPDATE ON app_ingress_configs
         WHEN NEW.app_name = 'sonarr'
         BEGIN SELECT RAISE(ABORT, 'fixture rejected ingress update'); END;",
    )
    .unwrap();

    let units = ["sonarr".to_string()];
    let planned =
        af_db::plan_lifecycle_ingress("sonarr", 28989, "base.example.test", Some(&original))
            .unwrap()
            .unwrap();
    let writes = || {
        conn.query_row("SELECT count(*) FROM ingress_writes", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    };
    let run = |blueprint_failed, status: &'static str| {
        let planned = planned.clone();
        finalize_post_script_lifecycle_with(
            &units,
            async move {
                if blueprint_failed {
                    Err("fixture vhost synchronization failed".into())
                } else {
                    Ok(Some(planned))
                }
            },
            |_, _| async { Ok(()) },
            move |_| status.into(),
            async { None },
            |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, job_id, "update"),
        )
    };
    for (blueprint_failed, status, expected_kind, cause) in [
        (
            true,
            "running",
            Configuration,
            "fixture vhost synchronization failed",
        ),
        (false, "stopped", ServiceRestore, "failed to remain active"),
        (
            false,
            "running",
            Configuration,
            "fixture rejected ingress update",
        ),
    ] {
        std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:28989/\n").unwrap();
        let failure = run(blueprint_failed, status).await.unwrap_err();
        assert_eq!(failure.kind, expected_kind);
        assert!(failure.message.contains(cause), "{}", failure.message);
        let (_, restore_error, restart_failures) =
            marketplace::handle_post_certification_finalization_failure_ext_with(
                "update",
                failure,
                "sonarr",
                &units,
                &[],
                &blueprint_snapshots,
                false,
                None,
                None,
                |_, _| async { Ok(()) },
                |_| "running".into(),
            )
            .await;
        assert!(restore_error.is_none());
        assert!(restart_failures.is_empty());
        assert_eq!(std::fs::read(&vhost).unwrap(), prior_vhost);
        assert_eq!(
            af_db::get_app_ingress_config("sonarr").unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            af_db::get_retained_app_ingress_config("sonarr").unwrap(),
            retained
        );
        assert_eq!(writes(), 0);
    }

    conn.execute_batch("DROP TRIGGER fail_ingress_update")
        .unwrap();
    std::fs::write(&vhost, b"ProxyPass / http://127.0.0.1:28989/\n").unwrap();
    run(false, "running").await.unwrap();
    let committed = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(committed.listen_port, 28989);
    assert_eq!(committed.public_domain, original.public_domain);
    assert_eq!(
        committed.external_access_enabled,
        original.external_access_enabled
    );
    assert_eq!(committed.tls_enabled, original.tls_enabled);
    assert_eq!(writes(), 1);
    af_services::finish_package_job("sonarr", "update", true, "done", job_id).unwrap();
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn package_ingress_callbacks_require_the_current_lifecycle_owner() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let job = |identity: &str, action: &str, status: &str| af_services::PackageJobInfo {
        job_id: identity.into(),
        package_id: "sonarr".into(),
        action: action.into(),
        status: status.into(),
        progress: 20,
        last_line: String::new(),
        started_at: "fixture-start".into(),
        expected_target_version: None,
    };
    assert!(af_services::try_start_package_job(job(
        "ingress-install",
        "install",
        "installing"
    )));
    finalize_post_script_lifecycle_with(
        &[],
        async {
            af_db::plan_lifecycle_ingress("sonarr", 18989, "example.com", None)
                .map_err(|err| err.to_string())
        },
        |_, _| async { Ok(()) },
        |_| unreachable!(),
        async { None },
        |cfg| af_db::set_app_ingress_config_for_lifecycle(cfg, "ingress-install", "install"),
    )
    .await
    .unwrap();
    let ingress = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(ingress.listen_port, 18989);
    assert!(af_db::set_app_ingress_config(&ingress).is_err());
    assert!(
        af_db::set_app_ingress_config_for_lifecycle(&ingress, "wrong-owner", "install").is_err()
    );
    af_services::finish_package_job("sonarr", "install", true, "done", "ingress-install").unwrap();
    assert!(af_services::try_start_package_job(job(
        "ingress-remove",
        "remove",
        "uninstalling"
    )));
    assert!(af_db::archive_app_ingress_config("sonarr", false).is_err());
    assert!(
        af_db::archive_app_ingress_config_for_lifecycle("sonarr", false, "ingress-install")
            .is_err()
    );
    af_db::archive_app_ingress_config_for_lifecycle("sonarr", false, "ingress-remove").unwrap();
    assert!(af_db::get_app_ingress_config("sonarr").unwrap().is_none());
    assert_eq!(
        load_authoritative_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .listen_port,
        18989
    );
    af_services::finish_package_job("sonarr", "remove", true, "done", "ingress-remove").unwrap();
    drop(connection);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn test_system_update_blocks_package_lifecycle_until_terminal() {
    let status = |completed: bool| af_models::SelfUpdateJobStatus {
        status: if completed { "succeeded" } else { "running" }.to_string(),
        completed,
        success: completed,
        job_unit: "aetherflow-self-update-deploy-nightly-0123abcd.service".to_string(),
        error: String::new(),
        exit_code: if completed { Some(0) } else { None },
    };
    assert!(
        system_update_lifecycle_block_with(|| async { Ok(status(false)) })
            .await
            .is_some()
    );
    let running = system_update_lifecycle_block_with(|| async { Ok(status(false)) })
        .await
        .expect("running updater must block lifecycle jobs");
    assert!(running.to_string().contains("in progress"));
    let unavailable = system_update_lifecycle_block_with(|| async {
        Err(anyhow::anyhow!("runner socket connection refused"))
    })
    .await
    .expect("unknown status for a launched updater fails closed");
    assert!(unavailable.to_string().contains("unavailable"));
    assert!(
        system_update_lifecycle_block_with(|| async { Ok(status(true)) })
            .await
            .is_none()
    );
    assert!(system_update_lifecycle_block_with(|| async {
        Err(anyhow::anyhow!("self-update job 'x' not found"))
    })
    .await
    .is_some());
}

#[tokio::test]
async fn test_update_prestop_uses_daemon_and_timer_policy_not_jobs_or_unconfigured_mounts() {
    for (app, expected) in [
        ("recyclarr", vec!["recyclarr.timer".to_string()]),
        ("rclone", vec!["rclone".to_string()]),
    ] {
        let stopped = pre_stop_units_for_package_update_with(
            "update",
            app,
            "",
            |app_id| af_services::resolve_controllable_service_units_with(app_id, "restart", false),
            |_unit| "running".to_string(),
            |_unit, _action| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(stopped, expected);
    }
}

#[test]
fn test_installer_managed_ports_use_marketplace_fallback_range() {
    let blueprint = af_services::get_blueprint("uptimekuma").unwrap();
    assert_eq!(blueprint.fallback_port_range, [0, 0]);
    let [start, end] = af_models::MARKETPLACE_FALLBACK_PORT_RANGE;
    let port = allocate_or_resolve_app_port_with(
        &blueprint.app_name,
        blueprint.default_port,
        |_| Ok(None),
        |_| Ok([blueprint.default_port, start].into()),
    );
    assert!((start + 1..=end).contains(&port));

    let plex = af_services::get_blueprint("plex").unwrap();
    assert_eq!(
        allocate_or_resolve_app_port_with(
            &plex.app_name,
            plex.default_port,
            |_| Ok(None),
            |_| Ok([plex.default_port].into()),
        ),
        0
    );
}

#[test]
fn test_port_reservation_lookup_failure_fails_closed() {
    let port_when_reserved_err = allocate_or_resolve_app_port_with(
        "sonarr",
        8989,
        |_| Ok(None),
        |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
    );
    assert_eq!(
        port_when_reserved_err, 0,
        "reserved-port query failure must return 0 instead of handing out default port"
    );

    let port_when_existing_err = allocate_or_resolve_app_port_with(
        "sonarr",
        8989,
        |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
        |_| Ok(std::collections::BTreeSet::new()),
    );
    assert_eq!(
        port_when_existing_err, 0,
        "existing ingress lookup failure must return 0 instead of falling through"
    );

    let resolved = resolve_package_lifecycle_port_with(
        "install",
        "sonarr",
        8989,
        |_| 0,
        |_| Ok(None),
        |app, def| {
            allocate_or_resolve_app_port_with(
                app,
                def,
                |_| Ok(None),
                |_| Err(anyhow::anyhow!("sqlite busy or unavailable")),
            )
        },
    );
    assert!(
        resolved.is_err(),
        "resolve_package_lifecycle_port_with must fail closed when reserved-port lookup fails"
    );
}

#[tokio::test]
async fn test_incomplete_rollback_refuses_to_restart_pre_stopped_units_in_api() {
    let restarted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let restarted_clone = restarted.clone();
    let stopped = vec!["sonarr".to_string(), "sonarr.timer".to_string()];
    let (kind, msg) = restore_pre_stopped_units_after_installer_failure_with(
            "sonarr",
            &stopped,
            "Package update failed; incomplete rollback: recovery backup preserved at /var/lib/sonarr.bak",
            move |unit, action| {
                let restarted_clone = restarted_clone.clone();
                async move {
                    restarted_clone
                        .lock()
                        .unwrap()
                        .push(format!("{action} {unit}"));
                    Ok(())
                }
            },
        )
        .await;
    assert_eq!(kind, af_services::PackageJobFailure::ServiceRestore);
    assert!(
        msg.contains("Refusing to restart pre-stopped service after incomplete rollback"),
        "unexpected message: {msg}"
    );
    assert!(
        restarted.lock().unwrap().is_empty(),
        "pre-stopped units must NOT be started when rollback is incomplete"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_action_dispatch_does_not_block_install_reinstall_or_remove_on_update_errors_or_retirement(
) {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    async fn settle_dispatched_job(response: axum::response::Response, package: &str) {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let job_id = body["job_id"].as_str().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
            loop {
                if af_services::get_package_job_outcome(package)
                    .is_some_and(|outcome| outcome.job_id == job_id)
                {
                    break;
                }
                interval.tick().await;
            }
            // The outcome is committed before the worker drops its guard.
            // Wait for that task to release admission before the next action.
            let _finished = af_services::PACKAGE_LIFECYCLE_MUTEX.lock().await;
        })
        .await
        .expect("the dispatched fixture job must settle before the next action");
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    let test_pkg = af_models::Package {
        name: "test-err-pkg".into(),
        label: "Test Error Pkg".into(),
        service_name: "test-err-pkg".into(),
        lock_file: "/install/.test-err-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let retired_pkg = af_models::Package {
        name: "readarr".into(),
        label: "Readarr".into(),
        service_name: "readarr".into(),
        lock_file: "/install/.readarr.lock".into(),
        status: "installed".into(),
        update_source: "retired".into(),
        ..Default::default()
    };
    let uninstalled_pkg = af_models::Package {
        name: "test-fresh-pkg".into(),
        label: "Test Fresh Pkg".into(),
        service_name: "test-fresh-pkg".into(),
        lock_file: "/install/.test-fresh-pkg.lock".into(),
        status: "not_installed".into(),
        ..Default::default()
    };

    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![
            test_pkg.clone(),
            retired_pkg.clone(),
            uninstalled_pkg.clone(),
        ])
        .unwrap(),
    )
    .unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    let install_scripts = root.join("packages/package/install");
    let remove_scripts = root.join("packages/package/remove");
    let update_scripts = root.join("packages/package/update");
    std::fs::create_dir_all(&install_scripts).unwrap();
    std::fs::create_dir_all(&remove_scripts).unwrap();
    std::fs::create_dir_all(&update_scripts).unwrap();
    for id in ["test-err-pkg", "readarr", "test-fresh-pkg"] {
        let inst_file = install_scripts.join(format!("installpackage-{id}"));
        let rem_file = remove_scripts.join(format!("removepackage-{id}"));
        let upd_file = update_scripts.join(format!("updatepackage-{id}"));
        std::fs::write(&inst_file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem_file, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&upd_file, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&inst_file, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&rem_file, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&upd_file, std::fs::Permissions::from_mode(0o755));
        }
    }
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    // Seed app_updates with an upstream error for test-err-pkg
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, latest_version, last_error) VALUES ('test-err-pkg', '', 'GitHub rate limit exceeded')",
                [],
            ).unwrap();
    }

    let admin = progress_test_user("admin", None);
    // A. Verify 'remove' succeeds even when app_updates has a last_error
    let res_remove = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_remove.status(),
        StatusCode::OK,
        "remove must not be blocked by app_updates last_error"
    );
    settle_dispatched_job(res_remove, "test-err-pkg").await;

    // B. Verify 'install' succeeds on uninstalled package without app_updates record
    let res_install = dispatch_package_lifecycle_with_target(
        "test-fresh-pkg".into(),
        "install",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_install.status(),
        StatusCode::OK,
        "install must not require app_updates or confirmed target"
    );
    settle_dispatched_job(res_install, "test-fresh-pkg").await;

    // C. Verify 'reinstall' succeeds even when app_updates has last_error
    let res_reinstall = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "reinstall",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_reinstall.status(),
        StatusCode::OK,
        "reinstall must not be blocked by app_updates last_error"
    );
    settle_dispatched_job(res_reinstall, "test-err-pkg").await;

    // D. Verify 'remove' succeeds unconditionally on a retired package (readarr)
    let res_retired_remove = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_retired_remove.status(),
        StatusCode::OK,
        "remove on retired package must succeed unconditionally"
    );
    settle_dispatched_job(res_retired_remove, "readarr").await;

    // E. Verify 'update' on test-err-pkg IS blocked by app_updates last_error
    let res_update_blocked = dispatch_package_lifecycle_with_target(
        "test-err-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(
        res_update_blocked.status(),
        StatusCode::CONFLICT,
        "update MUST be blocked by app_updates error"
    );

    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rclone_api_lifecycle_port_reservation_and_secondary_port_coordination() {
    use super::super::marketplace::{
        allocate_or_resolve_app_port_for_job, reserve_api_lifecycle_ports,
    };

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    let job = |pkg: &str, id: &str, action: &str, status: &str| af_services::PackageJobInfo {
        job_id: id.into(),
        package_id: pkg.into(),
        action: action.into(),
        status: status.into(),
        progress: 10,
        last_line: String::new(),
        started_at: "2026-04-20T00:00:00Z".into(),
        expected_target_version: None,
    };

    // 1. Pre-fix live split-port unit without SQLite secondary row protects RC port 8989 from Sonarr
    //    and records port:<N> on Sonarr's active job row.
    let systemd_dir = root.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    std::fs::write(
        systemd_dir.join("rclone.service"),
        "[Service]\nExecStart=/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:5572 --api-addr=127.0.0.1:8989\n",
    ).unwrap();
    assert!(af_services::try_start_package_job(job(
        "sonarr",
        "sonarr-preflight",
        "install",
        "installing"
    )));
    let sonarr_port = allocate_or_resolve_app_port_for_job(
        "sonarr",
        8989,
        "sonarr-preflight",
        "install",
        Some(&root),
    );
    assert!(
        (17000..=19999).contains(&sonarr_port) && sonarr_port != 8989,
        "{sonarr_port}"
    );
    let sonarr_units: String = connection
        .query_row("SELECT service_units FROM package_lifecycle_jobs WHERE package_id='sonarr' AND job_id='sonarr-preflight'", [], |r| r.get(0))
        .unwrap();
    assert!(
        sonarr_units.contains(&format!("port:{sonarr_port}")),
        "{sonarr_units}"
    );
    af_services::finish_package_job("sonarr", "install", true, "done", "sonarr-preflight").unwrap();
    std::fs::remove_file(systemd_dir.join("rclone.service")).unwrap();

    // 2. Concurrent API port allocations for colliding default ports never return the same port.
    assert!(af_services::try_start_package_job(job(
        "sonarr",
        "sonarr-conc",
        "install",
        "installing"
    )));
    assert!(af_services::try_start_package_job(job(
        "radarr",
        "radarr-conc",
        "install",
        "installing"
    )));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let (b1, r1, b2, r2) = (barrier.clone(), root.clone(), barrier, root.clone());
    let t1 = std::thread::spawn(move || {
        b1.wait();
        allocate_or_resolve_app_port_for_job("sonarr", 17888, "sonarr-conc", "install", Some(&r1))
    });
    let t2 = std::thread::spawn(move || {
        b2.wait();
        allocate_or_resolve_app_port_for_job("radarr", 17888, "radarr-conc", "install", Some(&r2))
    });
    let (p1, p2) = (t1.join().unwrap(), t2.join().unwrap());
    assert!(
        p1 > 0 && p2 > 0 && p1 != p2,
        "concurrent API allocations collided: {p1} vs {p2}"
    );
    af_services::finish_package_job("sonarr", "install", true, "done", "sonarr-conc").unwrap();
    af_services::finish_package_job("radarr", "install", true, "done", "radarr-conc").unwrap();

    // 3. Rclone split-port install commits primary + secondary RC port; retained remove keeps it; purge clears it.
    assert!(af_services::try_start_package_job(job(
        "rclone",
        "rclone-install-1",
        "install",
        "installing"
    )));
    let rclone_port = allocate_or_resolve_app_port_for_job(
        "rclone",
        5572,
        "rclone-install-1",
        "install",
        Some(&root),
    );
    assert!(rclone_port > 0);
    reserve_api_lifecycle_ports(
        "rclone",
        "rclone-install-1",
        "install",
        rclone_port,
        Some(&root),
    )
    .unwrap();
    let rclone_cfg = af_db::plan_lifecycle_ingress("rclone", rclone_port, "", None)
        .unwrap()
        .unwrap();
    af_db::set_app_ingress_and_secondary_port_for_lifecycle(
        &rclone_cfg,
        Some((af_models::RCLONE_RC_API_PORT_ROLE, Some(17915))),
        "rclone-install-1",
        "install",
    )
    .unwrap();
    af_services::finish_package_job("rclone", "install", true, "done", "rclone-install-1").unwrap();
    assert!(af_db::get_reserved_ports_excluding("radarr")
        .unwrap()
        .contains(&17915));

    assert!(af_services::try_start_package_job(job(
        "rclone",
        "rclone-remove-retain",
        "remove",
        "uninstalling"
    )));
    af_db::archive_app_ingress_config_for_lifecycle("rclone", false, "rclone-remove-retain")
        .unwrap();
    af_services::finish_package_job("rclone", "remove", true, "done", "rclone-remove-retain")
        .unwrap();
    assert!(af_db::get_reserved_ports_excluding("radarr")
        .unwrap()
        .contains(&17915));

    assert!(af_services::try_start_package_job(job(
        "rclone",
        "rclone-remove-purge",
        "remove",
        "uninstalling"
    )));
    af_db::archive_app_ingress_config_for_lifecycle("rclone", true, "rclone-remove-purge").unwrap();
    af_services::finish_package_job("rclone", "remove", true, "done", "rclone-remove-purge")
        .unwrap();
    assert!(!af_db::get_reserved_ports_excluding("radarr")
        .unwrap()
        .contains(&17915));

    let _ = std::fs::remove_dir_all(&root);
}
