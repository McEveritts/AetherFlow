use super::*;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn ambiguous_stop_is_restored_and_restoration_failure_is_reported() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let error = pre_stop_units_for_package_update_with(
        "update",
        "sonarr",
        "",
        |_| vec!["sonarr".into()],
        |_| "running".into(),
        move |unit, action| {
            recorded.lock().unwrap().push(format!("{action} {unit}"));
            async move { anyhow::bail!("fixture {action} acknowledgement lost") }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(*calls.lock().unwrap(), vec!["stop sonarr", "start sonarr"]);
    assert!(
        error.1.contains("restor"),
        "restoration failure must not disappear: {error:?}"
    );
}

#[tokio::test]
async fn lost_stop_acknowledgement_restores_running_state_without_dispatching_installer() {
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let observed = running.clone();
    let result = run_package_lifecycle_dispatch_gate_with(
        "update",
        "sonarr",
        8989,
        "",
        |_| 18989,
        |_| Ok(None),
        |_, _| unreachable!(),
        |_| vec!["sonarr".into()],
        |_| "running".into(),
        move |_, action| {
            let observed = observed.clone();
            async move {
                observed.store(action == "start", std::sync::atomic::Ordering::SeqCst);
                if action == "stop" {
                    anyhow::bail!("fixture stop completed but acknowledgement lost");
                }
                Ok(())
            }
        },
        |_| async { panic!("ambiguous preparation must not dispatch the installer") },
    )
    .await;
    assert!(result.is_err());
    assert!(running.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn unavailable_port_or_unknown_status_blocks_the_installer_dispatch_gate() {
    for uncertain_port in [true, false] {
        let result = run_package_lifecycle_dispatch_gate_with(
            "update",
            "sonarr",
            8989,
            "",
            |_| if uncertain_port { 0 } else { 18989 },
            |_| {
                if uncertain_port {
                    Err(anyhow::anyhow!("fixture ingress read unavailable"))
                } else {
                    Ok(None)
                }
            },
            |_, _| panic!("updates never allocate a port"),
            |_| vec!["sonarr".into()],
            |_| "unknown".into(),
            |_, _| async { panic!("unconfirmed preparation must not control services") },
            |_| async { panic!("unconfirmed preparation must not dispatch the installer") },
        )
        .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn unknown_or_transitioning_update_observations_fail_before_controls() {
    for observation in ["unknown", "restarting", "activating", "deactivating", ""] {
        let result = pre_stop_units_for_package_update_with(
            "update",
            "sonarr",
            "",
            |_| vec!["sonarr".into()],
            |_| observation.into(),
            |_, _| async { panic!("unknown observations must not trigger controls") },
        )
        .await;
        assert!(result.is_err(), "accepted {observation:?}");
    }
}

#[tokio::test]
async fn update_preparation_observes_all_units_before_stopping_and_restores_in_reverse() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    assert!(pre_stop_units_for_package_update_with(
        "update",
        "sonarr",
        "",
        |_| vec!["daemon".into(), "daemon.timer".into()],
        |unit| if unit.ends_with(".timer") {
            "running"
        } else {
            "unknown"
        }
        .into(),
        |_, _| async { panic!("all observations must be confirmed before the first stop") },
    )
    .await
    .is_err());
    let error = pre_stop_units_for_package_update_with(
        "update",
        "sonarr",
        "",
        |_| vec!["daemon".into(), "daemon.timer".into(), "daemon".into()],
        |_| "running".into(),
        move |unit, action| {
            recorded.lock().unwrap().push(format!("{action} {unit}"));
            async move {
                if unit == "daemon" && action == "stop" {
                    anyhow::bail!("fixture acknowledgement lost");
                }
                Ok(())
            }
        },
    )
    .await
    .unwrap_err();
    assert!(error.1.contains("acknowledgement lost"));
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            "stop daemon.timer",
            "stop daemon",
            "start daemon",
            "start daemon.timer"
        ]
    );
}

#[test]
fn updates_never_substitute_a_default_for_an_unknown_existing_port() {
    for existing in [
        Ok(None),
        Err(anyhow::anyhow!("fixture ingress unavailable")),
    ] {
        let mut existing = Some(existing);
        assert!(resolve_package_lifecycle_port_with(
            "update",
            "sonarr",
            8989,
            |_| 0,
            |_| existing.take().unwrap(),
            |_, _| panic!("updates must never allocate"),
        )
        .is_err());
    }
    assert!(resolve_package_lifecycle_port_with(
        "update",
        "sonarr",
        8989,
        |_| 18989,
        |_| Err(anyhow::anyhow!("fixture ingress unavailable")),
        |_, _| unreachable!(),
    )
    .is_err());
    let existing = AppIngressConfig {
        app_name: "sonarr".into(),
        listen_port: 18989,
        ..Default::default()
    };
    assert_eq!(
        resolve_package_lifecycle_port_with(
            "update",
            "sonarr",
            8989,
            |_| 0,
            |_| Ok(Some(existing.clone())),
            |_, _| unreachable!(),
        )
        .unwrap(),
        18989
    );
    assert_eq!(
        resolve_package_lifecycle_port_with(
            "update",
            "sonarr",
            8989,
            |_| 28989,
            |_| Ok(Some(existing.clone())),
            |_, _| unreachable!(),
        )
        .unwrap(),
        28989
    );
}

#[tokio::test]
async fn updater_observation_errors_do_not_expose_private_detail() {
    let block = system_update_lifecycle_block_with(|| async {
        Err(anyhow::anyhow!("fixture /private/operator/release-state"))
    })
    .await
    .unwrap();
    let response = block.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["code"], "STATUS_UNAVAILABLE");
    assert!(payload["error_id"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(!String::from_utf8_lossy(&body).contains("/private/"));
}

#[test]
fn blueprint_callback_failure_preserves_required_restoration_failure() {
    let failure = merge_blueprint_finalization(
        Err(PackageLifecycleFailure {
            kind: af_services::PackageJobFailure::ServiceRestore,
            message: "fixture restore failed".into(),
        }),
        Some("fixture vhost failed".into()),
    )
    .unwrap_err();
    assert_eq!(
        failure.kind,
        af_services::PackageJobFailure::ConfigurationAndServiceRestore
    );
    assert!(failure.message.contains("restore failed"));
    assert!(failure.message.contains("vhost failed"));
    assert!(merge_blueprint_finalization(Ok(()), Some("fixture DNS failed".into())).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn blueprint_http_sync_rejects_removal_without_side_effects_and_reports_callback_failure() {
    const TEST: &str = "routes::http_lifecycle_regressions::blueprint_http_sync_rejects_removal_without_side_effects_and_reports_callback_failure";
    if env::var("AF_HTTP_LIFECYCLE_CHILD").as_deref() != Ok(TEST) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("AF_HTTP_LIFECYCLE_CHILD", TEST)
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = env::temp_dir().join(format!("af-http-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
    std::fs::create_dir_all(root.join("etc/apache2/sites-available")).unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    let database = root.join("var/lib/aetherflow/aetherflow.sqlite");
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
    ] {
        env::set_var(key, &root);
    }
    for key in ["DB_PATH", "AF_DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &database);
    }
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent.sock"));
    env::set_var("AETHERFLOW_HOSTS_FILE", root.join("hosts"));
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    std::fs::write(root.join("automation.json"), "{}").unwrap();
    std::fs::write(root.join("packages.json"), r#"[{"name":"sonarr","label":"Sonarr","description":"fixture","category":"test","lock_file":"/install/.sonarr.lock","service_type":"systemd","service_name":"sonarr","default_port":8989}]"#).unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "fixture").unwrap();
    std::fs::write(root.join("hosts"), "127.0.0.1 localhost\n").unwrap();
    let config = root.join("var/lib/sonarr/config.xml");
    let before = "<Config><Port>18989</Port></Config>\n";
    std::fs::write(&config, before).unwrap();
    af_db::init_db().unwrap();
    let mut conn = rusqlite::Connection::open(&database).unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap()).unwrap();
    let owner = af_runner::af_release::lifecycle::admit_job(
        &mut conn,
        "sonarr",
        "remove",
        "remove",
        "now",
        &["sonarr".into()],
    )
    .unwrap();
    let auth = || AuthUser {
        user_id: 1,
        username: "fixture".into(),
        role: "admin".into(),
        jti: "fixture".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(root.join("etc/apache2/sites-available"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        std::fs::read_to_string(root.join("hosts")).unwrap(),
        "127.0.0.1 localhost\n"
    );
    af_runner::af_release::lifecycle::finish_job(&conn, "sonarr", "remove", "remove", true, "")
        .unwrap();
    drop(owner);
    af_db::set_app_ingress_config(&AppIngressConfig {
        app_name: "sonarr".into(),
        listen_port: 18989,
        ..Default::default()
    })
    .unwrap();
    let vhost = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    std::fs::create_dir(&vhost).unwrap();
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        "BLUEPRINT_SYNC_FAILED"
    );
    std::fs::remove_dir(vhost).unwrap();
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["result"]["allocated_port"], 18989);
    assert_eq!(payload["result"]["ingress_synced"], true);
    assert_eq!(payload["result"]["hosts_synced"], true);
    assert_eq!(payload["result"]["network_dns_synced"], true);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn f01_reinstall_action_preserves_install_port_and_finalization_contract() {
    let existing = AppIngressConfig {
        app_name: "sonarr".into(),
        listen_port: 18989,
        ..Default::default()
    };
    assert_eq!(
        resolve_package_lifecycle_port_with(
            "reinstall",
            "sonarr",
            8989,
            |_| 0,
            |_| Ok(Some(existing.clone())),
            |_, _| unreachable!(),
        )
        .unwrap(),
        18989
    );

    let pre_stopped = pre_stop_units_for_package_update_with(
        "reinstall",
        "sonarr",
        "",
        |_| vec!["sonarr".into()],
        |_| "running".into(),
        |_, _| async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(pre_stopped, vec!["sonarr".to_string()]);

    let saved = Arc::new(Mutex::new(Vec::new()));
    let saved_clone = saved.clone();
    let finalized = finalize_post_script_lifecycle_with(
        "reinstall",
        "sonarr",
        18989,
        vec![],
        "aetherflow.local",
        |_| Ok(None),
        move |cfg| {
            saved_clone.lock().unwrap().push(cfg.listen_port);
            Ok(())
        },
        |_, _| async { Ok(()) },
        |_| async {},
    )
    .await;
    assert!(finalized.is_ok());
    assert_eq!(*saved.lock().unwrap(), vec![18989]);
}
