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

#[tokio::test]
async fn blueprint_callback_failure_preserves_required_restoration_failure() {
    let failure = finalize_post_script_lifecycle_with(
        &["sonarr".into()],
        async { Err("fixture vhost failed".into()) },
        |_, _| async { anyhow::bail!("fixture restore failed") },
        |_| "stopped".into(),
        async { None },
        |_| panic!("failed blueprint must prevent ingress persistence"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.kind,
        af_services::PackageJobFailure::ConfigurationAndServiceRestore
    );
    assert!(failure.message.contains("restore failed"));
    assert!(failure.message.contains("vhost failed"));
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
    let failure: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(failure["code"], "BLUEPRINT_SYNC_FAILED");
    assert_eq!(failure["failed_phase"], "ingress");
    assert_eq!(failure["partial_commit"], true);
    assert_eq!(failure["retryable"], true);
    assert_eq!(failure["result"]["config_applied"], true);
    assert_eq!(failure["result"]["ingress_synced"], false);
    assert_eq!(failure["result"]["hosts_synced"], false);
    assert_eq!(failure["result"]["network_dns_synced"], false);
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

#[cfg(unix)]
#[tokio::test]
async fn blueprint_sync_reports_partial_commit_preserves_custom_tls_and_retries_idempotently() {
    const TEST: &str = "routes::http_lifecycle_regressions::blueprint_sync_reports_partial_commit_preserves_custom_tls_and_retries_idempotently";
    if env::var("AF_HTTP_LIFECYCLE_CHILD").as_deref() != Ok(TEST) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("AF_HTTP_LIFECYCLE_CHILD", TEST)
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = env::temp_dir().join(format!("af-http-bp-retry-{}", uuid::Uuid::new_v4()));
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
    env::remove_var("PRIVILEGED_RUNNER_ENABLED");
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    env::set_var("AETHERFLOW_BASE_DOMAIN", "other.example.test");
    env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent.sock"));
    let hosts_path = root.join("hosts");
    env::set_var("AETHERFLOW_HOSTS_FILE", &hosts_path);
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    std::fs::write(root.join("automation.json"), "{}").unwrap();
    std::fs::write(
        root.join("packages.json"),
        r#"[{"name":"sonarr","label":"Sonarr","description":"fixture","category":"test","lock_file":"/install/.sonarr.lock","service_type":"systemd","service_name":"sonarr","default_port":8989}]"#,
    )
    .unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "fixture").unwrap();
    std::fs::write(
        root.join("var/lib/sonarr/config.xml"),
        "<Config><Port>18989</Port></Config>\n",
    )
    .unwrap();
    af_db::init_db().unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap()).unwrap();
    let approved = AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "series.custom.example".into(),
        external_access_enabled: true,
        listen_port: 18989,
        tls_enabled: true,
        ..Default::default()
    };
    af_db::set_app_ingress_config(&approved).unwrap();
    let auth = || AuthUser {
        user_id: 1,
        username: "fixture".into(),
        role: "admin".into(),
        jti: "fixture".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // 1. Managed Apache failure rolls back DB ingress and reports config-only partial commit.
    let ext_vhost = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    std::fs::create_dir(&ext_vhost).unwrap();
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["code"], "BLUEPRINT_SYNC_FAILED");
    assert_eq!(payload["failed_phase"], "ingress");
    assert_eq!(payload["partial_commit"], true);
    assert_eq!(payload["retryable"], true);
    assert_eq!(payload["result"]["config_applied"], true);
    assert_eq!(payload["result"]["ingress_synced"], false);
    assert_eq!(payload["result"]["hosts_synced"], false);
    assert_eq!(payload["result"]["network_dns_synced"], false);
    let retained = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(retained.public_domain, "series.custom.example");
    assert!(retained.external_access_enabled);
    assert!(retained.tls_enabled);
    assert_eq!(retained.listen_port, 18989);
    std::fs::remove_dir(&ext_vhost).unwrap();

    // 2. Managed Apache publication succeeds, then local hosts fails -> truthful partial status.
    std::fs::create_dir(&hosts_path).unwrap();
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["code"], "BLUEPRINT_SYNC_FAILED");
    assert_eq!(payload["failed_phase"], "hosts");
    assert_eq!(payload["partial_commit"], true);
    assert_eq!(payload["retryable"], true);
    assert_eq!(payload["result"]["ingress_synced"], true);
    assert_eq!(payload["result"]["hosts_synced"], false);
    assert_eq!(payload["result"]["network_dns_synced"], false);
    let rendered_int = std::fs::read_to_string(
        root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf"),
    )
    .unwrap();
    assert!(rendered_int.contains("ServerName sonarr.aether.local"));
    assert!(rendered_int.contains("127.0.0.1:18989"));
    let rendered_ext = std::fs::read_to_string(&ext_vhost).unwrap();
    assert!(rendered_ext.contains("ServerName series.custom.example"));
    assert!(rendered_ext.contains("TLS certificate provisioning pending"));
    assert!(root
        .join("etc/apache2/sites-enabled/aetherflow-ext-sonarr.conf")
        .exists());

    // 3. After clearing the hosts blocker, retries converge idempotently and retain custom TLS/host.
    std::fs::remove_dir(&hosts_path).unwrap();
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
    let mut previous_hosts = String::new();
    for attempt in 0..2 {
        let response =
            sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["result"]["allocated_port"], 18989);
        assert_eq!(payload["result"]["public_domain"], "series.custom.example");
        assert_eq!(payload["result"]["external_access_enabled"], true);
        assert_eq!(payload["result"]["ingress_synced"], true);
        assert_eq!(payload["result"]["hosts_synced"], true);
        assert_eq!(payload["result"]["network_dns_synced"], true);
        let hosts_now = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(hosts_now.contains("sonarr.aether.local"));
        if attempt == 0 {
            previous_hosts = hosts_now;
        } else {
            assert_eq!(hosts_now, previous_hosts);
        }
        let persisted = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
        assert_eq!(persisted.public_domain, "series.custom.example");
        assert!(persisted.external_access_enabled);
        assert!(persisted.tls_enabled);
        assert_eq!(persisted.listen_port, 18989);
    }

    // 4. Unmanaged/unavailable Apache must not falsely report ingress_synced=true from DB write alone.
    std::fs::remove_dir_all(root.join("etc/apache2")).unwrap();
    std::fs::write(root.join("etc/apache2"), "unmanaged apache placeholder").unwrap();
    let response =
        sync_app_blueprint(Path("sonarr".into()), Extension(auth()), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["result"]["ingress_synced"], false);
    assert_eq!(payload["result"]["hosts_synced"], true);
    assert_eq!(payload["result"]["network_dns_synced"], true);
    assert!(payload["result"]["warnings"]
        .as_array()
        .is_some_and(|warnings| !warnings.is_empty()));

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

    let finalized = finalize_post_script_lifecycle_with(
        &pre_stopped,
        async {
            af_db::plan_lifecycle_ingress("sonarr", 18989, "", Some(&existing))
                .map_err(|err| err.to_string())
        },
        |_, _| async { Ok(()) },
        |_| "running".into(),
        async { None },
        |cfg| {
            assert_eq!(cfg.listen_port, 18989);
            Ok(())
        },
    )
    .await;
    assert!(finalized.is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn marketplace_failed_reinstall_recovery_gate_preserves_failure_and_blocks_incomplete_recovery(
) {
    const TEST: &str = "routes::http_lifecycle_regressions::marketplace_failed_reinstall_recovery_gate_preserves_failure_and_blocks_incomplete_recovery";
    if env::var("AF_HTTP_LIFECYCLE_CHILD").as_deref() != Ok(TEST) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("AF_HTTP_LIFECYCLE_CHILD", TEST)
            .status()
            .unwrap()
            .success());
        return;
    }

    let root = env::temp_dir().join(format!("af-reinstall-rec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/syncthing")).unwrap();
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
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    std::fs::write(root.join("automation.json"), "{}").unwrap();
    std::fs::write(
        root.join("packages.json"),
        r#"[{"name":"syncthing","label":"Syncthing","description":"fixture","category":"test","lock_file":"/install/.syncthing.lock","service_type":"systemd","service_name":"syncthing","default_port":8384}]"#,
    )
    .unwrap();
    let lock = root.join("install/.syncthing.lock");
    let receipt = root.join("var/lib/syncthing/.af-version");
    std::fs::write(&lock, "installed\n").unwrap();
    std::fs::write(&receipt, "1.28.0\n").unwrap();

    af_db::init_db().unwrap();
    af_db::set_base_domain("review.test").unwrap();
    af_db::set_app_ingress_config(&AppIngressConfig {
        app_name: "syncthing".into(),
        public_domain: "sync.review.test".into(),
        external_access_enabled: true,
        listen_port: 18384,
        ..Default::default()
    })
    .unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap()).unwrap();

    let fs_root_str = root.to_string_lossy().to_string();
    let prior_installed = is_lock_file_present("/install/.syncthing.lock", Some(&fs_root_str));
    assert!(prior_installed);

    // 1. Complete recovery through normal rollback + finish_package_lifecycle_with_recovery path.
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "http-reinstall-complete".into(),
            package_id: "syncthing".into(),
            action: "reinstall".into(),
            status: "installing".into(),
            progress: 15,
            last_line: "reinstalling".into(),
            started_at: "2026-11-20T01:00:00Z".into(),
            expected_target_version: None,
        }
    ));
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    let env_cfg = af_runner::PackageExecutionEnv {
        fs_root: Some(root.clone()),
        ..af_runner::PackageExecutionEnv::default()
    };
    let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        "syncthing",
        &["syncthing".into()],
        &env_cfg,
        false,
    )
    .unwrap();
    // Simulate failed reinstall mutating receipt and removing lock before rollback restores them.
    std::fs::write(&receipt, "1.29.0-broken\n").unwrap();
    std::fs::remove_file(&lock).unwrap();

    let (restore_err, restart_failures) =
        quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
            "syncthing",
            &["syncthing".into()],
            &["syncthing".into()],
            &snapshots,
            &[],
            false,
            Some(&mut rt_snap),
            None,
            |_, _| async { Ok(()) },
            |_| "running".into(),
        )
        .await;
    assert!(restore_err.is_none(), "restore_err={restore_err:?}");
    assert!(
        restart_failures.is_empty(),
        "restart_failures={restart_failures:?}"
    );
    assert!(lock.is_file());
    assert_eq!(std::fs::read_to_string(&receipt).unwrap(), "1.28.0\n");

    let recovered = verified_prior_state_recovery(
        "reinstall",
        prior_installed,
        true,
        restore_err.as_deref(),
        &restart_failures,
        "/install/.syncthing.lock",
        Some(&fs_root_str),
    );
    assert!(recovered);

    finish_package_lifecycle_with_recovery(
        "syncthing",
        "reinstall",
        Some(af_services::PackageJobFailure::Installer),
        60,
        "installer exited with status 1",
        "2026-11-20T01:00:00Z",
        "http-reinstall-complete",
        None,
        None,
        &[],
        recovered,
    );

    let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(outcome.status, "failed");
    assert_eq!(
        outcome.recovery_state.as_deref(),
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED)
    );
    let admin_payload = package_progress_payload("syncthing", None, Some(outcome.clone()), true);
    assert_eq!(admin_payload["status"], "failed");
    assert_eq!(
        admin_payload["last_job"]["recovery_state"],
        af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED
    );
    let viewer_payload = package_progress_payload("syncthing", None, Some(outcome), false);
    assert!(viewer_payload["last_job"].get("recovery_state").is_none());

    assert_eq!(
        crate::middlewares::resolve_app_target_for_host("sync.review.test"),
        Some(("syncthing".into(), 18384))
    );
    // Survives simulated API restart.
    af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap()).unwrap();
    af_db::invalidate_ingress_cache();
    assert_eq!(
        crate::middlewares::resolve_app_target_for_host("sync.review.test"),
        Some(("syncthing".into(), 18384))
    );

    // 2. Incomplete rollback (refuse_restart=true) stays failed AND keeps gateway unavailable.
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "http-reinstall-incomplete".into(),
            package_id: "syncthing".into(),
            action: "reinstall".into(),
            status: "installing".into(),
            progress: 15,
            last_line: "reinstalling".into(),
            started_at: "2026-11-20T01:05:00Z".into(),
            expected_target_version: None,
        }
    ));
    let (inc_err, inc_failures) = quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
        "syncthing",
        &["syncthing".into()],
        &["syncthing".into()],
        &snapshots,
        &[],
        true,
        None,
        None,
        |_, _| async { Ok(()) },
        |_| "running".into(),
    )
    .await;
    assert!(inc_err.is_some());
    let inc_recovered = verified_prior_state_recovery(
        "reinstall",
        prior_installed,
        false,
        inc_err.as_deref(),
        &inc_failures,
        "/install/.syncthing.lock",
        Some(&fs_root_str),
    );
    assert!(!inc_recovered);
    finish_package_lifecycle_with_recovery(
        "syncthing",
        "reinstall",
        Some(af_services::PackageJobFailure::ServiceRestore),
        60,
        "installer failed; incomplete rollback",
        "2026-11-20T01:05:00Z",
        "http-reinstall-incomplete",
        None,
        None,
        &[],
        inc_recovered,
    );
    let inc_outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(inc_outcome.status, "failed");
    assert!(inc_outcome.recovery_state.is_none());
    assert!(crate::middlewares::resolve_app_target_for_host("sync.review.test").is_none());

    // 3. Inactive pre-stopped unit during finish_package_lifecycle_with_recovery forces fail-closed.
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "http-reinstall-inactive-unit".into(),
            package_id: "syncthing".into(),
            action: "reinstall".into(),
            status: "installing".into(),
            progress: 15,
            last_line: "reinstalling".into(),
            started_at: "2026-11-20T01:10:00Z".into(),
            expected_target_version: None,
        }
    ));
    finish_package_lifecycle_with_recovery(
        "syncthing",
        "reinstall",
        Some(af_services::PackageJobFailure::Installer),
        60,
        "installer failed",
        "2026-11-20T01:10:00Z",
        "http-reinstall-inactive-unit",
        None,
        None,
        &["nonexistent-aetherflow-fixture-unit-xyz".into()],
        true,
    );
    let inactive_outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(inactive_outcome.status, "failed");
    assert!(inactive_outcome.recovery_state.is_none());
    assert!(crate::middlewares::resolve_app_target_for_host("sync.review.test").is_none());

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn pre_stop_and_restore_order_librespeed_socket_and_novnc_companions_with_legacy_and_unknown()
{
    // 1. Modern LibreSpeed update & reinstall: stops librespeed.socket before librespeed, restores socket first
    for action in ["update", "reinstall"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let stopped = pre_stop_units_for_package_update_with(
            action,
            "librespeed",
            "",
            |_| vec!["librespeed".into(), "librespeed.socket".into()],
            |_| "running".into(),
            move |unit, act| {
                recorded.lock().unwrap().push(format!("{act} {unit}"));
                async { Ok(()) }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            stopped,
            vec!["librespeed.socket".to_string(), "librespeed".to_string()],
            "{action}"
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["stop librespeed.socket", "stop librespeed"],
            "{action}"
        );

        let restore_calls = Arc::new(Mutex::new(Vec::new()));
        let restore_recorded = restore_calls.clone();
        let (kind, _) = restore_pre_stopped_units_after_installer_failure_with(
            "librespeed",
            &stopped,
            "fixture installer failure",
            move |unit, act| {
                restore_recorded
                    .lock()
                    .unwrap()
                    .push(format!("{act} {unit}"));
                async { Ok(()) }
            },
        )
        .await;
        assert_eq!(kind, af_services::PackageJobFailure::Installer, "{action}");
        assert_eq!(
            *restore_calls.lock().unwrap(),
            vec!["start librespeed.socket", "start librespeed"],
            "{action}"
        );
    }

    // 2. Legacy pre-socket LibreSpeed: confirmed not-found socket is skipped while running worker is stopped
    let legacy_calls = Arc::new(Mutex::new(Vec::new()));
    let legacy_recorded = legacy_calls.clone();
    let legacy_stopped = pre_stop_units_for_package_update_with(
        "update",
        "librespeed",
        "",
        |_| vec!["librespeed".into(), "librespeed.socket".into()],
        |unit| {
            if unit == "librespeed.socket" {
                "not-found".into()
            } else {
                "running".into()
            }
        },
        move |unit, act| {
            legacy_recorded
                .lock()
                .unwrap()
                .push(format!("{act} {unit}"));
            async { Ok(()) }
        },
    )
    .await
    .unwrap();
    assert_eq!(legacy_stopped, vec!["librespeed".to_string()]);
    assert_eq!(*legacy_calls.lock().unwrap(), vec!["stop librespeed"]);

    // 3. Unknown socket status fails closed BEFORE stopping any unit
    assert!(pre_stop_units_for_package_update_with(
        "update",
        "librespeed",
        "",
        |_| vec!["librespeed".into(), "librespeed.socket".into()],
        |unit| {
            if unit == "librespeed.socket" {
                "unknown".into()
            } else {
                "running".into()
            }
        },
        |_, _| async { panic!("unknown companion status must fail closed before stopping") },
    )
    .await
    .is_err());

    // 4. Modern noVNC: stops novnc -> novnc-session -> novnc-xvnc, restores novnc-xvnc -> novnc-session -> novnc
    let novnc_calls = Arc::new(Mutex::new(Vec::new()));
    let novnc_recorded = novnc_calls.clone();
    let novnc_stopped = pre_stop_units_for_package_update_with(
        "update",
        "novnc",
        "",
        |_| vec!["novnc-xvnc".into(), "novnc-session".into(), "novnc".into()],
        |_| "running".into(),
        move |unit, act| {
            novnc_recorded.lock().unwrap().push(format!("{act} {unit}"));
            async { Ok(()) }
        },
    )
    .await
    .unwrap();
    assert_eq!(
        novnc_stopped,
        vec![
            "novnc".to_string(),
            "novnc-session".to_string(),
            "novnc-xvnc".to_string(),
        ]
    );
    let novnc_restore_calls = Arc::new(Mutex::new(Vec::new()));
    let novnc_restore_recorded = novnc_restore_calls.clone();
    let (novnc_kind, _) = restore_pre_stopped_units_after_installer_failure_with(
        "novnc",
        &novnc_stopped,
        "fixture installer failure",
        move |unit, act| {
            novnc_restore_recorded
                .lock()
                .unwrap()
                .push(format!("{act} {unit}"));
            async { Ok(()) }
        },
    )
    .await;
    assert_eq!(novnc_kind, af_services::PackageJobFailure::Installer);
    assert_eq!(
        *novnc_restore_calls.lock().unwrap(),
        vec!["start novnc-xvnc", "start novnc-session", "start novnc",]
    );

    // 5. Legacy pre-companion noVNC: not-found novnc-session skipped, unknown fails closed
    let legacy_novnc_stopped = pre_stop_units_for_package_update_with(
        "reinstall",
        "novnc",
        "",
        |_| vec!["novnc".into(), "novnc-xvnc".into(), "novnc-session".into()],
        |unit| {
            if unit == "novnc-session" {
                "not-found".into()
            } else {
                "running".into()
            }
        },
        |_, _| async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(
        legacy_novnc_stopped,
        vec!["novnc".to_string(), "novnc-xvnc".to_string()]
    );
    assert!(pre_stop_units_for_package_update_with(
        "reinstall",
        "novnc",
        "",
        |_| vec!["novnc".into(), "novnc-xvnc".into(), "novnc-session".into()],
        |unit| {
            if unit == "novnc-session" {
                "unknown".into()
            } else {
                "running".into()
            }
        },
        |_, _| async { panic!("unknown novnc-session must fail closed before stopping") },
    )
    .await
    .is_err());

    // 6. Rollback quiesce & restore stops librespeed.socket first and restarts librespeed.socket first
    let rb_calls = Arc::new(Mutex::new(Vec::new()));
    let rb_recorded = rb_calls.clone();
    let (rb_err, rb_restart_failures) =
        quiesce_and_restore_candidate_receipts_and_runtime_ext_with(
            "librespeed",
            &["librespeed".into(), "librespeed.socket".into()],
            &["librespeed".into(), "librespeed.socket".into()],
            &[],
            &[],
            false,
            None,
            None,
            move |unit, act| {
                rb_recorded.lock().unwrap().push(format!("{act} {unit}"));
                async { Ok(()) }
            },
            |unit| {
                let started = format!("start {unit}");
                if rb_calls.lock().unwrap().contains(&started) {
                    "running".into()
                } else {
                    "stopped".into()
                }
            },
        )
        .await;
    assert!(rb_err.is_none(), "{rb_err:?}");
    assert!(rb_restart_failures.is_empty(), "{rb_restart_failures:?}");
    assert_eq!(
        *rb_calls.lock().unwrap(),
        vec![
            "stop librespeed.socket",
            "stop librespeed",
            "start librespeed.socket",
            "start librespeed",
        ]
    );
}

#[test]
fn admin_settings_generated_domain_classification_preserves_custom_domains_under_old_suffix() {
    let sources = vec!["old.example".to_string()];
    assert!(is_generated_public_domain(
        "sonarr",
        "sonarr.old.example",
        "old.example"
    ));
    assert!(is_generated_public_domain(
        "sonarr",
        "SONARR.OLD.EXAMPLE.",
        "old.example"
    ));
    assert!(!is_generated_public_domain(
        "sonarr",
        "tv.old.example",
        "old.example"
    ));
    assert!(!is_generated_public_domain(
        "sonarr",
        "media.sonarr.old.example",
        "old.example"
    ));
    assert!(!is_generated_public_domain(
        "sonarr",
        "sonarr-4k.old.example",
        "old.example"
    ));

    // Active configs: generated & empty migrate; custom under old or other suffix stays untouched.
    assert!(should_auto_update_active_domain(
        "sonarr",
        "sonarr.old.example",
        &sources,
        "new.example"
    ));
    assert!(should_auto_update_active_domain(
        "sonarr",
        "",
        &sources,
        "new.example"
    ));
    assert!(!should_auto_update_active_domain(
        "radarr",
        "movies.old.example",
        &sources,
        "new.example"
    ));
    assert!(!should_auto_update_active_domain(
        "sonarr",
        "media.sonarr.old.example",
        &sources,
        "new.example"
    ));
    assert!(!should_auto_update_active_domain(
        "radarr",
        "movies.custom.test",
        &sources,
        "new.example"
    ));

    // Retained configs: generated old domain migrates; empty and custom domains stay untouched.
    assert!(should_auto_update_retained_domain(
        "lidarr",
        "lidarr.old.example",
        &sources,
        "new.example"
    ));
    assert!(!should_auto_update_retained_domain(
        "lidarr",
        "",
        &sources,
        "new.example"
    ));
    assert!(!should_auto_update_retained_domain(
        "readarr",
        "books.old.example",
        &sources,
        "new.example"
    ));

    // Multi-source retry/revert: covers both original and partially-applied generated domains,
    // while still preserving custom domains under the old suffix.
    let retry_sources = vec!["old.example".to_string(), "new.example".to_string()];
    assert!(should_auto_update_active_domain(
        "sabnzbd",
        "sabnzbd.new.example",
        &retry_sources,
        "third.example"
    ));
    assert!(should_auto_update_active_domain(
        "sonarr",
        "sonarr.old.example",
        &retry_sources,
        "third.example"
    ));
    assert!(!should_auto_update_active_domain(
        "radarr",
        "movies.old.example",
        &retry_sources,
        "third.example"
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn admin_settings_base_domain_update_handles_partial_failure_same_value_retry_and_preserves_custom_and_retained_domains(
) {
    use tower::ServiceExt;

    const TEST: &str = "routes::http_lifecycle_regressions::admin_settings_base_domain_update_handles_partial_failure_same_value_retry_and_preserves_custom_and_retained_domains";
    if env::var("AF_HTTP_LIFECYCLE_CHILD").as_deref() != Ok(TEST) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("AF_HTTP_LIFECYCLE_CHILD", TEST)
            .status()
            .unwrap()
            .success());
        return;
    }

    let root = env::temp_dir().join(format!("af-http-base-domain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/sabnzbd")).unwrap();
    std::fs::create_dir_all(root.join("var/lib/sonarr")).unwrap();
    std::fs::create_dir_all(root.join("etc/apache2/sites-available")).unwrap();
    std::fs::create_dir_all(root.join("etc/apache2/sites-enabled")).unwrap();
    std::fs::create_dir_all(root.join("etc/dnsmasq.d")).unwrap();
    let database = root.join("var/lib/aetherflow/aetherflow.sqlite");
    let hosts_path = root.join("hosts");
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
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
    env::remove_var("PRIVILEGED_RUNNER_ENABLED");
    env::remove_var("AETHERFLOW_BASE_DOMAIN");
    env::remove_var("AETHERFLOW_DOMAIN");
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent.sock"));
    env::set_var("AETHERFLOW_HOSTS_FILE", &hosts_path);
    env::set_var("AETHERFLOW_DNSMASQ_DIR", root.join("etc/dnsmasq.d"));
    env::set_var("AETHERFLOW_LAN_IP", "192.0.2.10");
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    std::fs::write(root.join("automation.json"), "{}").unwrap();
    std::fs::write(
        root.join("packages.json"),
        r#"[
            {"name":"sabnzbd","label":"SABnzbd","description":"fixture","category":"test","lock_file":"/install/.sabnzbd.lock","service_type":"systemd","service_name":"sabnzbd","default_port":8080},
            {"name":"sonarr","label":"Sonarr","description":"fixture","category":"test","lock_file":"/install/.sonarr.lock","service_type":"systemd","service_name":"sonarr","default_port":8989},
            {"name":"radarr","label":"Radarr","description":"fixture","category":"test","lock_file":"/install/.radarr.lock","service_type":"systemd","service_name":"radarr","default_port":7878},
            {"name":"bazarr","label":"Bazarr","description":"fixture","category":"test","lock_file":"/install/.bazarr.lock","service_type":"systemd","service_name":"bazarr","default_port":6767},
            {"name":"lidarr","label":"Lidarr","description":"fixture","category":"test","lock_file":"/install/.lidarr.lock","service_type":"systemd","service_name":"lidarr","default_port":8686},
            {"name":"readarr","label":"Readarr","description":"fixture","category":"test","lock_file":"/install/.readarr.lock","service_type":"systemd","service_name":"readarr","default_port":8787}
        ]"#,
    )
    .unwrap();
    for installed in ["sabnzbd", "sonarr", "radarr", "bazarr"] {
        std::fs::write(
            root.join(format!("install/.{installed}.lock")),
            "installed\n",
        )
        .unwrap();
    }
    let sab_ini = root.join("var/lib/sabnzbd/sabnzbd.ini");
    std::fs::write(
        &sab_ini,
        "[misc]\nport = 18080\nhost = 127.0.0.1\nhost_whitelist = sabnzbd.old.example, sabnzbd.aether.local, localhost, 127.0.0.1\n",
    )
    .unwrap();
    std::fs::write(
        root.join("var/lib/sonarr/config.xml"),
        "<Config><Port>18989</Port></Config>\n",
    )
    .unwrap();

    af_db::init_db().unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap()).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        let encrypted_openai = af_db::encrypt_key("sk-test-preserve-9876").unwrap();
        conn.execute(
            "INSERT INTO users(id, username, role) VALUES(701, 'domain-admin', 'admin')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE settings SET ai_model='gemini-4-argon', system_prompt='keep-system-prompt',
             base_domain='old.example', openai_api_key=?1, backup_schedule_mode='smart' WHERE id=1",
            params![encrypted_openai],
        )
        .unwrap();
    }
    af_db::invalidate_ingress_cache();

    // Active ingress: generated sabnzbd (tls=false), generated sonarr (tls=true),
    // and operator-owned custom radarr under the OLD suffix (movies.old.example).
    let sab_cfg = AppIngressConfig {
        app_name: "sabnzbd".into(),
        public_domain: "sabnzbd.old.example".into(),
        external_access_enabled: true,
        listen_port: 18080,
        tls_enabled: false,
        ..Default::default()
    };
    let sonarr_cfg = AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "sonarr.old.example".into(),
        external_access_enabled: true,
        listen_port: 18989,
        tls_enabled: true,
        ..Default::default()
    };
    let radarr_cfg = AppIngressConfig {
        app_name: "radarr".into(),
        public_domain: "movies.old.example".into(),
        external_access_enabled: true,
        listen_port: 17878,
        tls_enabled: true,
        ..Default::default()
    };
    af_db::set_app_ingress_config(&sab_cfg).unwrap();
    af_db::set_app_ingress_config(&sonarr_cfg).unwrap();
    af_db::set_app_ingress_config(&radarr_cfg).unwrap();
    // Seed radarr's existing Apache vhost so we can verify it stays untouched.
    assert!(sync_ingress_vhost(&radarr_cfg, "radarr.aether.local").unwrap());

    // Retained ingress (uninstalled apps): generated lidarr + custom readarr under old suffix.
    af_db::set_app_ingress_config(&AppIngressConfig {
        app_name: "lidarr".into(),
        public_domain: "lidarr.old.example".into(),
        external_access_enabled: true,
        listen_port: 18686,
        tls_enabled: true,
        ..Default::default()
    })
    .unwrap();
    af_db::archive_app_ingress_config("lidarr", false).unwrap();
    af_db::set_app_ingress_config(&AppIngressConfig {
        app_name: "readarr".into(),
        public_domain: "books.old.example".into(),
        external_access_enabled: true,
        listen_port: 18787,
        tls_enabled: true,
        ..Default::default()
    })
    .unwrap();
    af_db::archive_app_ingress_config("readarr", false).unwrap();

    let (token, _) = crate::auth::create_standard_jwt(701, &HeaderMap::new()).unwrap();
    let app = build_router();
    async fn send_admin_settings_put(
        app: &Router,
        token: &str,
        domain: &str,
        prompt: &str,
    ) -> (StatusCode, serde_json::Value) {
        let payload = SettingsPayload {
            ai_model: "gemini-4-argon".into(),
            system_prompt: prompt.into(),
            language: "en".into(),
            timezone: "UTC".into(),
            update_channel: "stable".into(),
            default_dashboard: "overview".into(),
            setup_completed: true,
            base_domain: domain.into(),
            openai_api_key: "****9876".into(),
            ..Default::default()
        };
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/admin/settings")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&payload).unwrap(),
            ))
            .unwrap();
        let res = Box::pin(app.clone().oneshot(req)).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }
    async fn send_auth_settings_get(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .uri("/api/v1/auth/settings")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let res = Box::pin(app.clone().oneshot(req)).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    // 1. Lifecycle serialization: active reservation on an affected app rejects with 409 LIFECYCLE_BUSY
    //    before mutating settings, active/retained ingress, native configs, Apache, or DNS.
    let mut job_conn = rusqlite::Connection::open(&database).unwrap();
    let job_owner = af_runner::af_release::lifecycle::admit_job(
        &mut job_conn,
        "sonarr",
        "busy-job-1",
        "update",
        "2026-11-21T01:00:00Z",
        &["sonarr".into()],
    )
    .unwrap();
    let (busy_status, busy_body) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "new.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(busy_status, StatusCode::CONFLICT);
    assert_eq!(busy_body["code"], "LIFECYCLE_BUSY");
    assert_eq!(af_db::get_base_domain(), "old.example");
    assert_eq!(
        af_db::get_app_ingress_config("sabnzbd")
            .unwrap()
            .unwrap()
            .public_domain,
        "sabnzbd.old.example"
    );
    assert!(std::fs::read_to_string(&sab_ini)
        .unwrap()
        .contains("sabnzbd.old.example"));
    {
        let conn = af_db::get_conn().unwrap();
        assert_eq!(af_db::get_pending_base_domain_sync(&conn).unwrap(), None);
    }
    af_runner::af_release::lifecycle::finish_job(
        &job_conn,
        "sonarr",
        "busy-job-1",
        "update",
        true,
        "",
    )
    .unwrap();
    drop(job_owner);
    drop(job_conn);

    // 2. Partial failure during managed Apache: sabnzbd commits, sonarr fails Apache -> sonarr rolls back,
    //    settings.base_domain restores to old.example, and pending sync state records old->new.
    let sonarr_ext_vhost = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    std::fs::create_dir(&sonarr_ext_vhost).unwrap();
    let (partial_status, partial_body) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "new.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(partial_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(partial_body["code"], "BLUEPRINT_SYNC_FAILED");
    assert_eq!(partial_body["failed_phase"], "ingress");
    assert_eq!(partial_body["partial_commit"], true);
    assert_eq!(partial_body["retryable"], true);
    // sabnzbd committed with tls_enabled preserved as false; sonarr rolled back; radarr untouched.
    let sab_mid = af_db::get_app_ingress_config("sabnzbd").unwrap().unwrap();
    assert_eq!(sab_mid.public_domain, "sabnzbd.new.example");
    assert!(!sab_mid.tls_enabled);
    assert!(std::fs::read_to_string(&sab_ini)
        .unwrap()
        .contains("sabnzbd.new.example"));
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "sonarr.old.example"
    );
    assert_eq!(
        af_db::get_app_ingress_config("radarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "movies.old.example"
    );
    assert_eq!(af_db::get_base_domain(), "old.example");
    assert_eq!(
        af_db::get_retained_app_ingress_config("lidarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "lidarr.old.example"
    );
    {
        let conn = af_db::get_conn().unwrap();
        assert_eq!(
            af_db::get_pending_base_domain_sync(&conn).unwrap(),
            Some(af_db::PendingBaseDomainSync {
                previous_base_domain: "old.example".into(),
                target_base_domain: "new.example".into(),
            })
        );
    }
    std::fs::remove_dir(&sonarr_ext_vhost).unwrap();

    // 3. DNS failure after all active apps commit, followed by same-value retry converging everything.
    std::fs::remove_file(&hosts_path).unwrap();
    std::fs::create_dir(&hosts_path).unwrap();
    let (dns_fail_status, dns_fail_body) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "new.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(dns_fail_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(dns_fail_body["failed_phase"], "network_dns");
    assert_eq!(dns_fail_body["partial_commit"], true);
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "sonarr.new.example"
    );
    assert_eq!(af_db::get_base_domain(), "old.example");
    std::fs::remove_dir(&hosts_path).unwrap();
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();

    // Same-value retry with baseDomain = "new.example" now succeeds and converges all layers.
    let (retry_status, retry_body) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "new.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(retry_status, StatusCode::OK);
    assert_eq!(retry_body["data"]["baseDomain"], "new.example");
    assert_eq!(retry_body["data"]["systemPrompt"], "updated-prompt");

    // Verify persisted settings fields, masked secret preservation, untouched columns, and cleared pending state.
    let (get_status, get_body) = Box::pin(send_auth_settings_get(&app, &token)).await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(get_body["baseDomain"], "new.example");
    assert_eq!(get_body["systemPrompt"], "updated-prompt");
    assert_eq!(get_body["openaiApiKey"], "****9876");
    {
        let conn = af_db::get_conn().unwrap();
        let (backup_mode, enc_key): (String, String) = conn
            .query_row(
                "SELECT backup_schedule_mode, openai_api_key FROM settings WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(backup_mode, "smart");
        assert_eq!(
            af_db::decrypt_key(&enc_key).unwrap(),
            "sk-test-preserve-9876"
        );
        assert_eq!(af_db::get_pending_base_domain_sync(&conn).unwrap(), None);
    }

    // Verify active ingress, native config, and Apache vhosts.
    let sab_now = af_db::get_app_ingress_config("sabnzbd").unwrap().unwrap();
    assert_eq!(sab_now.public_domain, "sabnzbd.new.example");
    assert!(!sab_now.tls_enabled);
    assert_eq!(sab_now.listen_port, 18080);
    let sab_ini_text = std::fs::read_to_string(&sab_ini).unwrap();
    assert!(sab_ini_text.contains("sabnzbd.new.example"));
    assert!(!sab_ini_text.contains("sabnzbd.old.example"));
    assert!(std::fs::read_to_string(
        root.join("etc/apache2/sites-available/aetherflow-ext-sabnzbd.conf")
    )
    .unwrap()
    .contains("ServerName sabnzbd.new.example"));

    let sonarr_now = af_db::get_app_ingress_config("sonarr").unwrap().unwrap();
    assert_eq!(sonarr_now.public_domain, "sonarr.new.example");
    assert!(sonarr_now.tls_enabled);
    assert_eq!(sonarr_now.listen_port, 18989);
    assert!(std::fs::read_to_string(&sonarr_ext_vhost)
        .unwrap()
        .contains("ServerName sonarr.new.example"));

    let bazarr_now = af_db::get_app_ingress_config("bazarr").unwrap().unwrap();
    assert_eq!(bazarr_now.public_domain, "bazarr.new.example");
    assert!(!bazarr_now.external_access_enabled);
    assert!(bazarr_now.tls_enabled);
    assert_eq!(bazarr_now.listen_port, 6767);

    // Custom domain under the old suffix must remain untouched in DB and Apache!
    let radarr_now = af_db::get_app_ingress_config("radarr").unwrap().unwrap();
    assert_eq!(radarr_now.public_domain, "movies.old.example");
    assert!(std::fs::read_to_string(
        root.join("etc/apache2/sites-available/aetherflow-ext-radarr.conf")
    )
    .unwrap()
    .contains("ServerName movies.old.example"));

    // Retained ingress: generated lidarr updated in place (not promoted); custom readarr preserved!
    assert!(af_db::get_app_ingress_config("lidarr").unwrap().is_none());
    assert!(af_db::get_app_ingress_config("readarr").unwrap().is_none());
    let lidarr_ret = af_db::get_retained_app_ingress_config("lidarr")
        .unwrap()
        .unwrap();
    assert_eq!(lidarr_ret.public_domain, "lidarr.new.example");
    assert_eq!(lidarr_ret.listen_port, 18686);
    assert!(lidarr_ret.external_access_enabled);
    let readarr_ret = af_db::get_retained_app_ingress_config("readarr")
        .unwrap()
        .unwrap();
    assert_eq!(readarr_ret.public_domain, "books.old.example");
    assert!(!root
        .join("etc/apache2/sites-available/aetherflow-ext-lidarr.conf")
        .exists());

    // DNS reconciliation: active new domains + custom radarr present; stale old & phantom domains absent.
    let dnsmasq_conf =
        std::fs::read_to_string(root.join("etc/dnsmasq.d/05-aetherflow-dns.conf")).unwrap();
    for expected in [
        "sabnzbd.new.example",
        "sonarr.new.example",
        "bazarr.new.example",
        "movies.old.example",
    ] {
        assert!(
            dnsmasq_conf.contains(expected),
            "dnsmasq missing {expected}: {dnsmasq_conf}"
        );
    }
    for absent in [
        "sabnzbd.old.example",
        "sonarr.old.example",
        "radarr.new.example",
        "lidarr.new.example",
        "books.old.example",
    ] {
        assert!(
            !dnsmasq_conf.contains(absent),
            "dnsmasq should not contain {absent}: {dnsmasq_conf}"
        );
    }

    // 4. Reverting back to the committed base domain after a partial failure toward a third domain
    //    must still converge partially-migrated apps back cleanly.
    std::fs::remove_file(&hosts_path).unwrap();
    std::fs::create_dir(&hosts_path).unwrap();
    let (third_fail_status, _) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "third.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(third_fail_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "sonarr.third.example"
    );
    std::fs::remove_dir(&hosts_path).unwrap();
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
    let (revert_status, _) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "new.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(revert_status, StatusCode::OK);
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "sonarr.new.example"
    );
    assert_eq!(
        af_db::get_app_ingress_config("sabnzbd")
            .unwrap()
            .unwrap()
            .public_domain,
        "sabnzbd.new.example"
    );
    assert_eq!(
        af_db::get_app_ingress_config("radarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "movies.old.example"
    );

    // 5. Unmanaged Apache: base-domain update still succeeds via apply_ingress_vhost_policy.
    std::fs::remove_dir_all(root.join("etc/apache2")).unwrap();
    std::fs::write(root.join("etc/apache2"), "unmanaged apache placeholder").unwrap();
    let (unmanaged_status, _) = Box::pin(send_admin_settings_put(
        &app,
        &token,
        "unmanaged.example",
        "updated-prompt",
    ))
    .await;
    assert_eq!(unmanaged_status, StatusCode::OK);
    assert_eq!(af_db::get_base_domain(), "unmanaged.example");
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "sonarr.unmanaged.example"
    );
    assert_eq!(
        af_db::get_app_ingress_config("radarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "movies.old.example"
    );
    assert_eq!(
        af_db::get_retained_app_ingress_config("lidarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "lidarr.unmanaged.example"
    );
    assert_eq!(
        af_db::get_retained_app_ingress_config("readarr")
            .unwrap()
            .unwrap()
            .public_domain,
        "books.old.example"
    );

    let _ = std::fs::remove_dir_all(root);
}
