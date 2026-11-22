use super::*;

#[tokio::test(flavor = "current_thread")]
async fn test_explicit_target_confirmation_and_stale_error_policy() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();

    let pkg = af_models::Package {
        name: "test-target-pkg".into(),
        label: "Test Target Pkg".into(),
        service_name: "test-target-pkg".into(),
        lock_file: "/install/.test-target-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let rem_pkg = af_models::Package {
        name: "test-remove-pkg".into(),
        label: "Test Remove Pkg".into(),
        service_name: "test-remove-pkg".into(),
        lock_file: "/install/.test-remove-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let reinst_pkg = af_models::Package {
        name: "test-reinstall-pkg".into(),
        label: "Test Reinstall Pkg".into(),
        service_name: "test-reinstall-pkg".into(),
        lock_file: "/install/.test-reinstall-pkg.lock".into(),
        status: "installed".into(),
        ..Default::default()
    };
    let inst_pkg = af_models::Package {
        name: "test-install-pkg".into(),
        label: "Test Install Pkg".into(),
        service_name: "test-install-pkg".into(),
        lock_file: "/install/.test-install-pkg.lock".into(),
        status: "not_installed".into(),
        ..Default::default()
    };
    let readarr_pkg = af_models::Package {
        name: "readarr".into(),
        label: "Readarr".into(),
        service_name: "readarr".into(),
        lock_file: "/install/.readarr.lock".into(),
        status: "installed".into(),
        update_source: "retired".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![
            pkg.clone(),
            rem_pkg.clone(),
            reinst_pkg.clone(),
            inst_pkg.clone(),
            readarr_pkg.clone(),
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

    let update_scripts = root.join("packages/package/update");
    let install_scripts = root.join("packages/package/install");
    let remove_scripts = root.join("packages/package/remove");
    std::fs::create_dir_all(&update_scripts).unwrap();
    std::fs::create_dir_all(&install_scripts).unwrap();
    std::fs::create_dir_all(&remove_scripts).unwrap();
    for id in [
        "test-target-pkg",
        "test-remove-pkg",
        "test-reinstall-pkg",
        "test-install-pkg",
        "readarr",
    ] {
        for dir in [&update_scripts, &install_scripts, &remove_scripts] {
            let script = dir.join(format!("updatepackage-{id}"));
            let _ = std::fs::write(&script, "#!/bin/sh\nexit 0\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
            }
        }
        let inst_script = install_scripts.join(format!("installpackage-{id}"));
        let rem_script = remove_scripts.join(format!("removepackage-{id}"));
        std::fs::write(&inst_script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem_script, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&inst_script, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&rem_script, std::fs::Permissions::from_mode(0o755));
        }
    }

    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::write(root.join("install/.test-target-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.test-remove-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.test-reinstall-pkg.lock"), "installed").unwrap();
    std::fs::write(root.join("install/.readarr.lock"), "installed").unwrap();

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    let admin = progress_test_user("admin", None);
    async fn wait_and_clear_job(pkg_name: &str) {
        for _ in 0..500 {
            let still_active = af_services::package_job_snapshot()
                .map(|snap| snap.active.contains_key(pkg_name))
                .unwrap_or(false);
            if !still_active {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        af_services::clear_package_job_info(pkg_name);
    }

    // 1. Update with explicit target when app_updates row is missing -> 409 Conflict
    let res_missing = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_missing.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    let expected_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &pkg);
    // Seed app_updates with db_latest = "v1.2.0" and last_error non-empty but WITHOUT prior confirmation provenance (checked_at = "", update_available = 0)
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
    }

    // 2a. Update with matching explicit target when app_updates has last_error and NO prior confirmation provenance -> 409 Conflict
    let res_unproven = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unproven.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // Now seed app_updates with proven prior confirmation provenance and subsequent rate limit error
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', 'GitHub rate limit exceeded', ?1)",
                [&expected_source],
            ).unwrap();
    }

    // 2b. Implicit update (no explicit target) when last_error is present -> 409 Conflict
    let res_implicit = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_implicit.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 2c. Update with explicit unconfirmed target ("v9.9.9") when app_updates has db_latest = "v1.2.0" -> 409 Conflict
    let res_mismatch = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v9.9.9".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_mismatch.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 3. Update with explicit target matching previously confirmed db_latest = "v1.2.0" with proven provenance -> succeeds (200)
    let res_matching = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("v1.2.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_matching.status(), StatusCode::OK);
    wait_and_clear_job("test-target-pkg").await;

    // 4. Install, reinstall, and remove still succeed when app_updates has last_error
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-remove-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-reinstall-pkg', 'v1.0.0', 'v2.0.0', 'Upstream repository unreachable')",
                [],
            ).unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, last_error) VALUES ('test-install-pkg', '', '', 'Upstream repository unreachable')",
                [],
            ).unwrap();
    }

    let res_rem = dispatch_package_lifecycle_with_target(
        "test-remove-pkg".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_rem.status(), StatusCode::OK);
    wait_and_clear_job("test-remove-pkg").await;

    let res_reinst = dispatch_package_lifecycle_with_target(
        "test-reinstall-pkg".into(),
        "reinstall",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_reinst.status(), StatusCode::OK);
    wait_and_clear_job("test-reinstall-pkg").await;

    let res_inst = dispatch_package_lifecycle_with_target(
        "test-install-pkg".into(),
        "install",
        "installing",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_inst.status(), StatusCode::OK);
    wait_and_clear_job("test-install-pkg").await;

    // 5. Update with explicit target when last_error is present and update_available = 0 (even with valid checked_at and matching target) -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '2.0.0', '1.0.0', 0, '2026-11-08T10:00:00Z', 'Latest version could not be confirmed: 500', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unavail = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        Some("1.0.0".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unavail.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 6. Update on retired package (readarr) when app_updates is missing -> 409 Conflict
    let res_retired_missing = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_missing.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    let readarr_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &readarr_pkg);
    // 7. Update on retired package (readarr) when app_updates has unconfirmed last_error -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('readarr', '0.4.17.2700', '0.4.18.2805', 0, '2026-11-08T10:00:00Z', 'Upstream repository unreachable', ?1)",
                [&readarr_source],
            ).unwrap();
    }
    let res_retired_err = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_err.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    let res_retired_err_explicit = dispatch_package_lifecycle_with_target(
        "readarr".into(),
        "update",
        "updating",
        false,
        Some("0.4.18.2805".to_string()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_retired_err_explicit.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("readarr");

    // 8. Enforce confirmed provenance & source_key validation on EVERY update path (empty last_error)
    // 8a. Update with empty last_error and valid provenance & source_key -> 200 OK
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_clean_update = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_clean_update.status(), StatusCode::OK);
    wait_and_clear_job("test-target-pkg").await;

    // 8b. action == "update" with empty last_error and empty checked_at -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_empty_checked_at = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_empty_checked_at.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8c. action == "update" with empty last_error and empty/unknown installed_version -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', '', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_empty_installed = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_empty_installed.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'unknown', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unknown_installed = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unknown_installed.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8d. action == "update" with empty last_error and update_available = 0 -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 0, '2026-11-08T10:00:00Z', '', ?1)",
                [&expected_source],
            ).unwrap();
    }
    let res_unavail_no_err = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_unavail_no_err.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    // 8e. action == "update" with legacy empty source_key = '' or mismatched source_key -> 409 Conflict
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', '')",
                [],
            ).unwrap();
    }
    let res_legacy_empty_source = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_legacy_empty_source.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
                "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('test-target-pkg', 'v1.1.0', 'v1.2.0', 1, '2026-11-08T10:00:00Z', '', 'mismatched:source:key')",
                [],
            ).unwrap();
    }
    let res_mismatched_source = dispatch_package_lifecycle_with_target(
        "test-target-pkg".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_mismatched_source.status(), StatusCode::CONFLICT);
    af_services::clear_package_job_info("test-target-pkg");

    drop(connection);
    std::env::set_current_dir(previous_directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_enforces_threadfin_pinned_and_pihole_vendor_target_policies() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);
    std::env::remove_var("AF_THREADFIN_SHA256");
    std::env::remove_var("AF_THREADFIN_VERSION");

    let pihole_pkg = af_models::Package {
        name: "pihole".into(),
        label: "Pi-hole".into(),
        service_name: "pihole-FTL".into(),
        lock_file: "/install/.pihole.lock".into(),
        status: "installed".into(),
        update_source: "vendor".into(),
        ..Default::default()
    };
    let threadfin_pkg = af_models::Package {
        name: "threadfin".into(),
        label: "Threadfin".into(),
        service_name: "threadfin".into(),
        lock_file: "/install/.threadfin.lock".into(),
        status: "installed".into(),
        update_source: "pinned".into(),
        update_package: "1.2.37".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![pihole_pkg.clone(), threadfin_pkg.clone()]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &automation,
        serde_json::json!({
            "pihole": { "update_source": "vendor", "require_download_sha256": true },
            "threadfin": { "update_source": "pinned", "update_package": "1.2.37", "require_download_sha256": true }
        })
        .to_string(),
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    for id in ["pihole", "threadfin"] {
        std::fs::write(root.join(format!("install/.{id}.lock")), "installed\n").unwrap();
        let inst = root.join(format!("packages/package/install/installpackage-{id}"));
        let rem = root.join(format!("packages/package/remove/removepackage-{id}"));
        std::fs::write(&inst, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&rem, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&rem, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        af_services::clear_package_job_info(id);
    }

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let admin = progress_test_user("admin", None);

    // 1. Pi-hole update fails closed with 409 CONFLICT (even with stale DB row or explicit target)
    let res_ph_upd = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "update",
        "updating",
        false,
        Some("6.9".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_upd.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("pihole").is_none());

    // 2. Pi-hole pinned install/reinstall fails closed with 409 CONFLICT
    let res_ph_pin = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "reinstall",
        "reinstalling",
        false,
        Some("6.8".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_pin.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("pihole").is_none());

    // 3. Threadfin mismatched target fails closed on install/reinstall/update with 409 CONFLICT
    let res_tf_bad = dispatch_package_lifecycle_with_target(
        "threadfin".into(),
        "reinstall",
        "reinstalling",
        false,
        Some("1.2.36".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_tf_bad.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("threadfin").is_none());

    // 4. Threadfin confirmed update to pinned 1.2.37 succeeds and records expected_target_version=1.2.37
    let tf_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &threadfin_pkg);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('threadfin', '1.2.36', '1.2.37', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [&tf_source],
        )
        .unwrap();
    }
    let res_tf_ok = dispatch_package_lifecycle_with_target(
        "threadfin".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_tf_ok.status(), StatusCode::OK);
    let tf_job = af_services::get_package_job_info("threadfin").unwrap();
    assert_eq!(tf_job.expected_target_version.as_deref(), Some("1.2.37"));
    af_services::clear_package_job_info("threadfin");

    // 5. Unpinned Pi-hole reinstall is accepted with expected_target_version = None
    let res_ph_ok = dispatch_package_lifecycle_with_target(
        "pihole".into(),
        "reinstall",
        "reinstalling",
        false,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ph_ok.status(), StatusCode::OK);
    let ph_job = af_services::get_package_job_info("pihole").unwrap();
    assert_eq!(ph_job.expected_target_version, None);
    af_services::clear_package_job_info("pihole");

    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "current_thread")]
async fn marketplace_supports_listenarr_prerelease_updates_and_capitalized_receipt_path() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);

    // 1. resolve_candidate_receipt_paths includes /opt/Listenarr/.af-version
    let receipt_candidates =
        super::super::marketplace::resolve_candidate_receipt_paths("listenarr");
    assert!(
        receipt_candidates.contains(&root.join("opt/Listenarr/.af-version")),
        "expected /opt/Listenarr/.af-version in {receipt_candidates:?}"
    );

    let listenarr_pkg = af_models::Package {
        name: "listenarr".into(),
        label: "Listenarr".into(),
        service_name: "listenarr".into(),
        lock_file: "/install/.listenarr.lock".into(),
        status: "installed".into(),
        update_source: "github".into(),
        update_repo: "Listenarrs/Listenarr".into(),
        update_channel: "prerelease".into(),
        version_command: vec!["cat".into(), "/opt/Listenarr/.af-version".into()],
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&vec![listenarr_pkg.clone()]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &automation,
        serde_json::json!({
            "listenarr": {
                "update_source": "github",
                "update_repo": "Listenarrs/Listenarr",
                "update_channel": "prerelease",
                "version_command": ["cat", "/opt/Listenarr/.af-version"],
                "require_download_sha256": true
            }
        })
        .to_string(),
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    std::env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        short_test_socket_path(&format!(
            "afr-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        )),
    );

    std::fs::write(root.join("install/.listenarr.lock"), "installed\n").unwrap();
    let inst = root.join("packages/package/install/installpackage-listenarr");
    let rem = root.join("packages/package/remove/removepackage-listenarr");
    std::fs::write(&inst, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(&rem, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&rem, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    af_services::clear_package_job_info("listenarr");

    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    let admin = progress_test_user("admin", None);

    // 2. Floating non-concrete target fails closed before creating a job
    let res_bad = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "install",
        "installing",
        false,
        Some("canary".into()),
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_bad.status(), StatusCode::BAD_REQUEST);
    assert!(af_services::get_package_job_info("listenarr").is_none());

    // 3. Stale stable-channel app_updates row is rejected with 409 CONFLICT
    let stale_source = "github:https://api.github.com|listenarrs/listenarr|stable";
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('listenarr', '1.10.5-canary', '1.10.6-canary', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [stale_source],
        )
        .unwrap();
    }
    let res_stale = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "update",
        "updating",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_stale.status(), StatusCode::CONFLICT);
    assert!(af_services::get_package_job_info("listenarr").is_none());

    // 4. Confirmed prerelease-channel update dispatches with expected_target_version = 1.10.6-canary
    let expected_source =
        af_services::workers::canonical_update_source_key("https://api.github.com", &listenarr_pkg);
    assert!(
        expected_source.ends_with("|prerelease"),
        "{expected_source}"
    );
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO app_updates (package_name, installed_version, latest_version, update_available, checked_at, last_error, source_key) VALUES ('listenarr', '1.10.5-canary', '1.10.6-canary', 1, '2026-11-21T08:00:00Z', '', ?1)",
            [&expected_source],
        )
        .unwrap();
    }
    let res_ok = dispatch_package_lifecycle_with_target(
        "listenarr".into(),
        "update",
        "updating",
        false,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(res_ok.status(), StatusCode::OK);
    let job = af_services::get_package_job_info("listenarr").unwrap();
    assert_eq!(
        job.expected_target_version.as_deref(),
        Some("1.10.6-canary")
    );
    af_services::clear_package_job_info("listenarr");

    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "current_thread")]
async fn uninstall_purge_addresses_retained_installation_and_refuses_ambiguous_or_unmanaged() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    async fn settle_dispatched_job(response: axum::response::Response, package: &str) {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let job_id = body["job_id"].as_str().unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
            loop {
                if let Some(outcome) = af_services::get_package_job_outcome(package) {
                    if outcome.job_id == job_id {
                        break outcome;
                    }
                }
                interval.tick().await;
            }
        })
        .await
        .expect("dispatched lifecycle job did not finish");
        assert_eq!(outcome.status, "completed", "{outcome:?}");
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    let hosts_file = root.join("etc/hosts");
    std::fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/remove")).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);
    std::env::set_var("AF_HOSTS_FILE", &hosts_file);

    let rclone_pkg = af_models::Package {
        name: "rclone".into(),
        label: "Rclone".into(),
        service_name: "rclone".into(),
        lock_file: "/install/.rclone.lock".into(),
        default_port: 5572,
        status: "installed".into(),
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![rclone_pkg]).unwrap()).unwrap();
    std::fs::write(&automation, "{}").unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);

    let sock_path = short_test_socket_path(&format!(
        "afr-{}.sock",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    let _ = std::fs::remove_file(&sock_path);
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let runner_root = root.clone();
    let fake_runner = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buffer = [0u8; 8192];
            let Ok(count) = stream.read(&mut buffer).await else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let req_text = String::from_utf8_lossy(&buffer[..count]);
            let path = req_text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let body_str = req_text.split("\r\n\r\n").nth(1).unwrap_or("");
            if path == "/v1/package" {
                let delete_data = serde_json::from_str::<serde_json::Value>(body_str)
                    .ok()
                    .and_then(|v| v.get("delete_data").and_then(|b| b.as_bool()))
                    .unwrap_or(false);
                let lock_path = runner_root.join("install/.rclone.lock");
                let retained_path = runner_root.join("install/.rclone.retained");
                if delete_data {
                    let _ = std::fs::remove_file(&retained_path);
                    let _ = std::fs::remove_file(&lock_path);
                } else {
                    let _ = std::fs::write(
                        &retained_path,
                        af_models::format_retained_package_receipt(
                            "rclone",
                            "2026-11-22T00:00:00Z",
                        ),
                    );
                    let _ = std::fs::remove_file(&lock_path);
                }
                let out = "[PROGRESS:100] Package removal completed\n";
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                            out.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            } else if path.ends_with("/v1/self-update/status") {
                let resp = af_models::RunnerResponse {
                    success: true,
                    output: serde_json::json!({
                        "status": "succeeded",
                        "completed": true,
                        "success": true,
                        "job_unit": "",
                        "error": "",
                        "exit_code": null
                    })
                    .to_string(),
                    error: String::new(),
                };
                let body = serde_json::to_string(&resp).unwrap();
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            } else {
                let resp = af_models::RunnerResponse {
                    success: true,
                    output: "ok".to_string(),
                    error: String::new(),
                };
                let body = serde_json::to_string(&resp).unwrap();
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        }
    });

    let remove_script = root.join("packages/package/remove/removepackage-rclone");
    std::fs::write(&remove_script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&remove_script, std::fs::Permissions::from_mode(0o755));
    }
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    // Seed installed rclone receipt
    std::fs::write(root.join("install/.rclone.lock"), b"installed\n").unwrap();
    let admin = progress_test_user("admin", None);

    // 1. Retained remove (delete_data=false) clears .rclone.lock, creates .rclone.retained,
    //    and records retention_state='retained'.
    let retained_res = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        false,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(retained_res.status(), StatusCode::OK);
    settle_dispatched_job(retained_res, "rclone").await;
    assert!(!root.join("install/.rclone.lock").exists());
    assert!(root.join("install/.rclone.retained").is_file());
    {
        let conn = af_db::get_read_conn().unwrap();
        let rec =
            af_runner::af_release::lifecycle::query_package_retention_history(&conn, "rclone")
                .unwrap()
                .expect("retained remove record");
        assert_eq!(
            rec.retention_state,
            af_runner::af_release::lifecycle::RETENTION_STATE_RETAINED
        );
    }

    // 2. Explicit purge (delete_data=true) after retained remove MUST succeed (200 OK),
    //    clear .rclone.retained, and record retention_state='purged'.
    let purge_res = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        true,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(purge_res.status(), StatusCode::OK);
    settle_dispatched_job(purge_res, "rclone").await;
    assert!(!root.join("install/.rclone.retained").exists());
    {
        let conn = af_db::get_read_conn().unwrap();
        let rec =
            af_runner::af_release::lifecycle::query_package_retention_history(&conn, "rclone")
                .unwrap()
                .expect("purged remove record");
        assert_eq!(
            rec.retention_state,
            af_runner::af_release::lifecycle::RETENTION_STATE_PURGED
        );
    }

    // 3. Subsequent purge when neither installed nor retained MUST return 409 PACKAGE_NOT_INSTALLED.
    let second_purge = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        true,
        None,
        admin.clone(),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(second_purge.status(), StatusCode::CONFLICT);
    let second_body = axum::body::to_bytes(second_purge.into_body(), usize::MAX)
        .await
        .unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();
    assert_eq!(
        second_json["code"], "PACKAGE_NOT_INSTALLED",
        "{second_json}"
    );

    // 4. Ambiguous markerless config on disk MUST fail closed with 409 AMBIGUOUS_RETAINED_OWNERSHIP
    //    and preserve the unmanaged file.
    std::fs::create_dir_all(root.join("etc/rclone")).unwrap();
    std::fs::write(
        root.join("etc/rclone/rclone.conf"),
        b"[manual-remote]\ntype = s3\n",
    )
    .unwrap();
    let ambiguous_purge = dispatch_package_lifecycle_with_target(
        "rclone".into(),
        "remove",
        "uninstalling",
        true,
        None,
        admin,
        HeaderMap::new(),
    )
    .await;
    assert_eq!(ambiguous_purge.status(), StatusCode::CONFLICT);
    let amb_body = axum::body::to_bytes(ambiguous_purge.into_body(), usize::MAX)
        .await
        .unwrap();
    let amb_json: serde_json::Value = serde_json::from_slice(&amb_body).unwrap();
    assert_eq!(
        amb_json["code"], "AMBIGUOUS_RETAINED_OWNERSHIP",
        "{amb_json}"
    );
    assert!(
        amb_json["message"]
            .as_str()
            .unwrap_or("")
            .contains("Refusing to purge 'rclone'"),
        "{amb_json}"
    );
    assert_eq!(
        std::fs::read(root.join("etc/rclone/rclone.conf")).unwrap(),
        b"[manual-remote]\ntype = s3\n"
    );

    fake_runner.abort();
    let _ = std::fs::remove_file(&sock_path);
    std::env::set_current_dir(previous_directory).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test(flavor = "current_thread")]
async fn test_api_apt_exact_target_policy_rejects_non_debian_tokens() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let (root, _connection) = lifecycle_status_fixture();
    af_db::init_db().unwrap();
    af_services::workers::ensure_app_updates_columns();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("packages/package/install")).unwrap();
    let install_script = root.join("packages/package/install/installpackage-quassel");
    std::fs::write(&install_script, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&install_script, std::fs::Permissions::from_mode(0o755));
    }

    let quassel_pkg = af_models::Package {
        name: "quassel".into(),
        label: "Quassel Core".into(),
        service_name: "quasselcore".into(),
        lock_file: "/install/.quassel.lock".into(),
        update_source: "apt".into(),
        update_package: "quassel-core".into(),
        default_port: 4242,
        ..Default::default()
    };
    let catalog = root.join("catalog.json");
    let automation = root.join("automation.json");
    std::fs::write(&catalog, serde_json::to_vec(&vec![quassel_pkg]).unwrap()).unwrap();
    std::fs::write(
        &automation,
        r#"{"quassel":{"update_source":"apt","update_package":"quassel-core"}}"#,
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_INSTALL_ROOT", &root);
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    let previous_directory = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    let admin = progress_test_user("admin", None);
    for bad_target in ["v1.2.3", "1.2.*", "deadbeef", "1.2_3", "1.2.3-"] {
        let resp = dispatch_package_lifecycle_with_target(
            "quassel".to_string(),
            "install",
            "installing",
            false,
            Some(bad_target.to_string()),
            admin.clone(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "APT install with non-Debian token {bad_target:?} must return 400 BAD_REQUEST"
        );
    }

    std::env::set_current_dir(previous_directory).unwrap();
    std::env::remove_var("AETHERFLOW_FS_ROOT");
    std::env::remove_var("AETHERFLOW_INSTALL_ROOT");
    std::env::remove_var("AETHERFLOW_PACKAGES_CONFIG");
    std::env::remove_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
    let _ = std::fs::remove_dir_all(&root);
}
