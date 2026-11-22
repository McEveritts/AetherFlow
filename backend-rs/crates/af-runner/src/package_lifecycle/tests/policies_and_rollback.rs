use super::*;

#[tokio::test]
async fn pihole_and_adguardhome_are_mutually_exclusive_on_install_only() {
    let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
    struct FsRootRestore {
        prev: Option<std::ffi::OsString>,
        root: std::path::PathBuf,
    }
    impl Drop for FsRootRestore {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("AETHERFLOW_FS_ROOT", v),
                None => std::env::remove_var("AETHERFLOW_FS_ROOT"),
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    let (root, db_path, conn, _) = fixture();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    let _restore = FsRootRestore {
        prev: prev_fs_root,
        root: root.clone(),
    };
    std::fs::create_dir_all(root.join("install")).unwrap();

    let pihole_pkg = Package {
        name: "pihole".into(),
        label: "Pi-hole".into(),
        lock_file: "/install/.pihole.lock".into(),
        service_name: "pihole-FTL".into(),
        service_type: "systemd".into(),
        default_port: 8089,
        ..Default::default()
    };
    let adguard_pkg = Package {
        name: "adguardhome".into(),
        label: "AdGuard Home".into(),
        lock_file: "/install/.adguardhome.lock".into(),
        service_name: "adguardhome".into(),
        service_type: "systemd".into(),
        default_port: 3080,
        ..Default::default()
    };

    // 1. When AdGuard Home is installed, installing Pi-hole must fail with a :53 conflict error.
    std::fs::write(root.join("install/.adguardhome.lock"), "installed\n").unwrap();
    let err = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "install".into(),
            script_name: "installpackage-pihole".into(),
            ..Default::default()
        },
        pihole_pkg.clone(),
        vec!["pihole-FTL".into()],
    )
    .err()
    .expect("pihole install must be rejected when adguardhome is installed");
    let msg = err.to_string();
    assert!(msg.contains(":53") && msg.contains("AdGuard Home"), "{msg}");

    // Updating/removing already-installed AdGuard Home must still be admitted.
    let upd_adguard = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "adguardhome".into(),
            action: "update".into(),
            script_name: "installpackage-adguardhome".into(),
            expected_target_version: Some("0.107.52".into()),
            ..Default::default()
        },
        adguard_pkg.clone(),
        vec!["adguardhome".into()],
    )
    .unwrap();
    drop(upd_adguard);
    conn.execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();

    let rm_adguard = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "adguardhome".into(),
            action: "remove".into(),
            script_name: "removepackage-adguardhome".into(),
            ..Default::default()
        },
        adguard_pkg.clone(),
        vec!["adguardhome".into()],
    )
    .unwrap();
    drop(rm_adguard);
    conn.execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();

    // 2. Swap: remove AdGuard Home lock, create Pi-hole lock; installing AdGuard Home must fail.
    std::fs::remove_file(root.join("install/.adguardhome.lock")).unwrap();
    std::fs::write(root.join("install/.pihole.lock"), "installed\n").unwrap();
    let err2 = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "adguardhome".into(),
            action: "install".into(),
            script_name: "installpackage-adguardhome".into(),
            ..Default::default()
        },
        adguard_pkg,
        vec!["adguardhome".into()],
    )
    .err()
    .expect("adguardhome install must be rejected when pihole is installed");
    let msg2 = err2.to_string();
    assert!(msg2.contains(":53") && msg2.contains("Pi-hole"), "{msg2}");

    // Updating/removing already-installed Pi-hole must still be admitted.
    let upd_pihole = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "update".into(),
            script_name: "installpackage-pihole".into(),
            expected_target_version: Some("6.0.0".into()),
            ..Default::default()
        },
        pihole_pkg.clone(),
        vec!["pihole-FTL".into()],
    )
    .unwrap();
    drop(upd_pihole);
    conn.execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();

    let rm_pihole = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "remove".into(),
            script_name: "removepackage-pihole".into(),
            ..Default::default()
        },
        pihole_pkg,
        vec!["pihole-FTL".into()],
    )
    .unwrap();
    drop(rm_pihole);
    conn.execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();
}

#[tokio::test]
async fn admit_enforces_threadfin_pinned_and_pihole_vendor_exact_version_policies() {
    let _lock = crate::ENV_TEST_MUTEX.lock().await;
    let (root, db_path, conn, _) = fixture();
    let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("AETHERFLOW_FS_ROOT", v),
                None => std::env::remove_var("AETHERFLOW_FS_ROOT"),
            }
        }
    }
    let _restore = Restore(prev_fs_root);

    let pihole_pkg = crate::get_runner_package_definition_in_root("pihole", Some(&root)).unwrap();
    assert_eq!(pihole_pkg.update_source, "vendor");
    assert!(pihole_pkg.update_repo.is_empty());

    let err_pihole_upd = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "update".into(),
            script_name: "installpackage-pihole".into(),
            expected_target_version: Some("6.9".into()),
            ..Default::default()
        },
        pihole_pkg.clone(),
        vec!["pihole-FTL".into()],
    )
    .err()
    .expect("pihole update must fail closed at admission");
    assert!(
        err_pihole_upd.to_string().contains("vendor installer"),
        "{err_pihole_upd}"
    );

    let err_pihole_pin = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "install".into(),
            script_name: "installpackage-pihole".into(),
            expected_target_version: Some("6.8".into()),
            ..Default::default()
        },
        pihole_pkg.clone(),
        vec!["pihole-FTL".into()],
    )
    .err()
    .expect("pihole pinned install must fail closed at admission");
    assert!(
        err_pihole_pin.to_string().contains("vendor installer"),
        "{err_pihole_pin}"
    );

    let ok_pihole_install = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "pihole".into(),
            action: "install".into(),
            script_name: "installpackage-pihole".into(),
            expected_target_version: None,
            ..Default::default()
        },
        pihole_pkg,
        vec!["pihole-FTL".into()],
    )
    .unwrap();
    drop(ok_pihole_install);
    conn.execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();

    let threadfin_pkg =
        crate::get_runner_package_definition_in_root("threadfin", Some(&root)).unwrap();
    assert_eq!(threadfin_pkg.update_source, "pinned");
    assert_eq!(
        threadfin_pkg.update_package,
        crate::THREADFIN_PINNED_VERSION
    );

    let err_tf_bad = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "threadfin".into(),
            action: "update".into(),
            script_name: "installpackage-threadfin".into(),
            expected_target_version: Some("1.2.36".into()),
            ..Default::default()
        },
        threadfin_pkg.clone(),
        vec!["threadfin".into()],
    )
    .err()
    .expect("threadfin mismatched target must fail closed at admission");
    assert!(
        err_tf_bad.to_string().contains("pinned to version 1.2.37"),
        "{err_tf_bad}"
    );

    let ok_tf_pin = CoordinatedOperation::admit(
        Connection::open(&db_path).unwrap(),
        PackageRunnerRequest {
            package_id: "threadfin".into(),
            action: "update".into(),
            script_name: "installpackage-threadfin".into(),
            expected_target_version: Some("1.2.37".into()),
            ..Default::default()
        },
        threadfin_pkg,
        vec!["threadfin".into()],
    )
    .unwrap();
    drop(ok_tf_pin);
}

#[tokio::test]
async fn failed_reinstall_verified_recovery_vs_incomplete_fresh_and_remove_receipts() {
    let (root, path, conn, mut package) = fixture();
    package.lock_file = "/install/.syncthing.lock".into();
    let lock_path = root.join("install/.syncthing.lock");
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    std::fs::write(&lock_path, "installed\n").unwrap();
    let version_path = root.join("var/lib/syncthing/.af-version");
    std::fs::create_dir_all(version_path.parent().unwrap()).unwrap();
    std::fs::write(&version_path, "1.28.0\n").unwrap();
    let vhost_dir = root.join("etc/apache2/sites-available");
    std::fs::create_dir_all(&vhost_dir).unwrap();
    let vhost_path = vhost_dir.join("aetherflow-ext-syncthing.conf");
    std::fs::write(&vhost_path, "# prior vhost\n").unwrap();

    let read_recovery = |c: &Connection| -> (String, String, String) {
        c.query_row(
            "SELECT status, failure_category, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
    };

    let (sender, _receiver) = mpsc::channel(32);

    // 1. Failed reinstall with complete restoration of runtime/lock/receipt/vhost and service.
    let backend_complete = FakeBackend {
        fail_script: true,
        ..Default::default()
    };
    let mut op1 = CoordinatedOperation::admit(
        conn,
        request("reinstall"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    let r1 = op1.execute(&backend_complete, &sender).await.unwrap();
    assert_eq!(r1.status, "failed");
    assert_eq!(
        read_recovery(&op1.conn),
        (
            "failed".into(),
            "installer".into(),
            lifecycle::RECOVERY_STATE_PRIOR_VERIFIED.into()
        )
    );
    assert!(lock_path.is_file());
    assert_eq!(
        std::fs::read_to_string(&vhost_path).unwrap(),
        "# prior vhost\n"
    );
    drop(op1);

    // 2. Failed reinstall with incomplete rollback must NOT record verified recovery.
    let backend_incomplete = FakeBackend {
        script_error_message: Some("script failed; incomplete rollback: partial files".into()),
        ..Default::default()
    };
    let mut op2 = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("reinstall"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    let r2 = op2.execute(&backend_incomplete, &sender).await.unwrap();
    assert_eq!(r2.status, "failed");
    assert_eq!(read_recovery(&op2.conn).2, "");
    drop(op2);

    // 3. Failed reinstall where service restart fails after rollback must NOT record verified recovery.
    let backend_restore_fail = FakeBackend {
        fail_script: true,
        fail_restore: true,
        ..Default::default()
    };
    let mut op3 = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("reinstall"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    let r3 = op3.execute(&backend_restore_fail, &sender).await.unwrap();
    assert_eq!(r3.status, "failed");
    assert_eq!(read_recovery(&op3.conn).2, "");
    drop(op3);

    // 4. Failed remove must NEVER record verified recovery.
    let mut op4 = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("remove"),
        package.clone(),
        vec!["syncthing".into()],
    )
    .unwrap();
    let r4 = op4.execute(&backend_complete, &sender).await.unwrap();
    assert_eq!(r4.status, "failed");
    assert_eq!(read_recovery(&op4.conn).2, "");
    drop(op4);

    // 5. Failed fresh install (not previously installed) must NEVER record verified recovery.
    std::fs::remove_file(&lock_path).unwrap();
    let mut op5 = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        request("install"),
        package,
        vec!["syncthing".into()],
    )
    .unwrap();
    let r5 = op5.execute(&backend_complete, &sender).await.unwrap();
    assert_eq!(r5.status, "failed");
    assert_eq!(read_recovery(&op5.conn).2, "");
    drop(op5);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn coordinated_remove_persists_retention_state_and_explicit_purge_clears_retained_ingress() {
    let (root, path, conn, mut package) = fixture();
    package.name = "rclone".into();
    package.service_name = "rclone".into();
    package.lock_file = "/install/.rclone.lock".into();
    package.default_port = 5572;
    conn.execute(
        "INSERT INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled, created_at, updated_at)
         VALUES ('rclone', 'rclone.example.test', 1, 5572, 1, '2026-11-22T00:00:00Z', '2026-11-22T00:00:00Z')",
        [],
    )
    .unwrap();
    let (sender, _rx) = mpsc::channel(32);
    let backend = FakeBackend::default();

    // 1. Retained remove (delete_data=false) persists retention_state='retained' and moves
    //    ingress config into retained_app_ingress_configs.
    let mut op_retain = CoordinatedOperation::admit(
        conn,
        PackageRunnerRequest {
            action: "remove".into(),
            package_id: "rclone".into(),
            script_name: "removepackage-rclone".into(),
            delete_data: false,
            ..Default::default()
        },
        package.clone(),
        vec!["rclone".into()],
    )
    .unwrap();
    let rec_retain = op_retain.execute(&backend, &sender).await.unwrap();
    assert_eq!(rec_retain.status, "completed");
    let after_retain = lifecycle::query_package_retention_history(&op_retain.conn, "rclone")
        .unwrap()
        .expect("retained remove record");
    assert_eq!(
        after_retain.retention_state,
        lifecycle::RETENTION_STATE_RETAINED
    );
    let retained_count: i64 = op_retain
        .conn
        .query_row(
            "SELECT COUNT(*) FROM retained_app_ingress_configs WHERE app_name='rclone'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_count, 1);

    let insp = crate::inspect_package_purge_state_with_conn(
        "rclone",
        Some("/install/.rclone.lock"),
        Some(&root),
        Some(&op_retain.conn),
    )
    .unwrap();
    assert_eq!(
        insp.eligibility,
        crate::PackagePurgeEligibility::RetainedProven
    );
    drop(op_retain);

    // 2. Explicit purge (delete_data=true) persists retention_state='purged' and clears
    //    retained_app_ingress_configs, leaving eligibility NotPresent.
    let mut op_purge = CoordinatedOperation::admit(
        Connection::open(&path).unwrap(),
        PackageRunnerRequest {
            action: "remove".into(),
            package_id: "rclone".into(),
            script_name: "removepackage-rclone".into(),
            delete_data: true,
            ..Default::default()
        },
        package,
        vec!["rclone".into()],
    )
    .unwrap();
    let rec_purge = op_purge.execute(&backend, &sender).await.unwrap();
    assert_eq!(rec_purge.status, "completed");
    let after_purge = lifecycle::query_package_retention_history(&op_purge.conn, "rclone")
        .unwrap()
        .expect("purged remove record");
    assert_eq!(
        after_purge.retention_state,
        lifecycle::RETENTION_STATE_PURGED
    );
    let retained_count_after: i64 = op_purge
        .conn
        .query_row(
            "SELECT COUNT(*) FROM retained_app_ingress_configs WHERE app_name='rclone'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_count_after, 0);

    let insp_after = crate::inspect_package_purge_state_with_conn(
        "rclone",
        Some("/install/.rclone.lock"),
        Some(&root),
        Some(&op_purge.conn),
    )
    .unwrap();
    assert_eq!(
        insp_after.eligibility,
        crate::PackagePurgeEligibility::NotPresent
    );
    drop(op_purge);

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn coordinated_rclone_split_port_lifecycle_rollback_inactive_retain_purge_and_concurrency() {
    let role = af_models::RCLONE_RC_API_PORT_ROLE;
    let (root, confined_db, conn, base_pkg) = fixture();
    let mk_pkg = |name: &str, default_port: i32| Package {
        name: name.into(),
        service_name: name.into(),
        lock_file: format!("/install/.{name}.lock"),
        default_port,
        ..base_pkg.clone()
    };
    let mk_req = |pkg: &str, act: &str, app_port: i32, secondary_port: i32, delete_data: bool| {
        let prefix = if act == "remove" {
            "removepackage-"
        } else {
            "installpackage-"
        };
        PackageRunnerRequest {
            action: act.into(),
            package_id: pkg.into(),
            script_name: format!("{prefix}{pkg}"),
            app_port,
            secondary_port,
            delete_data,
            ..Default::default()
        }
    };
    let (rclone_pkg, sonarr_pkg, radarr_pkg) = (
        mk_pkg("rclone", 5572),
        mk_pkg("sonarr", 17455),
        mk_pkg("radarr", 17455),
    );

    let systemd_dir = root.join("etc/systemd/system");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    std::fs::write(
        systemd_dir.join("rclone.service"),
        "[Service]\nExecStart=/opt/AetherFlow/apps/rclone/rclone gui --addr=127.0.0.1:5572 --api-addr=127.0.0.1:17455\n",
    ).unwrap();

    let (sender, _rx) = mpsc::channel(32);
    let backend = FakeBackend::default();

    // 1. Split-port install commits GUI 5572 + RC 17455.
    let mut op = CoordinatedOperation::admit(
        conn,
        mk_req("rclone", "install", 5572, 0, false),
        rclone_pkg.clone(),
        vec!["rclone".into()],
    )
    .unwrap();
    assert_eq!(
        op.execute(&backend, &sender).await.unwrap().status,
        "completed"
    );
    assert_eq!(
        af_db::load_lifecycle_secondary_port(&op.conn, "rclone", role).unwrap(),
        Some(17455)
    );
    drop(op);

    // 2. Sonarr requesting Rclone's active RC port 17455 is rejected at admission.
    assert!(CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("sonarr", "install", 17455, 0, false),
        sonarr_pkg.clone(),
        vec!["sonarr".into()],
    )
    .is_err());

    // 3. Failed reinstall rolls back without overwriting 17455 and releases temp secondary reservation 17499.
    let fail_backend = FakeBackend {
        fail_script: true,
        ..Default::default()
    };
    let mut op_fail = CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("rclone", "reinstall", 5572, 17499, false),
        rclone_pkg.clone(),
        vec!["rclone".into()],
    )
    .unwrap();
    assert_eq!(
        op_fail
            .execute(&fail_backend, &sender)
            .await
            .unwrap()
            .status,
        "failed"
    );
    assert_eq!(
        af_db::load_lifecycle_secondary_port(&op_fail.conn, "rclone", role).unwrap(),
        Some(17455)
    );
    assert!(
        !af_db::list_reserved_ports_excluding(&op_fail.conn, "sonarr")
            .unwrap()
            .contains(&17499)
    );
    drop(op_fail);

    // 4. Inactive retained remove (unit deleted on disk) retains 17455 and blocks other apps.
    std::fs::remove_file(systemd_dir.join("rclone.service")).unwrap();
    let inactive_backend = FakeBackend {
        inactive_after_start: true,
        ..Default::default()
    };
    let mut op_retain = CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("rclone", "remove", 0, 0, false),
        rclone_pkg.clone(),
        vec!["rclone".into()],
    )
    .unwrap();
    assert_eq!(
        op_retain
            .execute(&inactive_backend, &sender)
            .await
            .unwrap()
            .status,
        "completed"
    );
    assert_eq!(
        af_db::load_lifecycle_secondary_port(&op_retain.conn, "rclone", role).unwrap(),
        Some(17455)
    );
    drop(op_retain);

    // 5. Concurrent coordinated installs with colliding default ports skip 17455 and never choose the same port.
    let mut op_sonarr = CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("sonarr", "install", 0, 0, false),
        sonarr_pkg,
        vec!["sonarr".into()],
    )
    .unwrap();
    let mut op_radarr = CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("radarr", "install", 0, 0, false),
        radarr_pkg,
        vec!["radarr".into()],
    )
    .unwrap();
    let (sonarr_res, radarr_res) = tokio::join!(
        op_sonarr.execute(&backend, &sender),
        op_radarr.execute(&backend, &sender),
    );
    let (sonarr_port, radarr_port) = (sonarr_res.unwrap().app_port, radarr_res.unwrap().app_port);
    assert_ne!(sonarr_port, 17455);
    assert_ne!(radarr_port, 17455);
    assert_ne!(
        sonarr_port, radarr_port,
        "concurrent coordinated installs must never allocate the same port"
    );
    drop(op_sonarr);
    drop(op_radarr);

    // 6. Explicit purge removes retained secondary port 17455 and releases it.
    let mut op_purge = CoordinatedOperation::admit(
        Connection::open(&confined_db).unwrap(),
        mk_req("rclone", "remove", 0, 0, true),
        rclone_pkg,
        vec!["rclone".into()],
    )
    .unwrap();
    assert_eq!(
        op_purge.execute(&backend, &sender).await.unwrap().status,
        "completed"
    );
    assert_eq!(
        af_db::load_lifecycle_secondary_port(&op_purge.conn, "rclone", role).unwrap(),
        None
    );
    assert!(
        !af_db::list_reserved_ports_excluding(&op_purge.conn, "sonarr")
            .unwrap()
            .contains(&17455)
    );
    drop(op_purge);
    let _ = std::fs::remove_dir_all(root);
}
