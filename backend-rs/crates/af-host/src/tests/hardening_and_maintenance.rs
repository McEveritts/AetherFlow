use super::{create_sample_wal_database, TempTestDir};
use crate::restore::execute_coordinated_restore;
use crate::*;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
#[test]
fn s01_atomic_install_rejects_pre_rename_staging_swap_and_records_unverified_post_rename_fault() {
    let tmp = TempTestDir::new("s01-atomic-install-post-rename");
    let src_file = tmp.path().join("staged_source.txt");
    fs::write(&src_file, b"verified_payload_bytes").unwrap();
    let dest_dir = tmp.path().join("dest");
    fs::create_dir_all(&dest_dir).unwrap();
    let dest_file = dest_dir.join("target.conf");

    let expected_dest = dest_file.clone();
    crate::verify::set_pre_rename_install_hook(Some(Box::new(
        move |dest, parent_dir, temp_name| {
            if dest == expected_dest.as_path() {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                assert_ne!(Some(parent_dir), dest.parent());
                let metadata = fs::metadata(parent_dir).unwrap();
                assert_eq!(metadata.permissions().mode() & 0o077, 0);
                assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
                let temp_path = parent_dir.join(temp_name);
                let rogue_path = parent_dir.join(".rogue_swap_candidate");
                fs::write(&rogue_path, b"rogue_tampered_bytes").unwrap();
                fs::rename(&rogue_path, &temp_path).unwrap();
            }
        },
    )));
    let pre_swap_res = atomic_install_file_at_destination(
        &src_file,
        &dest_file,
        0o600,
        None,
        None,
        "testing S-01 pre-rename staging swap detection",
    );
    crate::verify::set_pre_rename_install_hook(None);
    let pre_swap_err = pre_swap_res.unwrap_err();
    assert!(pre_swap_err.is_security_rejection());
    assert!(!dest_file.exists());

    let host_root = tmp.path().join("host-s01");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=restored_v2\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-120000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=original_v1\n").unwrap();

    let rb_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(1),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(rb_err, HostBackupError::RestoreRolledBack { .. }));
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=original_v1\n"
    );
}

#[test]
fn s02_parent_dir_fsync_failure_after_provenance_rename_preserves_committed_authority_without_rollback(
) {
    let tmp = TempTestDir::new("s02-provenance-parent-sync-boundary");
    let host_root = tmp.path().join("host-s02");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=committed_authority\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-121000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=stale_before_restore\n").unwrap();

    let sync_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_provenance_parent_sync_on_commit: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(!matches!(
        sync_err,
        HostBackupError::RestoreRolledBack { .. }
    ));
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=committed_authority\n"
    );

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=committed_authority\n"
    );
}

#[cfg(unix)]
#[test]
fn s03_s04_s08_shared_runtime_lock_interoperability_and_strict_root_lock_parent_guard() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let tmp = TempTestDir::new("s03-s04-s08-lock-interop");
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let default_resolved =
        resolve_maintenance_lock_path(Some(Path::new("/var/lib/aetherflow/backups")));
    assert_eq!(
        default_resolved,
        PathBuf::from("/run/aetherflow/.snapshot.lock")
    );

    let sticky_parent = tmp.path().join("run/aetherflow");
    fs::create_dir_all(&sticky_parent).unwrap();
    fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1770)).unwrap();
    let sticky_lock = sticky_parent.join(".snapshot.lock");
    let guard =
        HostMaintenanceLockGuard::acquire(&sticky_lock, Duration::from_millis(100)).unwrap();
    guard.verify_still_active().unwrap();
    drop(guard);

    if euid == 0 {
        let group_writable_non_sticky = tmp.path().join("group-writable-non-sticky");
        fs::create_dir_all(&group_writable_non_sticky).unwrap();
        let c_gw = std::ffi::CString::new(group_writable_non_sticky.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c_gw.as_ptr(), 0, 65534) }, 0);
        fs::set_permissions(
            &group_writable_non_sticky,
            fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        let bad_lock_path = group_writable_non_sticky.join(".snapshot.lock");
        let gw_err = HostMaintenanceLockGuard::acquire(&bad_lock_path, Duration::from_millis(100))
            .unwrap_err();
        assert!(gw_err.is_security_rejection());

        let service_owned_var_lib = tmp.path().join("service-owned-var-lib");
        fs::create_dir_all(&service_owned_var_lib).unwrap();
        fs::set_permissions(&service_owned_var_lib, fs::Permissions::from_mode(0o700)).unwrap();
        let c_var_lib = std::ffi::CString::new(service_owned_var_lib.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c_var_lib.as_ptr(), 65534, 65534) }, 0);

        let rejected_root_lock = service_owned_var_lib.join(".snapshot.lock");
        let root_reject_err =
            HostMaintenanceLockGuard::acquire(&rejected_root_lock, Duration::from_millis(100))
                .unwrap_err();
        assert!(root_reject_err.is_security_rejection());

        let nested_root_under_service = service_owned_var_lib.join("locks/.snapshot.lock");
        let nested_reject_err = HostMaintenanceLockGuard::acquire(
            nested_root_lock_under_service(&nested_root_under_service),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(nested_reject_err.is_security_rejection());

        let shared_run = tmp.path().join("shared-run/aetherflow");
        fs::create_dir_all(&shared_run).unwrap();
        let c_shared_run = std::ffi::CString::new(shared_run.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c_shared_run.as_ptr(), 0, 65534) }, 0);
        fs::set_permissions(&shared_run, fs::Permissions::from_mode(0o1770)).unwrap();

        let shared_lock_file = shared_run.join(".snapshot.lock");
        let c_lock = std::ffi::CString::new(shared_lock_file.to_str().unwrap()).unwrap();
        let fd = unsafe {
            libc::open(
                c_lock.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o660,
            )
        };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::fchown(fd, 65534, 65534) }, 0);
        assert_eq!(unsafe { libc::fchmod(fd, 0o660) }, 0);
        unsafe {
            libc::close(fd);
        }

        std::env::set_var("AETHERFLOW_SERVICE_UID", "65534");
        std::env::set_var("AETHERFLOW_SERVICE_GID", "65534");
        let root_guard_res =
            HostMaintenanceLockGuard::acquire(&shared_lock_file, Duration::from_millis(100));
        std::env::remove_var("AETHERFLOW_SERVICE_UID");
        std::env::remove_var("AETHERFLOW_SERVICE_GID");
        let root_guard = root_guard_res.unwrap();
        root_guard.verify_still_active().unwrap();
        let lock_meta = fs::symlink_metadata(&shared_lock_file).unwrap();
        assert_eq!(lock_meta.uid(), 0);
        assert_eq!(lock_meta.gid(), 65534);
        assert_eq!(lock_meta.permissions().mode() & 0o777, 0o660);
        drop(root_guard);
    } else if egid != 0 {
        let s08_dir = tmp.path().join("s08-nonroot-zero-gid");
        fs::create_dir_all(&s08_dir).unwrap();
        fs::set_permissions(&s08_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let s08_lock = s08_dir.join(".snapshot.lock");
        fs::write(&s08_lock, b"pid=1\n").unwrap();
        fs::set_permissions(&s08_lock, fs::Permissions::from_mode(0o660)).unwrap();

        std::env::set_var("AETHERFLOW_SERVICE_UID", euid.to_string());
        std::env::set_var("AETHERFLOW_SERVICE_GID", "0");
        let zero_gid_res = HostMaintenanceLockGuard::acquire(&s08_lock, Duration::from_millis(100));
        std::env::remove_var("AETHERFLOW_SERVICE_UID");
        std::env::remove_var("AETHERFLOW_SERVICE_GID");
        assert!(zero_gid_res.is_err());
    }
}

fn nested_root_lock_under_service(lock_path: &Path) -> PathBuf {
    if let Some(parent_dir) = lock_path.parent() {
        let _ = fs::create_dir_all(parent_dir);
    }
    lock_path.to_path_buf()
}

#[cfg(unix)]
#[test]
fn s05_sqlite_snapshot_detects_connection_specific_inode_swap_despite_held_guard_fd() {
    let tmp = TempTestDir::new("s05-sqlite-conn-fd-binding");
    let db_dir = tmp.path().join("db");
    fs::create_dir_all(&db_dir).unwrap();
    let live_db = db_dir.join("aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let existing_conn = Connection::open(&live_db).unwrap();
    let _: i64 = existing_conn
        .query_row("PRAGMA schema_version;", [], |row| row.get(0))
        .unwrap();

    let decoy_db = db_dir.join("decoy.sqlite");
    create_sample_wal_database(&decoy_db);

    let expected_source_db = live_db.clone();
    crate::snapshot::set_pre_sqlite_connect_hook(Some(Box::new(move |source_db_path| {
        if source_db_path == expected_source_db.as_path() {
            let parent_dir = source_db_path.parent().unwrap();
            let swapped_db = parent_dir.join("decoy.sqlite");
            fs::rename(&swapped_db, source_db_path).unwrap();
        }
    })));
    let snap_dest = tmp.path().join("out/snap.sqlite");
    let swap_res = snapshot_sqlite_database(
        &live_db,
        &snap_dest,
        "snap.sqlite",
        &SnapshotOptions::default(),
    );
    crate::snapshot::set_pre_sqlite_connect_hook(None);
    drop(existing_conn);
    let swap_err = swap_res.unwrap_err();
    assert!(swap_err.is_security_rejection());
    assert!(!snap_dest.exists());
}

#[cfg(unix)]
#[test]
fn sqlite_connection_substitution_is_rejected_after_original_name_is_restored() {
    let temporary = TempTestDir::new("sqlite-restored-name-substitution");
    let database = temporary.path().join("live.sqlite");
    let substitute = temporary.path().join("substitute.sqlite");
    let saved = temporary.path().join("saved.sqlite");
    for (path, marker) in [(&database, "original"), (&substitute, "substitute")] {
        let connection = Connection::open(path).unwrap();
        connection
            .execute("CREATE TABLE identity (value TEXT)", [])
            .unwrap();
        connection
            .execute("INSERT INTO identity VALUES (?1)", [marker])
            .unwrap();
    }
    let existing_connection = Connection::open(&database).unwrap();
    existing_connection
        .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .unwrap();
    let expected_database = database.clone();
    let saved_before = saved.clone();
    let substitute_before = substitute.clone();
    crate::snapshot::set_pre_sqlite_connect_hook(Some(Box::new(move |path| {
        if path == expected_database {
            fs::rename(path, &saved_before).unwrap();
            fs::rename(&substitute_before, path).unwrap();
        }
    })));
    let expected_database = database.clone();
    crate::snapshot::set_post_sqlite_connect_hook(Some(Box::new(move |path| {
        if path == expected_database {
            fs::rename(path, &substitute).unwrap();
            fs::rename(&saved, path).unwrap();
        }
    })));
    let destination = temporary.path().join("output/snapshot.sqlite");
    let result = snapshot_sqlite_database(
        &database,
        &destination,
        "snapshot.sqlite",
        &SnapshotOptions::default(),
    );
    crate::snapshot::set_pre_sqlite_connect_hook(None);
    crate::snapshot::set_post_sqlite_connect_hook(None);
    drop(existing_connection);
    assert!(result.unwrap_err().is_security_rejection());
    assert!(!destination.exists());
}

#[test]
fn s06_s10_s11_recovery_cleans_post_commit_sidecars_blocks_partial_restart_and_binds_checkpoint() {
    let tmp = TempTestDir::new("s06-s10-s11-recovery-closure");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_a = etc_af.join("alpha.conf");
    let conf_b = etc_af.join("beta.conf");
    fs::write(&conf_a, b"alpha=restored\n").unwrap();
    fs::write(&conf_b, b"beta=restored\n").unwrap();

    let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    cfg.config_targets = vec![
        HostBackupTargetSpec {
            source_path: conf_a.clone(),
            archive_relative_path: "etc/AetherFlow/alpha.conf".to_string(),
            logical_fhs_path: Some("/etc/AetherFlow/alpha.conf".to_string()),
            required: true,
        },
        HostBackupTargetSpec {
            source_path: conf_b.clone(),
            archive_relative_path: "etc/AetherFlow/beta.conf".to_string(),
            logical_fhs_path: Some("/etc/AetherFlow/beta.conf".to_string()),
            required: true,
        },
    ];
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-123000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_a, b"alpha=pre_crash\n").unwrap();
    fs::write(&conf_b, b"beta=pre_crash\n").unwrap();

    let rb_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-api.service".to_string()],
            fail_after_replacements: Some(1),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    let (rb_dir, failure_journal_path) = match rb_err {
        HostBackupError::RestoreRollbackFailed {
            recovery_dir,
            failure_journal_path,
            ..
        } => (recovery_dir, failure_journal_path),
        other => panic!("expected RestoreRollbackFailed, got {:?}", other),
    };

    let prov_dir = resolve_recovery_provenance_dir(&host_root, None);
    let rb_dir_name = rb_dir.file_name().unwrap().to_str().unwrap();
    let prev_prov_path = prov_dir.join(format!("{}.journal.json.prev", rb_dir_name));
    assert!(prev_prov_path.is_file());
    let (prev_digest, _) = compute_file_sha256(&prev_prov_path).unwrap();
    let local_failure_sidecar = checksum_sidecar_path(&failure_journal_path);
    fs::write(
        &local_failure_sidecar,
        format!("{}  rollback-failure-journal.json\n", prev_digest),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&local_failure_sidecar, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered_s06 = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered_s06, vec![rb_dir]);
    assert_eq!(fs::read_to_string(&conf_a).unwrap(), "alpha=pre_crash\n");

    let legacy_authority_dir = host_root.join("etc/AetherFlow/legacy-authority");
    fs::create_dir_all(&legacy_authority_dir).unwrap();
    let pending_journal = legacy_authority_dir.join(".rollback-restore.pending999.journal.json");
    fs::write(&pending_journal, b"{}").unwrap();

    let deep_dest = host_root.join("etc/AetherFlow/legacy-authority/sub/nested/deep.conf");
    let s10_err = crate::restore::validate_destination_not_provenance(&deep_dest, &host_root, None)
        .unwrap_err();
    assert!(s10_err.is_security_rejection());
    fs::remove_file(&pending_journal).unwrap();

    let s11_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_initial_local_journal_write: true,
            fail_early_cleanup_remove_rb_dir: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    let s11_msg = s11_err.to_string();
    assert!(
        s11_msg.contains("initial recovery journal persistence failed")
            && s11_msg.contains("cleanup of"),
        "expected compound early publication + cleanup failure message, got: {}",
        s11_msg
    );

    let recovered_s11 = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered_s11.len(), 1);
}

#[cfg(unix)]
#[test]
fn s07_s09_relative_path_dirfd_containment_and_archive_custom_sqlite_uid_verification() {
    use std::os::unix::fs::symlink;

    let tmp = TempTestDir::new("s07-s09-rel-path-and-archive-uid");
    let outside_secret = tmp.path().join("outside_secret.txt");
    fs::write(&outside_secret, b"top_secret").unwrap();

    let rel_dir_name = format!(
        ".af-s07-rel-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let rel_base = PathBuf::from(&rel_dir_name);
    if fs::create_dir(&rel_base).is_ok() {
        let rel_sym = rel_base.join("symdir");
        let _ = symlink(tmp.path(), &rel_sym);
        let rel_target = rel_base.join("symdir/outside_secret.txt");
        let rel_err = compute_file_sha256(&rel_target).unwrap_err();
        let _ = fs::remove_dir_all(&rel_base);
        assert!(rel_err.is_security_rejection());
    } else {
        let abs_sym = tmp.path().join("symdir");
        symlink(tmp.path(), &abs_sym).unwrap();
        let abs_err = compute_file_sha256(&abs_sym.join("outside_secret.txt")).unwrap_err();
        assert!(abs_err.is_security_rejection());
    }
}
#[test]
fn sentinel_scan_auth_log_aggregates_ipv4_and_ipv6_and_flags_offenders() {
    let tmp = TempTestDir::new("sentinel-test");
    let log_path = tmp.path().join("auth.log");

    let log_content = "\
Nov  1 04:01:00 host sshd[100]: Failed password for invalid user root from 192.168.1.100 port 45123 ssh2
Nov  1 04:01:02 host sshd[101]: Failed password for invalid user admin from 192.168.1.100 port 45124 ssh2
Nov  1 04:01:05 host sshd[102]: Failed password for root from 192.168.1.100 port 45125 ssh2
Nov  1 04:01:10 host sshd[103]: Invalid user test from 2001:db8::1 port 50000
Nov  1 04:01:12 host sshd[104]: Failed password for test from 2001:db8::1 port 50001
Nov  1 04:01:15 host sshd[105]: Failed password for test from 2001:db8::1 port 50002
Nov  1 04:01:20 host sshd[106]: Failed password for operator from 10.0.0.5 port 40000
Nov  1 04:01:25 host sshd[107]: Accepted publickey for admin from 10.0.0.1 port 38000 ssh2
";
    fs::write(&log_path, log_content).unwrap();

    // Threshold = 3: 192.168.1.100 (3) and 2001:db8::1 (3) meet threshold, 10.0.0.5 (1) does not
    let report = sentinel_scan_auth_log(&log_path, 3).expect("sentinel scan succeeds");
    assert_eq!(report.scanned_lines, 8);
    assert_eq!(report.failed_event_count, 7);
    assert_eq!(report.threshold, 3);
    assert_eq!(report.ip_counts.get("192.168.1.100"), Some(&3));
    assert_eq!(report.ip_counts.get("2001:db8::1"), Some(&3));
    assert_eq!(report.ip_counts.get("10.0.0.5"), Some(&1));
    assert_eq!(
        report.offending_ips,
        vec!["192.168.1.100".to_string(), "2001:db8::1".to_string()]
    );

    // Threshold = 5: none meet threshold
    let report5 = sentinel_scan_auth_log(&log_path, 5).unwrap();
    assert!(report5.offending_ips.is_empty());
}

#[test]
fn clean_system_logs_truncates_oversized_files_safely() {
    let tmp = TempTestDir::new("clean-log");
    let root = tmp.path().join("rootfs");

    let var_log = root.join("var/log");
    let lock_dir = root.join("srv/aetherflow/lock");
    fs::create_dir_all(&var_log).unwrap();
    fs::create_dir_all(&lock_dir).unwrap();

    let big_log = var_log.join("daemon.log");
    let small_log = var_log.join("small.log");
    let lock_log = lock_dir.join("worker.log");

    fs::write(&big_log, vec![b'a'; 10_000]).unwrap();
    fs::write(&small_log, vec![b'b'; 500]).unwrap();
    fs::write(&lock_log, vec![b'c'; 8_000]).unwrap();

    // 1. Dry run with threshold 1000 bytes: identifies big_log and lock_log without modifying disk
    let dry_rep = clean_system_logs(&root, 1000, true).unwrap();
    assert!(dry_rep.dry_run);
    assert_eq!(dry_rep.cleaned_files.len(), 2);
    assert_eq!(dry_rep.total_bytes_freed, 18_000);
    assert_eq!(fs::metadata(&big_log).unwrap().len(), 10_000);
    assert_eq!(fs::metadata(&lock_log).unwrap().len(), 8_000);

    // 2. Live clean: truncates oversized logs to 0 bytes while small_log remains 500 bytes
    let live_rep = clean_system_logs(&root, 1000, false).unwrap();
    assert!(!live_rep.dry_run);
    assert_eq!(live_rep.cleaned_files.len(), 2);
    assert_eq!(fs::metadata(&big_log).unwrap().len(), 0);
    assert_eq!(fs::metadata(&lock_log).unwrap().len(), 0);
    assert_eq!(fs::metadata(&small_log).unwrap().len(), 500);
}

#[test]
fn sysctl_tuning_computes_exact_parameters_and_writes_atomically() {
    let tmp = TempTestDir::new("sysctl-tune");
    let root = tmp.path().join("sysctl-root");

    let settings = compute_sysctl_network_tuning();
    assert_eq!(settings.get("net.core.rmem_max").unwrap(), "67108864");
    assert_eq!(settings.get("net.core.wmem_max").unwrap(), "67108864");
    assert_eq!(
        settings.get("net.ipv4.tcp_rmem").unwrap(),
        "4096 87380 33554432"
    );
    assert_eq!(
        settings.get("net.ipv4.tcp_wmem").unwrap(),
        "4096 65536 33554432"
    );
    assert_eq!(settings.get("net.core.default_qdisc").unwrap(), "fq");
    assert_eq!(
        settings.get("net.ipv4.tcp_congestion_control").unwrap(),
        "bbr"
    );

    // Dry-run mode must not create any file on disk
    let dry_rep = apply_network_tuning(&root, true).expect("dry run succeeds");
    assert!(dry_rep.dry_run);
    assert!(!dry_rep.applied);
    assert!(!dry_rep.config_path.exists());

    // Live mode creates /etc/sysctl.d/99-aetherflow-tune.conf atomically
    let live_rep = apply_network_tuning(&root, false).expect("live tuning succeeds");
    assert!(live_rep.applied);
    assert!(!live_rep.dry_run);
    assert!(!live_rep.sysctl_reloaded);
    assert!(live_rep.config_path.is_file());

    let content = fs::read_to_string(&live_rep.config_path).unwrap();
    assert!(content.contains("net.core.rmem_max = 67108864"));
    assert!(content.contains("net.ipv4.tcp_congestion_control = bbr"));
}

#[test]
fn inspect_home_disk_space_calculates_per_user_usage() {
    let tmp = TempTestDir::new("showspace-test");
    let root = tmp.path().join("rootfs");

    let user1_dir = root.join("home/alice");
    let user2_dir = root.join("home/bob/downloads");
    fs::create_dir_all(&user1_dir).unwrap();
    fs::create_dir_all(&user2_dir).unwrap();

    fs::write(user1_dir.join("test.txt"), vec![b'x'; 2048]).unwrap();
    fs::write(user2_dir.join("data.bin"), vec![b'y'; 4096]).unwrap();

    let entries = inspect_home_disk_space(&root).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].user, "alice");
    assert_eq!(entries[0].bytes, 2048);
    assert_eq!(entries[0].human, "2.0KB");

    assert_eq!(entries[1].user, "bob");
    assert_eq!(entries[1].bytes, 4096);
    assert_eq!(entries[1].human, "4.0KB");
}

#[test]
fn execute_coordinated_restore_safely_extracts_verifies_and_cleans_stale_wal() {
    let tmp = TempTestDir::new("staged-restore");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=replica\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt =
        create_host_archive_backup(&cfg, Some("2026-11-01-restore")).expect("create backup");

    let stage_root = tmp.path().join("staging-restore-target");
    fs::create_dir_all(&stage_root).unwrap();

    // Plant stale -wal and -shm files in the staging target where the database will be restored
    let stale_wal = stage_root.join("var/lib/aetherflow/aetherflow.sqlite-wal");
    let stale_shm = stage_root.join("var/lib/aetherflow/aetherflow.sqlite-shm");
    fs::create_dir_all(stale_wal.parent().unwrap()).unwrap();
    fs::write(&stale_wal, b"stale-wal-bytes-should-be-purged").unwrap();
    fs::write(&stale_shm, b"stale-shm-bytes-should-be-purged").unwrap();

    let opts = RestorePreflightOptions {
        host_app_version: "v4.0.0".to_string(),
        max_supported_sqlite_user_version: Some(50),
        overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
        require_artifact_sidecar: true,
    };

    let restore_receipt =
        execute_coordinated_restore(&receipt.primary_artifact_path, &stage_root, opts)
            .expect("coordinated staged restore succeeds");

    assert!(restore_receipt.sqlite_verified);
    assert_eq!(restore_receipt.backup_id, receipt.manifest.backup_id);
    assert!(!stale_wal.exists(), "stale -wal file must be removed");
    assert!(!stale_shm.exists(), "stale -shm file must be removed");

    // Verify restored SQLite database is valid and readable
    let restored_db = stage_root.join("var/lib/aetherflow/aetherflow.sqlite");
    assert!(restored_db.is_file());
    let (uv, _, ic) = verify_sqlite_snapshot_integrity(&restored_db).unwrap();
    assert_eq!(uv, 42);
    assert_eq!(ic.to_lowercase(), "ok");

    // System root overwrite must fail closed
    let bad_opts = RestorePreflightOptions::default();
    let err_root =
        execute_coordinated_restore(&receipt.primary_artifact_path, Path::new("/"), bad_opts)
            .unwrap_err();
    assert!(err_root.is_security_rejection());
}

#[test]
fn default_host_targets_prioritize_etc_aetherflow_and_omit_v3_php_dashboard() {
    let tmp = TempTestDir::new("v4-backup-targets");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_v4 = host_root.join("etc/aetherflow");
    fs::create_dir_all(&etc_v4).unwrap();
    fs::write(etc_v4.join("aetherflow.env"), b"PORT=8080\n").unwrap();
    fs::write(
        etc_v4.join("release-manager.conf"),
        b"RELEASE_CHANNEL=stable\n",
    )
    .unwrap();

    let targets = default_host_targets_for_root(&host_root, &host_root.join("home/aetherflow"));
    assert_eq!(targets[0].archive_relative_path, "etc/aetherflow");
    assert!(!targets
        .iter()
        .any(|t| t.archive_relative_path.contains("var/www/html/dashboard")));

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-19-v4")).unwrap();
    assert!(receipt
        .manifest
        .entries
        .iter()
        .any(|e| e.relative_path == "etc/aetherflow/aetherflow.env"));
    assert!(receipt
        .manifest
        .entries
        .iter()
        .any(|e| e.relative_path == "etc/aetherflow/release-manager.conf"));

    let stage_root = tmp.path().join("stage");
    fs::create_dir_all(&stage_root).unwrap();
    let restore_receipt = execute_coordinated_restore(
        &receipt.primary_artifact_path,
        &stage_root,
        RestorePreflightOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: Some(50),
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            require_artifact_sidecar: true,
        },
    )
    .unwrap();
    assert!(restore_receipt.sqlite_verified);
    assert!(stage_root.join("etc/aetherflow/aetherflow.env").is_file());
    assert!(stage_root
        .join("etc/aetherflow/release-manager.conf")
        .is_file());
}
