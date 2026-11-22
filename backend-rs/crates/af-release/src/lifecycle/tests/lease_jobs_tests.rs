use super::super::lease::{lease_path, retire_finished_owners};
use super::super::*;
use super::{admission, fixture, insert, state};
use crate::{ReleaseCommand, ReleaseLockGuard};
use rusqlite::Connection;
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn shared_companion_allows_only_matching_owner_not_unrelated_admin() {
    let (root, _, database, conn) = fixture();
    let owner = OwnerLease::create(&database).unwrap();
    insert(&conn, &owner.id);
    conn.execute(
        "UPDATE package_lifecycle_jobs SET service_units='[\"apache2.service\"]'",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,service_units) VALUES ('queued','other','update','updating','now',?1,'[\"apache2.service\"]')", [&owner.id]).unwrap();
    assert!(check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err());
    assert!(check_reservation(&conn, ReservationTarget::Service("apache2"), "", None).is_err());
    assert!(check_reservation(
        &conn,
        ReservationTarget::Service("apache2"),
        "foreign",
        None
    )
    .is_err());
    assert!(check_reservation(&conn, ReservationTarget::System, "job", None).is_err());
    conn.execute(
        "UPDATE package_lifecycle_jobs SET status='unknown' WHERE package_id='queued'",
        [],
    )
    .unwrap();
    assert!(check_reservation(&conn, ReservationTarget::Service("apache2"), "job", None).is_err());
    drop((conn, owner));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn finished_jobs_retire_owner_files_without_changing_receipts() {
    let (root, _, database, mut conn) = fixture();
    let directory = database.with_extension("lifecycle-owners");
    for success in [true, false] {
        for index in 0..64 {
            let job = format!("finished-{success}-{index}");
            let lease = admit_job(&mut conn, "fixture", &job, "update", "now", &[]).unwrap();
            assert!(owner_is_alive(&database, &lease.id).unwrap());
            finish_job(&conn, "fixture", &job, "update", success, "configuration").unwrap();
            let receipt: (String, String, String, String, String) = conn
                .query_row(
                    "SELECT owner_id,job_id,action,status,failure_category FROM package_lifecycle_jobs",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .unwrap();
            assert_eq!(receipt.0, lease.id);
            assert_eq!(receipt.1, job);
            assert_eq!(receipt.2, "update");
            assert_eq!(receipt.3, if success { "completed" } else { "failed" });
            assert_eq!(receipt.4, if success { "" } else { "configuration" });
            assert!(owner_is_alive(&database, &lease.id).unwrap());
            drop(lease);
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        }
    }
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cleanup_preserves_shared_active_owner_and_direct_sql_receipts() {
    let (root, _, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    let owner = lease.id.clone();
    insert(&conn, &owner);
    conn.execute("INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES ('other','other-job','remove','uninstalling','now',?1)", [&owner]).unwrap();
    conn.execute("UPDATE package_lifecycle_jobs SET status='failed',finished_at='finished',failure_category='configuration' WHERE package_id='fixture'", []).unwrap();
    drop(lease);
    assert!(lease_path(&database, &owner).unwrap().exists());
    assert!(!owner_is_alive(&database, &owner).unwrap());
    check_reservation(
        &conn,
        ReservationTarget::Package("other"),
        "other-job",
        Some("remove"),
    )
    .unwrap();
    assert!(check_reservation(
        &conn,
        ReservationTarget::Package("other"),
        "job",
        Some("remove")
    )
    .is_err());
    reconcile_jobs(&conn, &database).unwrap();
    assert!(!lease_path(&database, &owner).unwrap().exists());
    let receipts: Vec<(String, String, String, String, String)> = conn
        .prepare("SELECT package_id,job_id,action,status,owner_id FROM package_lifecycle_jobs ORDER BY package_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        receipts,
        vec![
            (
                "fixture".into(),
                "job".into(),
                "update".into(),
                "failed".into(),
                owner.clone()
            ),
            (
                "other".into(),
                "other-job".into(),
                "remove".into(),
                "interrupted".into(),
                owner
            ),
        ]
    );
    let finished: String = conn
        .query_row(
            "SELECT finished_at FROM package_lifecycle_jobs WHERE package_id='fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(finished, "finished");
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn terminal_cleanup_preserves_live_and_successor_owner_identities() {
    let (root, _, database, mut conn) = fixture();
    let lease = admit_job(&mut conn, "fixture", "first", "update", "now", &[]).unwrap();
    let first_path = lease_path(&database, &lease.id).unwrap();
    finish_job(&conn, "fixture", "first", "update", true, "").unwrap();
    reconcile_jobs(&conn, &database).unwrap();
    assert!(owner_is_alive(&database, &lease.id).unwrap());
    let successor = admit_job(&mut conn, "fixture", "second", "remove", "later", &[]).unwrap();
    let successor_path = lease_path(&database, &successor.id).unwrap();
    assert_ne!(lease.id, successor.id);
    drop(lease);
    assert!(!first_path.exists());
    assert!(owner_is_alive(&database, &successor.id).unwrap());
    for (package, job, action) in [
        ("fixture", "first", "update"),
        ("other", "second", "remove"),
        ("fixture", "second", "update"),
    ] {
        assert!(finish_job(&conn, package, job, action, true, "").is_err());
    }
    let identity: (String, String, String, String) = conn
        .query_row(
            "SELECT job_id,action,status,owner_id FROM package_lifecycle_jobs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        identity,
        (
            "second".into(),
            "remove".into(),
            "uninstalling".into(),
            successor.id.clone()
        )
    );
    drop(successor);
    assert!(successor_path.exists());
    reconcile_jobs(&conn, &database).unwrap();
    assert_eq!(state(&conn), "interrupted");
    assert!(!successor_path.exists());
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn uncommitted_receipts_never_remove_recovery_evidence() {
    let (root, _, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    insert(&conn, &lease.id);
    let path = lease_path(&database, &lease.id).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
    drop(lease);
    retire_finished_owners(&conn, &database).unwrap();
    assert!(path.exists());
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(state(&conn), "updating");
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    reconcile_jobs(&conn, &database).unwrap();
    assert_eq!(state(&conn), "interrupted");
    assert!(path.exists());
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(state(&conn), "updating");
    reconcile_jobs(&conn, &database).unwrap();
    assert_eq!(state(&conn), "interrupted");
    assert!(!path.exists());
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn cleanup_failures_preserve_receipts_and_retry_without_weakening_locks() {
    use std::os::unix::fs::PermissionsExt;

    let (root, _, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    insert(&conn, &lease.id);
    let path = lease_path(&database, &lease.id).unwrap();
    let directory = path.parent().unwrap();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o777)).unwrap();
    finish_job(&conn, "fixture", "job", "update", false, "configuration").unwrap();
    drop(lease);
    assert!(path.exists());
    reconcile_jobs(&conn, &database).unwrap();
    assert!(path.exists());
    assert_eq!(state(&conn), "failed");
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    reconcile_jobs(&conn, &database).unwrap();
    assert!(!path.exists());
    assert_eq!(state(&conn), "failed");
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn link_substitutions_never_unlink_executor_locks_or_owner_evidence() {
    use std::os::unix::fs::{symlink, MetadataExt};

    for hard_link in [false, true] {
        let (root, _, database, conn) = fixture();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        let path = lease_path(&database, &lease.id).unwrap();
        let evidence = root.join("original-owner");
        std::fs::rename(&path, &evidence).unwrap();
        let executor_path = root.join("package-executor.lock");
        let executor = ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).unwrap();
        let executor_identity = executor.file_identity().unwrap();
        let executor_contents = std::fs::read(&executor_path).unwrap();
        if hard_link {
            std::fs::hard_link(&executor_path, &path).unwrap();
        } else {
            symlink(&executor_path, &path).unwrap();
        }
        assert!(owner_is_alive(&database, &lease.id).is_err());
        reconcile_jobs(&conn, &database).unwrap();
        assert_eq!(state(&conn), "updating");
        finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
        drop(lease);
        reconcile_jobs(&conn, &database).unwrap();
        assert!(std::fs::symlink_metadata(&path).is_ok());
        assert!(evidence.exists());
        assert_eq!(std::fs::read(&executor_path).unwrap(), executor_contents);
        let metadata = std::fs::metadata(&executor_path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino()), executor_identity);
        assert!(ReleaseLockGuard::acquire(&executor_path, Duration::ZERO).is_err());
        assert_eq!(state(&conn), "completed");
        drop((conn, executor));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[cfg(unix)]
fn owner_directory_symlink_substitution_is_not_followed_during_cleanup() {
    use std::os::unix::fs::symlink;

    let (root, _, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    insert(&conn, &lease.id);
    finish_job(&conn, "fixture", "job", "update", true, "").unwrap();
    let directory = database.with_extension("lifecycle-owners");
    let saved = root.join("saved-owners");
    let substituted = root.join("unrelated-owners");
    std::fs::create_dir(&substituted).unwrap();
    let sentinel = substituted.join(&lease.id);
    std::fs::write(&sentinel, b"unrelated executor evidence").unwrap();
    std::fs::rename(&directory, &saved).unwrap();
    symlink(&substituted, &directory).unwrap();
    drop(lease);
    reconcile_jobs(&conn, &database).unwrap();
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"unrelated executor evidence"
    );
    assert_eq!(std::fs::read_dir(&saved).unwrap().count(), 1);
    std::fs::remove_file(&directory).unwrap();
    std::fs::rename(&saved, &directory).unwrap();
    reconcile_jobs(&conn, &database).unwrap();
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    assert!(sentinel.exists());
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn live_owner_survives_same_process_reopen_and_dead_owner_is_interrupted() {
    let (root, cfg, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    let path = lease_path(&database, &lease.id).unwrap();
    insert(&conn, &lease.id);
    let replacement_instance = OwnerLease::create(&database).unwrap();
    assert_ne!(replacement_instance.id, lease.id);
    drop(replacement_instance);
    assert!(admission(&cfg).is_err());
    assert_eq!(state(&conn), "updating");
    check_reservation(
        &conn,
        ReservationTarget::Service("fixture.timer"),
        "job",
        None,
    )
    .unwrap();
    assert!(check_reservation(
        &conn,
        ReservationTarget::Package("fixture"),
        "job",
        Some("remove")
    )
    .is_err());
    check_reservation(
        &conn,
        ReservationTarget::Package("other"),
        "",
        Some("remove"),
    )
    .unwrap();
    drop(lease);
    assert!(path.exists());
    admission(&cfg).unwrap();
    assert_eq!(state(&conn), "interrupted");
    assert!(!path.exists());
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn inherited_maintenance_survives_guard_drop_until_child_exits() {
    let (root, cfg, _database, conn) = fixture();
    let path = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
    let guard = ReleaseLockGuard::acquire(&path, Duration::ZERO).unwrap();
    let mut command = Command::new("/bin/cat");
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    guard.preserve_in_child(&mut command).unwrap();
    let mut child = command.spawn().unwrap();
    drop(command);
    drop(guard);
    assert!(admission(&cfg).is_err());
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    admission(&cfg).unwrap();
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_lifecycle_table_preserves_explicit_rollback_admission() {
    use std::io::{Seek, SeekFrom};
    let (root, cfg, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    insert(&conn, &lease.id);
    let page: u64 = conn
        .query_row(
            "SELECT rootpage FROM sqlite_master WHERE name='package_lifecycle_jobs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let size: u64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap();
    drop(conn);
    let mut file = OpenOptions::new().write(true).open(&database).unwrap();
    file.seek(SeekFrom::Start((page - 1) * size)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
    let _guard = ReleaseLockGuard::acquire(lock, Duration::ZERO).unwrap();
    assert!(
        crate::admin::ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Deploy)
            .is_err()
    );
    crate::admin::ensure_no_active_package_lifecycle_jobs(&cfg, ReleaseCommand::Rollback).unwrap();
    drop(lease);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_owners_fail_closed_and_runner_lock_prevents_premature_reconciliation() {
    let (root, cfg, database, conn) = fixture();
    let lease = OwnerLease::create(&database).unwrap();
    insert(&conn, &lease.id);
    let lock = crate::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
    let runner = ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
    drop(lease);
    assert!(admission(&cfg).is_err());
    assert_eq!(state(&conn), "updating");
    drop(runner);
    admission(&cfg).unwrap();
    assert_eq!(state(&conn), "interrupted");
    for unknown in ["", "bad-identity", "c37209aa-a27b-4812-b2ae-cbb605d04135"] {
        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='updating',owner_id=?1",
            [unknown],
        )
        .unwrap();
        assert!(admission(&cfg).is_err());
        assert_eq!(state(&conn), "updating");
    }
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery() {
    const WORKER: &str = "AF_OWNER_CRASH_FIXTURE";
    if let Some(database) = std::env::var_os(WORKER) {
        let database = PathBuf::from(database);
        let conn = Connection::open(&database).unwrap();
        let lease = OwnerLease::create(&database).unwrap();
        insert(&conn, &lease.id);
        println!("OWNER_READY");
        std::io::stdout().flush().unwrap();
        let mut release = [0u8];
        std::io::stdin().read_exact(&mut release).unwrap();
        drop(lease);
        return;
    }
    let (root, cfg, database, conn) = fixture();
    std::fs::create_dir_all(&cfg.releases_dir).unwrap();
    let recovery = cfg.releases_dir.join(".recovery_state.json");
    std::fs::write(&recovery, b"release-recovery-sentinel").unwrap();
    let test_name = format!(
        "{}::standalone_recovers_crashed_api_without_starting_api_or_erasing_release_recovery",
        module_path!()
            .strip_prefix("af_release::")
            .unwrap_or(module_path!())
    );
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(WORKER, &database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        if line.contains("OWNER_READY") {
            break;
        }
    }
    assert!(admission(&cfg).is_err());
    let owner: String = conn
        .query_row("SELECT owner_id FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    let path = lease_path(&database, &owner).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(path.exists());
    assert!(!owner_is_alive(&database, &owner).unwrap());
    admission(&cfg).unwrap();
    assert_eq!(state(&conn), "interrupted");
    assert!(!path.exists());
    assert_eq!(
        std::fs::read(&recovery).unwrap(),
        b"release-recovery-sentinel"
    );
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_package_lifecycle_history_and_diagnostics() {
    let (root, _, _database, mut conn) = fixture();
    let lease = admit_job_with_target(
        &mut conn,
        "radarr",
        "job-history-1",
        "update",
        "2026-11-08T12:00:00Z",
        &[],
        Some("5.3.6"),
    )
    .unwrap();

    finish_job_with_diagnostics(
        &conn,
        "radarr",
        "job-history-1",
        "update",
        false,
        LifecycleJobDiagnostics {
            failure_category: "target_verification",
            failed_stage: Some("target_verification"),
            exit_code: Some(1),
            sanitized_summary: Some("version did not advance"),
            expected_target_version: Some("5.3.6"),
            achieved_version: Some("5.3.5"),
            ..Default::default()
        },
    )
    .unwrap();

    let history = get_lifecycle_history(&conn, "radarr", 10).unwrap();
    assert_eq!(history.len(), 1);
    let item = &history[0];
    assert_eq!(item.job_id, "job-history-1");
    assert_eq!(item.status, "failed");
    assert_eq!(item.expected_target_version.as_deref(), Some("5.3.6"));
    assert_eq!(item.achieved_version.as_deref(), Some("5.3.5"));
    assert_eq!(item.failed_stage.as_deref(), Some("target_verification"));
    assert_eq!(item.exit_code, Some(1));

    // Start a second job
    let lease2 = admit_job_with_target(
        &mut conn,
        "radarr",
        "job-history-2",
        "update",
        "2026-11-08T12:05:00Z",
        &[],
        Some("5.3.6"),
    )
    .unwrap();

    finish_job_with_diagnostics(
        &conn,
        "radarr",
        "job-history-2",
        "update",
        true,
        LifecycleJobDiagnostics {
            exit_code: Some(0),
            expected_target_version: Some("5.3.6"),
            achieved_version: Some("5.3.6"),
            ..Default::default()
        },
    )
    .unwrap();

    let history_updated = get_lifecycle_history(&conn, "radarr", 10).unwrap();
    assert_eq!(history_updated.len(), 2);
    assert_eq!(history_updated[0].job_id, "job-history-2");
    assert_eq!(history_updated[0].status, "completed");
    assert_eq!(
        history_updated[0].achieved_version.as_deref(),
        Some("5.3.6")
    );
    assert_eq!(history_updated[1].job_id, "job-history-1");

    drop(lease);
    drop(lease2);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn test_finish_job_inserts_history_if_0_rows_updated() {
    let (root, _, _database, mut conn) = fixture();
    let lease = admit_job_with_target(
        &mut conn,
        "prowlarr",
        "job-zero-row-1",
        "update",
        "2026-11-08T12:00:00Z",
        &[],
        Some("1.0.0"),
    )
    .unwrap();

    // Delete history row to simulate 0-row update
    conn.execute(
        "DELETE FROM package_lifecycle_history WHERE job_id='job-zero-row-1'",
        [],
    )
    .unwrap();

    // Finish should insert new history row
    finish_job_with_diagnostics(
        &conn,
        "prowlarr",
        "job-zero-row-1",
        "update",
        true,
        LifecycleJobDiagnostics {
            exit_code: Some(0),
            expected_target_version: Some("1.0.0"),
            achieved_version: Some("1.0.0"),
            ..Default::default()
        },
    )
    .unwrap();

    let history = get_lifecycle_history(&conn, "prowlarr", 10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].job_id, "job-zero-row-1");
    assert_eq!(history[0].status, "completed");

    drop(lease);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_state_persistence_invariants_and_reset_on_readmit_or_interrupt() {
    assert_eq!(
        normalize_recovery_state(
            false,
            "reinstall",
            "installer",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        RECOVERY_STATE_PRIOR_VERIFIED
    );
    assert_eq!(
        normalize_recovery_state(
            false,
            "update",
            "target_verification",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        RECOVERY_STATE_PRIOR_VERIFIED
    );
    assert_eq!(
        normalize_recovery_state(
            false,
            "install",
            "installer",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        RECOVERY_STATE_PRIOR_VERIFIED
    );
    // Never allowed for completed, remove, retention, interrupted, or arbitrary values.
    assert_eq!(
        normalize_recovery_state(true, "reinstall", "", Some(RECOVERY_STATE_PRIOR_VERIFIED)),
        ""
    );
    assert_eq!(
        normalize_recovery_state(
            false,
            "remove",
            "installer",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        ""
    );
    assert_eq!(
        normalize_recovery_state(
            false,
            "reinstall",
            "retention",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        ""
    );
    assert_eq!(
        normalize_recovery_state(
            false,
            "reinstall",
            "interrupted",
            Some(RECOVERY_STATE_PRIOR_VERIFIED)
        ),
        ""
    );
    assert_eq!(
        normalize_recovery_state(false, "reinstall", "installer", Some("partial")),
        ""
    );
    assert_eq!(
        normalize_recovery_state(false, "update", "installer", None),
        RECOVERY_STATE_UNVERIFIED
    );

    let root = std::env::temp_dir().join(format!("af-recovery-inv-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("aetherflow.sqlite");
    let mut conn = Connection::open(&db).unwrap();
    initialize_schema(&conn).unwrap();

    let lease1 = admit_job(
        &mut conn,
        "syncthing",
        "job-1",
        "reinstall",
        "t1",
        &["syncthing".into()],
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "syncthing",
        "job-1",
        "reinstall",
        false,
        LifecycleJobDiagnostics {
            failure_category: "installer",
            recovery_state: Some(RECOVERY_STATE_PRIOR_VERIFIED),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease1);

    let (status, rec): (String, String) = conn
        .query_row(
            "SELECT status, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(rec, RECOVERY_STATE_PRIOR_VERIFIED);
    let hist_rec: String = conn
        .query_row(
            "SELECT recovery_state FROM package_lifecycle_history WHERE job_id='job-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(hist_rec, RECOVERY_STATE_PRIOR_VERIFIED);

    // Re-admitting resets recovery_state to empty and abandoning marks interrupted with empty recovery_state.
    let lease2 = admit_job(
        &mut conn,
        "syncthing",
        "job-2",
        "reinstall",
        "t2",
        &["syncthing".into()],
    )
    .unwrap();
    let active_rec: String = conn
        .query_row(
            "SELECT recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_rec, "");
    drop(lease2);
    reconcile_jobs(&conn, &db).unwrap();
    let (int_status, int_rec): (String, String) = conn
        .query_row(
            "SELECT status, recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(int_status, "interrupted");
    assert_eq!(int_rec, "");

    // Remove failure cannot persist prior_state_verified even if passed.
    let lease3 = admit_job(
        &mut conn,
        "syncthing",
        "job-3",
        "remove",
        "t3",
        &["syncthing".into()],
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "syncthing",
        "job-3",
        "remove",
        false,
        LifecycleJobDiagnostics {
            failure_category: "installer",
            recovery_state: Some(RECOVERY_STATE_PRIOR_VERIFIED),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease3);
    let rm_rec: String = conn
        .query_row(
            "SELECT recovery_state FROM package_lifecycle_jobs WHERE package_id='syncthing'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rm_rec, "");

    drop(conn);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_service_activation_and_companion_ordering_rules() {
    assert!(is_socket_unit("librespeed.socket"));
    assert!(is_activation_unit("librespeed.socket"));
    assert!(is_timer_unit("recyclarr.timer"));
    assert!(is_activation_unit("recyclarr.timer"));
    assert!(!is_activation_unit("librespeed.service"));

    assert!(is_legacy_optional_companion_unit("librespeed.socket"));
    assert!(is_legacy_optional_companion_unit("LIBRESPEED.SOCKET"));
    assert!(is_legacy_optional_companion_unit("novnc-session"));
    assert!(is_legacy_optional_companion_unit("novnc-session.service"));
    assert!(!is_legacy_optional_companion_unit("librespeed.service"));
    assert!(!is_legacy_optional_companion_unit("novnc-xvnc.service"));

    let mut librespeed = vec![
        "librespeed.service".to_string(),
        "librespeed.socket".to_string(),
    ];
    sort_units_for_stop(&mut librespeed);
    assert_eq!(librespeed, vec!["librespeed.socket", "librespeed.service"]);
    assert_eq!(
        ordered_units_for_start(&librespeed),
        vec!["librespeed.socket", "librespeed.service"]
    );

    let mut novnc = vec![
        "novnc-xvnc.service".to_string(),
        "novnc-session.service".to_string(),
        "novnc.service".to_string(),
    ];
    sort_units_for_stop(&mut novnc);
    assert_eq!(
        novnc,
        vec![
            "novnc.service",
            "novnc-session.service",
            "novnc-xvnc.service"
        ]
    );
    assert_eq!(
        ordered_units_for_start(&novnc),
        vec![
            "novnc-xvnc.service",
            "novnc-session.service",
            "novnc.service"
        ]
    );

    let mut mixed = vec![
        "app.service".to_string(),
        "app.timer".to_string(),
        "app.socket".to_string(),
    ];
    sort_units_for_stop(&mut mixed);
    assert_eq!(mixed[2], "app.service");
    assert!(is_activation_unit(&mixed[0]) && is_activation_unit(&mixed[1]));
    assert_eq!(
        ordered_units_for_start(&mixed),
        vec!["app.socket", "app.service", "app.timer"]
    );

    let generic_stopped = vec!["web.service".to_string(), "db.service".to_string()];
    assert_eq!(
        ordered_units_for_start(&generic_stopped),
        vec!["db.service", "web.service"]
    );

    let ls_res = package_resources(
        "librespeed",
        &["librespeed.service".into(), "librespeed.socket".into()],
    );
    assert!(ls_res.contains("librespeed"));
    assert!(ls_res.contains("librespeed.socket"));
    let novnc_res = package_resources(
        "novnc",
        &[
            "novnc.service".into(),
            "novnc-xvnc.service".into(),
            "novnc-session.service".into(),
        ],
    );
    assert!(novnc_res.contains("novnc"));
    assert!(novnc_res.contains("novnc-xvnc"));
    assert!(novnc_res.contains("novnc-session"));
}
#[test]
fn retention_state_persists_survives_failed_purge_and_clears_on_purge_or_reinstall() {
    let root =
        std::env::temp_dir().join(format!("af-lifecycle-retention-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("aetherflow.db");
    let mut conn = Connection::open(&db).unwrap();
    initialize_schema(&conn).unwrap();

    // 1. Retained remove records retention_state='retained'
    let lease1 = admit_job(
        &mut conn,
        "rclone",
        "job-remove-retained",
        "remove",
        "2026-11-22T00:00:01Z",
        &[],
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "rclone",
        "job-remove-retained",
        "remove",
        true,
        LifecycleJobDiagnostics {
            retention_state: Some(RETENTION_STATE_RETAINED),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease1);

    let rec = query_package_retention_history(&conn, "rclone")
        .unwrap()
        .expect("retained removal record");
    assert_eq!(rec.action, "remove");
    assert_eq!(rec.retention_state, RETENTION_STATE_RETAINED);
    assert!(query_retained_lifecycle_packages(&conn)
        .unwrap()
        .contains("rclone"));

    // 2. A subsequent failed purge overwrites package_lifecycle_jobs with status='failed',
    //    but history query still recovers the prior completed retained removal.
    let lease2 = admit_job(
        &mut conn,
        "rclone",
        "job-purge-failed",
        "remove",
        "2026-11-22T00:01:00Z",
        &[],
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "rclone",
        "job-purge-failed",
        "remove",
        false,
        LifecycleJobDiagnostics {
            failure_category: "runtime",
            retention_state: Some(RETENTION_STATE_PURGED),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease2);

    let after_failed = query_package_retention_history(&conn, "rclone")
        .unwrap()
        .expect("prior completed retained removal preserved in history");
    assert_eq!(after_failed.job_id, "job-remove-retained");
    assert_eq!(after_failed.retention_state, RETENTION_STATE_RETAINED);
    assert!(query_retained_lifecycle_packages(&conn)
        .unwrap()
        .contains("rclone"));

    // 3. A successful purge records retention_state='purged'.
    let lease3 = admit_job(
        &mut conn,
        "rclone",
        "job-purge-ok",
        "remove",
        "2026-11-22T00:02:00Z",
        &[],
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "rclone",
        "job-purge-ok",
        "remove",
        true,
        LifecycleJobDiagnostics {
            retention_state: Some(RETENTION_STATE_PURGED),
            ..Default::default()
        },
    )
    .unwrap();
    drop(lease3);

    let after_purge = query_package_retention_history(&conn, "rclone")
        .unwrap()
        .expect("completed purge record");
    assert_eq!(after_purge.job_id, "job-purge-ok");
    assert_eq!(after_purge.retention_state, RETENTION_STATE_PURGED);
    assert!(!query_retained_lifecycle_packages(&conn)
        .unwrap()
        .contains("rclone"));

    // 4. Older schema without retention_state column is tolerated gracefully.
    let legacy_conn = Connection::open_in_memory().unwrap();
    legacy_conn
        .execute_batch(
            "CREATE TABLE package_lifecycle_jobs (
                package_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL
            );
            INSERT INTO package_lifecycle_jobs VALUES ('rclone','old-rm','remove','completed','2026-01-01T00:00:00Z');",
        )
        .unwrap();
    let legacy_rec = query_package_retention_history(&legacy_conn, "rclone")
        .unwrap()
        .expect("legacy remove record");
    assert_eq!(legacy_rec.action, "remove");
    assert_eq!(legacy_rec.retention_state, "");
    assert!(query_retained_lifecycle_packages(&legacy_conn)
        .unwrap()
        .is_empty());

    drop(conn);
    let _ = std::fs::remove_dir_all(root);
}
