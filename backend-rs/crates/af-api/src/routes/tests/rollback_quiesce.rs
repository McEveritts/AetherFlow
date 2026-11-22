use super::*;

#[tokio::test]
async fn test_candidate_receipt_restoration_quiesces_stopped_units_before_restoring_and_restarts_afterward(
) {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-quiesce-order-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_file = temp_dir.join("opt/syncthing/.af-version");
    let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
    std::fs::write(&receipt_file, b"v1.0.0").unwrap();

    // 1. Create snapshot
    let snapshots = vec![(
        receipt_file.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    // 2. Simulate installer having overwritten the receipt to v2.0.0
    std::fs::write(&receipt_file, b"v2.0.0").unwrap();

    let stopped_units = vec!["syncthing.service".to_string()];
    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let receipt_at_stop = std::sync::Arc::new(std::sync::Mutex::new(None));
    let receipt_at_start = std::sync::Arc::new(std::sync::Mutex::new(None));

    let t_clone = timeline.clone();
    let r_stop_clone = receipt_at_stop.clone();
    let r_start_clone = receipt_at_start.clone();
    let receipt_file_clone = receipt_file.clone();

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "syncthing",
        &stopped_units,
        &stopped_units,
        &snapshots,
        false,
        move |unit, action| {
            let t_clone = t_clone.clone();
            let r_stop_clone = r_stop_clone.clone();
            let r_start_clone = r_start_clone.clone();
            let r_file = receipt_file_clone.clone();
            async move {
                let cur_content = std::fs::read_to_string(&r_file).unwrap_or_default();
                t_clone.lock().unwrap().push(format!("{action} {unit}"));
                if action == "stop" {
                    *r_stop_clone.lock().unwrap() = Some(cur_content);
                } else if action == "start" {
                    *r_start_clone.lock().unwrap() = Some(cur_content);
                }
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;

    assert!(restore_err.is_none(), "Receipt restoration should succeed");
    assert!(restart_fails.is_empty(), "Service restart should succeed");

    let events = timeline.lock().unwrap().clone();
    assert_eq!(
        events,
        vec!["stop syncthing.service", "start syncthing.service"],
        "Must stop (quiesce) unit BEFORE restoration, and start unit AFTER restoration"
    );

    // Crucial verification: at time of "stop", the receipt was un-restored (v2.0.0)
    assert_eq!(
        receipt_at_stop.lock().unwrap().as_deref(),
        Some("v2.0.0"),
        "Unit must be stopped BEFORE receipt is restored"
    );

    // At time of "start", the receipt was restored (v1.0.0)
    assert_eq!(
        receipt_at_start.lock().unwrap().as_deref(),
        Some("v1.0.0"),
        "Unit must be started AFTER receipt is restored"
    );

    // Final disk state
    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"v1.0.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_candidate_receipt_quiesce_failure_skips_restoration_and_restart() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-quiesce-fail-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_file = temp_dir.join("opt/syncthing/.af-version");
    let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
    std::fs::write(&receipt_file, b"v2.0.0").unwrap();

    let snapshots = vec![(
        receipt_file.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    let stopped_units = vec!["syncthing.service".to_string()];
    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t_clone = timeline.clone();

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "syncthing",
        &stopped_units,
        &stopped_units,
        &snapshots,
        false,
        move |unit, action| {
            let t_clone = t_clone.clone();
            async move {
                t_clone.lock().unwrap().push(format!("{action} {unit}"));
                if action == "stop" {
                    anyhow::bail!("systemctl stop failed: device or resource busy");
                }
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;

    assert!(
        restore_err.is_some(),
        "Must return error when quiescence fails"
    );
    let err_msg = restore_err.unwrap();
    assert!(
        err_msg.contains("Skipped candidate receipt restoration because service quiescence failed")
    );
    assert_eq!(restart_fails.len(), 1);
    assert!(restart_fails[0].contains("Failed to quiesce unit 'syncthing.service'"));

    let events = timeline.lock().unwrap().clone();
    assert_eq!(
        events,
        vec!["stop syncthing.service"],
        "Must not attempt to start after quiesce failure"
    );

    // Crucial: restore_candidate_receipts must NOT have been called, receipt remains v2.0.0
    assert_eq!(
        std::fs::read(&receipt_file).unwrap(),
        b"v2.0.0",
        "Receipt must NOT be modified when quiescence fails"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_quiesce_and_restore_candidate_receipts_absent_unit_allows_restoration() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-absent-unit-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_file = temp_dir.join("opt/radarr/.af-version");
    let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
    std::fs::write(&receipt_file, b"v2.0.0").unwrap();

    let snapshots = vec![(
        receipt_file.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    let stopped_units = vec!["radarr.service".to_string()];

    // Case 1: Stop fails with not loaded error AND query_status returns "stopped"
    // Receipt restoration should succeed and restore to v1.0.0.
    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
            "radarr",
            &stopped_units,
            &[],
            &snapshots,
            false,
            move |_unit, action| async move {
                if action == "stop" {
                    anyhow::bail!("systemctl stop radarr.service failed: Unit radarr.service not loaded. (exit status: 5)");
                }
                Ok(())
            },
            |_unit| "stopped".to_string(),
        )
        .await;

    assert!(
        restore_err.is_none(),
        "Receipt restoration should succeed when absent unit is confirmed stopped: {restore_err:?}"
    );
    assert!(
        restart_fails.is_empty(),
        "Expected no restart failures: {restart_fails:?}"
    );
    assert_eq!(
        std::fs::read(&receipt_file).unwrap(),
        b"v1.0.0",
        "Receipt must be restored to v1.0.0 when absent unit is quiescent"
    );

    // Reset receipt back to v2.0.0
    std::fs::write(&receipt_file, b"v2.0.0").unwrap();

    // Case 2: Stop fails with not loaded error BUT query_status returns "running"
    // Should fail closed, return error, and leave receipt at v2.0.0.
    let (restore_err_fail, restart_fails_fail) = quiesce_and_restore_candidate_receipts_with(
            "radarr",
            &stopped_units,
            &[],
            &snapshots,
            false,
            move |_unit, action| async move {
                if action == "stop" {
                    anyhow::bail!("systemctl stop radarr.service failed: Unit radarr.service not loaded. (exit status: 5)");
                }
                Ok(())
            },
            |_unit| "running".to_string(),
        )
        .await;

    assert!(
        restore_err_fail.is_some(),
        "Candidate receipt restoration must fail when query_status reports running"
    );
    let err_msg = restore_err_fail.unwrap();
    assert!(
        err_msg.contains("Skipped candidate receipt restoration because service quiescence failed")
    );
    assert_eq!(restart_fails_fail.len(), 1);
    assert!(restart_fails_fail[0].contains("Failed to quiesce unit 'radarr.service'"));

    assert_eq!(
        std::fs::read(&receipt_file).unwrap(),
        b"v2.0.0",
        "Receipt must NOT be modified when service quiescence fails"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_candidate_receipt_restoration_failure_skips_service_restart() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-restore-fail-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Snapshot with invalid path (e.g. root "/") so restore_candidate_receipts fails
    let invalid_path = PathBuf::from("/");
    let snapshots = vec![(invalid_path, None)];

    let stopped_units = vec!["syncthing.service".to_string()];
    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t_clone = timeline.clone();

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "syncthing",
        &stopped_units,
        &stopped_units,
        &snapshots,
        false,
        move |unit, action| {
            let t_clone = t_clone.clone();
            async move {
                t_clone.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;

    assert!(restore_err.is_some(), "Receipt restoration should fail");
    assert_eq!(restart_fails.len(), 1);
    assert_eq!(
        restart_fails[0],
        "Refusing to restart pre-stopped service after receipt restoration failure"
    );

    let events = timeline.lock().unwrap().clone();
    assert_eq!(
        events,
        vec!["stop syncthing.service"],
        "Must stop unit during quiescence, but NEVER start unit when restoration fails"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_quiesce_and_restore_stops_inactive_units_and_restarts_only_active_units() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-quiesce-inactive-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_file = temp_dir.join("opt/syncthing/.af-version");
    let _ = std::fs::create_dir_all(receipt_file.parent().unwrap());
    std::fs::write(&receipt_file, b"v2.0.0").unwrap();

    let snapshots = vec![(
        receipt_file.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    let quiesce_units = vec![
        "syncthing.service".to_string(),
        "syncthing-helper.service".to_string(),
    ];
    let restart_units = vec!["syncthing.service".to_string()];

    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t_clone = timeline.clone();

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "syncthing",
        &quiesce_units,
        &restart_units,
        &snapshots,
        false,
        move |unit, action| {
            let t_clone = t_clone.clone();
            async move {
                t_clone.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;

    assert!(restore_err.is_none());
    assert!(restart_fails.is_empty());

    let events = timeline.lock().unwrap().clone();
    assert!(events.contains(&"stop syncthing.service".to_string()));
    assert!(events.contains(&"stop syncthing-helper.service".to_string()));
    assert!(events.contains(&"start syncthing.service".to_string()));
    assert!(!events.contains(&"start syncthing-helper.service".to_string()));

    assert_eq!(
        events,
        vec![
            "stop syncthing.service".to_string(),
            "stop syncthing-helper.service".to_string(),
            "start syncthing.service".to_string(),
        ]
    );

    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"v1.0.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_quiesce_and_restore_candidate_receipts_quiesces_oneshots_without_restart() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-oneshot-quiesce-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Case 1: recyclarr (has timer recyclarr.timer and oneshot recyclarr)
    let recyclarr_receipt = temp_dir.join("opt/recyclarr/.af-version");
    let _ = std::fs::create_dir_all(recyclarr_receipt.parent().unwrap());
    std::fs::write(&recyclarr_receipt, b"v2.0.0").unwrap();
    let snapshots = vec![(
        recyclarr_receipt.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    *CANDIDATE_QUIESCE_RECORDER.lock().unwrap() = Some(Vec::new());

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts(
        "recyclarr",
        &["recyclarr.timer".to_string()],
        &snapshots,
        false,
    )
    .await;

    assert!(restore_err.is_none());
    assert!(restart_fails.is_empty());
    assert_eq!(std::fs::read(&recyclarr_receipt).unwrap(), b"v1.0.0");

    let recorded = CANDIDATE_QUIESCE_RECORDER
        .lock()
        .unwrap()
        .take()
        .unwrap_or_default();
    // Quiescence must stop both timer and oneshot service, with timer first
    assert!(recorded.contains(&"stop recyclarr.timer".to_string()));
    assert!(recorded.contains(&"stop recyclarr".to_string()));
    let stop_timer_idx = recorded
        .iter()
        .position(|r| r == "stop recyclarr.timer")
        .unwrap();
    let stop_service_idx = recorded.iter().position(|r| r == "stop recyclarr").unwrap();
    assert!(
        stop_timer_idx < stop_service_idx,
        "timer must be stopped before oneshot"
    );
    // Restart must only restart the timer, NEVER the oneshot
    assert!(recorded.contains(&"start recyclarr.timer".to_string()));
    assert!(!recorded.contains(&"start recyclarr".to_string()));

    // Case 2: scrutiny (has scrutiny-collector.timer, scrutiny-collector [oneshot], scrutiny)
    let scrutiny_receipt = temp_dir.join("opt/scrutiny/.af-version");
    let _ = std::fs::create_dir_all(scrutiny_receipt.parent().unwrap());
    std::fs::write(&scrutiny_receipt, b"v2.0.0").unwrap();
    let scrutiny_snapshots = vec![(
        scrutiny_receipt.clone(),
        Some(ReceiptSnapshotEntry::from(b"v1.0.0".to_vec())),
    )];

    *CANDIDATE_QUIESCE_RECORDER.lock().unwrap() = Some(Vec::new());

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts(
        "scrutiny",
        &[
            "scrutiny-collector.timer".to_string(),
            "scrutiny".to_string(),
        ],
        &scrutiny_snapshots,
        false,
    )
    .await;

    assert!(restore_err.is_none());
    assert!(restart_fails.is_empty());
    assert_eq!(std::fs::read(&scrutiny_receipt).unwrap(), b"v1.0.0");

    let recorded = CANDIDATE_QUIESCE_RECORDER
        .lock()
        .unwrap()
        .take()
        .unwrap_or_default();
    // Quiescence must stop scrutiny-collector.timer, scrutiny, and oneshot scrutiny-collector
    assert!(recorded.contains(&"stop scrutiny-collector.timer".to_string()));
    assert!(recorded.contains(&"stop scrutiny-collector".to_string()));
    assert!(recorded.contains(&"stop scrutiny".to_string()));
    let stop_timer_idx = recorded
        .iter()
        .position(|r| r == "stop scrutiny-collector.timer")
        .unwrap();
    let stop_collector_idx = recorded
        .iter()
        .position(|r| r == "stop scrutiny-collector")
        .unwrap();
    assert!(
        stop_timer_idx < stop_collector_idx,
        "timer must be stopped before collector oneshot"
    );
    // Restart must only restart scrutiny and timer, NEVER the oneshot collector
    assert!(recorded.contains(&"start scrutiny-collector.timer".to_string()));
    assert!(recorded.contains(&"start scrutiny".to_string()));
    assert!(!recorded.contains(&"start scrutiny-collector".to_string()));

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_run_package_lifecycle_dispatch_gate_with_quiesces_oneshots_and_excludes_from_restart()
{
    use std::sync::{Arc, Mutex};

    // 1. Recyclarr: pre-stop quiesces timer + oneshot, but stopped_units excludes oneshot
    let recorded_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let control_rec = recorded_controls.clone();

    let (_port, stopped_units, dispatch_res) = run_package_lifecycle_dispatch_gate_with(
        "update",
        "recyclarr",
        0,
        "",
        |_app_id| 0,
        |_app_id| Ok(None),
        |_app_id, _port| 0,
        |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
        |_unit| "running".to_string(),
        move |unit, action| {
            let rec = control_rec.clone();
            async move {
                rec.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_port| async move {
            Err(anyhow::anyhow!(
                "simulated script failure to trigger rollback"
            ))
        },
    )
    .await
    .expect("dispatch gate itself should complete");

    assert!(dispatch_res.is_err());
    // Stopped units must ONLY contain restart-eligible units (timer), excluding oneshot
    assert_eq!(stopped_units, vec!["recyclarr.timer".to_string()]);

    let pre_controls = recorded_controls.lock().unwrap().clone();
    assert!(pre_controls.contains(&"stop recyclarr.timer".to_string()));
    assert!(pre_controls.contains(&"stop recyclarr".to_string()));

    // Rollback quiescence test: quiesce_units gets both from resolve("stop"), restart gets stopped_units
    let rollback_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let rb_rec = rollback_controls.clone();
    let all_quiesce = af_services::resolve_controllable_service_units("recyclarr", "stop");
    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "recyclarr",
        &all_quiesce,
        &stopped_units,
        &[],
        false,
        move |unit, action| {
            let rec = rb_rec.clone();
            async move {
                rec.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;
    assert!(restore_err.is_none());
    assert!(restart_fails.is_empty());

    let rb_events = rollback_controls.lock().unwrap().clone();
    assert!(rb_events.contains(&"stop recyclarr.timer".to_string()));
    assert!(rb_events.contains(&"stop recyclarr".to_string()));
    assert!(rb_events.contains(&"start recyclarr.timer".to_string()));
    assert!(!rb_events.contains(&"start recyclarr".to_string()));

    // 2. Scrutiny: pre-stop quiesces collector timer + collector oneshot + service, excludes collector oneshot from restart
    recorded_controls.lock().unwrap().clear();
    let control_rec = recorded_controls.clone();

    let (_port, stopped_units, dispatch_res) = run_package_lifecycle_dispatch_gate_with(
        "update",
        "scrutiny",
        8080,
        "",
        |_app_id| 8080,
        |_app_id| Ok(None),
        |_app_id, _port| 8080,
        |app_id| af_services::resolve_controllable_service_units(app_id, "stop"),
        |_unit| "running".to_string(),
        move |unit, action| {
            let rec = control_rec.clone();
            async move {
                rec.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_port| async move { Err(anyhow::anyhow!("simulated script failure")) },
    )
    .await
    .expect("dispatch gate should complete");

    assert!(dispatch_res.is_err());
    assert!(!stopped_units.contains(&"scrutiny-collector".to_string()));
    assert!(stopped_units.contains(&"scrutiny-collector.timer".to_string()));
    assert!(stopped_units.contains(&"scrutiny".to_string()));

    let pre_controls = recorded_controls.lock().unwrap().clone();
    assert!(pre_controls.contains(&"stop scrutiny-collector.timer".to_string()));
    assert!(pre_controls.contains(&"stop scrutiny".to_string()));
    assert!(pre_controls.contains(&"stop scrutiny-collector".to_string()));

    // Rollback quiescence test for scrutiny
    let rollback_controls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let rb_rec = rollback_controls.clone();
    let all_quiesce = af_services::resolve_controllable_service_units("scrutiny", "stop");
    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_with(
        "scrutiny",
        &all_quiesce,
        &stopped_units,
        &[],
        false,
        move |unit, action| {
            let rec = rb_rec.clone();
            async move {
                rec.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;
    assert!(restore_err.is_none());
    assert!(restart_fails.is_empty());

    let rb_events = rollback_controls.lock().unwrap().clone();
    assert!(rb_events.contains(&"stop scrutiny-collector.timer".to_string()));
    assert!(rb_events.contains(&"stop scrutiny".to_string()));
    assert!(rb_events.contains(&"stop scrutiny-collector".to_string()));
    assert!(rb_events.contains(&"start scrutiny-collector.timer".to_string()));
    assert!(rb_events.contains(&"start scrutiny".to_string()));
    assert!(!rb_events.contains(&"start scrutiny-collector".to_string()));
}

#[tokio::test]
async fn test_wave22_quiesce_and_restore_runtime_snapshot_restores_binary_and_state() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-w22-rt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let bin_file = temp_dir.join("opt/syncthing/syncthing");
    let state_file = temp_dir.join("var/lib/syncthing/state.txt");
    let receipt_file = temp_dir.join("opt/syncthing/.af-version");

    std::fs::create_dir_all(bin_file.parent().unwrap()).unwrap();
    std::fs::create_dir_all(state_file.parent().unwrap()).unwrap();

    std::fs::write(&bin_file, b"bin-1.22.0").unwrap();
    std::fs::write(&state_file, b"state-1.22.0").unwrap();
    std::fs::write(&receipt_file, b"1.22.0").unwrap();

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    assert!(
        snapshots
            .iter()
            .any(|(p, bytes)| p == &receipt_file && bytes.as_deref() == Some(b"1.22.0")),
        "receipt must be snapshotted"
    );

    // 2. Snapshot package runtime
    let mut env_cfg = af_runner::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        "syncthing",
        &["syncthing.service".to_string()],
        &env_cfg,
        false,
    )
    .expect("Runtime snapshot must capture successfully");

    // 3. Overwrite files to 1.23.4
    std::fs::write(&bin_file, b"bin-1.23.4").unwrap();
    std::fs::write(&state_file, b"state-1.23.4").unwrap();
    std::fs::write(&receipt_file, b"1.23.4").unwrap();

    // 4. Quiesce, restore runtime and receipts, and restart
    let stopped_units = vec!["syncthing.service".to_string()];
    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t_clone = timeline.clone();

    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_and_runtime_with(
        "syncthing",
        &stopped_units,
        &stopped_units,
        &snapshots,
        false,
        Some(&mut rt_snap),
        move |unit, action| {
            let t_clone = t_clone.clone();
            async move {
                t_clone.lock().unwrap().push(format!("{action} {unit}"));
                Ok(())
            }
        },
        |_unit| "running".to_string(),
    )
    .await;

    assert!(
        restore_err.is_none(),
        "Expected no restore error: {restore_err:?}"
    );
    assert!(
        restart_fails.is_empty(),
        "Expected no restart failures: {restart_fails:?}"
    );

    let events = timeline.lock().unwrap().clone();
    assert_eq!(
        events,
        vec!["stop syncthing.service", "start syncthing.service"],
        "Must stop unit before restore, and start unit after restore"
    );

    // 5. Assert disk contents restored to 1.22.0
    assert_eq!(std::fs::read(&bin_file).unwrap(), b"bin-1.22.0");
    assert_eq!(std::fs::read(&state_file).unwrap(), b"state-1.22.0");
    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"1.22.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wave23_configuration_only_failure_triggers_runtime_and_receipt_rollback() {
    // 1. Verify should_rollback_post_certification_failure returns true for Configuration
    assert!(should_rollback_post_certification_failure(
        "update",
        af_services::PackageJobFailure::Configuration
    ));
    assert!(should_rollback_post_certification_failure(
        "install",
        af_services::PackageJobFailure::Configuration
    ));
    assert!(should_rollback_post_certification_failure(
        "reinstall",
        af_services::PackageJobFailure::Configuration
    ));
    assert!(should_rollback_post_certification_failure(
        "update",
        af_services::PackageJobFailure::ServiceRestore
    ));
    assert!(should_rollback_post_certification_failure(
        "update",
        af_services::PackageJobFailure::ConfigurationAndServiceRestore
    ));
    assert!(!should_rollback_post_certification_failure(
        "remove",
        af_services::PackageJobFailure::Configuration
    ));
    assert!(!should_rollback_post_certification_failure(
        "update",
        af_services::PackageJobFailure::Installer
    ));

    // 2. Exercise handle_post_certification_finalization_failure_with with PackageJobFailure::Configuration
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-cfg-rb-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let bin_file = temp_dir.join("opt/sonarr/Sonarr");
    let db_file = temp_dir.join("var/lib/sonarr/sonarr.db");
    let receipt_file = temp_dir.join("opt/sonarr/.af-version");

    std::fs::create_dir_all(bin_file.parent().unwrap()).unwrap();
    std::fs::create_dir_all(db_file.parent().unwrap()).unwrap();

    std::fs::write(&bin_file, b"bin-old").unwrap();
    std::fs::write(&db_file, b"db-old").unwrap();
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();

    let snapshots = snapshot_candidate_receipts("sonarr").unwrap();

    let mut env_cfg = af_runner::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        "sonarr",
        &["sonarr.service".to_string()],
        &env_cfg,
        false,
    )
    .expect("Runtime snapshot must capture");

    // Simulate installer mutating binary, DB, and receipt
    std::fs::write(&bin_file, b"bin-candidate").unwrap();
    std::fs::write(&db_file, b"db-mutated").unwrap();
    std::fs::write(&receipt_file, b"2.0.0\n").unwrap();

    let stopped_units = vec!["sonarr.service".to_string()];
    let timeline = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t_clone = timeline.clone();

    let failure = PackageLifecycleFailure {
        kind: af_services::PackageJobFailure::Configuration,
        message: "Failed to persist ingress configuration".into(),
    };

    let (final_err, receipt_restore_error, restart_failures) =
        handle_post_certification_finalization_failure_with(
            "update",
            failure,
            "sonarr",
            &stopped_units,
            &snapshots,
            false,
            Some(&mut rt_snap),
            move |unit, action| {
                let t_clone = t_clone.clone();
                async move {
                    t_clone.lock().unwrap().push(format!("{action} {unit}"));
                    Ok(())
                }
            },
            |_unit| "running".to_string(),
        )
        .await;

    assert!(
        receipt_restore_error.is_none(),
        "receipt_restore_error should be None: {:?}",
        receipt_restore_error
    );
    assert!(
        restart_failures.is_empty(),
        "restart_failures should be empty: {:?}",
        restart_failures
    );
    assert_eq!(
        final_err.kind,
        af_services::PackageJobFailure::Configuration
    );

    // Verify units quiesced and restarted
    let events = timeline.lock().unwrap().clone();
    assert!(events.contains(&"stop sonarr.service".to_string()));
    assert_eq!(
        events.last().map(|s| s.as_str()),
        Some("start sonarr.service")
    );

    // Verify disk files rolled back
    assert_eq!(std::fs::read(&bin_file).unwrap(), b"bin-old");
    assert_eq!(std::fs::read(&db_file).unwrap(), b"db-old");
    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"1.0.0\n");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wave24_incomplete_rollback_keeps_candidate_receipt() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w24-receipt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_file = temp_dir.join("opt/sonarr/.af-version");
    std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
    std::fs::write(&receipt_file, b"1.0.0").unwrap();
    let snapshots = snapshot_candidate_receipts("sonarr").unwrap();
    std::fs::write(&receipt_file, b"2.0.0").unwrap();

    let units = vec!["sonarr.service".to_string()];
    let (restore_err, restart_fails) = quiesce_and_restore_candidate_receipts_and_runtime_with(
        "sonarr",
        &units,
        &units,
        &snapshots,
        true,
        None,
        |_unit, _action| async { Ok(()) },
        |_unit| "running".to_string(),
    )
    .await;

    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"2.0.0");
    let err = restore_err.expect("incomplete rollback reports skipped receipt restoration");
    assert!(
        err.contains("Skipped candidate receipt restoration after incomplete rollback"),
        "{err}"
    );
    assert!(
        restart_fails.iter().any(
            |f| f.contains("Refusing to restart pre-stopped service after incomplete rollback")
        ),
        "{restart_fails:?}"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_wave24_configuration_restore_error_upgrades_failure_kind() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-w24-kind-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let etc_cfg = temp_dir.join("etc/maintainerr/config");
    std::fs::create_dir_all(etc_cfg.parent().unwrap()).unwrap();
    std::fs::write(&etc_cfg, b"OLD_CFG").unwrap();
    let receipt_file = temp_dir.join("opt/maintainerr/.af-version");
    std::fs::create_dir_all(receipt_file.parent().unwrap()).unwrap();
    std::fs::write(&receipt_file, b"1.0.0").unwrap();

    let snapshots = snapshot_candidate_receipts("maintainerr").unwrap();
    let mut env_cfg = af_runner::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    let mut rt_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        "maintainerr",
        &[],
        &env_cfg,
        false,
    )
    .expect("maintainerr runtime capture");

    std::fs::write(&receipt_file, b"2.0.0").unwrap();
    std::fs::write(&etc_cfg, b"NEW_CFG").unwrap();
    std::fs::remove_dir_all(temp_dir.join("etc")).unwrap();
    std::fs::write(temp_dir.join("etc"), b"blocker").unwrap();

    let failure = PackageLifecycleFailure {
        kind: af_services::PackageJobFailure::Configuration,
        message: "Failed to persist ingress configuration".into(),
    };
    let (final_err, receipt_restore_error, restart_failures) =
        handle_post_certification_finalization_failure_with(
            "update",
            failure,
            "maintainerr",
            &[],
            &snapshots,
            false,
            Some(&mut rt_snap),
            |_unit, _action| async { Ok(()) },
            |_unit| "running".to_string(),
        )
        .await;

    assert!(
        receipt_restore_error.is_some(),
        "runtime restore failure must surface"
    );
    assert!(restart_failures.is_empty(), "{restart_failures:?}");
    assert_eq!(
        final_err.kind,
        af_services::PackageJobFailure::ConfigurationAndServiceRestore
    );
    assert_eq!(std::fs::read(&receipt_file).unwrap(), b"2.0.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_file(temp_dir.join("etc"));
    let _ = std::fs::remove_dir_all(&temp_dir);
}
