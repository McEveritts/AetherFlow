use super::*;
use crate::cluster_daemon::{
    acknowledge_worker_command, enqueue_cluster_command, ensure_cluster_schema,
    lease_next_worker_command, list_cluster_commands, process_worker_heartbeat,
    register_worker_node, route_cluster_http_request, PeerTransportAuth, RegisterWorkerRequest,
    WorkerCommandAckRequest, WorkerHeartbeatRequest,
};
use std::collections::HashMap;

#[cfg(unix)]
#[test]
fn worker_command_restart_between_intent_and_result_reports_unknown_without_replay() {
    let name = "cluster_daemon::receipts::tests::worker_command_restart_between_intent_and_result_reports_unknown_without_replay";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-cluster-dur-1-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("cluster.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    let psk = "durability-master-psk-at-least-32-chars!!";
    env::set_var("CLUSTER_PSK", psk);
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    let reg = register_worker_node(&RegisterWorkerRequest {
        node_id: "node-alpha".to_string(),
        hostname: "alpha".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg.accepted);

    let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
    let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

    // 1. Enqueue non-idempotent service restart and lease generation 1.
    let queued = enqueue_cluster_command("node-alpha", "restart_service", "sonarr").unwrap();
    let first_lease = lease_next_worker_command("node-alpha", 1000, 30).unwrap();
    assert_eq!(first_lease.id, queued.id);
    assert_eq!(first_lease.lease_generation, 1);

    // Worker #1 admits mutation -> persists confined 0600 `Intent` receipt BEFORE mutation runs.
    let worker_1 =
        WorkerCommandCoordinator::load_and_recover("node-alpha", &outbox_path, &receipts_path);
    let plan_1 = worker_1.prepare_command_dispatch(first_lease);
    let mutation = match plan_1 {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("expected Execute plan for unstarted command, got {other:?}"),
    };
    assert_eq!(mutation.service, "sonarr");
    assert_eq!(mutation.action, "restart");

    let receipts_mode = std::fs::symlink_metadata(&receipts_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(receipts_mode, 0o600);
    let on_disk = load_worker_command_receipts_strict(&receipts_path).unwrap();
    assert_eq!(on_disk.len(), 1);
    assert_eq!(on_disk[0].phase, WorkerCommandReceiptPhase::Intent);
    assert_eq!(on_disk[0].lease_generation, Some(1));

    // Simulate crash/restart BEFORE `complete_admitted_mutation` persists a final outcome.
    drop(worker_1);

    // 2. Restarted worker #2 transitions orphaned `Intent` -> distinct `Unknown` without replay.
    let worker_2 =
        WorkerCommandCoordinator::load_and_recover("node-alpha", &outbox_path, &receipts_path);
    let recovered = load_worker_command_receipts_strict(&receipts_path).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].phase, WorkerCommandReceiptPhase::Unknown);
    assert_eq!(recovered[0].lease_generation, Some(1));
    assert!(recovered[0]
        .result_message
        .as_deref()
        .unwrap_or("")
        .contains("inspect service state before retrying"));

    let pending_before_gen2 = worker_2.pending_acks_snapshot();
    assert_eq!(pending_before_gen2.len(), 1);
    assert_eq!(pending_before_gen2[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
    assert_eq!(pending_before_gen2[0].lease_generation, Some(1));

    // Master lease expires -> lease generation advances to 2 before gen-1 ACK arrives.
    let expired_re_lease = lease_next_worker_command("node-alpha", 1031, 30).unwrap();
    assert_eq!(expired_re_lease.id, queued.id);
    assert_eq!(expired_re_lease.lease_generation, 2);

    // Heartbeat carrying stale gen-1 `unknown` ACK MUST be fenced by master!
    let hb_stale = process_worker_heartbeat(&WorkerHeartbeatRequest {
        node_id: "node-alpha".to_string(),
        hostname: "alpha".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: psk.to_string(),
        timestamp: 1035,
        command_acks: pending_before_gen2,
        ..Default::default()
    })
    .unwrap();
    assert!(hb_stale.confirmed_command_ids.is_empty());

    // Worker #2 observes fresh lease_generation=2 -> reattaches durable `unknown` WITHOUT rerunning!
    let plan_2 = worker_2.prepare_command_dispatch(expired_re_lease);
    let reattached_ack = match plan_2 {
        WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
        other => panic!("expected SendAckOnly reattachment of unknown receipt, got {other:?}"),
    };
    assert_eq!(reattached_ack.id, queued.id);
    assert_eq!(reattached_ack.status, WORKER_COMMAND_STATUS_UNKNOWN);
    assert_eq!(reattached_ack.lease_generation, Some(2));

    // Reattached generation=2 ACK is persisted before delivery and commits `unknown` on master.
    assert_eq!(
        load_worker_ack_outbox_nofollow(&outbox_path)[0].lease_generation,
        Some(2)
    );
    let hb_commit = process_worker_heartbeat(&WorkerHeartbeatRequest {
        node_id: "node-alpha".to_string(),
        hostname: "alpha".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: psk.to_string(),
        timestamp: 1040,
        command_acks: worker_2.pending_acks_snapshot(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(hb_commit.confirmed_command_ids, vec![queued.id.clone()]);
    assert!(hb_commit.command.is_none());
    worker_2.mark_confirmed(&hb_commit.confirmed_command_ids);
    assert!(load_worker_ack_outbox_nofollow(&outbox_path).is_empty());

    let listed = list_cluster_commands(Some("node-alpha"), 10).unwrap();
    assert_eq!(listed[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
    assert_eq!(listed[0].lease_generation, 2);
    assert!(listed[0]
        .result_message
        .as_deref()
        .unwrap_or("")
        .contains("inspect service state"));
    assert!(lease_next_worker_command("node-alpha", 2000, 30).is_none());

    // 3. Normal retry semantics for a genuinely unstarted command (lease 1 lost on wire).
    let unstarted = enqueue_cluster_command("node-alpha", "restart_service", "radarr").unwrap();
    let lost_gen1 = lease_next_worker_command("node-alpha", 2010, 30).unwrap();
    assert_eq!(lost_gen1.lease_generation, 1);
    let gen2 = lease_next_worker_command("node-alpha", 2045, 30).unwrap();
    assert_eq!(gen2.id, unstarted.id);
    assert_eq!(gen2.lease_generation, 2);

    let unstarted_mutation = match worker_2.prepare_command_dispatch(gen2) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("genuinely unstarted command must still execute, got {other:?}"),
    };
    let done_ack = worker_2
        .complete_admitted_mutation(&unstarted_mutation, Ok(()))
        .unwrap();
    assert_eq!(done_ack.status, WORKER_COMMAND_STATUS_EXECUTED);
    assert_eq!(done_ack.lease_generation, Some(2));
    assert!(acknowledge_worker_command("node-alpha", &done_ack).unwrap());

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn worker_command_retry_after_lost_ack_and_new_lease_reattaches_without_rerun() {
    let name = "cluster_daemon::receipts::tests::worker_command_retry_after_lost_ack_and_new_lease_reattaches_without_rerun";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }

    let root = env::temp_dir().join(format!("af-cluster-dur-2-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("cluster.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    let psk = "durability-retry-psk-at-least-32-chars!!";
    env::set_var("CLUSTER_PSK", psk);
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    let reg = register_worker_node(&RegisterWorkerRequest {
        node_id: "node-beta".to_string(),
        hostname: "beta".to_string(),
        address: "127.0.0.1:8081".to_string(),
        psk: psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg.accepted);

    let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
    let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

    // 1. Execute once on gen=1, persist completed result before ACK, then lose ACK & re-lease gen=2.
    let cmd_rec = enqueue_cluster_command("node-beta", "restart_service", "plex").unwrap();
    let lease_1 = lease_next_worker_command("node-beta", 3000, 30).unwrap();
    assert_eq!(lease_1.lease_generation, 1);

    let worker =
        WorkerCommandCoordinator::load_and_recover("node-beta", &outbox_path, &receipts_path);
    let mut exec_count = 0usize;
    let mutation = match worker.prepare_command_dispatch(lease_1) {
        WorkerCommandDispatchPlan::Execute(m) => {
            exec_count += 1;
            m
        }
        other => panic!("expected Execute on first delivery, got {other:?}"),
    };
    let ack_gen1 = worker
        .complete_admitted_mutation(&mutation, Ok(()))
        .unwrap();
    assert_eq!(ack_gen1.status, WORKER_COMMAND_STATUS_EXECUTED);
    assert_eq!(ack_gen1.lease_generation, Some(1));
    assert_eq!(load_worker_ack_outbox_nofollow(&outbox_path).len(), 1);
    assert_eq!(
        load_worker_command_receipts_strict(&receipts_path).unwrap()[0].phase,
        WorkerCommandReceiptPhase::Executed
    );

    // ACK response is lost; master lease expires and issues gen=2.
    let lease_2 = lease_next_worker_command("node-beta", 3035, 30).unwrap();
    assert_eq!(lease_2.id, cmd_rec.id);
    assert_eq!(lease_2.lease_generation, 2);

    // Same worker reattaches durable `executed` result to gen=2 WITHOUT rerunning the mutation.
    let ack_gen2 = match worker.prepare_command_dispatch(lease_2) {
        WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
        other => panic!("expected SendAckOnly reattachment on gen=2, got {other:?}"),
    };
    assert_eq!(exec_count, 1, "side effect must not be rerun on new lease");
    assert_eq!(ack_gen2.status, WORKER_COMMAND_STATUS_EXECUTED);
    assert_eq!(ack_gen2.lease_generation, Some(2));
    assert_eq!(
        ack_gen2.result_message.as_deref(),
        Some("restart plex succeeded")
    );

    // Deliver reattached gen=2 ACK via /cluster/v1/commands/ack -> master commits and confirms.
    let ack_req_bytes = serde_json::to_vec(&WorkerCommandAckRequest {
        node_id: "node-beta".to_string(),
        psk: String::new(),
        acks: vec![ack_gen2],
    })
    .unwrap();
    let (code, _, body) = route_cluster_http_request(
        "POST",
        "/cluster/v1/commands/ack",
        "/cluster/v1/commands/ack",
        psk,
        &ack_req_bytes,
        &PeerTransportAuth::InsecureLoopback,
    );
    assert_eq!(code, 200);
    assert_eq!(
        body["confirmed_command_ids"],
        serde_json::json!([cmd_rec.id])
    );
    worker.mark_confirmed(std::slice::from_ref(&cmd_rec.id));
    assert!(load_worker_ack_outbox_nofollow(&outbox_path).is_empty());
    assert!(load_worker_command_receipts_strict(&receipts_path).unwrap()[0].ack_confirmed);

    // 2. Legacy outbox compatibility: restarted worker with ONLY legacy 0600 outbox file
    //    reattaches completed result to freshly observed lease generation without rerunning.
    let legacy_outbox = root.join("legacy/cluster_worker_ack_outbox.json");
    let legacy_receipts = resolve_worker_command_receipts_path(&legacy_outbox);
    let legacy_rec = enqueue_cluster_command("node-beta", "stop_service", "radarr").unwrap();
    let _legacy_gen1 = lease_next_worker_command("node-beta", 3100, 30).unwrap();
    let legacy_gen2 = lease_next_worker_command("node-beta", 3135, 30).unwrap();
    assert_eq!(legacy_gen2.lease_generation, 2);

    persist_worker_ack_outbox_atomic(
        &legacy_outbox,
        &[WorkerCommandAck {
            id: legacy_rec.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("stop radarr succeeded".to_string()),
            lease_generation: Some(1),
        }],
    )
    .unwrap();
    assert!(!legacy_receipts.exists());

    let upgraded_worker = WorkerCommandCoordinator::load_and_recover(
        "node-beta",
        &legacy_outbox,
        &legacy_receipts,
    );
    let reattached_legacy = match upgraded_worker.prepare_command_dispatch(legacy_gen2) {
        WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
        other => panic!("legacy outbox record must reattach without rerun, got {other:?}"),
    };
    assert_eq!(reattached_legacy.id, legacy_rec.id);
    assert_eq!(reattached_legacy.status, WORKER_COMMAND_STATUS_EXECUTED);
    assert_eq!(reattached_legacy.lease_generation, Some(2));
    assert!(acknowledge_worker_command("node-beta", &reattached_legacy).unwrap());

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn worker_command_stale_lease_conflicting_identity_and_confined_storage_guards() {
    let name = "cluster_daemon::receipts::tests::worker_command_stale_lease_conflicting_identity_and_confined_storage_guards";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }

    let root = env::temp_dir().join(format!("af-cluster-dur-3-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("cluster.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    let psk = "durability-fence-psk-at-least-32-chars!!";
    env::set_var("CLUSTER_PSK", psk);
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    for (nid, host, addr) in [
        ("node-gamma", "gamma", "127.0.0.1:8082"),
        ("node-other", "other", "127.0.0.1:8083"),
    ] {
        let reg = register_worker_node(&RegisterWorkerRequest {
            node_id: nid.to_string(),
            hostname: host.to_string(),
            address: addr.to_string(),
            psk: psk.to_string(),
            version: "4.0.0".to_string(),
            system_info: None,
        })
        .unwrap();
        assert!(reg.accepted);
    }

    // 1. Master lease fencing & conflicting node/status rejection.
    let queued = enqueue_cluster_command("node-gamma", "restart_service", "sonarr").unwrap();
    let gen1 = lease_next_worker_command("node-gamma", 4000, 30).unwrap();
    let gen2 = lease_next_worker_command("node-gamma", 4035, 30).unwrap();
    assert_eq!(gen1.lease_generation, 1);
    assert_eq!(gen2.lease_generation, 2);

    assert!(!acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: None,
            lease_generation: Some(0),
        }
    )
    .unwrap());
    assert!(!acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("stale gen 1".to_string()),
            lease_generation: Some(1),
        }
    )
    .unwrap());
    assert!(!acknowledge_worker_command(
        "node-other",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("wrong node".to_string()),
            lease_generation: Some(2),
        }
    )
    .unwrap());
    assert!(acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("restart sonarr succeeded".to_string()),
            lease_generation: Some(2),
        }
    )
    .unwrap());

    // Post-terminal stale lease & conflicting status ACKs must be rejected, while exact duplicate succeeds.
    assert!(!acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: None,
            lease_generation: Some(1),
        }
    )
    .unwrap());
    assert!(!acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_FAILED.to_string(),
            result_message: Some("conflicting outcome".to_string()),
            lease_generation: Some(2),
        }
    )
    .unwrap());
    assert!(acknowledge_worker_command(
        "node-gamma",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("restart sonarr succeeded".to_string()),
            lease_generation: Some(2),
        }
    )
    .unwrap());

    // 2. Worker-side stale lease rejection and conflicting command identity rejection.
    let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
    let receipts_path = resolve_worker_command_receipts_path(&outbox_path);
    let worker =
        WorkerCommandCoordinator::load_and_recover("node-gamma", &outbox_path, &receipts_path);
    let m = match worker.prepare_command_dispatch(gen2.clone()) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("expected Execute on gen=2, got {other:?}"),
    };
    worker.complete_admitted_mutation(&m, Ok(())).unwrap();

    // Stale gen=1 delivery must be rejected without downgrading stored gen=2.
    assert_eq!(
        worker.prepare_command_dispatch(gen1),
        WorkerCommandDispatchPlan::RejectedStaleLease
    );
    assert_eq!(
        load_worker_command_receipts_strict(&receipts_path).unwrap()[0].lease_generation,
        Some(2)
    );

    // Conflicting verb/target under same cmd_id must be rejected without executing or overwriting.
    let mut conflicting_target = gen2.clone();
    conflicting_target.lease_generation = 3;
    conflicting_target
        .params
        .insert("service".to_string(), "radarr".to_string());
    conflicting_target
        .params
        .insert("target".to_string(), "radarr".to_string());
    assert_eq!(
        worker.prepare_command_dispatch(conflicting_target),
        WorkerCommandDispatchPlan::RejectedConflictingIdentity
    );

    let mut conflicting_verb = gen2.clone();
    conflicting_verb.lease_generation = 3;
    conflicting_verb.cmd_type = "stop_service".to_string();
    assert_eq!(
        worker.prepare_command_dispatch(conflicting_verb),
        WorkerCommandDispatchPlan::RejectedConflictingIdentity
    );

    // 3. Confined storage rejects symlinks/hardlinks and fails closed on tampered receipt store.
    let sym_receipts = root.join("state/symlink_receipts.json");
    std::os::unix::fs::symlink(&receipts_path, &sym_receipts).unwrap();
    assert!(load_worker_command_receipts_strict(&sym_receipts).is_err());
    assert!(persist_worker_command_receipts_atomic(&sym_receipts, &[]).is_err());
    let tampered_worker =
        WorkerCommandCoordinator::load_and_recover("node-gamma", &outbox_path, &sym_receipts);
    assert_eq!(
        tampered_worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-fresh-tampered".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
            lease_generation: 1,
        }),
        WorkerCommandDispatchPlan::RejectedStorageFailure
    );

    let hardlink_alias = root.join("state/hardlink_alias.json");
    std::fs::hard_link(&receipts_path, &hardlink_alias).unwrap();
    assert!(load_worker_command_receipts_strict(&receipts_path).is_err());
    let _ = std::fs::remove_file(&hardlink_alias);

    // 4. Bounded storage caps receipt ledger at MAX_WORKER_COMMAND_RECEIPTS while keeping active intents.
    let bounded_path = root.join("bounded/cluster_worker_command_receipts.json");
    let mut many: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS + 5)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-confirmed-{i}"),
            node_id: Some("node-gamma".to_string()),
            cmd_type: Some("ping".to_string()),
            target: Some(String::new()),
            action: None,
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("pong".to_string()),
            ack_confirmed: true,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    many.insert(
        0,
        WorkerCommandReceipt {
            id: "cmd-active-intent".to_string(),
            node_id: Some("node-gamma".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Intent,
            lease_generation: Some(1),
            result_message: None,
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        },
    );
    persist_worker_command_receipts_atomic(&bounded_path, &many).unwrap();
    let loaded_bounded = load_worker_command_receipts_strict(&bounded_path).unwrap();
    assert_eq!(loaded_bounded.len(), MAX_WORKER_COMMAND_RECEIPTS);
    assert!(
        loaded_bounded.iter().any(|r| r.id == "cmd-active-intent"),
        "active intent receipt must survive eviction of older confirmed receipts"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn worker_command_saturation_preserves_unconfirmed_and_intents_applies_backpressure_and_drains()
{
    let root = env::temp_dir().join(format!("af-cluster-sat-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let outbox_path = root.join("state/cluster_worker_ack_outbox.json");
    let receipts_path = resolve_worker_command_receipts_path(&outbox_path);

    // 1. Direct persistence must NEVER evict unconfirmed terminal receipts or active intents.
    let unconfirmed_overflow: Vec<WorkerCommandReceipt> = (0..=MAX_WORKER_COMMAND_RECEIPTS)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-direct-unconfirmed-{i}"),
            node_id: Some("node-sat".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("restart sonarr succeeded".to_string()),
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    assert!(
        persist_worker_command_receipts_atomic(&receipts_path, &unconfirmed_overflow).is_err()
    );

    let intent_overflow: Vec<WorkerCommandReceipt> = (0..=MAX_WORKER_COMMAND_RECEIPTS)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-direct-intent-{i}"),
            node_id: Some("node-sat".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Intent,
            lease_generation: Some(1),
            result_message: None,
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    assert!(persist_worker_command_receipts_atomic(&receipts_path, &intent_overflow).is_err());

    // 2. Saturate coordinator with 255 unconfirmed terminal receipts + 1 active in-flight Intent
    //    (seed the first 254 via durable startup reconciliation, then execute slots 255 & 256 live).
    let seeded_unconfirmed: Vec<WorkerCommandReceipt> = (0..(MAX_WORKER_COMMAND_RECEIPTS - 2))
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-unconfirmed-{i}"),
            node_id: Some("node-sat".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("restart sonarr succeeded".to_string()),
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    persist_worker_command_receipts_atomic(&receipts_path, &seeded_unconfirmed).unwrap();

    let worker =
        WorkerCommandCoordinator::load_and_recover("node-sat", &outbox_path, &receipts_path);
    assert_eq!(
        worker.pending_acks_snapshot().len(),
        MAX_WORKER_COMMAND_RECEIPTS - 2
    );
    let slot_255_cmd = PendingWorkerCommand {
        id: format!("cmd-unconfirmed-{}", MAX_WORKER_COMMAND_RECEIPTS - 2),
        cmd_type: "restart_service".to_string(),
        params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
        lease_generation: 1,
    };
    let slot_255_mutation = match worker.prepare_command_dispatch(slot_255_cmd) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("expected Execute for 255th slot, got {other:?}"),
    };
    worker
        .complete_admitted_mutation(&slot_255_mutation, Ok(()))
        .unwrap();
    let inflight_cmd = PendingWorkerCommand {
        id: "cmd-inflight-last".to_string(),
        cmd_type: "restart_service".to_string(),
        params: HashMap::from([("service".to_string(), "radarr".to_string())]),
        lease_generation: 1,
    };
    let inflight_mutation = match worker.prepare_command_dispatch(inflight_cmd) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("expected Execute for 256th slot, got {other:?}"),
    };

    // 3. At saturation, unseen new commands (both mutating and non-mutating) MUST fail closed
    //    with explicit backpressure BEFORE dispatch and WITHOUT evicting any entry.
    let fresh_mutation = PendingWorkerCommand {
        id: "cmd-fresh-blocked".to_string(),
        cmd_type: "restart_service".to_string(),
        params: HashMap::from([("service".to_string(), "plex".to_string())]),
        lease_generation: 1,
    };
    assert_eq!(
        worker.prepare_command_dispatch(fresh_mutation.clone()),
        WorkerCommandDispatchPlan::RejectedCapacitySaturated
    );
    assert_eq!(
        worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-fresh-ping-blocked".to_string(),
            cmd_type: "ping".to_string(),
            params: HashMap::new(),
            lease_generation: 1,
        }),
        WorkerCommandDispatchPlan::RejectedCapacitySaturated
    );

    let disk_at_sat = load_worker_command_receipts_strict(&receipts_path).unwrap();
    assert_eq!(disk_at_sat.len(), MAX_WORKER_COMMAND_RECEIPTS);
    assert!(disk_at_sat.iter().any(|r| r.id == "cmd-unconfirmed-0"));
    assert!(disk_at_sat
        .iter()
        .any(|r| r.id == "cmd-inflight-last" && r.phase == WorkerCommandReceiptPhase::Intent));
    assert!(!disk_at_sat.iter().any(|r| r.id == "cmd-fresh-blocked"));

    // 4. At saturation, existing commands MUST still reattach, complete, and drain ACKs.
    let reattach_cmd = PendingWorkerCommand {
        id: "cmd-unconfirmed-0".to_string(),
        cmd_type: "restart_service".to_string(),
        params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
        lease_generation: 2,
    };
    let reattached = match worker.prepare_command_dispatch(reattach_cmd) {
        WorkerCommandDispatchPlan::SendAckOnly(ack) => ack,
        other => panic!("existing receipt must reattach at saturation, got {other:?}"),
    };
    assert_eq!(reattached.id, "cmd-unconfirmed-0");
    assert_eq!(reattached.lease_generation, Some(2));
    assert_eq!(reattached.status, WORKER_COMMAND_STATUS_EXECUTED);

    let finished_ack = worker
        .complete_admitted_mutation(&inflight_mutation, Ok(()))
        .expect("in-flight intent must complete cleanly at saturation");
    assert_eq!(finished_ack.id, "cmd-inflight-last");
    assert_eq!(finished_ack.status, WORKER_COMMAND_STATUS_EXECUTED);
    assert_eq!(
        worker.pending_acks_snapshot().len(),
        MAX_WORKER_COMMAND_RECEIPTS
    );

    // 5. Confirming ONE receipt via master ACK frees exactly one recyclable slot and unblocks
    //    the next dispatch without losing any other unconfirmed receipt.
    worker.mark_confirmed(&["cmd-unconfirmed-0".to_string()]);
    assert_eq!(
        worker.pending_acks_snapshot().len(),
        MAX_WORKER_COMMAND_RECEIPTS - 1
    );

    let unblocked = match worker.prepare_command_dispatch(fresh_mutation) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => panic!("expected Execute after one confirmed receipt drained, got {other:?}"),
    };
    assert_eq!(unblocked.id, "cmd-fresh-blocked");
    let after_recycle = load_worker_command_receipts_strict(&receipts_path).unwrap();
    assert_eq!(after_recycle.len(), MAX_WORKER_COMMAND_RECEIPTS);
    assert!(!after_recycle.iter().any(|r| r.id == "cmd-unconfirmed-0"));
    assert!(after_recycle.iter().any(|r| r.id == "cmd-unconfirmed-1"));
    assert!(after_recycle.iter().any(|r| r.id == "cmd-inflight-last"));
    assert!(after_recycle
        .iter()
        .any(|r| r.id == "cmd-fresh-blocked" && r.phase == WorkerCommandReceiptPhase::Intent));

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn worker_command_byte_bound_and_legacy_outbox_reconciliation_guards() {
    let root = env::temp_dir().join(format!("af-cluster-recon-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();

    // 1. Outbox fits 256 max-length (1024-byte) result messages cleanly and rejects overflow.
    let full_outbox_path = root.join("full_outbox/cluster_worker_ack_outbox.json");
    let msg_1024 = "m".repeat(1024);
    let full_acks: Vec<WorkerCommandAck> = (0..MAX_WORKER_ACK_OUTBOX_ENTRIES)
        .map(|i| WorkerCommandAck {
            id: format!("cmd-full-ack-{i:03}"),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some(msg_1024.clone()),
            lease_generation: Some(1),
        })
        .collect();
    persist_worker_ack_outbox_atomic(&full_outbox_path, &full_acks)
        .expect("256 max-length ACKs must fit within outbox byte bound");
    assert_eq!(
        load_worker_ack_outbox_strict(&full_outbox_path)
            .unwrap()
            .len(),
        MAX_WORKER_ACK_OUTBOX_ENTRIES
    );

    let mut oversized_outbox = vec![WorkerCommandAck {
        id: "cmd-giant-outbox".to_string(),
        status: WORKER_COMMAND_STATUS_FAILED.to_string(),
        result_message: Some("z".repeat(MAX_WORKER_ACK_OUTBOX_BYTES + 16)),
        lease_generation: Some(1),
    }];
    let giant_outbox_path = root.join("giant_outbox/cluster_worker_ack_outbox.json");
    assert!(
        persist_worker_ack_outbox_atomic(&giant_outbox_path, &oversized_outbox).is_err(),
        "outbox persistence must fail closed instead of writing an unreadable oversized file"
    );
    oversized_outbox.clear();

    // 2. Receipt byte-bound enforcement recycles ONLY confirmed entries and applies
    //    backpressure before dispatch even when entry count < MAX_WORKER_COMMAND_RECEIPTS.
    let byte_outbox = root.join("byte_bound/cluster_worker_ack_outbox.json");
    let byte_receipts = resolve_worker_command_receipts_path(&byte_outbox);
    let big_target = "s".repeat(16 * 1024);
    let unconfirmed_heavy: Vec<WorkerCommandReceipt> = (0..31)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-heavy-{i:02}"),
            node_id: Some("node-bytes".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some(big_target.clone()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("ok".to_string()),
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    persist_worker_command_receipts_atomic(&byte_receipts, &unconfirmed_heavy).unwrap();

    let mut too_big_unconfirmed = unconfirmed_heavy.clone();
    too_big_unconfirmed.push(WorkerCommandReceipt {
        id: "cmd-heavy-overflow".to_string(),
        node_id: Some("node-bytes".to_string()),
        cmd_type: Some("restart_service".to_string()),
        target: Some(big_target.clone()),
        action: Some("restart".to_string()),
        phase: WorkerCommandReceiptPhase::Executed,
        lease_generation: Some(1),
        result_message: Some("ok".to_string()),
        ack_confirmed: false,
        updated_at: "2026-11-21T00:00:00Z".to_string(),
    });
    assert!(
        persist_worker_command_receipts_atomic(&byte_receipts, &too_big_unconfirmed).is_err(),
        "receipt persistence must fail closed on byte overflow when no confirmed entries exist"
    );

    let byte_worker =
        WorkerCommandCoordinator::load_and_recover("node-bytes", &byte_outbox, &byte_receipts);
    assert_eq!(
        byte_worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-heavy-new".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), big_target.clone())]),
            lease_generation: 1,
        }),
        WorkerCommandDispatchPlan::RejectedCapacitySaturated
    );

    // Confirming one heavy receipt frees enough bytes to recycle it and admit the new command,
    // and the reserved Intent completion headroom lets it complete cleanly within the byte bound.
    byte_worker.mark_confirmed(&["cmd-heavy-00".to_string()]);
    let admitted_heavy = match byte_worker.prepare_command_dispatch(PendingWorkerCommand {
        id: "cmd-heavy-new".to_string(),
        cmd_type: "restart_service".to_string(),
        params: HashMap::from([("service".to_string(), big_target)]),
        lease_generation: 1,
    }) {
        WorkerCommandDispatchPlan::Execute(m) => m,
        other => {
            panic!("expected Execute after recycling confirmed heavy receipt, got {other:?}")
        }
    };
    assert_eq!(admitted_heavy.id, "cmd-heavy-new");
    let completed_heavy = byte_worker
        .complete_admitted_mutation(&admitted_heavy, Err("e".repeat(1024)))
        .expect(
            "reserved byte headroom must allow admitted intent to persist full-size outcome",
        );
    assert_eq!(completed_heavy.status, WORKER_COMMAND_STATUS_FAILED);
    assert_eq!(
        load_worker_command_receipts_strict(&byte_receipts)
            .unwrap()
            .len(),
        31
    );

    // 3. Corrupt / invalid legacy outbox fails closed instead of disappearing authority.
    let bad_outbox_dir = root.join("bad_outbox");
    std::fs::create_dir_all(&bad_outbox_dir).unwrap();
    let bad_outbox = bad_outbox_dir.join("cluster_worker_ack_outbox.json");
    let bad_receipts = resolve_worker_command_receipts_path(&bad_outbox);
    std::fs::write(
        &bad_outbox,
        r#"[{"id":"cmd-bad-gen","status":"executed","lease_generation":0}]"#,
    )
    .unwrap();
    assert!(load_worker_ack_outbox_strict(&bad_outbox).is_err());
    let bad_worker =
        WorkerCommandCoordinator::load_and_recover("node-bad", &bad_outbox, &bad_receipts);
    assert_eq!(
        bad_worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-bad-gen".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
            lease_generation: 1,
        }),
        WorkerCommandDispatchPlan::RejectedStorageFailure
    );

    // 4. Generation-less legacy outbox entry MUST NOT overwrite a leased `Intent` as `Executed`.
    let gen_outbox = root.join("gen_guard/cluster_worker_ack_outbox.json");
    let gen_receipts = resolve_worker_command_receipts_path(&gen_outbox);
    persist_worker_command_receipts_atomic(
        &gen_receipts,
        &[WorkerCommandReceipt {
            id: "cmd-leased-intent".to_string(),
            node_id: Some("node-gen".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Intent,
            lease_generation: Some(2),
            result_message: None,
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        }],
    )
    .unwrap();
    persist_worker_ack_outbox_atomic(
        &gen_outbox,
        &[WorkerCommandAck {
            id: "cmd-leased-intent".to_string(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("unproven legacy ack".to_string()),
            lease_generation: None,
        }],
    )
    .unwrap();
    let gen_worker =
        WorkerCommandCoordinator::load_and_recover("node-gen", &gen_outbox, &gen_receipts);
    let recovered_gen = load_worker_command_receipts_strict(&gen_receipts).unwrap();
    assert_eq!(recovered_gen.len(), 1);
    assert_eq!(recovered_gen[0].phase, WorkerCommandReceiptPhase::Unknown);
    assert_eq!(recovered_gen[0].lease_generation, Some(2));
    let reconciled_outbox = load_worker_ack_outbox_strict(&gen_outbox).unwrap();
    assert_eq!(reconciled_outbox.len(), 1);
    assert_eq!(reconciled_outbox[0].status, WORKER_COMMAND_STATUS_UNKNOWN);
    assert_eq!(reconciled_outbox[0].lease_generation, Some(2));
    drop(gen_worker);

    // 5. Startup legacy outbox import with 256 unconfirmed receipts + 1 extra legacy outbox
    //    entry fails closed instead of dropping authority, while preserving pending ACKs.
    let sat_recon_outbox = root.join("sat_recon/cluster_worker_ack_outbox.json");
    let sat_recon_receipts = resolve_worker_command_receipts_path(&sat_recon_outbox);
    let sat_256: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-sat-rec-{i:03}"),
            node_id: Some("node-recon".to_string()),
            cmd_type: Some("restart_service".to_string()),
            target: Some("sonarr".to_string()),
            action: Some("restart".to_string()),
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("ok".to_string()),
            ack_confirmed: false,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    persist_worker_command_receipts_atomic(&sat_recon_receipts, &sat_256).unwrap();
    persist_worker_ack_outbox_atomic(
        &sat_recon_outbox,
        &[WorkerCommandAck {
            id: "cmd-legacy-extra-257".to_string(),
            status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
            result_message: Some("legacy ok".to_string()),
            lease_generation: Some(1),
        }],
    )
    .unwrap();
    let sat_recon_worker = WorkerCommandCoordinator::load_and_recover(
        "node-recon",
        &sat_recon_outbox,
        &sat_recon_receipts,
    );
    assert_eq!(
        sat_recon_worker.prepare_command_dispatch(PendingWorkerCommand {
            id: "cmd-blocked-after-overflow".to_string(),
            cmd_type: "restart_service".to_string(),
            params: HashMap::from([("service".to_string(), "sonarr".to_string())]),
            lease_generation: 1,
        }),
        WorkerCommandDispatchPlan::RejectedStorageFailure
    );
    assert_eq!(sat_recon_worker.pending_acks_snapshot().len(), 1);
    assert_eq!(
        load_worker_command_receipts_strict(&sat_recon_receipts)
            .unwrap()
            .len(),
        MAX_WORKER_COMMAND_RECEIPTS
    );

    // 6. Startup legacy outbox import with confirmed receipts recycles confirmed entries and
    //    prunes already-confirmed IDs lingering in the outbox.
    let recycle_recon_outbox = root.join("recycle_recon/cluster_worker_ack_outbox.json");
    let recycle_recon_receipts = resolve_worker_command_receipts_path(&recycle_recon_outbox);
    let confirmed_256: Vec<WorkerCommandReceipt> = (0..MAX_WORKER_COMMAND_RECEIPTS)
        .map(|i| WorkerCommandReceipt {
            id: format!("cmd-conf-rec-{i:03}"),
            node_id: Some("node-recon2".to_string()),
            cmd_type: Some("ping".to_string()),
            target: Some(String::new()),
            action: None,
            phase: WorkerCommandReceiptPhase::Executed,
            lease_generation: Some(1),
            result_message: Some("pong".to_string()),
            ack_confirmed: true,
            updated_at: "2026-11-21T00:00:00Z".to_string(),
        })
        .collect();
    persist_worker_command_receipts_atomic(&recycle_recon_receipts, &confirmed_256).unwrap();
    persist_worker_ack_outbox_atomic(
        &recycle_recon_outbox,
        &[
            WorkerCommandAck {
                id: "cmd-conf-rec-000".to_string(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("pong".to_string()),
                lease_generation: Some(1),
            },
            WorkerCommandAck {
                id: "cmd-conf-rec-005".to_string(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("pong".to_string()),
                lease_generation: Some(1),
            },
            WorkerCommandAck {
                id: "cmd-legacy-imported".to_string(),
                status: WORKER_COMMAND_STATUS_EXECUTED.to_string(),
                result_message: Some("legacy done".to_string()),
                lease_generation: Some(1),
            },
        ],
    )
    .unwrap();
    let recycle_worker = WorkerCommandCoordinator::load_and_recover(
        "node-recon2",
        &recycle_recon_outbox,
        &recycle_recon_receipts,
    );
    let post_recon_receipts =
        load_worker_command_receipts_strict(&recycle_recon_receipts).unwrap();
    assert_eq!(post_recon_receipts.len(), MAX_WORKER_COMMAND_RECEIPTS);
    assert!(post_recon_receipts
        .iter()
        .any(|r| r.id == "cmd-legacy-imported" && !r.ack_confirmed));
    let post_recon_outbox = load_worker_ack_outbox_strict(&recycle_recon_outbox).unwrap();
    assert_eq!(post_recon_outbox.len(), 1);
    assert_eq!(post_recon_outbox[0].id, "cmd-legacy-imported");
    drop(recycle_worker);

    let _ = std::fs::remove_dir_all(&root);
}
