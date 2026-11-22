use crate::pending_actions::{
    count_pending_actions_with_connection, finalize_queued_action_by_id_with_connection,
    finalize_queued_action_by_job_unit_with_connection, get_pending_action_by_id_with_connection,
    list_queued_actions_with_receipts_with_connection, mark_action_queued_with_connection,
    query_pending_actions_with_connection, queue_action_with_connection,
};
use crate::schema::ensure_pending_actions_schema_invariants;
use crate::tests::TEST_DB_MUTEX;
use crate::*;
use rusqlite::{params, Connection};
use std::env;
use std::fs;
use std::time::Duration;

fn connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE pending_actions (
            id INTEGER PRIMARY KEY, classification TEXT, source TEXT, action TEXT,
            reason TEXT, status TEXT, created_at TEXT, resolved_at TEXT,
            resolved_by TEXT, execution_log TEXT
        );",
    )
    .unwrap();
    conn
}

#[test]
fn status_filter_precedes_pagination_and_counts_all_matching_rows() {
    let conn = connection();
    conn.execute(
        "INSERT INTO pending_actions (id, action, status, created_at) VALUES (1, 'older-pending', 'pending', '2020-01-01')",
        [],
    )
    .unwrap();
    for id in 2..=506 {
        conn.execute(
            "INSERT INTO pending_actions (id, action, status, created_at) VALUES (?1, 'newer-executed', 'executed', '2026-01-01')",
            params![id],
        )
        .unwrap();
    }
    let (pending, total) = query_pending_actions_with_connection(&conn, "pending", 50, 0).unwrap();
    assert_eq!(total, 1);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, 1);
    assert_eq!(pending[0].action, "older-pending");
    let (history, total) =
        query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
    assert_eq!(total, 505);
    assert_eq!(history.len(), 50);
    assert_eq!(history[0].id, 506);
    assert_eq!(history[49].id, 457);
    let (last_page, total) =
        query_pending_actions_with_connection(&conn, "approved_history", 50, 500).unwrap();
    assert_eq!(total, 505);
    assert_eq!(
        last_page.iter().map(|action| action.id).collect::<Vec<_>>(),
        vec![6, 5, 4, 3, 2]
    );
    for filter in ["all", ""] {
        let (actions, total) =
            query_pending_actions_with_connection(&conn, filter, 1000, -1).unwrap();
        assert_eq!(total, 506);
        assert_eq!(actions.len(), 500);
    }
    assert_eq!(
        query_pending_actions_with_connection(&conn, "executed", 0, 0)
            .unwrap()
            .0
            .len(),
        50
    );
    assert!(query_pending_actions_with_connection(&conn, "unknown", 50, 0).is_err());
}

#[test]
fn null_status_is_pending_and_history_includes_only_approved_outcomes() {
    let conn = connection();
    for (id, status) in [
        None,
        Some("approved"),
        Some("rejected"),
        Some("executed"),
        Some("failed"),
    ]
    .into_iter()
    .enumerate()
    {
        conn.execute(
            "INSERT INTO pending_actions (id, status) VALUES (?1, ?2)",
            params![id as i64, status],
        )
        .unwrap();
    }
    let (pending, total) = query_pending_actions_with_connection(&conn, "pending", 50, 0).unwrap();
    assert_eq!(total, 1);
    assert_eq!(pending[0].status, "pending");
    let (history, total) =
        query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
    assert_eq!(total, 3);
    assert_eq!(
        history.iter().map(|action| action.id).collect::<Vec<_>>(),
        vec![4, 3, 1]
    );
    for filter in ["approved", "rejected", "executed", "failed"] {
        let (actions, total) = query_pending_actions_with_connection(&conn, filter, 1, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(actions[0].status, filter);
    }
    let (actions, total) = query_pending_actions_with_connection(&conn, "pending", 50, 1).unwrap();
    assert_eq!(total, 1);
    assert!(actions.is_empty());
}

#[test]
fn deferred_restart_receipt_schema_upgrade_preserves_rows_and_history_filters() {
    let conn = connection();
    conn.execute(
        "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
         VALUES (1, 'warn', 'FlowAI', 'restart:sonarr', 'legacy row', 'executed', '2026-01-01')",
        [],
    )
    .unwrap();
    // Legacy table without job_unit still reads cleanly.
    let legacy = get_pending_action_by_id_with_connection(&conn, 1)
        .unwrap()
        .unwrap();
    assert_eq!(legacy.status, "executed");
    assert_eq!(legacy.job_unit, None);

    // Invariant upgrade adds job_unit without modifying existing rows.
    ensure_pending_actions_schema_invariants(&conn).unwrap();
    ensure_pending_actions_schema_invariants(&conn).unwrap();
    let preserved = get_pending_action_by_id_with_connection(&conn, 1)
        .unwrap()
        .unwrap();
    assert_eq!(preserved.action, "restart:sonarr");
    assert_eq!(preserved.status, "executed");
    assert_eq!(preserved.job_unit, None);

    for (id, status, unit) in [
        (2, "approved", None),
        (
            3,
            "queued",
            Some("aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service"),
        ),
        (
            4,
            "unavailable",
            Some("aetherflow-self-update-restart-aetherflow-runner-fedcba9876543210.service"),
        ),
        (5, "rejected", None),
        (6, "pending", None),
    ] {
        conn.execute(
            "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at, job_unit) \
             VALUES (?1, 'critical', 'FlowAI', 'restart_service:aetherflow-api:systemd', 'test', ?2, '2026-01-02', ?3)",
            params![id, status, unit],
        )
        .unwrap();
    }

    let (history, total) =
        query_pending_actions_with_connection(&conn, "approved_history", 50, 0).unwrap();
    assert_eq!(total, 4);
    assert_eq!(
        history.iter().map(|a| a.id).collect::<Vec<_>>(),
        vec![4, 3, 2, 1]
    );

    let (queued, q_total) = query_pending_actions_with_connection(&conn, "queued", 50, 0).unwrap();
    assert_eq!(q_total, 1);
    assert_eq!(queued[0].id, 3);
    assert_eq!(
        queued[0].job_unit.as_deref(),
        Some("aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service")
    );

    let (unavail, u_total) =
        query_pending_actions_with_connection(&conn, "unavailable", 50, 0).unwrap();
    assert_eq!(u_total, 1);
    assert_eq!(unavail[0].id, 4);

    let tracked = list_queued_actions_with_receipts_with_connection(&conn, 50).unwrap();
    assert_eq!(tracked.len(), 1);
    assert_eq!(tracked[0].id, 3);
}

#[test]
fn deferred_restart_receipt_transitions_guard_against_mismatches_and_replays() {
    let conn = connection();
    ensure_pending_actions_schema_invariants(&conn).unwrap();
    conn.execute(
        "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
         VALUES (10, 'critical', 'FlowAI', 'restart_service:aetherflow-api:systemd', 'recycle', 'approved', '2026-01-03')",
        [],
    )
    .unwrap();

    let unit = "aetherflow-self-update-restart-aetherflow-api-abcdef0123456789.service";
    let queued = mark_action_queued_with_connection(&conn, 10, unit, "queued for restart").unwrap();
    assert_eq!(queued.status, "queued");
    assert_eq!(queued.job_unit.as_deref(), Some(unit));

    // Second queue attempt on an already-queued row is rejected.
    assert!(mark_action_queued_with_connection(&conn, 10, unit, "duplicate").is_err());

    // Mismatched receipt cannot finalize the action.
    let wrong = finalize_queued_action_by_id_with_connection(
        &conn,
        10,
        "aetherflow-self-update-restart-aetherflow-api-ffffffffffffffff.service",
        "executed",
        "wrong receipt",
    )
    .unwrap()
    .unwrap();
    assert_eq!(wrong.status, "queued");

    // Matching receipt finalizes atomically by job_unit.
    let changed = finalize_queued_action_by_job_unit_with_connection(
        &conn,
        unit,
        "executed",
        "confirmed via durable receipt",
    )
    .unwrap();
    assert_eq!(changed, 1);
    let done = get_pending_action_by_id_with_connection(&conn, 10)
        .unwrap()
        .unwrap();
    assert_eq!(done.status, "executed");
    assert_eq!(done.job_unit.as_deref(), Some(unit));
    assert_eq!(
        done.execution_log.as_deref(),
        Some("confirmed via durable receipt")
    );

    // Terminal row cannot be overwritten back to failed or unavailable.
    let repeat =
        finalize_queued_action_by_job_unit_with_connection(&conn, unit, "failed", "stale failure")
            .unwrap();
    assert_eq!(repeat, 0);
    assert_eq!(
        get_pending_action_by_id_with_connection(&conn, 10)
            .unwrap()
            .unwrap()
            .status,
        "executed"
    );
}

#[test]
fn queue_action_enforces_typed_outcomes_hidden_pending_cap_and_write_rejection() {
    let mut conn = connection();

    assert_eq!(
        queue_action_with_connection(&mut conn, "safe", "FlowAI", "noop", "safe check", false),
        QueueActionOutcome::SkippedSafe
    );
    assert_eq!(count_pending_actions_with_connection(&conn).unwrap(), 0);

    // Seed 50 older pending rows (including NULL status and mixed sources) hidden
    // behind 150 newer resolved rows so unfiltered LIMIT 100 scans miss them.
    for idx in 1..=MAX_PENDING_ACTIONS {
        let status = if idx == 1 { None } else { Some("pending") };
        let source = if idx % 2 == 0 { "af-heal" } else { "FlowAI" };
        conn.execute(
            "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
             VALUES (?1, 'warn', ?2, ?3, 'older pending', ?4, '2020-01-01')",
            params![idx, source, format!("Restart svc-{idx}"), status],
        )
        .unwrap();
    }
    for idx in 1..=150i64 {
        conn.execute(
            "INSERT INTO pending_actions (id, classification, source, action, reason, status, created_at) \
             VALUES (?1, 'warn', 'FlowAI', 'Restart resolved', 'recent history', 'executed', '2026-01-01')",
            params![1000 + idx],
        )
        .unwrap();
    }

    assert_eq!(
        count_pending_actions_with_connection(&conn).unwrap(),
        MAX_PENDING_ACTIONS
    );
    assert_eq!(
        queue_action_with_connection(
            &mut conn,
            "warn",
            "FlowAI",
            "Restart apache2",
            "cap blocked",
            false
        ),
        QueueActionOutcome::CapacityReached {
            pending_count: MAX_PENDING_ACTIONS,
            limit: MAX_PENDING_ACTIONS,
        }
    );

    // Resolving one pending row frees exactly one slot and preserves history rows.
    conn.execute(
        "UPDATE pending_actions SET status = 'executed' WHERE id = 2",
        [],
    )
    .unwrap();
    let queued = queue_action_with_connection(
        &mut conn,
        "warn",
        "af-heal",
        "systemctl restart fixture-main",
        "heal",
        true,
    );
    let action_id = queued.queued_action_id().expect("expected positive row id");
    assert!(action_id > 0);
    assert_eq!(
        queue_action_with_connection(
            &mut conn,
            "warn",
            "af-heal",
            "systemctl restart fixture-main",
            "heal dup",
            true
        ),
        QueueActionOutcome::AlreadyPending
    );
    assert_eq!(
        queue_action_with_connection(
            &mut conn,
            "warn",
            "FlowAI",
            "Restart apache2",
            "cap restored",
            false
        ),
        QueueActionOutcome::CapacityReached {
            pending_count: MAX_PENDING_ACTIONS,
            limit: MAX_PENDING_ACTIONS,
        }
    );

    // Free a slot, then reject writes via trigger and verify DbError leaves zero phantom rows.
    conn.execute(
        "UPDATE pending_actions SET status = 'rejected' WHERE id = 3",
        [],
    )
    .unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_pending_insert BEFORE INSERT ON pending_actions \
         BEGIN SELECT RAISE(ABORT, 'simulated write rejection'); END;",
    )
    .unwrap();
    let rejected = queue_action_with_connection(
        &mut conn,
        "warn",
        "FlowAI",
        "Restart apache2",
        "rejected write",
        false,
    );
    assert!(matches!(rejected, QueueActionOutcome::DbError(_)));
    assert_eq!(rejected.queued_action_id(), None);
    assert_eq!(
        count_pending_actions_with_connection(&conn).unwrap(),
        MAX_PENDING_ACTIONS - 1
    );
    conn.execute_batch("DROP TRIGGER reject_pending_insert;")
        .unwrap();

    // Read-only connection mode also fails cleanly with DbError.
    conn.execute_batch("PRAGMA query_only = ON;").unwrap();
    let ro_err = queue_action_with_connection(
        &mut conn,
        "warn",
        "FlowAI",
        "Restart apache2",
        "read only",
        false,
    );
    assert!(matches!(ro_err, QueueActionOutcome::DbError(_)));
    assert_eq!(ro_err.queued_action_id(), None);
}

#[test]
fn queue_action_immediate_transaction_enforces_cap_across_competing_writers() {
    let dir = env::temp_dir().join(format!("af-db-pending-cap-{}", rand::random::<u64>()));
    fs::create_dir_all(&dir).unwrap();
    let db_file = dir.join("pending-cap.sqlite");

    {
        let setup = Connection::open(&db_file).unwrap();
        setup
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA busy_timeout=5000;
                 CREATE TABLE pending_actions (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     classification TEXT DEFAULT 'warn',
                     source TEXT DEFAULT '',
                     action TEXT DEFAULT '',
                     reason TEXT DEFAULT '',
                     status TEXT DEFAULT 'pending',
                     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                     resolved_at DATETIME,
                     resolved_by TEXT,
                     execution_log TEXT
                 );",
            )
            .unwrap();
        for idx in 1..=(MAX_PENDING_ACTIONS - 3) {
            setup
                .execute(
                    "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                     VALUES ('warn', 'FlowAI', ?1, 'seed', 'pending', '2020-01-01')",
                    params![format!("Restart seed-{idx}")],
                )
                .unwrap();
        }
        for idx in 1..=120i64 {
            setup
                .execute(
                    "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                     VALUES ('warn', 'FlowAI', ?1, 'resolved', 'executed', '2026-01-01')",
                    params![format!("Restart done-{idx}")],
                )
                .unwrap();
        }
    }

    let workers = 12usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);
    for idx in 0..workers {
        let db_path = db_file.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut conn = Connection::open(&db_path).unwrap();
            conn.busy_timeout(Duration::from_secs(5)).unwrap();
            barrier.wait();
            queue_action_with_connection(
                &mut conn,
                "warn",
                if idx % 2 == 0 { "FlowAI" } else { "af-heal" },
                &format!("Restart worker-{idx}"),
                "concurrent cap test",
                false,
            )
        }));
    }

    let mut queued_ids = Vec::new();
    let mut capacity_hits = 0usize;
    for handle in handles {
        match handle.join().unwrap() {
            QueueActionOutcome::Queued { action_id } => {
                assert!(action_id > 0);
                queued_ids.push(action_id);
            }
            QueueActionOutcome::CapacityReached {
                pending_count,
                limit,
            } => {
                assert_eq!(pending_count, MAX_PENDING_ACTIONS);
                assert_eq!(limit, MAX_PENDING_ACTIONS);
                capacity_hits += 1;
            }
            other => panic!("unexpected competing writer outcome: {other:?}"),
        }
    }
    queued_ids.sort_unstable();
    queued_ids.dedup();
    assert_eq!(queued_ids.len(), 3);
    assert_eq!(capacity_hits, workers - 3);

    // Verify locked-writer timeout returns DbError without advertising a row ID.
    let locker = Connection::open(&db_file).unwrap();
    locker.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let mut contender = Connection::open(&db_file).unwrap();
    contender.busy_timeout(Duration::from_millis(50)).unwrap();
    let busy = queue_action_with_connection(
        &mut contender,
        "warn",
        "FlowAI",
        "Restart locked",
        "locked test",
        false,
    );
    assert!(matches!(busy, QueueActionOutcome::DbError(_)));
    assert_eq!(busy.queued_action_id(), None);
    locker.execute_batch("ROLLBACK;").unwrap();

    let verify = Connection::open(&db_file).unwrap();
    assert_eq!(
        count_pending_actions_with_connection(&verify).unwrap(),
        MAX_PENDING_ACTIONS
    );
    let (_, history_total) =
        query_pending_actions_with_connection(&verify, "executed", 10, 0).unwrap();
    assert_eq!(history_total, 120);

    drop(verify);
    drop(contender);
    drop(locker);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_readiness_check_succeeds_during_active_writer_lock() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = env::temp_dir().join(format!("af-db-wal-ready-{}", rand::random::<u64>()));
    fs::create_dir_all(&dir).unwrap();
    let db_file = dir.join("aetherflow.sqlite");
    let prev_af = env::var("AF_DB_PATH").ok();
    let prev_db = env::var("DB_PATH").ok();
    let prev_af2 = env::var("AETHERFLOW_DB_PATH").ok();
    env::set_var("AF_DB_PATH", &db_file);
    env::set_var("DB_PATH", &db_file);
    env::set_var("AETHERFLOW_DB_PATH", &db_file);

    init_db().unwrap();
    let writer = get_conn().unwrap();
    writer.execute(
        "INSERT INTO users (username, password_hash, role) VALUES ('committed', 'hash', 'user')",
        [],
    ).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer
        .execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('alice', 'hash', 'admin')",
            [],
        )
        .unwrap();

    let latency = db_readiness_check()
        .expect("read-only WAL readiness check must not stall on active writer lock");
    assert!(latency < 1000);
    let health =
        db_health_check().expect("read-only WAL health check must not stall on writer lock");
    assert_eq!(health["status"], "healthy");
    assert!(health["wal_pages"].as_u64().unwrap() > 0);

    writer.execute_batch("ROLLBACK").unwrap();
    drop(writer);
    match prev_af {
        Some(v) => env::set_var("AF_DB_PATH", v),
        None => env::remove_var("AF_DB_PATH"),
    }
    match prev_db {
        Some(v) => env::set_var("DB_PATH", v),
        None => env::remove_var("DB_PATH"),
    }
    match prev_af2 {
        Some(v) => env::set_var("AETHERFLOW_DB_PATH", v),
        None => env::remove_var("AETHERFLOW_DB_PATH"),
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_notification_channel_secret_encryption_migration_and_masking() {
    let _guard = TEST_DB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = env::temp_dir().join(format!("af-db-notif-enc-{}", rand::random::<u64>()));
    fs::create_dir_all(&dir).unwrap();
    let db_file = dir.join("aetherflow.sqlite");
    let prev_af = env::var("AF_DB_PATH").ok();
    let prev_aes = env::var("AES_MASTER_KEY").ok();
    env::set_var("AF_DB_PATH", &db_file);
    env::set_var(
        "AES_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    init_aes_key().unwrap();
    init_db().unwrap();

    {
        let conn = get_conn().unwrap();
        conn.execute(
            "INSERT INTO notification_channels (name, type, config, enabled) VALUES (?1, ?2, ?3, 1)",
            params![
                "tg",
                "telegram",
                r#"{"bot_token":"123456:ABC-DEF","chat_id":"-1001"}"#
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notification_channels (name, type, config, enabled) VALUES (?1, ?2, ?3, 1)",
            params![
                "hook",
                "webhook",
                r#"{"webhook_url":"https://hooks.example.com/sec","headers":{"Authorization":"Bearer tok123","Content-Type":"application/json"},"password":"smtp-secret"}"#
            ],
        )
        .unwrap();
    }

    migrate_legacy_secrets().unwrap();

    let conn = get_conn().unwrap();
    let (tg_type, tg_cfg): (String, String) = conn
        .query_row(
            "SELECT type, config FROM notification_channels WHERE name = 'tg'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!tg_cfg.contains("123456:ABC-DEF"));
    assert!(tg_cfg.contains("enc:v1:"));
    let tg_masked = mask_notification_channel_config_str(&tg_type, &tg_cfg);
    assert_eq!(tg_masked["bot_token"], SECRET_MASK);
    assert_eq!(tg_masked["chat_id"], "-1001");
    let tg_dec = decrypt_notification_channel_config_str(&tg_type, &tg_cfg).unwrap();
    assert_eq!(tg_dec["bot_token"], "123456:ABC-DEF");

    let (hk_type, hk_cfg): (String, String) = conn
        .query_row(
            "SELECT type, config FROM notification_channels WHERE name = 'hook'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!hk_cfg.contains("https://hooks.example.com/sec"));
    assert!(!hk_cfg.contains("Bearer tok123"));
    assert!(!hk_cfg.contains("smtp-secret"));
    let hk_masked = mask_notification_channel_config_str(&hk_type, &hk_cfg);
    assert_eq!(hk_masked["webhook_url"], SECRET_MASK);
    assert_eq!(hk_masked["password"], SECRET_MASK);
    assert_eq!(hk_masked["headers"]["Authorization"], SECRET_MASK);
    assert_eq!(hk_masked["headers"]["Content-Type"], "application/json");
    let hk_dec = decrypt_notification_channel_config_str(&hk_type, &hk_cfg).unwrap();
    assert_eq!(hk_dec["webhook_url"], "https://hooks.example.com/sec");
    assert_eq!(hk_dec["headers"]["Authorization"], "Bearer tok123");
    assert_eq!(hk_dec["password"], "smtp-secret");

    drop(conn);
    match prev_af {
        Some(v) => env::set_var("AF_DB_PATH", v),
        None => env::remove_var("AF_DB_PATH"),
    }
    match prev_aes {
        Some(v) => env::set_var("AES_MASTER_KEY", v),
        None => {
            env::remove_var("AES_MASTER_KEY");
            let _ = init_aes_key();
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn mediaflow_schema_migration_preserves_legacy_rows_and_allows_replaced_paths() {
    let conn = Connection::open_in_memory().unwrap();
    // Simulate a legacy v16 database where file_path is globally UNIQUE and no source_* columns exist.
    conn.execute_batch(
        r#"CREATE TABLE mediaflow_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'PENDING_APPROVAL',
            original_codec TEXT DEFAULT '',
            original_size INTEGER DEFAULT 0,
            new_codec TEXT DEFAULT '',
            new_size INTEGER DEFAULT 0,
            error_log TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO mediaflow_queue (id, file_path, status, original_codec, original_size)
        VALUES
            (1, '/mnt/media/old_completed.mp4', 'COMPLETED', 'h264', 1000),
            (2, '/mnt/media/old_declined.mp4', 'DECLINED', 'h264', 2000),
            (3, '/mnt/media/old_pending.mp4', 'PENDING_APPROVAL', 'h264', 3000);"#,
    )
    .unwrap();

    ensure_mediaflow_schema_invariants(&conn).unwrap();
    // Second invocation must be an idempotent no-op.
    ensure_mediaflow_schema_invariants(&conn).unwrap();

    // All legacy rows preserved with NULL/empty identity columns.
    let (path, status, fp): (String, String, String) = conn
        .query_row(
            "SELECT file_path, status, source_fingerprint FROM mediaflow_queue WHERE id = 2",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(path, "/mnt/media/old_declined.mp4");
    assert_eq!(status, "DECLINED");
    assert!(fp.is_empty());

    // Genuinely new file at an old terminal path (DECLINED) can now be enqueued alongside history.
    conn.execute(
        "INSERT INTO mediaflow_queue (file_path, status, original_codec, original_size, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, source_fingerprint)
         VALUES ('/mnt/media/old_declined.mp4', 'PENDING_APPROVAL', 'h264', 4096, 1, 99, 4096, 1700000000, 123, 'v1:sha256:newfile')",
        [],
    )
    .unwrap();

    // Duplicate active row for the same path must still be rejected atomically by SQLite.
    let dup_active = conn.execute(
        "INSERT INTO mediaflow_queue (file_path, status, original_codec, original_size, source_fingerprint)
         VALUES ('/mnt/media/old_declined.mp4', 'APPROVED', 'h264', 4096, 'v1:sha256:dup')",
        [],
    );
    assert!(dup_active.is_err());
}

#[test]
fn test_notification_durable_delivery_schema_invariants_and_pruning() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"CREATE TABLE notification_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            condition_type TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            level TEXT DEFAULT 'warning',
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE notification_delivery_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            channel_type TEXT NOT NULL,
            notification_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER DEFAULT 0,
            last_error TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME
        );
        INSERT INTO notification_delivery_log (id, channel_id, channel_type, notification_id, status, attempts, created_at)
        VALUES
            (1, 1, 'webhook', 10, 'delivered', 1, datetime('now', '-120 days')),
            (2, 1, 'webhook', 11, 'failed', 3, datetime('now', '-120 days')),
            (3, 1, 'webhook', 12, 'uncertain', 3, datetime('now', '-120 days')),
            (4, 1, 'webhook', 13, 'pending', 0, datetime('now', '-120 days')),
            (5, 1, 'webhook', 14, 'sending', 1, datetime('now', '-120 days')),
            (6, 1, 'webhook', 15, 'delivered', 1, datetime('now', '-5 days'));"#,
    )
    .unwrap();

    ensure_notification_schema_invariants(&conn).unwrap();
    // Second call must remain idempotent.
    ensure_notification_schema_invariants(&conn).unwrap();

    conn.execute(
        "INSERT INTO notification_rules (name, condition_type, condition_value, last_triggered_at)
         VALUES ('Disk', 'disk_usage', '90', 1700000000)",
        [],
    )
    .unwrap();

    conn.execute(PRUNE_NOTIFICATION_DELIVERY_LOG_SQL, [])
        .unwrap();
    let remaining: Vec<i64> = conn
        .prepare("SELECT id FROM notification_delivery_log ORDER BY id ASC")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        remaining,
        vec![4, 5, 6],
        "pruning must only delete terminal rows older than 90 days and preserve active pending/sending rows"
    );
}
