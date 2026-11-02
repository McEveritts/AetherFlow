use super::*;
use crate::auth::{csrf_middleware, AuthUser};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::middleware;
use http_body_util::BodyExt;
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use tower::ServiceExt;

struct IsolatedTestDb {
    dir: PathBuf,
}

impl IsolatedTestDb {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let dir = std::env::temp_dir().join(format!("af-mcbrowser-events-db-{token:032x}"));
            if fs::create_dir(&dir).is_ok() {
                let db_file = dir.join("test.sqlite");
                std::env::set_var("DB_PATH", &db_file);
                af_db::init_db().expect("initialize isolated test sqlite db");
                return Self { dir };
            }
        }
        panic!("failed to allocate isolated test sqlite directory");
    }
}

impl Drop for IsolatedTestDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn setup_in_memory_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .unwrap();
    ensure_events_tables(&conn).unwrap();
    conn
}

fn make_user(user_id: i64, username: &str, role: &str) -> AuthUser {
    AuthUser {
        user_id,
        username: username.to_string(),
        role: role.to_string(),
        jti: format!("jti-{user_id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

#[test]
fn incomplete_accounting_never_finalizes_or_enqueues_a_mutation() {
    let conn = setup_in_memory_conn();
    conn.execute("INSERT INTO users (id, username) VALUES (1, 'alice')", [])
        .unwrap();
    conn.execute("UPDATE mcbrowser_event_settings SET queue_enabled = 1", [])
        .unwrap();
    let actor = make_user(1, "alice", "user");
    let (output, outcome) = execute_with_audit_intent_conn(
        &conn,
        &actor,
        McBrowserEventTrigger::FileSaved,
        "saved.txt",
        None,
        -4,
        |_, _| Ok((None, None, -4, "published", false)),
    )
    .unwrap();
    assert_eq!(output, "published");
    assert!(matches!(
        outcome,
        PostPublicationAuditOutcome::RetainedPending { .. }
    ));
    let failed = execute_with_audit_intent_conn::<(), _>(
        &conn,
        &actor,
        McBrowserEventTrigger::FileSaved,
        "unpublished.txt",
        None,
        8,
        |_, _| {
            Err(McBrowserError::AccountingPending(
                "Quota cleanup failed".into(),
            ))
        },
    );
    assert!(matches!(failed, Err(McBrowserError::AccountingPending(_))));
    let pending: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM mcbrowser_audit_events WHERE status = 'pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let queued: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(pending, 2);
    assert_eq!(queued, 0);
}

#[test]
fn closed_trigger_enum_and_audit_event_schema_validation() {
    let expected = [
        (
            McBrowserEventTrigger::UploadCompleted,
            "upload_completed",
            "UploadCompleted",
            false,
        ),
        (
            McBrowserEventTrigger::EntryDeleted,
            "entry_deleted",
            "EntryDeleted",
            false,
        ),
        (
            McBrowserEventTrigger::FileSaved,
            "file_saved",
            "FileSaved",
            false,
        ),
        (
            McBrowserEventTrigger::EntryCopied,
            "entry_copied",
            "EntryCopied",
            true,
        ),
        (
            McBrowserEventTrigger::EntryRenamed,
            "entry_renamed",
            "EntryRenamed",
            true,
        ),
        (
            McBrowserEventTrigger::ShareCreated,
            "share_created",
            "ShareCreated",
            false,
        ),
        (
            McBrowserEventTrigger::ShareRevoked,
            "share_revoked",
            "ShareRevoked",
            false,
        ),
    ];

    assert_eq!(McBrowserEventTrigger::ALL.len(), 7);
    for (trigger, snake, pascal, needs_dst) in expected {
        assert_eq!(trigger.as_str(), snake);
        assert_eq!(trigger.pascal_name(), pascal);
        assert_eq!(trigger.requires_destination_path(), needs_dst);
        assert_eq!(McBrowserEventTrigger::parse(snake).unwrap(), trigger);
        assert_eq!(McBrowserEventTrigger::parse(pascal).unwrap(), trigger);

        let serialized = serde_json::to_string(&trigger).unwrap();
        assert_eq!(serialized, format!("\"{snake}\""));
        let deserialized_snake: McBrowserEventTrigger = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized_snake, trigger);
        let deserialized_pascal: McBrowserEventTrigger =
            serde_json::from_str(&format!("\"{pascal}\"")).unwrap();
        assert_eq!(deserialized_pascal, trigger);
    }

    for bad_trigger in [
        "",
        "before_upload",
        "after_upload",
        "shell_exec",
        "command_runner",
        "file_opened",
    ] {
        assert!(matches!(
            McBrowserEventTrigger::parse(bad_trigger),
            Err(McBrowserError::BadRequest(_))
        ));
        assert!(
            serde_json::from_str::<McBrowserEventTrigger>(&format!("\"{bad_trigger}\"")).is_err()
        );
    }

    let event = McBrowserAuditEvent {
        event_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        timestamp: "2026-11-02T00:00:00+00:00".to_string(),
        user_id: 7,
        username: "alice".to_string(),
        trigger: McBrowserEventTrigger::EntryRenamed,
        relative_path: "docs/draft.md".to_string(),
        destination_path: Some("docs/final.md".to_string()),
        byte_delta: 0,
    };
    let json_val = serde_json::to_value(&event).unwrap();
    assert_eq!(json_val["event_id"], "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(json_val["timestamp"], "2026-11-02T00:00:00+00:00");
    assert_eq!(json_val["user_id"], 7);
    assert_eq!(json_val["username"], "alice");
    assert_eq!(json_val["trigger"], "entry_renamed");
    assert_eq!(json_val["relative_path"], "docs/draft.md");
    assert_eq!(json_val["destination_path"], "docs/final.md");
    assert_eq!(json_val["byte_delta"], 0);

    let roundtrip: McBrowserAuditEvent = serde_json::from_value(json_val).unwrap();
    assert_eq!(roundtrip, event);

    let with_extra = r#"{
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2026-11-02T00:00:00+00:00",
        "user_id": 7,
        "username": "alice",
        "trigger": "file_saved",
        "relative_path": "docs/final.md",
        "destination_path": null,
        "byte_delta": 42,
        "command": "/bin/sh"
    }"#;
    assert!(serde_json::from_str::<McBrowserAuditEvent>(with_extra).is_err());
}

#[test]
fn path_and_uuid_validation_normalizes_relative_paths_and_rejects_escapes() {
    assert_eq!(
        validate_event_relative_path("projects//alpha/report.txt/").unwrap(),
        "projects/alpha/report.txt"
    );

    for bad_path in [
        "",
        "   ",
        "/",
        "/etc/passwd",
        "../secret.txt",
        "docs/../../secret.txt",
        "./local.txt",
        "docs/./local.txt",
        "dir\\file.txt",
        "file\0name.txt",
        "file\nname.txt",
        "dir/   /file.txt",
        ".af-upload-tmp.12345",
        "uploads/.af-upload-tmp.part",
        ".af-upload-staging",
        ".af-upload-staging/7/session-1",
        "nested/.AF-UPLOAD-STAGING/part",
        "C:secret.txt",
        "D:/windows/system32",
    ] {
        assert!(
            matches!(
                validate_event_relative_path(bad_path),
                Err(McBrowserError::BadRequest(_))
            ),
            "expected path {bad_path:?} to be rejected"
        );
    }

    for copy_or_rename in [
        McBrowserEventTrigger::EntryCopied,
        McBrowserEventTrigger::EntryRenamed,
    ] {
        assert!(matches!(
            validate_event_paths_for_trigger(copy_or_rename, "src/a.txt", None),
            Err(McBrowserError::BadRequest(_))
        ));
        assert!(matches!(
            validate_event_paths_for_trigger(copy_or_rename, "src/a.txt", Some("../escape.txt")),
            Err(McBrowserError::BadRequest(_))
        ));
        let (src, dst) =
            validate_event_paths_for_trigger(copy_or_rename, "src//a.txt", Some("dst//b.txt/"))
                .unwrap();
        assert_eq!(src, "src/a.txt");
        assert_eq!(dst.as_deref(), Some("dst/b.txt"));
    }

    for single_path_trigger in [
        McBrowserEventTrigger::UploadCompleted,
        McBrowserEventTrigger::EntryDeleted,
        McBrowserEventTrigger::FileSaved,
        McBrowserEventTrigger::ShareCreated,
        McBrowserEventTrigger::ShareRevoked,
    ] {
        assert!(matches!(
            validate_event_paths_for_trigger(single_path_trigger, "docs/a.txt", Some("docs/b.txt")),
            Err(McBrowserError::BadRequest(_))
        ));
        let (rel, dst) =
            validate_event_paths_for_trigger(single_path_trigger, "docs//a.txt/", None).unwrap();
        assert_eq!(rel, "docs/a.txt");
        assert_eq!(dst, None);
    }

    let canonical = validate_event_uuid("  550E8400-E29B-41D4-A716-446655440000 ").unwrap();
    assert_eq!(canonical, "550e8400-e29b-41d4-a716-446655440000");
    for bad_uuid in [
        "",
        "not-a-uuid",
        "12345",
        "550e8400-e29b-41d4-a716-44665544000Z",
    ] {
        assert!(matches!(
            validate_event_uuid(bad_uuid),
            Err(McBrowserError::BadRequest(_))
        ));
    }
}

#[test]
fn durable_two_phase_intent_atomic_queue_and_idempotent_finalization() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) \
         VALUES (1, 'admin', 0, 0, 'active'), (2, 'alice', 1048576, 0, 'active')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");

    let default_settings = load_event_settings_for_admin_with_conn(&conn, &admin).unwrap();
    assert!(!default_settings.enabled);

    let pending1 = record_pending_intent_with_conn(
        &conn,
        &alice,
        McBrowserEventTrigger::UploadCompleted,
        "uploads//video.mp4/",
        None,
        1024,
    )
    .unwrap();
    assert!(Uuid::parse_str(&pending1.event.event_id).is_ok());
    assert_eq!(pending1.event.user_id, 2);
    assert_eq!(pending1.event.username, "alice");
    assert_eq!(pending1.event.relative_path, "uploads/video.mp4");
    assert_eq!(pending1.event.destination_path, None);
    assert_eq!(pending1.event.byte_delta, 1024);

    let stored_pending = load_audit_record_by_id_with_conn(&conn, &pending1.event.event_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored_pending.status, AuditEventStatus::Pending);
    assert_eq!(stored_pending.error_code, None);

    let completed1 = finalize_event_completed_with_conn(
        &conn,
        &pending1.event.event_id,
        Some("uploads/video(1).mp4"),
        None,
        2048,
    )
    .unwrap();
    assert_eq!(completed1.status, AuditEventStatus::Completed);
    assert_eq!(completed1.event.relative_path, "uploads/video(1).mp4");
    assert_eq!(completed1.event.byte_delta, 2048);

    let queue_list_disabled =
        list_event_queue_for_admin_with_conn(&conn, &admin, &EventQueueListQuery::default())
            .unwrap();
    assert!(!queue_list_disabled.enabled);
    assert!(queue_list_disabled.tasks.is_empty());

    let enabled_settings = save_event_settings_for_admin_with_conn(
        &conn,
        &admin,
        EventSettingsDocument { enabled: true },
    )
    .unwrap();
    assert!(enabled_settings.enabled);

    let pending2 = record_pending_intent_with_conn(
        &conn,
        &alice,
        McBrowserEventTrigger::EntryCopied,
        "docs/source.txt",
        Some("docs/copy.txt"),
        512,
    )
    .unwrap();
    let queue_while_pending =
        list_event_queue_for_admin_with_conn(&conn, &admin, &EventQueueListQuery::default())
            .unwrap();
    assert!(queue_while_pending.enabled);
    assert!(
        queue_while_pending.tasks.is_empty(),
        "pending events must never be enqueued before completion"
    );

    let completed2 = finalize_event_completed_with_conn(
        &conn,
        &pending2.event.event_id,
        None,
        Some("docs/copy(1).txt"),
        512,
    )
    .unwrap();
    assert_eq!(completed2.status, AuditEventStatus::Completed);
    assert_eq!(
        completed2.event.destination_path.as_deref(),
        Some("docs/copy(1).txt")
    );

    let completed2_repeat = finalize_event_completed_with_conn(
        &conn,
        &pending2.event.event_id,
        None,
        Some("docs/copy(1).txt"),
        512,
    )
    .unwrap();
    assert_eq!(completed2_repeat.event, completed2.event);
    assert_eq!(completed2_repeat.status, AuditEventStatus::Completed);

    let queue_after_complete =
        list_event_queue_for_admin_with_conn(&conn, &admin, &EventQueueListQuery::default())
            .unwrap();
    assert_eq!(queue_after_complete.tasks.len(), 1);
    assert_eq!(
        queue_after_complete.tasks[0].event_id,
        pending2.event.event_id
    );
    assert_eq!(
        queue_after_complete.tasks[0].status,
        EventQueueStatus::Queued
    );
    assert_eq!(queue_after_complete.tasks[0].event, completed2.event);
    assert_eq!(queue_after_complete.tasks[0].acknowledged_at, None);

    assert!(matches!(
        finalize_event_failed_with_conn(&conn, &pending2.event.event_id, Some("LATE_ERR")),
        Err(McBrowserError::Conflict(_))
    ));

    let pending3 = record_pending_intent_with_conn(
        &conn,
        &alice,
        McBrowserEventTrigger::FileSaved,
        "notes/todo.txt",
        None,
        256,
    )
    .unwrap();
    let failed3 = finalize_event_failed_with_conn(
        &conn,
        &pending3.event.event_id,
        Some("QUOTA_EXCEEDED\nwith-control-stripped"),
    )
    .unwrap();
    assert_eq!(failed3.status, AuditEventStatus::Failed);
    assert_eq!(failed3.event.byte_delta, 0);
    assert_eq!(
        failed3.error_code.as_deref(),
        Some("QUOTA_EXCEEDEDwith-control-stripped")
    );

    let failed3_repeat =
        finalize_event_failed_with_conn(&conn, &pending3.event.event_id, Some("IGNORED")).unwrap();
    assert_eq!(failed3_repeat.status, AuditEventStatus::Failed);
    assert_eq!(failed3_repeat.error_code, failed3.error_code);

    assert!(matches!(
        finalize_event_completed_with_conn(&conn, &pending3.event.event_id, None, None, 256),
        Err(McBrowserError::Conflict(_))
    ));

    let queue_after_fail =
        list_event_queue_for_admin_with_conn(&conn, &admin, &EventQueueListQuery::default())
            .unwrap();
    assert_eq!(queue_after_fail.tasks.len(), 1);

    let acked =
        acknowledge_event_queue_task_for_admin_with_conn(&conn, &admin, &pending2.event.event_id)
            .unwrap();
    assert_eq!(acked.status, EventQueueStatus::Acknowledged);
    assert!(acked.acknowledged_at.is_some());

    let acked_again =
        acknowledge_event_queue_task_for_admin_with_conn(&conn, &admin, &pending2.event.event_id)
            .unwrap();
    assert_eq!(acked_again.status, EventQueueStatus::Acknowledged);
    assert_eq!(acked_again.acknowledged_at, acked.acknowledged_at);
}

#[test]
fn post_publication_db_failure_retains_pending_intent_and_atomic_completion_enqueue_rolls_back() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) \
         VALUES (1, 'admin', 0, 0, 'active'), (2, 'alice', 1048576, 0, 'active')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");

    save_event_settings_for_admin_with_conn(&conn, &admin, EventSettingsDocument { enabled: true })
        .unwrap();

    let pending = record_pending_intent_with_conn(
        &conn,
        &alice,
        McBrowserEventTrigger::EntryDeleted,
        "archive/old.zip",
        None,
        -4096,
    )
    .unwrap();

    conn.execute_batch(
        r#"
        CREATE TRIGGER fail_queue_insert
        BEFORE INSERT ON mcbrowser_event_queue
        BEGIN
            SELECT RAISE(ABORT, 'simulated queue storage failure');
        END;
        "#,
    )
    .unwrap();

    let outcome = finalize_published_mutation_with_conn(&conn, &pending, None, None, -4096);
    assert_eq!(
        outcome,
        PostPublicationAuditOutcome::RetainedPending {
            event_id: pending.event.event_id.clone()
        }
    );

    let retained = load_audit_record_by_id_with_conn(&conn, &pending.event.event_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.status, AuditEventStatus::Pending);
    assert_eq!(retained.event.relative_path, "archive/old.zip");

    conn.execute_batch("DROP TRIGGER fail_queue_insert")
        .unwrap();
    let recovered = finalize_published_mutation_with_conn(&conn, &pending, None, None, -4096);
    assert!(matches!(
        recovered,
        PostPublicationAuditOutcome::Finalized(_)
    ));

    let (op_out, op_audit) = execute_with_audit_intent_conn(
        &conn,
        &alice,
        McBrowserEventTrigger::ShareCreated,
        "shared/report.pdf",
        None,
        0,
        |_conn, _intent| Ok((None, None, 0, "share-id-123", true)),
    )
    .unwrap();
    assert_eq!(op_out, "share-id-123");
    assert!(matches!(
        op_audit,
        PostPublicationAuditOutcome::Finalized(ref rec)
            if rec.status == AuditEventStatus::Completed
                && rec.event.trigger == McBrowserEventTrigger::ShareCreated
    ));

    let unpublished_err = execute_with_audit_intent_conn::<(), _>(
        &conn,
        &alice,
        McBrowserEventTrigger::FileSaved,
        "docs/locked.txt",
        None,
        100,
        |_conn, _intent| Err(McBrowserError::Conflict("Target locked".to_string())),
    )
    .unwrap_err();
    assert!(matches!(unpublished_err, McBrowserError::Conflict(_)));

    let failed_list = list_audit_events_for_admin_with_conn(
        &conn,
        &admin,
        &AuditListQuery {
            status: Some("failed".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(failed_list.events.len(), 1);
    assert_eq!(failed_list.events[0].event.relative_path, "docs/locked.txt");
    assert_eq!(failed_list.events[0].event.byte_delta, 0);
    assert_eq!(
        failed_list.events[0].error_code.as_deref(),
        Some("CONFLICT")
    );
}

#[tokio::test]
async fn admin_http_routes_enforce_live_lifecycle_no_store_bounds_and_prevent_owner_leaks() {
    let _guard = super::super::TEST_DATABASE_LOCK.lock().await;
    let _db = IsolatedTestDb::new();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES \
             (1, 'admin', 'admin'), \
             (2, 'alice', 'user'), \
             (3, 'demoted_admin', 'user'), \
             (4, 'suspended_admin', 'admin')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES \
             (1, 'admin', 0, 0, 'active'), \
             (2, 'alice', 1048576, 0, 'active'), \
             (3, 'demoted_admin', 0, 0, 'active'), \
             (4, 'suspended_admin', 0, 0, 'suspended')",
            [],
        )
        .unwrap();
    }

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");
    let demoted_admin = make_user(3, "demoted_admin", "admin");
    let suspended_admin = make_user(4, "suspended_admin", "admin");
    let deleted_admin = make_user(999, "deleted_admin", "admin");
    let mut plugin_admin = make_user(1, "admin", "admin");
    plugin_admin.plugin_id = Some("sonarr".to_string());

    for (method, uri) in [
        ("GET", "/mcbrowser/events"),
        ("GET", "/mcbrowser/audit-events"),
        ("GET", "/mcbrowser/events/settings"),
        ("PUT", "/mcbrowser/events/settings"),
        ("GET", "/mcbrowser/events/queue"),
        (
            "POST",
            "/mcbrowser/events/queue/550e8400-e29b-41d4-a716-446655440000/ack",
        ),
    ] {
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    for (caller, expected_status) in [
        (alice.clone(), StatusCode::FORBIDDEN),
        (plugin_admin, StatusCode::FORBIDDEN),
        (demoted_admin, StatusCode::FORBIDDEN),
        (suspended_admin, StatusCode::FORBIDDEN),
        (deleted_admin, StatusCode::UNAUTHORIZED),
    ] {
        for (method, uri, body) in [
            ("GET", "/mcbrowser/events", ""),
            ("GET", "/mcbrowser/events?user_id=2", ""),
            ("GET", "/mcbrowser/events/settings", ""),
            ("PUT", "/mcbrowser/events/settings", r#"{"enabled":true}"#),
            ("GET", "/mcbrowser/events/queue", ""),
            (
                "POST",
                "/mcbrowser/events/queue/550e8400-e29b-41d4-a716-446655440000/ack",
                "",
            ),
        ] {
            let resp = router()
                .layer(Extension(caller.clone()))
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                expected_status,
                "caller={} {method} {uri}",
                caller.username
            );
            assert_eq!(
                resp.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
        }
    }

    if !std::env::var("CSRF_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        let csrf_app = Router::new()
            .merge(router())
            .layer(middleware::from_fn(csrf_middleware))
            .layer(Extension(admin.clone()));
        let csrf_resp = csrf_app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mcbrowser/events/settings")
                    .header("content-type", "application/json")
                    .header("cookie", "aetherflow_session=tok")
                    .body(Body::from(r#"{"enabled":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csrf_resp.status(), StatusCode::FORBIDDEN);
    }

    let get_settings_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/events/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_settings_resp.status(), StatusCode::OK);
    assert_eq!(
        get_settings_resp
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let settings_bytes = get_settings_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let settings_json: serde_json::Value = serde_json::from_slice(&settings_bytes).unwrap();
    assert_eq!(settings_json["enabled"], false);
    assert_eq!(settings_json["queue_enabled"], false);

    for bad_settings_body in [
        r#"{}"#,
        r#"{"enabled":true,"queue_enabled":false}"#,
        r#"{"enabled":true,"webhook_url":"http://127.0.0.1"}"#,
    ] {
        let bad_put = router()
            .layer(Extension(admin.clone()))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mcbrowser/events/settings")
                    .header("content-type", "application/json")
                    .body(Body::from(bad_settings_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_put.status(), StatusCode::BAD_REQUEST);
    }

    let put_settings_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/events/settings")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_settings_resp.status(), StatusCode::OK);
    let put_settings_bytes = put_settings_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let put_settings_json: serde_json::Value = serde_json::from_slice(&put_settings_bytes).unwrap();
    assert_eq!(put_settings_json["enabled"], true);
    assert_eq!(put_settings_json["queue_enabled"], true);

    let p_upload = record_pending_intent(
        &alice,
        McBrowserEventTrigger::UploadCompleted,
        "media/photo.png",
        None,
        4096,
    )
    .unwrap();
    let c_upload = finalize_event_completed(&p_upload.event.event_id, None, None, 4096).unwrap();

    let p_rename = record_pending_intent(
        &alice,
        McBrowserEventTrigger::EntryRenamed,
        "media/photo.png",
        Some("media/banner.png"),
        0,
    )
    .unwrap();
    let c_rename =
        finalize_event_completed(&p_rename.event.event_id, None, Some("media/banner.png"), 0)
            .unwrap();

    let p_failed = record_pending_intent(
        &alice,
        McBrowserEventTrigger::EntryDeleted,
        "media/missing.png",
        None,
        0,
    )
    .unwrap();
    let _ = finalize_event_failed(&p_failed.event.event_id, Some("NOT_FOUND")).unwrap();

    let list_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/events?limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    assert_eq!(
        list_resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let list_bytes = list_resp.into_body().collect().await.unwrap().to_bytes();
    let list_doc: AuditEventsListResponse = serde_json::from_slice(&list_bytes).unwrap();
    assert_eq!(list_doc.events.len(), 2);
    assert!(list_doc.truncated);
    assert_eq!(list_doc.events[0].event.event_id, p_failed.event.event_id);
    assert_eq!(list_doc.events[1].event.event_id, c_rename.event.event_id);

    let filtered_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/audit-events?status=completed&trigger=upload_completed&user_id=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered_resp.status(), StatusCode::OK);
    let filtered_bytes = filtered_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let filtered_doc: AuditEventsListResponse = serde_json::from_slice(&filtered_bytes).unwrap();
    assert_eq!(filtered_doc.events.len(), 1);
    assert!(!filtered_doc.truncated);
    assert_eq!(filtered_doc.events[0].event, c_upload.event);

    for bad_uri in [
        "/mcbrowser/events?limit=0",
        "/mcbrowser/events?limit=501",
        "/mcbrowser/events?status=unknown",
        "/mcbrowser/events?trigger=before_upload",
        "/mcbrowser/events?unknown_param=1",
    ] {
        let bad_resp = router()
            .layer(Extension(admin.clone()))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(bad_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST, "{bad_uri}");
    }

    let queue_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/events/queue?status=queued")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(queue_resp.status(), StatusCode::OK);
    let queue_bytes = queue_resp.into_body().collect().await.unwrap().to_bytes();
    let queue_doc: EventQueueListResponse = serde_json::from_slice(&queue_bytes).unwrap();
    assert!(queue_doc.enabled);
    assert_eq!(queue_doc.tasks.len(), 2);
    assert_eq!(queue_doc.tasks[0].event_id, c_upload.event.event_id);
    assert_eq!(queue_doc.tasks[1].event_id, c_rename.event.event_id);

    let ack_uri = format!("/mcbrowser/events/queue/{}/ack", c_upload.event.event_id);
    let ack_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&ack_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ack_resp.status(), StatusCode::OK);
    assert_eq!(
        ack_resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let ack_bytes = ack_resp.into_body().collect().await.unwrap().to_bytes();
    let ack_doc: AcknowledgeQueueTaskResponse = serde_json::from_slice(&ack_bytes).unwrap();
    assert!(ack_doc.success);
    assert_eq!(ack_doc.task.status, EventQueueStatus::Acknowledged);
    assert!(ack_doc.task.acknowledged_at.is_some());

    let rem_queue_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/events/queue?status=queued")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let rem_bytes = rem_queue_resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let rem_doc: EventQueueListResponse = serde_json::from_slice(&rem_bytes).unwrap();
    assert_eq!(rem_doc.tasks.len(), 1);
    assert_eq!(rem_doc.tasks[0].event_id, c_rename.event.event_id);
}
