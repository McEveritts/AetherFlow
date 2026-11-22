use super::{consume_live_ws_ticket, issue_ws_ticket_for_user, websocket_message_for_session};

#[test]
fn websocket_progress_filters_installer_output_per_recipient() {
    let message = serde_json::json!({
        "type": "package:progress", "package_id": "sonarr", "job_id": "job-42",
        "action": "update", "status": "updating", "progress": 42,
        "started_at": "fixture", "line": "PASSWORD=private-installer-output",
        "message": "PASSWORD=private-installer-output", "stderr": "TOKEN=private-installer-output",
    })
    .to_string();
    let admin = websocket_message_for_session(message.clone(), true).unwrap();
    assert!(
        !admin.contains("private-installer-output"),
        "raw secrets must be redacted for admin"
    );
    assert!(
        admin.contains("[REDACTED]"),
        "sanitized secrets must be marked REDACTED"
    );
    let admin_val: serde_json::Value = serde_json::from_str(&admin).unwrap();
    assert_eq!(admin_val["job_id"], "job-42");
    assert_eq!(admin_val["package_id"], "sonarr");
    assert_eq!(admin_val["status"], "updating");
    assert_eq!(admin_val["progress"], 42);
    assert_eq!(admin_val["line"], "PASSWORD=[REDACTED]");

    let ordinary = websocket_message_for_session(message, false).unwrap();
    assert!(!ordinary.contains("private-installer-output"));
    let ordinary: serde_json::Value = serde_json::from_str(&ordinary).unwrap();
    assert_eq!(ordinary["job_id"], "job-42");
    assert_eq!(ordinary["package_id"], "sonarr");
    assert_eq!(ordinary["status"], "updating");
    assert_eq!(ordinary["progress"], 42);
    assert_eq!(ordinary["line"], "Updating application.");
    assert!(ordinary.get("stderr").is_none());
    assert!(ordinary.get("message").is_none());
}

#[test]
fn test_websocket_progress_escaped_quote_and_nested_json_redaction() {
    let message = serde_json::json!({
        "type": "package:progress", "package_id": "sonarr", "job_id": "job-99",
        "action": "install", "status": "installing", "progress": 50,
        "line": "{\"password\": \"my\\\"super\\\\secret\"}",
        "message": "auth config: {\"credentials\": {\"token\": \"nested\\\"token\\\"val\"}}",
        "stderr": "error: password=\"truncated\\\"pass",
    })
    .to_string();

    let admin = websocket_message_for_session(message, true).unwrap();
    assert!(!admin.contains("super\\secret"));
    assert!(!admin.contains("nested\\\"token"));
    assert!(!admin.contains("truncated\\\"pass"));
    assert!(admin.contains("[REDACTED]"));
}

#[test]
fn websocket_service_snapshots_cannot_bypass_progress_sanitization() {
    let message = serde_json::json!({
        "type": "METRICS_UPDATE", "data": {
            "system": {"cpu_usage": 20}, "services": {"sonarr": {
                "job_id": "job-42", "job_status": "updating", "progress": 42,
                "api_key": "synthetic-service-credential",
                "future_private_field": "synthetic-private-config",
                "log_line": "STEP=private-installer-output",
                "last_job": {"job_id": "old-job", "status": "failed", "message": "private-installer-output"},
            }}
        }
    }).to_string();
    assert_eq!(
        websocket_message_for_session(message.clone(), true).unwrap(),
        message
    );
    let ordinary = websocket_message_for_session(message, false).unwrap();
    assert!(!ordinary.contains("private-installer-output"));
    let ordinary: serde_json::Value = serde_json::from_str(&ordinary).unwrap();
    assert!(!ordinary
        .to_string()
        .contains("synthetic-service-credential"));
    assert!(!ordinary.to_string().contains("synthetic-private-config"));
    assert!(ordinary["data"]["services"]["sonarr"]
        .get("api_key")
        .is_none());
    assert_eq!(ordinary["data"]["services"]["sonarr"]["job_id"], "job-42");
    assert_eq!(ordinary["data"]["services"]["sonarr"]["progress"], 42);
    assert_eq!(ordinary["data"]["system"]["cpu_usage"], 20);
}

#[test]
fn established_websocket_privileges_are_revoked_and_never_promoted() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection.execute_batch(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL); INSERT INTO users VALUES (1, 'admin');",
    ).unwrap();
    let ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
    let mut entry = consume_live_ws_ticket(&connection, &ticket).unwrap();
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        Some(true)
    );
    connection
        .execute("UPDATE users SET role='user' WHERE id=1", [])
        .unwrap();
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        Some(false)
    );
    connection
        .execute("UPDATE users SET role='admin' WHERE id=1", [])
        .unwrap();
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        Some(false)
    );
    connection.execute("DELETE FROM users", []).unwrap();
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        None
    );
    connection.execute_batch("DROP TABLE users").unwrap();
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        None
    );
}

#[test]
fn issued_websocket_tickets_are_single_use_and_reject_deleted_users() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL); INSERT INTO users VALUES (1, 'admin'), (2, 'user');",
        )
        .unwrap();
    let ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
    assert_eq!(
        consume_live_ws_ticket(&connection, &ticket)
            .unwrap()
            .user_id,
        1
    );
    assert!(consume_live_ws_ticket(&connection, &ticket).is_none());
    let demoted_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
    connection
        .execute("UPDATE users SET role='user' WHERE id=1", [])
        .unwrap();
    assert!(
        !consume_live_ws_ticket(&connection, &demoted_ticket)
            .unwrap()
            .diagnostics_allowed
    );
    let admin_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
    connection
        .execute("UPDATE users SET role='admin' WHERE id=1", [])
        .unwrap();
    assert!(
        consume_live_ws_ticket(&connection, &admin_ticket)
            .unwrap()
            .diagnostics_allowed
    );
    let deleted_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
    let live_ticket = issue_ws_ticket_for_user(2, "127.0.0.1");
    connection
        .execute("DELETE FROM users WHERE id = 1", [])
        .unwrap();
    assert!(consume_live_ws_ticket(&connection, &deleted_ticket).is_none());
    assert_eq!(
        consume_live_ws_ticket(&connection, &live_ticket)
            .unwrap()
            .user_id,
        2
    );
    connection.execute("DROP TABLE users", []).unwrap();
    let unavailable_ticket = issue_ws_ticket_for_user(2, "127.0.0.1");
    assert!(consume_live_ws_ticket(&connection, &unavailable_ticket).is_none());
}

#[test]
fn websocket_jti_revocation_does_not_rebind_after_grace_expires() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT 'admin', role TEXT NOT NULL, sessions_revoked_after INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
             INSERT INTO users VALUES (1, 'admin', 'admin', 0);
             INSERT INTO revoked_tokens VALUES ('jti-rotated-old', datetime('now', '+1 hour'));",
        )
        .unwrap();
    let mut entry = super::WsTicketEntry {
        user_id: 1,
        client_ip: "127.0.0.1".to_string(),
        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(30),
        diagnostics_allowed: true,
        session_jti: "jti-rotated-old".to_string(),
        session_ver: Some(0),
    };
    assert_eq!(
        super::refresh_ws_authorization(&connection, &mut entry),
        None
    );
}
