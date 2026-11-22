use super::channels::{
    parse_custom_webhook_header, validate_notification_channel_config, WEBHOOK_HEADER_FIELDS,
};
use super::engine::{
    claim_due_deliveries_in_conn, commit_rule_trigger_in_conn, complete_claimed_delivery_in_conn,
    load_delivery_context_in_conn, service_down_confirmed, ClaimedDelivery, DeliveryReceiptCommit,
    MAX_DELIVERIES_PER_TICK, MAX_DELIVERY_ATTEMPTS, RULE_COOLDOWN_SECS,
};
use super::recovery::replace_verified_recovery_codes;
use super::webhook::{
    is_allowed_webhook_ip, is_public_webhook_ip, parse_webhook_url, parse_webhook_url_with,
    sanitize_diagnostic_error, webhook_client, ChannelDispatchError, PreparedChannelRequest,
};
use super::*;
use crate::auth::AuthUser;
use axum::extract::{Extension, Path};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use chrono::Utc;
use rusqlite::params;
use std::time::Duration;

#[tokio::test]
async fn notification_rule_create_and_partial_update_validate_the_resulting_rule() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();

    for value in ["85%", "> 90", "NaN", "inf", "-1", "101"] {
        let response = create_notification_rule(Json(CreateRuleReq {
            name: "Test".into(),
            condition_type: "disk_usage".into(),
            condition_value: value.into(),
            level: "warning".into(),
        }))
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value}");
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("VALIDATION_ERROR"));
    }
    let response = create_notification_rule(Json(CreateRuleReq {
        name: "Test".into(),
        condition_type: "service_down".into(),
        condition_value: "netdata".into(),
        level: " CrItIcAl ".into(),
    }))
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let conn = af_db::get_read_conn().unwrap();
    let (id, level): (i64, String) = conn
        .query_row(
            "SELECT id, level FROM notification_rules WHERE name = 'Test'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(level, "critical");
    drop(conn);

    let response = update_notification_rule(
        Path(id),
        Json(UpdateRuleReq {
            condition_type: Some("memory_usage".into()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = update_notification_rule(
        Path(id),
        Json(UpdateRuleReq {
            condition_type: Some("memory_usage".into()),
            condition_value: Some("100".into()),
            level: Some("INFO".into()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = update_notification_rule(
        Path(id),
        Json(UpdateRuleReq {
            level: Some("error".into()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn forbidden_webhook_headers_are_rejected_and_cannot_be_parsed_for_dispatch() {
    for name in [
        "Host",
        "Content-LENGTH",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "Upgrade",
        "TE",
        "Trailer",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection",
    ] {
        let value = serde_json::json!("invalid override");
        assert!(
            parse_custom_webhook_header(name, &value).is_none(),
            "{name}"
        );
        for field in WEBHOOK_HEADER_FIELDS {
            let config = serde_json::json!({
                "url": "https://example.test/hook",
                (field): {(name): value},
            });
            assert!(
                validate_notification_channel_config("webhook", &config).is_err(),
                "{field}.{name}"
            );
        }
    }
    let config = serde_json::json!({
        "url": "https://example.test/hook",
        "headers": {"Authorization": "Bearer test", "X-Event": "alarm"}
    });
    assert!(validate_notification_channel_config("webhook", &config).is_ok());
    assert!(parse_custom_webhook_header("X-Event", &serde_json::json!("alert")).is_some());
}

#[test]
fn service_down_rule_skips_unknown_then_resumes_on_known_state() {
    assert!(!service_down_confirmed(None, "Fixture"));
    let mut services = std::collections::HashMap::new();
    services.insert(
        "Fixture".to_string(),
        af_services::ServiceStatusItem {
            process: "fixture".into(),
            status: "running".into(),
            ..Default::default()
        },
    );
    assert!(!service_down_confirmed(Some(&services), "fixture"));
    services.get_mut("Fixture").unwrap().status = "stopped".into();
    assert!(service_down_confirmed(Some(&services), "fixture"));
    assert!(!service_down_confirmed(None, "fixture"));
    services.get_mut("Fixture").unwrap().status = "running".into();
    assert!(!service_down_confirmed(Some(&services), "FIXTURE"));
}

fn recovery_database() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY,totp_secret TEXT,totp_enabled INTEGER,password_hash TEXT,last_totp_step INTEGER DEFAULT -1);
        INSERT INTO users VALUES (1,'JBSWY3DPEHPK3PXP',1,'test-hash',-1);
        CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY,user_id INTEGER,code_hash TEXT,used INTEGER DEFAULT 0);
        INSERT INTO recovery_codes VALUES (1,1,'old-hash',0);").unwrap();
    conn
}

fn recovery_totp() -> String {
    let key = data_encoding::BASE32_NOPAD
        .decode(b"JBSWY3DPEHPK3PXP")
        .unwrap();
    totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &key, Utc::now().timestamp() as u64)
}

#[test]
fn recovery_regeneration_consumes_totp_and_rejects_replay_or_changed_credentials() {
    let conn = recovery_database();
    let code = recovery_totp();
    assert!(
        replace_verified_recovery_codes(&conn, 1, "JBSWY3DPEHPK3PXP", "test-hash", "", true)
            .unwrap()
            .is_none()
    );
    assert!(replace_verified_recovery_codes(
        &conn,
        1,
        "JBSWY3DPEHPK3PXP",
        "test-hash",
        &code,
        true
    )
    .unwrap()
    .is_some());
    let hashes: Vec<String> = conn
        .prepare("SELECT code_hash FROM recovery_codes ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(replace_verified_recovery_codes(
        &conn,
        1,
        "JBSWY3DPEHPK3PXP",
        "test-hash",
        &code,
        true
    )
    .unwrap()
    .is_none());
    assert!(replace_verified_recovery_codes(
        &conn,
        1,
        "JBSWY3DPEHPK3PXP",
        "stale-password-hash",
        &code,
        true
    )
    .unwrap()
    .is_none());
    let unchanged: Vec<String> = conn
        .prepare("SELECT code_hash FROM recovery_codes ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(hashes, unchanged);
}

#[test]
fn recovery_storage_failure_rolls_back_totp_consumption_and_existing_codes() {
    let conn = recovery_database();
    let code = recovery_totp();
    conn.execute_batch("CREATE TRIGGER reject_recovery BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT,'simulated failure'); END;").unwrap();
    assert!(replace_verified_recovery_codes(
        &conn,
        1,
        "JBSWY3DPEHPK3PXP",
        "test-hash",
        &code,
        true
    )
    .is_err());
    let old: String = conn
        .query_row("SELECT code_hash FROM recovery_codes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(old, "old-hash");
    let step: i64 = conn
        .query_row("SELECT last_totp_step FROM users WHERE id=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(step, -1);
    conn.execute_batch("DROP TRIGGER reject_recovery;").unwrap();
    assert!(replace_verified_recovery_codes(
        &conn,
        1,
        "JBSWY3DPEHPK3PXP",
        "test-hash",
        &code,
        true
    )
    .unwrap()
    .is_some());
}

#[test]
fn webhook_rejects_nonpublic_and_embedded_addresses() {
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.1.1",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "168.63.129.16",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "64:ff9b::7f00:1",
        "2001:db8::1",
        "2002:7f00:1::",
        "3fff::1",
    ] {
        assert!(!is_public_webhook_ip(address.parse().unwrap()), "{address}");
    }
    for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(is_public_webhook_ip(address.parse().unwrap()), "{address}");
    }
}

#[tokio::test]
async fn webhook_dns_rejects_localhost_before_dispatch() {
    assert!(webhook_client("http://localhost/hook").await.is_err());
}

#[test]
fn webhook_url_validation_blocks_alternate_literal_encodings() {
    for target in [
        "file:///etc/passwd",
        "ftp://example.com",
        "http://127.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "https://user:password@example.com/",
    ] {
        assert!(parse_webhook_url(target).is_err(), "{target}");
    }
    assert!(parse_webhook_url("https://example.com/hook").is_ok());
    assert!(parse_webhook_url("https://8.8.8.8/hook").is_ok());
}

#[test]
fn channel_config_validation_blocks_ssrf_and_empty_email_relay() {
    assert!(validate_notification_channel_config(
        "discord",
        &serde_json::json!({"url": "http://169.254.169.254/latest/meta-data/"})
    )
    .is_err());
    assert!(validate_notification_channel_config("email", &serde_json::json!({})).is_err());
    assert!(validate_notification_channel_config(
        "discord",
        &serde_json::json!({"url": "https://8.8.8.8/webhook"})
    )
    .is_ok());
}

#[test]
fn webhook_private_flag_allows_tailscale_cgnat_and_rfc1918_while_blocking_loopback_and_metadata() {
    for private_target in [
        "http://100.64.0.1:8080/hook",
        "https://100.100.100.100/hook",
        "http://192.168.1.50/hook",
        "http://10.1.2.3/hook",
        "http://172.16.5.5/hook",
        "http://[fd00::1]/hook",
    ] {
        assert!(
            parse_webhook_url_with(private_target, false).is_err(),
            "must reject {private_target} when private webhooks are disabled"
        );
        assert!(
            parse_webhook_url_with(private_target, true).is_ok(),
            "must allow {private_target} when private webhooks are enabled"
        );
    }

    for always_blocked in [
        "http://127.0.0.1/hook",
        "http://[::1]/hook",
        "http://0.0.0.0/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://168.63.129.16/machine",
        "http://[::ffff:127.0.0.1]/hook",
        "http://[::ffff:169.254.169.254]/hook",
    ] {
        assert!(
            parse_webhook_url_with(always_blocked, true).is_err(),
            "must ALWAYS block {always_blocked}"
        );
    }
    assert!(is_allowed_webhook_ip("8.8.8.8".parse().unwrap()));
}

#[tokio::test]
async fn regenerate_2fa_rejects_empty_password_on_password_backed_user() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    let pw_hash = bcrypt::hash("correct-password", 4).unwrap();
    let enc_secret = af_db::encrypt_key("JBSWY3DPEHPK3PXP").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "DELETE FROM recovery_codes WHERE user_id IN (9101, 9102);
             DELETE FROM users WHERE id IN (9101, 9102);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role, password_hash, totp_secret, totp_enabled, last_totp_step)
             VALUES (9101, 'totp-pw-user', 'user', ?1, ?2, 1, -1)",
            params![pw_hash, enc_secret],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role, password_hash, totp_secret, totp_enabled, last_totp_step)
             VALUES (9102, 'totp-oauth-user', 'user', '', ?1, 1, -1)",
            params![enc_secret],
        )
        .unwrap();
    }

    let pw_user = AuthUser {
        user_id: 9101,
        username: "totp-pw-user".into(),
        role: "user".into(),
        jti: "jti-9101".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let code = recovery_totp();

    // Empty password must fail with 403 INVALID_CURRENT_PASSWORD and NOT consume the TOTP code
    let empty_pw_resp = regenerate_2fa_recovery_codes(
        Extension(pw_user.clone()),
        HeaderMap::new(),
        Json(RegenerateRecoveryReq {
            code: code.clone(),
            password: String::new(),
        }),
    )
    .await;
    assert_eq!(empty_pw_resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(empty_pw_resp.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INVALID_CURRENT_PASSWORD");

    // Valid password + same unconsumed TOTP code succeeds
    let ok_resp = regenerate_2fa_recovery_codes(
        Extension(pw_user),
        HeaderMap::new(),
        Json(RegenerateRecoveryReq {
            code: code.clone(),
            password: "correct-password".into(),
        }),
    )
    .await;
    assert_eq!(ok_resp.status(), StatusCode::OK);

    // OAuth-only user with empty password_hash can regenerate without a password
    let oauth_user = AuthUser {
        user_id: 9102,
        username: "totp-oauth-user".into(),
        role: "user".into(),
        jti: "jti-9102".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let oauth_resp = regenerate_2fa_recovery_codes(
        Extension(oauth_user),
        HeaderMap::new(),
        Json(RegenerateRecoveryReq {
            code,
            password: String::new(),
        }),
    )
    .await;
    assert_eq!(oauth_resp.status(), StatusCode::OK);
}

fn init_notification_test_schema(conn: &rusqlite::Connection) {
    conn.execute_batch(
        r#"CREATE TABLE notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            level TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE notification_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            condition_type TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            level TEXT DEFAULT 'warning',
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE notification_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            config TEXT NOT NULL,
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
        );"#,
    )
    .unwrap();
    af_db::ensure_notification_schema_invariants(conn).unwrap();
}

fn durable_notification_test_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    init_notification_test_schema(&conn);
    conn
}

fn drain_with_fake_sender<F>(
    conn: &rusqlite::Connection,
    now_epoch: i64,
    mut sender: F,
) -> Vec<(ClaimedDelivery, anyhow::Result<DeliveryReceiptCommit>)>
where
    F: FnMut(&StoredChannel, &PreparedChannelRequest) -> Result<(), ChannelDispatchError>,
{
    let now_rfc3339 = format!("2026-11-21T00:00:{}Z", now_epoch % 60);
    let claimed =
        claim_due_deliveries_in_conn(conn, now_epoch, &now_rfc3339, MAX_DELIVERIES_PER_TICK)
            .unwrap();
    let mut results = Vec::with_capacity(claimed.len());
    for item in claimed {
        let outcome = match load_delivery_context_in_conn(conn, &item) {
            Ok((channel, prepared)) => sender(&channel, &prepared),
            Err(err) => Err(err),
        };
        let commit =
            complete_claimed_delivery_in_conn(conn, &item, &outcome, now_epoch, &now_rfc3339);
        results.push((item, commit));
    }
    results
}

#[test]
fn durable_rule_admission_failure_rolls_back_cooldown_notification_and_intents() {
    let conn = durable_notification_test_db();
    conn.execute(
        "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
         VALUES (1, 'High Disk', 'disk_usage', '90', 'critical', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO notification_channels (id, name, type, config, enabled)
         VALUES (10, 'Ops Hook', 'webhook', '{\"url\":\"https://example.test/hook\",\"headers\":{\"Authorization\":\"Bearer top-secret-token\"}}', 1),
                (11, 'Disabled Hook', 'webhook', '{\"url\":\"https://example.test/off\"}', 0)",
        [],
    )
    .unwrap();

    let rule = af_services::NotificationRule {
        id: 1,
        name: "High Disk".into(),
        condition_type: "disk_usage".into(),
        condition_value: "90".into(),
        level: "critical".into(),
        enabled: true,
        created_at: String::new(),
    };

    // Failure while inserting channel delivery intents must roll back cooldown and notification.
    conn.execute_batch(
        "CREATE TRIGGER fail_delivery_intent BEFORE INSERT ON notification_delivery_log
         BEGIN SELECT RAISE(ABORT, 'simulated delivery queue write failure'); END;",
    )
    .unwrap();
    assert!(commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "Disk / is at 95.0% usage",
        10_000,
        RULE_COOLDOWN_SECS
    )
    .is_err());
    let last_triggered: Option<i64> = conn
        .query_row(
            "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(last_triggered, None);
    let notif_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
        .unwrap();
    assert_eq!(notif_count, 0);
    let delivery_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notification_delivery_log", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(delivery_count, 0);

    conn.execute_batch("DROP TRIGGER fail_delivery_intent;")
        .unwrap();

    // Failure while inserting the local notification must also roll back cooldown.
    conn.execute_batch(
        "CREATE TRIGGER fail_local_notification BEFORE INSERT ON notifications
         BEGIN SELECT RAISE(ABORT, 'simulated notification write failure'); END;",
    )
    .unwrap();
    assert!(commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "Disk / is at 95.0% usage",
        10_000,
        RULE_COOLDOWN_SECS
    )
    .is_err());
    let last_triggered: Option<i64> = conn
        .query_row(
            "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(last_triggered, None);
    conn.execute_batch("DROP TRIGGER fail_local_notification;")
        .unwrap();

    // Once storage recovers, admission commits cooldown, broadcast notification, and enabled-only intents together.
    let committed = commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "Disk / is at 95.0% usage",
        10_000,
        RULE_COOLDOWN_SECS,
    )
    .unwrap()
    .expect("rule must commit after admission failure clears");
    assert_eq!(committed.notification.user_id, None);
    assert_eq!(committed.queued_deliveries, 1);

    let last_triggered: Option<i64> = conn
        .query_row(
            "SELECT last_triggered_at FROM notification_rules WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(last_triggered, Some(10_000));

    let queued_rows: Vec<(i64, String, i32, String)> = conn
        .prepare(
            "SELECT channel_id, status, attempts, COALESCE(last_error, '')
             FROM notification_delivery_log",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        queued_rows,
        vec![(10, "pending".to_string(), 0, String::new())]
    );
}

#[test]
fn restart_recovery_resumes_unsent_deliveries_enforces_durable_cooldown_and_sanitizes_diagnostics()
{
    let conn = durable_notification_test_db();
    let (enc_hook, _) = af_db::encrypt_notification_channel_config_value(
        "webhook",
        &serde_json::json!({
            "url": "https://example.test/alerts?token=hook-secret-123",
            "headers": {
                "Authorization": "Bearer super-secret-bearer",
                "X-Event": "disk-alarm"
            }
        }),
    )
    .unwrap();
    let (enc_tg, _) = af_db::encrypt_notification_channel_config_value(
        "telegram",
        &serde_json::json!({
            "bot_token": "123456:TELEGRAM_SECRET_TOKEN",
            "chat_id": "998877"
        }),
    )
    .unwrap();

    conn.execute(
        "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
         VALUES (1, 'CPU High', 'cpu_usage', '90', 'warning', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO notification_channels (id, name, type, config, enabled)
         VALUES (20, 'Primary Hook', 'webhook', ?1, 1),
                (21, 'Ops Telegram', 'telegram', ?2, 1)",
        params![enc_hook.to_string(), enc_tg.to_string()],
    )
    .unwrap();

    let rule = af_services::NotificationRule {
        id: 1,
        name: "CPU High".into(),
        condition_type: "cpu_usage".into(),
        condition_value: "90".into(),
        level: "warning".into(),
        enabled: true,
        created_at: String::new(),
    };

    // First trigger commits cooldown + local alert + 2 pending delivery intents, then process "restarts" before sending.
    let committed = commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "CPU usage is at 94.0%",
        10_000,
        RULE_COOLDOWN_SECS,
    )
    .unwrap()
    .expect("initial trigger must commit");
    assert_eq!(committed.queued_deliveries, 2);

    // After restart, re-evaluating within cooldown (T+30s) must NOT repeat the alert.
    assert!(commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "CPU usage is at 95.0%",
        10_030,
        RULE_COOLDOWN_SECS,
    )
    .unwrap()
    .is_none());
    let notif_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
        .unwrap();
    assert_eq!(notif_count, 1);

    // Disable Telegram channel before restart drain completes to verify current channel policy is honored.
    conn.execute(
        "UPDATE notification_channels SET enabled = 0 WHERE id = 21",
        [],
    )
    .unwrap();

    // Startup drain at T+5: webhook gets transient 503 with credential-free diagnostic, disabled Telegram fails immediately without network call.
    let mut seen_channels = Vec::new();
    let first_pass = drain_with_fake_sender(&conn, 10_005, |ch, req| {
        seen_channels.push((ch.id, req.target_url.clone(), req.headers.clone()));
        Err(ChannelDispatchError::transient(
            "webhook returned HTTP 503 from https://example.test/alerts?token=hook-secret-123",
            true,
        ))
    });
    assert_eq!(first_pass.len(), 2);
    assert_eq!(seen_channels.len(), 1, "disabled channel must not be sent");
    assert_eq!(seen_channels[0].0, 20);
    assert_eq!(
        seen_channels[0].1,
        "https://example.test/alerts?token=hook-secret-123"
    );
    assert!(
        seen_channels[0].2.iter().any(|(k, v)| {
            k.as_str() == "authorization" && v.to_str().ok() == Some("Bearer super-secret-bearer")
        }),
        "decrypted custom headers must be passed to sender"
    );
    assert!(
        seen_channels[0]
            .2
            .iter()
            .any(|(k, v)| { k.as_str() == "x-event" && v.to_str().ok() == Some("disk-alarm") }),
        "accepted webhook headers must be preserved"
    );

    // Verify diagnostics redact URLs/tokens and never leak credentials.
    let (pending_20, last_20) = channel_delivery_overview_in_conn(&conn, 20);
    assert_eq!(pending_20, 1);
    let last_20 = last_20.unwrap();
    assert_eq!(last_20["status"], "pending");
    assert_eq!(last_20["attempts"], 1);
    let err_20 = last_20["last_error"].as_str().unwrap();
    assert!(!err_20.contains("hook-secret-123"));
    assert!(!err_20.contains("super-secret-bearer"));
    assert!(err_20.contains("503"));

    let (pending_21, last_21) = channel_delivery_overview_in_conn(&conn, 21);
    assert_eq!(pending_21, 0);
    let last_21 = last_21.unwrap();
    assert_eq!(last_21["status"], "failed");
    assert!(last_21["last_error"].as_str().unwrap().contains("disabled"));

    // Before backoff elapses (T+34s, next_attempt_at is 10_035), nothing is claimed.
    let early_pass = drain_with_fake_sender(&conn, 10_034, |_ch, _req| Ok(()));
    assert!(early_pass.is_empty());

    // Once backoff elapses (T+35s), attempt 2 succeeds.
    let retry_pass = drain_with_fake_sender(&conn, 10_035, |ch, _req| {
        assert_eq!(ch.id, 20);
        Ok(())
    });
    assert_eq!(retry_pass.len(), 1);
    assert_eq!(
        retry_pass[0].1.as_ref().unwrap(),
        &DeliveryReceiptCommit::Committed("delivered")
    );

    let (pending_after, last_after) = channel_delivery_overview_in_conn(&conn, 20);
    assert_eq!(pending_after, 0);
    let last_after = last_after.unwrap();
    assert_eq!(last_after["status"], "delivered");
    assert_eq!(last_after["attempts"], 2);

    // Once the 15-minute cooldown expires (T + 900s), the rule can fire again.
    let second_trigger = commit_rule_trigger_in_conn(
        &conn,
        &rule,
        "CPU usage is at 96.0%",
        10_000 + RULE_COOLDOWN_SECS,
        RULE_COOLDOWN_SECS,
    )
    .unwrap();
    assert!(second_trigger.is_some());

    // Sanitizer explicitly strips Telegram/Gotify URLs containing secrets.
    let sanitized = sanitize_diagnostic_error(
        "error sending request for url (https://api.telegram.org/bot123456:TELEGRAM_SECRET_TOKEN/sendMessage): timed out",
    );
    assert!(!sanitized.contains("TELEGRAM_SECRET_TOKEN"));
    assert!(sanitized.contains("[redacted-url]"));
}

#[test]
fn competing_claims_respect_lease_fencing_and_handle_ambiguous_interval() {
    let tmp_dir = std::env::temp_dir().join(format!("af-notif-competing-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let db_path = tmp_dir.join("notifications.sqlite");
    let conn_a = rusqlite::Connection::open(&db_path).unwrap();
    conn_a.busy_timeout(Duration::from_secs(5)).unwrap();
    conn_a.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    init_notification_test_schema(&conn_a);

    let conn_b = rusqlite::Connection::open(&db_path).unwrap();
    conn_b.busy_timeout(Duration::from_secs(5)).unwrap();

    conn_a
        .execute(
            "INSERT INTO notification_rules (id, name, condition_type, condition_value, level, enabled)
             VALUES (1, 'Service Down', 'service_down', 'netdata', 'critical', 1)",
            [],
        )
        .unwrap();
    conn_a
        .execute(
            "INSERT INTO notification_channels (id, name, type, config, enabled)
             VALUES (30, 'Alert Hook', 'webhook', '{\"url\":\"https://example.test/alert\"}', 1)",
            [],
        )
        .unwrap();

    let rule = af_services::NotificationRule {
        id: 1,
        name: "Service Down".into(),
        condition_type: "service_down".into(),
        condition_value: "netdata".into(),
        level: "critical".into(),
        enabled: true,
        created_at: String::new(),
    };

    // Competing evaluators on two separate SQLite connections: only one admits the trigger.
    let first = commit_rule_trigger_in_conn(
        &conn_a,
        &rule,
        "Service netdata is down",
        20_000,
        RULE_COOLDOWN_SECS,
    )
    .unwrap();
    let second = commit_rule_trigger_in_conn(
        &conn_b,
        &rule,
        "Service netdata is down",
        20_000,
        RULE_COOLDOWN_SECS,
    )
    .unwrap();
    assert!(first.is_some());
    assert!(second.is_none());

    // Worker A (conn_a) claims the pending delivery (attempt 1, active lease until 20_060).
    let worker_a_claims = claim_due_deliveries_in_conn(
        &conn_a,
        20_000,
        "2026-11-21T00:00:00Z",
        MAX_DELIVERIES_PER_TICK,
    )
    .unwrap();
    assert_eq!(worker_a_claims.len(), 1);
    let claim_a = worker_a_claims[0].clone();
    assert_eq!(claim_a.attempts, 1);
    assert!(!claim_a.reclaimed_expired_lease);

    // Competing Worker B (conn_b) running while lease is active must NOT claim the same delivery.
    let worker_b_early = claim_due_deliveries_in_conn(
        &conn_b,
        20_030,
        "2026-11-21T00:00:30Z",
        MAX_DELIVERIES_PER_TICK,
    )
    .unwrap();
    assert!(worker_b_early.is_empty());

    // Simulate ambiguous crash/stall past lease expiry (T = 20_061): Worker B reclaims attempt 2.
    let worker_b_claims = claim_due_deliveries_in_conn(
        &conn_b,
        20_061,
        "2026-11-21T00:01:01Z",
        MAX_DELIVERIES_PER_TICK,
    )
    .unwrap();
    assert_eq!(worker_b_claims.len(), 1);
    let claim_b = worker_b_claims[0].clone();
    assert_eq!(claim_b.id, claim_a.id);
    assert_eq!(claim_b.attempts, 2);
    assert!(claim_b.reclaimed_expired_lease);
    assert_ne!(claim_b.claim_token, claim_a.claim_token);
    assert!(load_delivery_context_in_conn(&conn_a, &claim_a).is_err());
    assert!(load_delivery_context_in_conn(&conn_b, &claim_b).is_ok());

    // Late Worker A tries to commit its stale receipt -> must be fenced out!
    let stale_res = complete_claimed_delivery_in_conn(
        &conn_a,
        &claim_a,
        &Ok(()),
        20_062,
        "2026-11-21T00:01:02Z",
    )
    .unwrap();
    assert_eq!(stale_res, DeliveryReceiptCommit::StaleClaim);

    // Worker B finishes and commits cleanly with an operator-visible note about the reclaimed claim.
    let fresh_res = complete_claimed_delivery_in_conn(
        &conn_b,
        &claim_b,
        &Ok(()),
        20_063,
        "2026-11-21T00:01:03Z",
    )
    .unwrap();
    assert_eq!(fresh_res, DeliveryReceiptCommit::Committed("delivered"));
    let (status, attempts, last_error): (String, i32, String) = conn_a
        .query_row(
            "SELECT status, attempts, COALESCE(last_error, '') FROM notification_delivery_log WHERE id = ?1",
            params![claim_b.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "delivered");
    assert_eq!(attempts, 2);
    assert!(last_error.contains("reclaiming expired claim"));

    // Now test ambiguous interval on the FINAL attempt (attempts == MAX_DELIVERY_ATTEMPTS):
    // when the final sending claim's lease expires without receipt, recovery must NOT resend
    // a 4th time and must transition the row to terminal `uncertain`.
    conn_a
        .execute(
            "INSERT INTO notification_delivery_log (
                id, channel_id, channel_type, notification_id, status, attempts,
                last_error, completed_at, next_attempt_at, claim_token, lease_until, updated_at
             ) VALUES (999, 30, 'webhook', 1, 'sending', ?1, '', '', 0, 'lost-final-token', 20100, 20040)",
            params![MAX_DELIVERY_ATTEMPTS],
        )
        .unwrap();

    let reclaimed_after_final = claim_due_deliveries_in_conn(
        &conn_b,
        20_101,
        "2026-11-21T00:01:41Z",
        MAX_DELIVERIES_PER_TICK,
    )
    .unwrap();
    assert!(
        reclaimed_after_final.is_empty(),
        "expired final attempt must not be resent past MAX_DELIVERY_ATTEMPTS"
    );
    let (final_status, final_attempts, final_completed, final_err): (String, i32, String, String) =
        conn_a
            .query_row(
                "SELECT status, attempts, COALESCE(CAST(completed_at AS TEXT), ''), COALESCE(last_error, '')
                 FROM notification_delivery_log WHERE id = 999",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
    assert_eq!(final_status, "uncertain");
    assert_eq!(final_attempts, MAX_DELIVERY_ATTEMPTS);
    assert!(!final_completed.is_empty());
    assert!(final_err.contains("uncertain"));

    // Also verify receipt-commit failure right after upstream accepts leaves row in `sending`
    // (does NOT revert to `pending`) so it stays bounded by lease & attempt cap.
    conn_a
        .execute(
            "INSERT INTO notification_delivery_log (
                id, channel_id, channel_type, notification_id, status, attempts,
                last_error, completed_at, next_attempt_at, claim_token, lease_until, updated_at
             ) VALUES (1000, 30, 'webhook', 1, 'pending', 0, '', '', 20200, '', NULL, 20200)",
            [],
        )
        .unwrap();
    let claim_c = claim_due_deliveries_in_conn(
        &conn_a,
        20_200,
        "2026-11-21T00:03:20Z",
        MAX_DELIVERIES_PER_TICK,
    )
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(claim_c.id, 1000);
    conn_a
        .execute_batch(
            "CREATE TRIGGER fail_receipt_commit BEFORE UPDATE ON notification_delivery_log
             BEGIN SELECT RAISE(ABORT, 'simulated db outage after upstream accept'); END;",
        )
        .unwrap();
    assert!(complete_claimed_delivery_in_conn(
        &conn_a,
        &claim_c,
        &Ok(()),
        20_201,
        "2026-11-21T00:03:21Z",
    )
    .is_err());
    conn_a
        .execute_batch("DROP TRIGGER fail_receipt_commit;")
        .unwrap();
    let (post_fail_status, post_fail_attempts): (String, i32) = conn_b
        .query_row(
            "SELECT status, attempts FROM notification_delivery_log WHERE id = 1000",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(post_fail_status, "sending");
    assert_eq!(post_fail_attempts, 1);

    drop(conn_b);
    drop(conn_a);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn test_notification_channel_returns_500_on_db_error_instead_of_404() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();

    // Missing row on an intact table must still return 404 NOT_FOUND.
    let missing_resp = test_notification_channel(Path(999_999)).await;
    assert_eq!(missing_resp.status(), StatusCode::NOT_FOUND);

    // Dropping the table triggers a real SQLite error, which must return 500 INTERNAL_SERVER_ERROR.
    let conn = af_db::get_conn().unwrap();
    conn.execute("DROP TABLE notification_channels", [])
        .unwrap();
    drop(conn);

    let db_err_resp = test_notification_channel(Path(1)).await;
    assert_eq!(db_err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(db_err_resp.into_body(), 4096)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&body)
        .unwrap()
        .contains("INTERNAL_ERROR"));
}
