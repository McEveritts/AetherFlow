use super::ai_providers::{call_gemini_api, resolve_provider, ALLOWED_AI_MODELS};
use super::audit_tests::init_ai_test_settings;
use super::flowai::{
    build_support_prompt, extract_proposed_action, extract_service_target, run_chat_session,
    test_ai_connection,
};
use crate::auth::AuthUser;
use axum::http::StatusCode;
use axum::response::{Json, Response};

#[tokio::test]
async fn ai_models_support_context_modes_and_non_admin_error_sanitization() {
    for model in [
        "gemini-4-argon",
        "gemini-4-carbon",
        "gemini-4-neon",
        "gemini-4-hydrogen",
        "gpt-6.2-sol",
        "gpt-6.2-astra",
        "gpt-4o",
        "gpt-4o-mini",
        "o3",
        "claude-sonnet-4-5",
        "claude-opus-4-6",
    ] {
        assert!(
            ALLOWED_AI_MODELS.contains(&model),
            "expected {model} in ALLOWED_AI_MODELS"
        );
    }
    assert_eq!(resolve_provider("", "o3"), "openai");
    assert_eq!(resolve_provider("", "gemini-4-hydrogen"), "gemini");
    assert_eq!(resolve_provider("", "claude-opus-4-6"), "anthropic");

    let body = serde_json::json!({
        "metrics_snapshot": { "cpu": 72.5 },
        "system_logs": ["ERROR: token=supersecret123 failed to connect"]
    });
    let logs_only = build_support_prompt("base", "logs", &body);
    assert!(logs_only.contains("=== SYSTEM LOGS ==="));
    assert!(logs_only.contains("[REDACTED]"));
    assert!(!logs_only.contains("supersecret123"));
    assert!(!logs_only.contains("=== CURRENT SYSTEM METRICS ==="));

    let metrics_only = build_support_prompt("base", "metrics", &body);
    assert!(metrics_only.contains("=== CURRENT SYSTEM METRICS ==="));
    assert!(metrics_only.contains("=== CLIENT METRICS SNAPSHOT ==="));
    assert!(!metrics_only.contains("=== SYSTEM LOGS ==="));

    let full = build_support_prompt("base", "full", &body);
    assert!(full.contains("=== CURRENT SYSTEM METRICS ==="));
    assert!(full.contains("=== SYSTEM LOGS ==="));

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    init_ai_test_settings();
    let non_admin = AuthUser {
        user_id: 42,
        username: "viewer".into(),
        role: "user".into(),
        jti: "jti-42".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let err_resp = run_chat_session(
        Some(non_admin),
        "",
        "",
        "",
        "gpt-4o",
        "openai",
        vec![],
        "hello".to_string(),
    )
    .await;
    assert_eq!(err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = axum::body::to_bytes(err_resp.into_body(), 4096)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains("api.openai.com"));
    assert!(!text.contains("OPENAI_API_KEY"));
    assert!(!text.contains("Settings"));
}

#[test]
fn flowai_action_extraction_canonicalizes_targets_and_ignores_user_or_negated_verbs() {
    assert_eq!(extract_service_target("check apache logs"), "apache2");
    assert_eq!(extract_service_target("check postgres pool"), "postgresql");
    assert_eq!(extract_service_target("inspect redis cache"), "valkey");

    // User message verbs must never trigger a proposed action when AI reply does not propose one
    assert!(extract_proposed_action(
        "Apache is healthy and serving traffic normally.",
        "Should I restart apache or stop it?"
    )
    .is_none());

    // Negated and interrogative sentences in AI reply must be ignored
    assert!(extract_proposed_action(
        "Do not restart apache right now! Never stop postgres without draining connections. Would you like to restart redis?",
        "apache status"
    )
    .is_none());

    // Affirmative AI proposal with canonicalized target succeeds
    let action = extract_proposed_action(
        "Logs show a wedged worker. Please restart apache to recover.",
        "help with web server",
    )
    .expect("affirmative restart proposal");
    assert_eq!(action.title, "Restart apache2");

    let valkey_action =
        extract_proposed_action("You should stop redis immediately.", "cache issue")
            .expect("affirmative stop proposal");
    assert_eq!(valkey_action.title, "Stop valkey");
}

#[tokio::test]
async fn flowai_chat_only_advertises_committed_proposals_and_recovers_plain_reply_on_queue_failure()
{
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    init_ai_test_settings();

    let reply_msg = "Logs show a wedged worker. Please restart apache to recover.";
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async move {
            axum::Json(serde_json::json!({
                "choices": [{ "message": { "content": reply_msg } }]
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET ollama_endpoint = ?1 WHERE id = 1",
            [endpoint.as_str()],
        )
        .unwrap();
        conn.execute("DELETE FROM pending_actions", []).unwrap();
        conn.execute(
            "DELETE FROM admin_audit_log WHERE action = 'ai_action_proposed'",
            [],
        )
        .unwrap();
    }

    let admin = AuthUser {
        user_id: 1,
        username: "admin".into(),
        role: "admin".into(),
        jti: "jti-admin".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let non_admin = AuthUser {
        user_id: 2,
        username: "viewer".into(),
        role: "user".into(),
        jti: "jti-viewer".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    let parse_body = |resp: Response| async move {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    };

    // 1. Non-admin users receive plain chat replies without queueing proposals.
    let (st, body) = parse_body(
        run_chat_session(
            Some(non_admin),
            "127.0.0.1",
            "test",
            "",
            "fixture-installed-model",
            "localai",
            vec![],
            "help with apache".to_string(),
        )
        .await,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["reply"], reply_msg);
    assert!(body.get("proposed_action").is_none());
    assert_eq!(af_db::count_pending_actions().unwrap(), 0);

    // 2. Admin receives a committed positive row ID and matching audit entry.
    let (st, body) = parse_body(
        run_chat_session(
            Some(admin.clone()),
            "127.0.0.1",
            "test",
            "",
            "fixture-installed-model",
            "localai",
            vec![],
            "help with apache".to_string(),
        )
        .await,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["reply"], reply_msg);
    let action_id = body["proposed_action"]["action_id"].as_i64().unwrap();
    assert!(action_id > 0);
    assert_eq!(body["proposed_action"]["title"], "Restart apache2");
    assert_eq!(body["proposed_action"]["danger_level"], "warn");
    let persisted = af_db::get_pending_action_by_id(action_id)
        .unwrap()
        .expect("committed pending_actions row");
    assert_eq!(persisted.status, "pending");
    assert_eq!(persisted.source, "FlowAI");

    let audit_count = || -> i64 {
        af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM admin_audit_log WHERE action = 'ai_action_proposed'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(audit_count(), 1);

    // 3. Hidden older pending rows reaching the 50-pending cap suppress proposals
    //    and return a recoverable plain chat reply.
    {
        let conn = af_db::get_conn().unwrap();
        for idx in 1..af_db::MAX_PENDING_ACTIONS {
            conn.execute(
                "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                 VALUES ('warn', 'FlowAI', ?1, 'older pending', 'pending', '2020-01-01')",
                [format!("Restart old-{idx}")],
            )
            .unwrap();
        }
        for idx in 1..=120i64 {
            conn.execute(
                "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                 VALUES ('warn', 'FlowAI', ?1, 'recent executed', 'executed', '2026-01-01')",
                [format!("Restart done-{idx}")],
            )
            .unwrap();
        }
    }
    assert_eq!(
        af_db::count_pending_actions().unwrap(),
        af_db::MAX_PENDING_ACTIONS
    );
    let (st, body) = parse_body(
        run_chat_session(
            Some(admin.clone()),
            "127.0.0.1",
            "test",
            "",
            "fixture-installed-model",
            "localai",
            vec![],
            "help with apache".to_string(),
        )
        .await,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["reply"], reply_msg);
    assert!(body.get("proposed_action").is_none());
    assert_eq!(
        af_db::count_pending_actions().unwrap(),
        af_db::MAX_PENDING_ACTIONS
    );
    assert_eq!(audit_count(), 1);

    // 4. DB write rejection returns a plain chat reply with no phantom proposal or audit.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM pending_actions", []).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_flowai_pending_insert BEFORE INSERT ON pending_actions \
             BEGIN SELECT RAISE(ABORT, 'fixture write rejection'); END;",
        )
        .unwrap();
    }
    let (st, body) = parse_body(
        run_chat_session(
            Some(admin),
            "127.0.0.1",
            "test",
            "",
            "fixture-installed-model",
            "localai",
            vec![],
            "help with apache".to_string(),
        )
        .await,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["reply"], reply_msg);
    assert!(body.get("proposed_action").is_none());
    assert_eq!(af_db::count_pending_actions().unwrap(), 0);
    assert_eq!(audit_count(), 1);

    af_db::get_conn()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_flowai_pending_insert;")
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn test_ai_connection_validates_gemini_model_and_redacts_upstream_secrets() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    init_ai_test_settings();

    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // 1. Gemini connection tests reject URL traversal and non-allowlisted model identifiers with 400.
    for bad_model in [
        "../../evil?leak=1",
        "gemini-2.5-flash/../../other",
        "gemini-2.5-flash?key=override",
        "gpt-4o",
        "not-allowlisted-model",
    ] {
        let resp = test_ai_connection(
            axum::Extension(admin.clone()),
            Json(serde_json::json!({
                "provider": "gemini",
                "gemini_api_key": "fixture-key",
                "model": bad_model,
            })),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "model '{bad_model}' must be rejected before outbound Gemini URL interpolation"
        );
    }

    // 2. Direct call_gemini_api rejects path-traversal and non-gemini model names before HTTP dispatch.
    assert!(
        call_gemini_api("fixture-key", "../v1/leak", "", &[], "ping")
            .await
            .is_err()
    );
    assert!(
        call_gemini_api("fixture-key", "gemini-2.5-flash#fragment", "", &[], "ping")
            .await
            .is_err()
    );

    // 3. Upstream error responses containing reflected secrets are redacted in test_ai_connection.
    let app = axum::Router::new().route(
        "/v1/messages",
        axum::routing::post(|| async {
            (
                StatusCode::UNAUTHORIZED,
                "rejected api_key=sk-ant-fixture-leaked-secret token=tok-fixture-999",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let err_resp = test_ai_connection(
        axum::Extension(admin),
        Json(serde_json::json!({
            "provider": "anthropic",
            "anthropic_api_key": "sk-ant-fixture-leaked-secret",
            "endpoint": endpoint,
            "model": "claude-sonnet-5-5",
        })),
    )
    .await;
    assert_eq!(err_resp.status(), StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(err_resp.into_body(), 4096)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains("sk-ant-fixture-leaked-secret"));
    assert!(!text.contains("tok-fixture-999"));
    assert!(text.contains("[REDACTED]"));

    server.abort();
}
