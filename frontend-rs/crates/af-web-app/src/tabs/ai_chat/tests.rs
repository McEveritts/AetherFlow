use super::*;

#[test]
fn failed_turn_rollback_preserves_identical_committed_history_and_other_threads() {
    let prior = json!({"role":"user","text":"same prompt"});
    let mut threads = vec![
        json!({"id":"origin","title":"Earlier title","messages":[prior.clone(),{"role":"assistant","text":"reply"}]}),
        json!({"id":"other","title":"Other","messages":[{"role":"user","text":"unrelated"}]}),
    ];
    let before = threads.clone();
    for _ in 0..3 {
        let pending = PendingTurn::append(&mut threads, "origin", "same prompt").unwrap();
        assert_eq!(threads[0]["messages"].as_array().unwrap().len(), 3);
        pending.rollback(&mut threads);
        assert_eq!(threads, before);
    }
    // Repeating cleanup cannot remove an earlier identical committed message.
    let pending = PendingTurn::append(&mut threads, "origin", "same prompt").unwrap();
    pending.rollback(&mut threads);
    pending.rollback(&mut threads);
    assert_eq!(threads, before);
}

#[test]
fn first_failed_turn_restores_title_and_successful_turn_remains_committed() {
    let mut threads = vec![json!({"id":"origin","title":"New conversation","messages":[]})];
    let pending = PendingTurn::append(&mut threads, "origin", "first prompt").unwrap();
    assert_eq!(threads[0]["title"], "first prompt");
    pending.rollback(&mut threads);
    assert_eq!(threads[0]["title"], "New conversation");
    assert_eq!(threads[0]["messages"], json!([]));
    let _committed = PendingTurn::append(&mut threads, "origin", "first prompt").unwrap();
    threads[0]["messages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"role":"assistant","text":"ok"}));
    assert_eq!(threads[0]["messages"].as_array().unwrap().len(), 2);
    assert!(PendingTurn::append(&mut threads, "missing", "prompt").is_none());
}

#[test]
fn endpoint_selection_requires_admin_role_for_attached_telemetry() {
    for attach in [false, true] {
        assert_eq!(
            resolve_ai_chat_endpoint(attach, false),
            ("/api/v1/auth/ai/chat", false)
        );
    }
    assert_eq!(
        resolve_ai_chat_endpoint(true, true),
        ("/api/v1/auth/ai/support", true)
    );
    assert_eq!(
        resolve_ai_chat_endpoint(false, true),
        ("/api/v1/auth/ai/chat", false)
    );
}

#[test]
fn provider_selection_respects_explicit_local_and_cloud_models() {
    assert_eq!(
        configured_selection(&json!({"aiModel":"ollama:qwen3:8b"})),
        ("ollama".into(), "qwen3:8b".into())
    );
    assert_eq!(
        configured_selection(
            &json!({"aiModel":"lm-studio:legacy","localModel":"qwen2.5-coder-7b-instruct"})
        ),
        ("lm-studio".into(), "qwen2.5-coder-7b-instruct".into())
    );
    assert_eq!(
        configured_selection(
            &json!({"aiModel":"gpt-6.1-sol","localProvider":"ollama","localModel":"local"})
        ),
        ("openai".into(), "gpt-6.1-sol".into())
    );
    assert!(!valid_model(" local-test "));
    assert!(valid_model("llama3.2:latest"));
}

#[test]
fn attached_service_health_excludes_credentials_and_private_configuration() {
    let source = json!({"jellyfin":{"status":"running","api_key":"secret","credentials":{"password":"secret"},"config":{"token":"secret"},"version":"1.0","degraded_components":["scanner"]}});
    let health = service_health(&source);
    assert_eq!(health[0]["name"], "jellyfin");
    assert_eq!(health[0]["status"], "running");
    assert_eq!(health[0]["degraded_components"][0], "scanner");
    for field in ["api_key", "credentials", "config"] {
        assert!(health[0].get(field).is_none());
    }
    let array = service_health(&json!([{"id":"plex","health":"healthy","token":"secret"}]));
    assert_eq!(array[0]["id"], "plex");
    assert!(array[0].get("token").is_none());
    assert_eq!(service_health(&Value::Null), json!([]));
}
