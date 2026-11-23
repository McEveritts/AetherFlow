use super::*;
use tower::ServiceExt;

#[tokio::test]
async fn local_ai_settings_round_trip_runtime_and_installed_model_without_overriding_cloud_selection(
) {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO users(id, username, role) VALUES(678, 'local-settings-contract', 'admin')",
            [],
        )
        .unwrap();
    let (token, _) = crate::auth::create_standard_jwt(678, &HeaderMap::new()).unwrap();
    let app = build_router();
    for runtime in ["lm-studio", "ollama", "anthropic-local"] {
        for model in ["qwen2.5:14b", "gemini-4-argon"] {
            let payload = SettingsPayload {
                ai_model: model.to_owned(),
                local_provider: runtime.to_owned(),
                local_model: "qwen2.5:14b".to_owned(),
                ..Default::default()
            };
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("PUT")
                        .uri("/api/v1/admin/settings")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(
                            serde_json::to_vec(&payload).unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{runtime} {model}");
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/api/v1/auth/settings")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            let returned: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(returned["aiModel"], model);
            assert_eq!(returned["localProvider"], runtime);
            assert_eq!(returned["localModel"], "qwen2.5:14b");
            let provider = crate::intelligence::resolve_provider_settings();
            assert_eq!(provider.default_model, model);
            assert_eq!(provider.local_model, "qwen2.5:14b");
            assert_eq!(
                provider.local_provider,
                if model == "gemini-4-argon" {
                    ""
                } else {
                    runtime
                }
            );
        }
    }
    let mut legacy_payload = serde_json::to_value(SettingsPayload::default()).unwrap();
    legacy_payload
        .as_object_mut()
        .unwrap()
        .remove("localProvider");
    legacy_payload.as_object_mut().unwrap().remove("localModel");
    let legacy: SettingsPayload = serde_json::from_value(legacy_payload).unwrap();
    assert!(legacy.local_provider.is_empty() && legacy.local_model.is_empty());
}

#[tokio::test]
async fn managed_ingress_failure_rolls_back_previous_settings() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    let database = ensure_shared_test_db();
    env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");
    let host_root = database.parent().unwrap().join("managed-apache-fixture");
    fs::create_dir_all(host_root.join("etc")).unwrap();
    fs::write(host_root.join("etc/apache2"), "not an Apache directory").unwrap();
    env::set_var("AETHERFLOW_FS_ROOT", &host_root);
    env::set_var("AETHERFLOW_CONFIG_ROOT", &host_root);
    env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        database.parent().unwrap().join("missing-runner.sock"),
    );
    let prior = AppIngressConfig {
        app_name: "test-ingress".into(),
        public_domain: "app.example.test".into(),
        external_access_enabled: true,
        listen_port: 11234,
        tls_enabled: false,
        ..Default::default()
    };
    af_db::set_app_ingress_config(&prior).unwrap();
    let result = upsert_app_ingress_config(
        prior.app_name.clone(),
        UpdateIngressReq {
            public_domain: None,
            external_access_enabled: Some(false),
            listen_port: None,
            tls_enabled: None,
        },
    )
    .await;
    assert!(result.is_err());
    let live = af_db::get_app_ingress_config(&prior.app_name)
        .unwrap()
        .unwrap();
    assert!(live.external_access_enabled);
    assert_eq!(live.public_domain, prior.public_domain);
    assert_eq!(live.listen_port, prior.listen_port);
}

#[tokio::test]
async fn settings_can_clear_keys_and_keep_masked_placeholders() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    assert_eq!(mask_secret("abc"), "****");
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch("UPDATE settings SET gemini_api_key = 'old-gemini', openai_api_key = 'old-openai', anthropic_api_key = 'old-anthropic' WHERE id = 1;").unwrap();
    drop(conn);
    let response = update_settings(
        Extension(AuthUser {
            user_id: 1,
            username: "admin".into(),
            role: "admin".into(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }),
        None,
        Json(SettingsPayload {
            ai_model: "qwen2.5:14b".into(),
            local_provider: "ollama".into(),
            local_model: "qwen2.5:14b".into(),
            openai_api_key: "****enai".into(),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let keys: (String, String, String) = af_db::get_read_conn()
        .unwrap()
        .query_row(
            "SELECT gemini_api_key, openai_api_key, anthropic_api_key FROM settings WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(keys, (String::new(), "old-openai".into(), String::new()));
}

#[tokio::test]
async fn settings_persistence_failure_does_not_report_success_or_change_saved_fields() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "UPDATE settings SET ai_model='gemini-4-argon', system_prompt='preserved' WHERE id=1",
        [],
    )
    .unwrap();
    conn.execute_batch("CREATE TRIGGER fail_settings_update BEFORE UPDATE OF local_provider ON settings BEGIN SELECT RAISE(FAIL, 'forced persistence failure'); END;").unwrap();
    drop(conn);
    let payload = SettingsPayload {
        ai_model: "qwen2.5:14b".to_owned(),
        local_provider: "ollama".to_owned(),
        local_model: "qwen2.5:14b".to_owned(),
        system_prompt: "not-saved".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        update_settings(
            Extension(AuthUser {
                user_id: 1,
                username: "admin".into(),
                role: "admin".into(),
                jti: String::new(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            }),
            None,
            Json(payload),
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let conn = af_db::get_conn().unwrap();
    let saved: (String, String) = conn
        .query_row(
            "SELECT ai_model, system_prompt FROM settings WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(saved, ("gemini-4-argon".to_owned(), "preserved".to_owned()));
}

#[tokio::test]
async fn role_routes_reject_last_usable_admin_demotion_and_failed_writes_without_success_audit() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch("INSERT INTO users(id, username, role) VALUES(679, 'role-operator', 'admin'), (680, 'role-target', 'user'), (681, 'disabled-role-admin', 'admin'); INSERT INTO user_quotas(user_id,username,status) VALUES(681, 'disabled-role-admin', 'suspended'); CREATE TRIGGER fail_role_update BEFORE UPDATE OF role ON users WHEN NEW.id=680 BEGIN SELECT RAISE(FAIL, 'forced persistence failure'); END;").unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(679, &HeaderMap::new()).unwrap();
    let app = build_router();
    for (target, role, expected) in [
        (679, "user", StatusCode::BAD_REQUEST),
        (680, "admin", StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/api/v1/admin/users/{target}/role"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"role":role}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let conn = af_db::get_conn().unwrap();
    let success_audits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM admin_audit_log WHERE action='user_role_change'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(success_audits, 0);
    let role: String = conn
        .query_row("SELECT role FROM users WHERE id=680", [], |row| row.get(0))
        .unwrap();
    assert_eq!(role, "user");
}

#[tokio::test]
async fn ai_endpoint_settings_reject_invalid_targets_before_persistence() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id, username, role) VALUES(677, 'settings-contract', 'admin')",
        [],
    )
    .unwrap();
    conn.execute(
        "UPDATE settings SET lm_studio_endpoint='http://localhost:1234' WHERE id=1",
        [],
    )
    .unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(677, &HeaderMap::new()).unwrap();
    let app = build_router();
    for (name, invalid) in [
        ("lmStudioEndpoint", "file:///etc/unused"),
        ("ollamaEndpoint", "http://169.254.169.254"),
        ("anthropicEndpoint", "https://fixture:password@example.test"),
    ] {
        let mut payload = serde_json::to_value(SettingsPayload::default()).unwrap();
        payload[name] = invalid.into();
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/settings")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let stored: String = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT lm_studio_endpoint FROM settings WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, "http://localhost:1234");
    }
}

#[tokio::test]
async fn afmp003_allocate_or_resolve_app_port_skips_ports_persisted_for_stopped_apps() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute("DELETE FROM app_ingress_configs", []).unwrap();
    drop(conn);

    // Persist Sonarr's default port (8989) and fallback port 17000 as owned by other stopped apps
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "stopped-owner-default".into(),
        listen_port: 8989,
        ..Default::default()
    })
    .unwrap();
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "stopped-owner-fallback".into(),
        listen_port: 17000,
        ..Default::default()
    })
    .unwrap();

    let allocated = allocate_or_resolve_app_port("sonarr", 8989);
    assert_ne!(
        allocated, 8989,
        "must not steal stopped app's persisted default port"
    );
    assert_ne!(
        allocated, 17000,
        "must not steal stopped app's persisted fallback port"
    );
    assert!(
        (17001..=19999).contains(&allocated),
        "expected fallback port >= 17001, got {allocated}"
    );
}

#[tokio::test]
async fn test_marketplace_auth_modes_and_target_version_matching() {
    use axum::http::Request;

    // Test target_version_matches logic
    assert!(target_version_matches("1.2.3", "1.2.3"));
    assert!(target_version_matches("v1.2.3", "1.2.3"));
    assert!(target_version_matches("1.2.3", "v1.2.3"));
    assert!(target_version_matches("Release-1.2.3", "1.2.3"));
    assert!(target_version_matches("abc1234", "abc123456789"));
    assert!(!target_version_matches("1.2.3", "1.2.4"));
    assert!(!target_version_matches("1.2.3", ""));
    assert!(!target_version_matches("1.2.3", "1.2.3-rc1"));
    assert!(!target_version_matches("1.2.3", "1.2.3.4"));
    assert!(target_version_matches(
        "frontend:abc1234,backend:def5678,proxy:0123456",
        "frontend:abc1234,backend:def5678,proxy:0123456"
    ));
    assert!(!target_version_matches(
        "frontend:abc1234,backend:def5678",
        "frontend:abc1234,backend:def5678"
    ));

    // Build router and test get_marketplace endpoint
    let app = build_router();

    // 1. Unauthenticated with require_auth=1 must return 401 UNAUTHORIZED
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/public/marketplace?require_auth=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. Unauthenticated without require_auth must return 200 with public_redacted mode
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/public/marketplace")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("x-aetherflow-inventory-mode").unwrap(),
        "public_redacted"
    );
    assert_eq!(
        res.headers()
            .get("x-aetherflow-inventory-authenticated")
            .unwrap(),
        "false"
    );
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    if let Some(item) = items.first() {
        assert_eq!(item["inventory_known"], false);
        assert!(!item["inventory_authenticated"].as_bool().unwrap_or(false));
    }
}

#[test]
fn avatar_uri_allowlist_blocks_svg_html_and_unsafe_schemes() {
    for rejected in [
        "",
        "javascript:alert(1)",
        "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "http://insecure.example.com/avatar.png",
        "https://user:pass@example.com/avatar.png",
        "//evil.example.com/avatar.png",
        "/uploads/../../etc/passwd",
        "data:image/png;base64,not-valid-base64!!!",
    ] {
        assert!(
            validate_avatar_uri(rejected).is_err(),
            "expected {rejected} to be rejected"
        );
    }
    for accepted in [
        "https://cdn.example.com/avatars/u1.png",
        "/uploads/avatars/u1.webp",
        "data:image/png;base64,iVBORw0KGgo=",
        "data:image/webp;base64,UklGRg==",
    ] {
        assert!(
            validate_avatar_uri(accepted).is_ok(),
            "expected {accepted} to be accepted"
        );
    }
}

#[tokio::test]
async fn openapi_swagger_routes_serve_zero_cdn_viewer_and_spec_with_expected_headers() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;

    let app = build_router();
    let api_csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    // The bare /swagger redirect uses the API policy.
    let redirect_resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/public/swagger")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(redirect_resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        redirect_resp.headers()[header::LOCATION],
        "./swagger/index.html"
    );
    assert_eq!(
        redirect_resp.headers()[header::CONTENT_SECURITY_POLICY],
        api_csp
    );

    // The viewer can load its bundled script, styles and same-origin API.
    let style_attributes = regex::Regex::new(r#"\bstyle="([^"]+)"|\bstyle:\s*'([^']+)'"#).unwrap();
    let hash = |content: &str| format!("'sha256-{}'", STANDARD.encode(Sha256::digest(content)));
    for path in [
        "/api/v1/public/swagger/",
        "/api/v1/public/swagger/index.html",
        "/api/public/swagger/index.html",
    ] {
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "path={path}");
        let ct = resp.headers()[header::CONTENT_TYPE].to_str().unwrap();
        assert!(ct.starts_with("text/html"), "path={path} ct={ct}");
        if path.starts_with("/api/public/") {
            assert_eq!(resp.headers()["deprecation"], "true");
            let link = resp.headers()[header::LINK].to_str().unwrap();
            assert_eq!(
                link,
                r#"</api/v1/public/swagger/index.html>; rel="successor-version""#
            );
        }
        let (parts, body) = resp.into_parts();
        let csp = parts.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        let bytes = axum::body::to_bytes(body, 2 * 1024 * 1024).await.unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains("../openapi.yaml"), "path={path}");
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "OpenAPI viewer HTML at {path} must not contain external http:// or https:// URLs"
        );

        let directives: HashMap<_, _> = csp
            .split("; ")
            .map(|directive| directive.split_once(' ').unwrap())
            .collect();
        let script = html
            .split_once("<script>")
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let style = html
            .split_once("<style>")
            .unwrap()
            .1
            .split_once("</style>")
            .unwrap()
            .0;
        assert_eq!(directives["default-src"], "'none'", "path={path}");
        assert_eq!(directives["script-src"], hash(script), "path={path}");
        assert_eq!(directives["style-src"], hash(style), "path={path}");
        assert_eq!(directives["img-src"], "data:", "path={path}");
        assert_eq!(directives["connect-src"], "'self'", "path={path}");
        assert_eq!(directives["frame-ancestors"], "'none'", "path={path}");
        let allowed: HashSet<_> = directives["style-src-attr"]
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let mut expected = HashSet::from(["'unsafe-hashes'".to_owned()]);
        for captures in style_attributes.captures_iter(&html) {
            let style = captures.get(1).or_else(|| captures.get(2)).unwrap();
            expected.insert(hash(style.as_str()));
        }
        assert_eq!(allowed, expected, "path={path}");
    }

    // Raw OpenAPI YAML uses the API policy, including decoded asset names.
    for spec_path in [
        "/api/v1/public/openapi.yaml",
        "/api/v1/public/swagger/openapi.yaml",
        "/api/v1/public/swagger/doc.yaml",
        "/api/public/swagger/%6fpenapi.yaml",
    ] {
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(spec_path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "spec_path={spec_path}");
        let ct = resp.headers()[header::CONTENT_TYPE].to_str().unwrap();
        assert!(
            ct.starts_with("application/yaml"),
            "spec_path={spec_path} ct={ct}"
        );
        assert_eq!(resp.headers()[header::CONTENT_SECURITY_POLICY], api_csp);
        let bytes = axum::body::to_bytes(resp.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let yaml = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(yaml.contains("openapi: 3.1.0"), "spec_path={spec_path}");
    }

    // Unknown Swagger assets use the API policy.
    let missing_resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/public/swagger/nonexistent.js")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        missing_resp.headers()[header::CONTENT_SECURITY_POLICY],
        api_csp
    );
}

#[tokio::test]
async fn metrics_endpoint_enforces_access_control_and_reports_runtime_version() {
    use axum::extract::connect_info::ConnectInfo;
    use std::net::SocketAddr;

    let expected_version = af_runner::af_release::runtime::runtime_identity()
        .version
        .clone();

    // /health includes dynamic runtime version
    let health = health_check().await.0;
    assert_eq!(health["version"], expected_version);

    // In-process oneshot without ConnectInfo is allowed
    let app = build_router();
    let in_proc_resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(in_proc_resp.status(), StatusCode::OK);
    let metrics_bytes = axum::body::to_bytes(in_proc_resp.into_body(), 65536)
        .await
        .unwrap();
    let metrics_text = String::from_utf8(metrics_bytes.to_vec()).unwrap();
    assert!(
        metrics_text.contains(&format!(r#"version="{}""#, expected_version)),
        "expected version {expected_version} in metrics output: {metrics_text}"
    );

    // Non-loopback ConnectInfo without credentials is rejected 401
    let mut remote_req = axum::http::Request::builder()
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    remote_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([198, 51, 100, 10], 44444))));
    let remote_resp = app.clone().oneshot(remote_req).await.unwrap();
    assert_eq!(remote_resp.status(), StatusCode::UNAUTHORIZED);

    // Loopback ConnectInfo is allowed
    let mut loopback_req = axum::http::Request::builder()
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    loopback_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 44444))));
    let loopback_resp = app.clone().oneshot(loopback_req).await.unwrap();
    assert_eq!(loopback_resp.status(), StatusCode::OK);

    // Non-loopback with valid METRICS_BEARER_TOKEN is allowed
    std::env::set_var("METRICS_BEARER_TOKEN", "test-metrics-secret-token");
    let mut bearer_req = axum::http::Request::builder()
        .uri("/metrics")
        .header(header::AUTHORIZATION, "Bearer test-metrics-secret-token")
        .body(axum::body::Body::empty())
        .unwrap();
    bearer_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([198, 51, 100, 10], 44445))));
    let bearer_resp = app.oneshot(bearer_req).await.unwrap();
    std::env::remove_var("METRICS_BEARER_TOKEN");
    assert_eq!(bearer_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn broadcast_notifications_dismiss_per_user_without_mutating_shared_row() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();

    let (broadcast_id, u1_notif_id, u2_notif_id) = {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "DELETE FROM notification_reads;
                 DELETE FROM notifications;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notifications (user_id, level, title, message, read)
                 VALUES (NULL, 'warning', 'Broadcast Alert', 'System-wide notice', 0)",
            [],
        )
        .unwrap();
        let b_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO notifications (user_id, level, title, message, read)
                 VALUES (7101, 'info', 'User1 Alert', 'Only user 1', 0)",
            [],
        )
        .unwrap();
        let u1_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO notifications (user_id, level, title, message, read)
                 VALUES (7102, 'info', 'User2 Alert', 'Only user 2', 0)",
            [],
        )
        .unwrap();
        let u2_id = conn.last_insert_rowid();
        (b_id, u1_id, u2_id)
    };

    let u1 = AuthUser {
        user_id: 7101,
        username: "notif-u1".into(),
        role: "user".into(),
        jti: "jti-u1".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let u2 = AuthUser {
        user_id: 7102,
        username: "notif-u2".into(),
        role: "user".into(),
        jti: "jti-u2".into(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    let query_default = || PageQuery {
        limit: 50,
        offset: 0,
        action: String::new(),
        username: String::new(),
    };

    // User 1 marks the broadcast notification read -> removed for user 1 only
    let resp = mark_notification_read(Path(broadcast_id), Extension(u1.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let u1_resp = get_notifications(Extension(u1.clone()), Query(query_default())).await;
    assert_eq!(u1_resp.status(), StatusCode::OK);
    let u1_list: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(u1_resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u1_list["unread_count"], 1);
    let u1_ids: Vec<i64> = u1_list["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_i64().unwrap())
        .collect();
    assert_eq!(u1_ids, vec![u1_notif_id]);

    // User 2 STILL sees both the broadcast and their own notification unread
    let u2_resp = get_notifications(Extension(u2.clone()), Query(query_default())).await;
    assert_eq!(u2_resp.status(), StatusCode::OK);
    let u2_list: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(u2_resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u2_list["unread_count"], 2);
    let u2_ids: Vec<i64> = u2_list["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_i64().unwrap())
        .collect();
    assert!(u2_ids.contains(&broadcast_id));
    assert!(u2_ids.contains(&u2_notif_id));

    // Broadcast row itself MUST remain read = 0
    let broadcast_read: i64 = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT read FROM notifications WHERE id = ?1",
            params![broadcast_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(broadcast_read, 0);

    // User 2 dismisses all -> User 2 unread_count = 0, broadcast row still read = 0
    let dismiss_resp = dismiss_all_notifications(Extension(u2.clone())).await;
    assert_eq!(dismiss_resp.status(), StatusCode::OK);
    let u2_after_resp = get_notifications(Extension(u2.clone()), Query(query_default())).await;
    assert_eq!(u2_after_resp.status(), StatusCode::OK);
    let u2_after: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(u2_after_resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u2_after["unread_count"], 0);
    assert!(u2_after["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["id"].as_i64() != Some(broadcast_id)));
    let broadcast_read_after: i64 = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT read FROM notifications WHERE id = ?1",
            params![broadcast_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(broadcast_read_after, 0);

    // DB failure during dismiss_all_notifications returns 500 instead of silent 200
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_notif_reads BEFORE INSERT ON notification_reads
                 BEGIN SELECT RAISE(ABORT, 'simulated db error'); END;",
        )
        .unwrap();
    }
    let err_resp = dismiss_all_notifications(Extension(u1)).await;
    assert_eq!(err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("DROP TRIGGER IF EXISTS fail_notif_reads;")
            .unwrap();
    }
}

#[tokio::test]
async fn public_auth_refresh_is_rate_limited_and_ingress_defaults_opt_in() {
    use axum::extract::connect_info::ConnectInfo;
    use std::net::SocketAddr;

    let now = Utc::now();
    let req_new: UpdateIngressReq = serde_json::from_value(serde_json::json!({
        "publicDomain": "sonarr.example.com"
    }))
    .unwrap();
    let created = resolve_patched_ingress_config("sonarr", &req_new, None, 8989, now).unwrap();
    assert!(
        !created.external_access_enabled,
        "newly auto-seeded ingress must default external_access_enabled to false"
    );

    let app = build_router();
    let unique_peer = SocketAddr::from(([198, 51, 100, 222], 51234));
    let mut saw_rate_limit = false;
    for _ in 0..15 {
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/public/auth/refresh")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(unique_peer));
        let resp = app.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limit = true;
            break;
        }
    }
    assert!(
        saw_rate_limit,
        "/api/v1/public/auth/refresh must enforce auth_rate_limit_middleware"
    );
}
