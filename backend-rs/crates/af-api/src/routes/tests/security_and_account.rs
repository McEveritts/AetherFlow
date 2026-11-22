use super::*;

#[tokio::test]
async fn plugin_proxy_response_is_always_sandboxed_by_outer_security_headers() {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request};
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    async fn upstream_response(request: Request<Body>) -> axum::response::Response {
        let mime = request.uri().query().unwrap_or("text/html");
        let body = if mime == "application/json" {
            r#"{"status":"ok"}"#
        } else {
            "plugin bytes"
        };
        let mut response = ([(header::CONTENT_TYPE, mime.to_string())], body).into_response();
        // An upstream-controlled policy must never override the host policy.
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static("sandbox allow-scripts allow-same-origin"),
        );
        response.headers_mut().append(
            header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static("default-src *"),
        );
        response.headers_mut().insert(
            header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("SAMEORIGIN"),
        );
        response.headers_mut().append(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
        response.headers_mut().append(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("s-maxage=31536000"),
        );
        response.headers_mut().insert(
            header::PRAGMA,
            axum::http::HeaderValue::from_static("cache"),
        );
        response.headers_mut().insert(
            header::EXPIRES,
            axum::http::HeaderValue::from_static("Wed, 21 Oct 2099 07:28:00 GMT"),
        );
        for name in [
            "surrogate-control",
            "cdn-cache-control",
            "cloudflare-cdn-cache-control",
        ] {
            response.headers_mut().insert(
                name,
                axum::http::HeaderValue::from_static("public, max-age=31536000"),
            );
        }
        response
            .extensions_mut()
            .insert(crate::plugins::ProxiedPluginResponse);
        response
    }

    let app = axum::Router::new()
        .fallback(upstream_response)
        .layer(axum::middleware::from_fn(
            super::super::security_headers_middleware,
        ));
    for prefix in [
        "/plugins/demo/proxy",
        "/api/auth/plugins/demo/proxy",
        "/api/v1/auth/plugins/%64emo/proxy",
    ] {
        for suffix in ["", "/landing", "/ui", "/%75i", "/asset-deadbeef.js"] {
            for mime in [
                "text/html",
                "application/xhtml+xml",
                "image/svg+xml",
                "application/javascript",
                "application/json",
            ] {
                let uri = format!("{prefix}{suffix}?{mime}");
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_proxy_document_policy(&response);
                assert_eq!(response.headers()[header::CONTENT_TYPE], mime, "{uri}");
                let body = to_bytes(response.into_body(), 1024).await.unwrap();
                if mime == "application/json" {
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(json["status"], "ok", "{uri}");
                } else {
                    assert_eq!(body, "plugin bytes", "{uri}");
                }
            }
        }
    }
}

#[tokio::test]
async fn security_headers_leave_ordinary_json_cache_policy_untouched() {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let app = axum::Router::new()
        .route(
            "/api/v1/public/catalog",
            axum::routing::get(|| async {
                (
                    [(header::CACHE_CONTROL, "public, max-age=60")],
                    axum::Json(serde_json::json!({"ok": true})),
                )
            }),
        )
        .layer(axum::middleware::from_fn(
            super::super::security_headers_middleware,
        ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/public/catalog")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "public, max-age=60"
    );
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(
        response.headers()[header::CONTENT_SECURITY_POLICY],
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"ok": true})
    );
}

#[tokio::test(flavor = "current_thread")]
async fn registered_plugin_proxy_handlers_mark_errors_and_preserve_plugin_ui() {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-proxy-policy-{}", uuid::Uuid::new_v4()));
    let plugin_dir = root.join("plugins/demo");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(
            plugin_dir.join("plugin.manifest.json"),
            r#"{"id":"demo","name":"Demo","version":"1.0","backend":{"health_path":"/healthz"},"frontend":{"bundle":"index.html"}}"#,
        )
        .unwrap();
    std::fs::write(
        plugin_dir.join("index.html"),
        "<!doctype html><title>Plugin UI</title>",
    )
    .unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        std::env::set_var(key, &root);
    }
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("fixture.sqlite"));
    }
    std::env::set_var("AETHERFLOW_PLUGINS_DIR", root.join("plugins"));
    std::env::set_var("ALLOWED_HOSTS", "localhost");
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    af_db::init_db().unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch(
        "INSERT INTO users(id, username, role) VALUES (1, 'proxy-test', 'admin');
             INSERT INTO plugins_registry(plugin_id, enabled, allocated_port, token_epoch, status)
             VALUES ('demo', 0, 0, 1, 'stopped');",
    )
    .unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(1, &axum::http::HeaderMap::new()).unwrap();
    // Match the outer layers installed by main without starting a server.
    let app = super::super::build_router()
        .layer(crate::build_cors_layer())
        .layer(axum::middleware::from_fn(
            crate::middlewares::app_subdomain_proxy_middleware,
        ));

    // These are the actual registered aliases, including encoded path parameters.
    // The stopped plugin reaches each handler without opening an upstream socket.
    for prefix in [
        "/plugins/demo/proxy",
        "/api/auth/plugins/de%6do/proxy",
        "/api/v1/auth/plugins/%64emo/proxy",
    ] {
        for suffix in ["", "/status", "/ui", "/%75i", "/asset-deadbeef.js"] {
            for method in [
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::DELETE,
            ] {
                let uri = format!("{prefix}{suffix}");
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method.clone())
                            .uri(&uri)
                            .header(header::HOST, "localhost")
                            .header(header::ORIGIN, "http://localhost:8080")
                            .header(header::AUTHORIZATION, format!("Bearer {token}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "{method} {uri}"
                );
                assert_proxy_document_policy(&response);
                assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
                let body = to_bytes(response.into_body(), 4096).await.unwrap();
                if method == Method::HEAD {
                    assert!(body.is_empty(), "{method} {uri}");
                } else {
                    assert!(
                        String::from_utf8_lossy(&body).contains("PLUGIN_STOPPED"),
                        "{method} {uri}"
                    );
                }
            }
        }
    }

    // A different early handler error is marked too.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/plugins/%40invalid/proxy/ui")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_proxy_document_policy(&response);

    let conn = af_db::get_conn().unwrap();
    conn.execute(
            "UPDATE plugins_registry SET enabled = 1, allocated_port = 21000, status = 'running' WHERE plugin_id = 'demo'",
            [],
        )
        .unwrap();
    drop(conn);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/plugins/demo/proxy/%2e%2e/ui")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_proxy_document_policy(&response);

    for uri in [
        "/plugins/demo/ui",
        "/api/auth/plugins/demo/ui",
        "/api/v1/auth/plugins/demo/ui",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::HOST, "localhost")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            response.headers()[header::X_FRAME_OPTIONS],
            "SAMEORIGIN",
            "{uri}"
        );
        let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(
            csp.split(';')
                .any(|directive| directive.trim() == "sandbox allow-scripts"),
            "{uri}: {csp}"
        );
        assert!(!csp.contains("allow-same-origin"), "{uri}: {csp}");
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            "<!doctype html><title>Plugin UI</title>"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn ui_csp_allows_streaming_wasm_and_dedicated_workers() {
    use tower::ServiceExt;
    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { "ui" }))
        .layer(axum::middleware::from_fn(
            super::super::security_headers_middleware,
        ));
    let request = axum::http::Request::builder()
        .uri("/")
        .header("host", "localhost:8080")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(csp
        .split("; ")
        .any(|directive| directive == "script-src 'self' 'wasm-unsafe-eval'"));
    assert!(!csp.contains("'unsafe-inline'"));
    assert!(csp.contains("worker-src 'self'"));
    assert!(csp.contains("img-src 'self' data: blob: https:"));
    assert!(csp.contains("media-src 'self' blob:"));
    assert!(csp.contains("object-src 'none'"));
}

#[test]
fn member_settings_hide_provider_keys_and_private_endpoints() {
    let original = SettingsPayload {
        ai_model: "model".into(),
        language: "en".into(),
        gemini_api_key: "****last".into(),
        openai_api_key: "****tail".into(),
        anthropic_api_key: "****more".into(),
        lm_studio_endpoint: "http://internal:1234".into(),
        ollama_endpoint: "http://internal:11434".into(),
        anthropic_endpoint: "http://private".into(),
        ..Default::default()
    };
    let mut member = original.clone();
    redact_settings_for_role(&mut member, "user");
    for value in [
        &member.gemini_api_key,
        &member.openai_api_key,
        &member.anthropic_api_key,
        &member.lm_studio_endpoint,
        &member.ollama_endpoint,
        &member.anthropic_endpoint,
    ] {
        assert!(value.is_empty());
    }
    assert_eq!(member.ai_model, original.ai_model);
    assert_eq!(member.language, original.language);
    let mut admin = original.clone();
    redact_settings_for_role(&mut admin, "admin");
    assert_eq!(admin.lm_studio_endpoint, original.lm_studio_endpoint);
    assert_eq!(mask_secret("enc:v1:not-decryptable-ciphertext"), "****");
}

#[tokio::test]
async fn wrong_current_password_is_forbidden_without_expiring_session() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    if std::env::var_os("AES_MASTER_KEY").is_none() {
        std::env::set_var("AES_MASTER_KEY", "ci-test-aes-key-exactly-32bytes!");
    }
    af_db::init_aes_key().unwrap();
    ensure_shared_test_db();
    let hash = bcrypt::hash("correct-password", 4).unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute("INSERT INTO users (id, username, password_hash, role) VALUES (876, 'password-contract', ?1, 'user')", params![hash]).unwrap();
    drop(conn);
    let response = update_password(
        Extension(AuthUser {
            user_id: 876,
            username: "password-contract".into(),
            role: "user".into(),
            jti: "current-session".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }),
        HeaderMap::new(),
        Json(ChangePasswordReq {
            current_password: "wrong".into(),
            new_password: "new-password".into(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response
        .headers()
        .contains_key(axum::http::header::SET_COOKIE));
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["code"], "INVALID_CURRENT_PASSWORD");
}

#[tokio::test]
async fn plex_streaming_put_persists_configuration_and_audits_the_change() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    if std::env::var_os("AES_MASTER_KEY").is_none() {
        std::env::set_var("AES_MASTER_KEY", "ci-test-aes-key-exactly-32bytes!");
    }
    af_db::init_aes_key().unwrap();
    ensure_shared_test_db();
    let writer = af_db::get_conn().unwrap();
    writer
        .execute(
            "INSERT INTO users (id, username, role) VALUES (49, 'plex-admin', 'admin')",
            [],
        )
        .unwrap();
    drop(writer);

    // Disable polling for this fixture so the PUT can be verified without a live Plex server.
    let app = super::super::build_v1_router();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::USER_AGENT, "streaming-route-test".parse().unwrap());
    let (token, _) = crate::auth::create_standard_jwt(49, &headers).unwrap();
    let response = app.oneshot(axum::http::Request::builder()
        .method("PUT")
        .uri("/admin/streaming/servers/plex")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::USER_AGENT, "streaming-route-test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"name":"Plex fixture","url":"http://127.0.0.1:32400","api_key":"plex-fixture-7799","enabled":false}"#))
        .unwrap()
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["message"], "Plex server configuration saved");
    assert_eq!(response["server"]["provider"], "plex");
    assert_eq!(response["server"]["name"], "Plex fixture");
    assert_eq!(response["server"]["apiKeyMasked"], "****7799");

    let reader = af_db::get_read_conn().unwrap();
    let (name, url, key, enabled): (String, String, String, bool) = reader
        .query_row(
            "SELECT name, url, api_key, enabled FROM streaming_servers WHERE provider = 'plex'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(name, "Plex fixture");
    assert_eq!(url, "http://127.0.0.1:32400");
    assert_ne!(key, "plex-fixture-7799");
    assert_eq!(af_db::decrypt_key(&key).unwrap(), "plex-fixture-7799");
    assert!(!enabled);
    assert!(reader.query_row(
        "SELECT EXISTS(SELECT 1 FROM admin_audit_log WHERE user_id = 49 AND action = 'streaming_server_update' AND target_type = 'streaming_server' AND target_id = 'plex')",
        [],
        |row| row.get::<_, bool>(0),
    ).unwrap());
}

#[tokio::test]
async fn google_login_and_callback_share_the_oidc_rate_limit() {
    use crate::plugins::tests::run_plugin_test_in_subprocess;
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    env::remove_var("AF_DISABLE_RATELIMIT");
    let router = super::super::build_v1_router();
    for _ in 0..20 {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/public/auth/google/callback")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }
    for operation in ["login", "callback"] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/public/auth/google/{operation}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn account_endpoints_report_sqlite_failures() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::extract::Extension;
    use axum::http::StatusCode;

    if run_plugin_test_in_subprocess() {
        return;
    }
    let admin = super::super::AuthUser {
        user_id: 891,
        username: "account-endpoint-fixture".into(),
        role: "admin".into(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    assert_eq!(
        super::super::get_users(Extension(admin.clone()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        super::super::delete_avatar(Extension(admin.clone()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    ensure_shared_test_db();
    af_db::get_conn()
        .unwrap()
        .execute_batch(
            "INSERT INTO users(id, username, role, avatar_url) \
             VALUES(891, 'account-endpoint-fixture', 'admin', '/avatar.png');
             CREATE TRIGGER reject_avatar_write BEFORE UPDATE OF avatar_url ON users
             BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END;",
        )
        .unwrap();
    assert_eq!(
        super::super::get_users(Extension(admin.clone()))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        super::super::delete_avatar(Extension(admin.clone()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    af_db::get_conn()
        .unwrap()
        .execute_batch(
            "DROP TRIGGER reject_avatar_write;
             UPDATE users SET totp_enabled = 'invalid-bool' WHERE id = 891;",
        )
        .unwrap();
    assert_eq!(
        super::super::get_users(Extension(admin.clone()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        super::super::delete_avatar(Extension(admin)).await.status(),
        StatusCode::OK
    );
}
